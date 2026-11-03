#!/usr/bin/env python3
"""Phase 2 of pocs/linux_kernel_module_backend.md: functional check and cost comparison of capture-only sniffing of forwarded
traffic with the swdivert ring, AF_PACKET (TPACKET_V3) and NFQUEUE.

Build first:   xmake build swbench swdivert
Everything except `swdiv` needs no privileges (the rig lives in throw-away user+network namespaces):
    python3 pocs/linux_kernel_module_backend/bench.py --check
    python3 pocs/linux_kernel_module_backend/bench.py --modes baseline,afpacket,nfq --pps 20000,100000
`swdiv` needs the module loaded (`sudo insmod build/linux/x86_64/debug/swdivert.ko`) and real root, because /dev/swdivert is
root-only and the module is host-wide:
    sudo python3 pocs/linux_kernel_module_backend/bench.py --check --modes swdiv
    sudo python3 pocs/linux_kernel_module_backend/bench.py --pps 20000,100000

Topology (the process runs in the gateway namespace; client and server are child namespaces):
    client 10.10.1.2 --- vc 10.10.1.1 [gateway, ip_forward] 10.10.2.1 vs --- 10.10.2.2 server
Traffic: UDP client -> server:9000. The sniffers capture the forwarded packets that match udp dport 9000.
Cost: host-wide CPU (/proc/stat, all CPUs) minus the load generator's and the sink's own CPU, per sent packet (that is the
forwarding path, the capture hook and the sniffer together), and the sniffer process's own CPU per captured packet. The
host-wide number includes whatever else the machine is doing: use an idle machine and read it against `baseline`.

Scenarios, measurements and the report are the ones every backend shares (pocs/bench_common.py, research/benchmark_strategy.md):
baseline, sniff, hold0, hold0-batch, hold2ms; backends that cannot do a scenario (NFQUEUE sniff, AF_PACKET hold) print n/a.
`--json FILE` also saves the rows for `python pocs/bench_common.py report`.
"""
import argparse
import glob
import os
import platform
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import bench_common as common  # noqa: E402  the scenarios, measurements and report shared with every other backend

PORT = common.PORT
DECOY_PORT = 9001
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))


def find_swbench(explicit):
    if explicit:
        return explicit
    found = sorted(glob.glob(os.path.join(ROOT, "build", "linux", "*", "*", "swbench")), key=os.path.getmtime)
    if not found:
        sys.exit("swbench not found; run: xmake build swbench")
    return found[-1]


def reexec_in_namespaces():
    """Re-runs this script inside a new network namespace (and a user namespace when not root)."""
    cmd = ["unshare", "-n"] if os.geteuid() == 0 else ["unshare", "-Urn"]
    env = dict(os.environ, SWBENCH_INNER="1")
    os.execvpe(cmd[0], cmd + [sys.executable, os.path.abspath(__file__)] + sys.argv[1:], env)


def sh(*args, check=True, **kw):
    return subprocess.run(args, check=check, capture_output=True, text=True, **kw)


class Rig:
    def __init__(self, swbench):
        self.swbench = swbench
        self.ns = {}
        self.holders = []

    def start(self):
        sh("ip", "link", "set", "lo", "up")
        own = os.readlink("/proc/self/ns/net")
        for name, gw_ip, peer_ip in (("client", "10.10.1.1", "10.10.1.2"), ("server", "10.10.2.1", "10.10.2.2")):
            holder = subprocess.Popen(["unshare", "-n", "sleep", "infinity"])
            self.holders.append(holder)
            deadline = time.time() + 5
            while os.readlink(f"/proc/{holder.pid}/ns/net") == own:
                if time.time() > deadline:
                    sys.exit("could not create the " + name + " namespace")
                time.sleep(0.01)
            self.ns[name] = holder.pid
            gw_dev, peer_dev = ("vc", "c0") if name == "client" else ("vs", "s0")
            sh("ip", "link", "add", gw_dev, "type", "veth", "peer", "name", peer_dev)
            sh("ip", "link", "set", peer_dev, "netns", str(holder.pid))
            sh("ip", "addr", "add", gw_ip + "/24", "dev", gw_dev)
            sh("ip", "link", "set", gw_dev, "up")
            self.exec(name, "ip", "link", "set", "lo", "up")
            self.exec(name, "ip", "addr", "add", peer_ip + "/24", "dev", peer_dev)
            self.exec(name, "ip", "link", "set", peer_dev, "up")
            self.exec(name, "ip", "route", "add", "default", "via", gw_ip)
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        # Prime ARP and routes so the first measured packets are not lost
        if shutil.which("ping"):
            self.exec("client", "ping", "-c", "2", "-W", "1", "10.10.2.2", check=False)

    def stop(self):
        for holder in self.holders:
            holder.terminate()
        for holder in self.holders:
            holder.wait()

    def argv(self, name, *args):
        return ["nsenter", "-t", str(self.ns[name]), "-n"] + list(args)

    def exec(self, name, *args, check=True):
        return sh(*self.argv(name, *args), check=check)

    def popen(self, name, *args, **kw):
        return subprocess.Popen(self.argv(name, *args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kw)


def wait_ready(proc, what):
    line = proc.stdout.readline().strip()
    if line != "ready":
        err = proc.stderr.read()
        sys.exit(f"{what} did not start: {line!r} {err.strip()}")


parse_kv = common.parse_kv
busy_ms = common.host_busy_ms


NFT_RULE = """
table ip swb {
  chain sniffchain {
    type filter hook forward priority -150; policy accept;
    udp dport %d queue flags bypass num 0
  }
}
"""


PARAMS = "/sys/module/swdivert/parameters/"
SWDIV_MODE = re.compile(r"^swdiv(?:_legacy|@(\d+)(?::(\d+))?)?$")


def set_param(path, value):
    with open(path, "w") as f:
        f.write(str(value))


def reader_for(mode, scenario):
    """The swbench sniff mode and arguments that realize a common scenario for a backend mode (None: not possible)."""
    if scenario == "baseline":
        return None
    spec = common.SCENARIOS[scenario]
    hold_args = ["--delay-ms", str(spec["delay_ms"]), "--batch", "yes" if spec["batch"] else "no"]
    if mode == "afpacket":
        return ("afpacket", []) if not spec["hold"] else None
    if mode == "nfq":
        return ("nfq-hold", hold_args) if spec["hold"] else None
    return ("swdiv-hold", hold_args) if spec["hold"] else ("swdiv", [])


def run_once(rig, mode, pps, size, seconds, snap=224, slots=16384, decoy=False, scenario=None):
    # swdiv@US[:BATCH] is the ring sniffer with module parameters wake_us=US (and wake_batch=BATCH) for that run only;
    # swdiv_legacy is swdiv@0, the wake-up per packet. Plain `swdiv` uses whatever the module currently has.
    match = SWDIV_MODE.match(mode)
    if match and mode != "swdiv":
        wake_us = 0 if mode == "swdiv_legacy" else int(match.group(1))
        saved = {name: open(PARAMS + name).read().strip() for name in ("wake_us", "wake_batch")}
        set_param(PARAMS + "wake_us", wake_us)
        if match.group(2):
            set_param(PARAMS + "wake_batch", match.group(2))
        try:
            return run_once(rig, "swdiv", pps, size, seconds, snap, slots, decoy, scenario)
        finally:
            for name, value in saved.items():
                set_param(PARAMS + name, value)
    # The functional check passes no scenario: the plain sniff mode of the backend
    reader = (mode, []) if scenario is None else reader_for(mode, scenario)
    sink = rig.popen("server", rig.swbench, "sink", "--port", str(PORT))
    wait_ready(sink, "sink")
    sniffer = None
    if mode != "baseline" and reader is not None:
        cmd = [rig.swbench, "sniff", "--mode", reader[0], "--port", str(PORT), "--iface", "vc", "--snap", str(snap), "--slots", str(slots)] + reader[1]
        sniffer = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        wait_ready(sniffer, mode + " sniffer")
        if mode == "nfq":
            subprocess.run(["nft", "-f", "-"], input=NFT_RULE % PORT, text=True, check=True)
    try:
        decoy_proc = None
        if decoy:
            decoy_proc = rig.popen("client", rig.swbench, "flood", "--dst", "10.10.2.2", "--port", str(DECOY_PORT), "--pps", "500", "--seconds", str(seconds), "--size", "100")
        busy0 = busy_ms()
        flood = rig.popen("client", rig.swbench, "flood", "--dst", "10.10.2.2", "--port", str(PORT), "--pps", str(pps), "--seconds", str(seconds), "--size", str(size))
        sent = parse_kv(flood.communicate()[0])
        busy1 = busy_ms()
        if decoy_proc:
            decoy_proc.communicate()
        time.sleep(0.4)
    finally:
        if mode == "nfq":
            subprocess.run(["nft", "delete", "table", "ip", "swb"], check=False)
    out = {"sent": sent.get("sent", 0), "failed": sent.get("failed", 0), "busy_ms": busy1 - busy0, "flood_cpu_ms": sent.get("cpu_ms", 0.0)}
    for proc, key in ((sniffer, "sniff"), (sink, "sink")):
        if proc is None:
            continue
        proc.send_signal(2)
        text, err = proc.communicate(timeout=10)
        if proc.returncode != 0:
            sys.exit(f"{key} failed: {err.strip()}")
        values = parse_kv(text)
        if key == "sink":
            out["recv"] = values.get("received", 0)
            out["sink_cpu_ms"] = values.get("cpu_ms", 0.0)
            out.update({k: v for k, v in values.items() if k.startswith("lat_") or k in ("dups", "reordered", "corrupt")})
        else:
            out.update(values)
            out["reader_cpu_ms"] = values.get("cpu_ms", 0.0)
    out["received"] = out.get("recv", 0)
    return out


def check(rig, modes, snap):
    failures = 0
    for mode in modes:
        if mode == "baseline":
            continue
        r = run_once(rig, mode, 2000, 400, 2, snap=snap, decoy=True)
        ok = r["sent"] > 0 and r.get("captured") == r["sent"] and r["recv"] == r["sent"] and r.get("dropped") == 0
        print(f"{'ok  ' if ok else 'FAIL'} {mode}: sent={int(r['sent'])} forwarded={int(r['recv'])} captured={int(r.get('captured', 0))} dropped={int(r.get('dropped', 0))}"
              " (a decoy flow to another port was running and must not be captured)")
        failures += not ok
        failures += check_killed_sniffer(rig, mode)
    return failures


def check_killed_sniffer(rig, mode):
    """A sniffer that dies without any cleanup (SIGKILL) must neither stop the forwarding nor leave anything behind."""
    sink = rig.popen("server", rig.swbench, "sink", "--port", str(PORT))
    wait_ready(sink, "sink")
    sniffer = subprocess.Popen([rig.swbench, "sniff", "--mode", mode, "--port", str(PORT), "--iface", "vc"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    wait_ready(sniffer, mode + " sniffer")
    if mode == "nfq":
        subprocess.run(["nft", "-f", "-"], input=NFT_RULE % PORT, text=True, check=True)
    try:
        first = rig.popen("client", rig.swbench, "flood", "--dst", "10.10.2.2", "--port", str(PORT), "--pps", "2000", "--seconds", "2", "--size", "100")
        time.sleep(1)
        sniffer.kill()
        sniffer.wait()
        sent = parse_kv(first.communicate()[0]).get("sent", 0)
        second = rig.popen("client", rig.swbench, "flood", "--dst", "10.10.2.2", "--port", str(PORT), "--pps", "2000", "--seconds", "1", "--size", "100")
        sent += parse_kv(second.communicate()[0]).get("sent", 0)
        time.sleep(0.4)
    finally:
        if mode == "nfq":
            subprocess.run(["nft", "delete", "table", "ip", "swb"], check=False)
    sink.send_signal(2)
    received = parse_kv(sink.communicate(timeout=10)[0]).get("received", 0)
    # NFQUEUE holds the packet until a verdict: when the listener dies, the kernel drops the packets that were waiting for one
    # (`bypass` only covers packets that arrive afterwards). A few in flight at 2 kpps is expected there; the sniff-only
    # paths never hold the original, so they must lose nothing.
    allowed = 5 if mode == "nfq" else 0
    lost = sent - received
    ok = sent > 0 and 0 <= lost <= allowed
    note = f" (in flight when the listener died: {int(lost)}, expected for NFQUEUE)" if mode == "nfq" and lost else ""
    print(f"{'ok  ' if ok else 'FAIL'} {mode} killed with SIGKILL while forwarding: sent={int(sent)} forwarded={int(received)}{note}")
    return not ok


BACKEND_OF = {"afpacket": "afpacket", "nfq": "nfqueue", "swdiv": "swdivert"}


def backend_label(mode):
    """swdiv_legacy and swdiv@US[:BATCH] are the swdivert backend with module parameters, reported as swdivert@..."""
    if mode == "swdiv_legacy":
        return "swdivert@0"
    return "swdivert@" + mode[len("swdiv@"):] if mode.startswith("swdiv@") else BACKEND_OF[mode]


def bench(rig, modes, pps_list, sizes, seconds, runs, snap, slots, scenarios, json_path):
    modes = [m for m in modes if m != "baseline"]  # the baseline is the `baseline` scenario, always run first
    scenarios = [s for s in common.SCENARIOS if s in scenarios]  # canonical order: baseline first, the others are read against it
    others = [s for s in scenarios if s != "baseline"]
    cells = len(pps_list) * len(sizes) * (("baseline" in scenarios) + len(modes) * len(others))
    print(f"# up to {cells} rows, {runs} run(s) of {seconds} s each: about {int(cells * runs * (seconds + 1.6) / 60) + 1} min.", file=sys.stderr)
    rows = []
    for size in sizes:
        for pps in pps_list:
            base = None
            if "baseline" in scenarios:
                results = [run_once(rig, "baseline", pps, size, seconds, snap, slots, scenario="baseline") for _ in range(runs)]
                row = common.summarize("linux", "none", "baseline", pps, size, results)
                base = row["host_cpu_us"]
                row["host_vs_base_us"] = 0.0
                rows.append(row)
            for mode in modes:
                backend = backend_label(mode)
                for scenario in scenarios:
                    if scenario == "baseline":
                        continue
                    if reader_for(mode.split("@")[0].split("_")[0], scenario) is None:
                        reason = common.BACKENDS[backend.split("@")[0]].get("na", {}).get(scenario, "not supported")
                        rows.append(common.na_row("linux", backend, scenario, pps, size, reason))
                        continue
                    results = [run_once(rig, mode, pps, size, seconds, snap, slots, scenario=scenario) for _ in range(runs)]
                    rows.append(common.summarize("linux", backend, scenario, pps, size, results, base))
    details = common.machine_details()
    details["kernel"] = platform.release()
    details["parameters"] = dict(pps=pps_list, sizes=sizes, seconds=seconds, runs=runs, snap=snap, slots=slots, scenarios=scenarios)
    print(common.render(rows, [details]))
    if json_path:
        common.write_json(json_path, details, rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--modes", default="afpacket,nfq,swdiv_legacy,swdiv", help="backends: afpacket, nfq, swdiv; swdiv@US[:BATCH] sets the module's wake_us/wake_batch for that run; swdiv_legacy = swdiv@0 (wake per packet); plain swdiv uses the current values. The baseline is the `baseline` scenario")
    common.add_common_arguments(parser)
    parser.add_argument("--snap", type=int, default=224, help="bytes of each packet that are copied (all modes)")
    parser.add_argument("--slots", type=int, default=16384)
    parser.add_argument("--check", action="store_true", help="functional check only (every mode must capture exactly what was sent)")
    parser.add_argument("--swbench")
    args = parser.parse_args()

    if os.environ.get("SWBENCH_INNER") != "1":
        reexec_in_namespaces()

    modes = args.modes.split(",")
    for mode in modes:
        if mode not in ("baseline", "afpacket", "nfq") and not SWDIV_MODE.match(mode):
            sys.exit(f"unknown mode {mode}: use afpacket, nfq, swdiv, swdiv_legacy or swdiv@WAKE_US[:WAKE_BATCH]")
    for swdiv_mode in [m for m in modes if m.startswith("swdiv")]:
        if not os.path.exists("/dev/swdivert"):
            print(f"note: /dev/swdivert not found, skipping {swdiv_mode} (load the module first)", file=sys.stderr)
            modes.remove(swdiv_mode)
        elif os.geteuid() != 0:
            print(f"note: {swdiv_mode} needs real root, skipping it", file=sys.stderr)
            modes.remove(swdiv_mode)

    rig = Rig(find_swbench(args.swbench))
    try:
        rig.start()
        if args.check:
            sys.exit(1 if check(rig, modes, args.snap) else 0)
        bench(rig, modes, [int(x) for x in args.pps.split(",")], [int(x) for x in args.sizes.split(",")], args.seconds, args.runs, args.snap, args.slots,
              common.parse_scenarios(args.scenarios), args.json)
    finally:
        rig.stop()


if __name__ == "__main__":
    main()
