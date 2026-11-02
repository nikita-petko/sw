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
"""
import argparse
import glob
import os
import re
import shutil
import statistics
import subprocess
import sys
import time

PORT = 9000
DECOY_PORT = 9001
HERE = os.path.dirname(os.path.abspath(__file__))
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


def parse_kv(text):
    return {k: float(v) for k, v in re.findall(r"(\w+)=([0-9.]+)", text)}


def busy_ms():
    """Host-wide busy CPU time in ms (user, nice, system, irq, softirq, steal), summed over all CPUs."""
    with open("/proc/stat") as f:
        fields = [int(x) for x in f.readline().split()[1:]]
    user, nice, system, idle, iowait, irq, softirq, steal = fields[:8]
    return (user + nice + system + irq + softirq + steal) * 10.0


NFT_RULE = """
table ip swb {
  chain sniffchain {
    type filter hook forward priority -150; policy accept;
    udp dport %d queue flags bypass num 0
  }
}
"""


def run_once(rig, mode, pps, size, seconds, snap=224, slots=16384, decoy=False):
    sink = rig.popen("server", rig.swbench, "sink", "--port", str(PORT))
    wait_ready(sink, "sink")
    sniffer = None
    if mode != "baseline":
        cmd = [rig.swbench, "sniff", "--mode", mode, "--port", str(PORT), "--iface", "vc", "--snap", str(snap), "--slots", str(slots)]
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
        else:
            out.update(values)
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
    ok = sent > 0 and received == sent
    print(f"{'ok  ' if ok else 'FAIL'} {mode} killed with SIGKILL while forwarding: sent={int(sent)} forwarded={int(received)}")
    return not ok


def bench(rig, modes, pps_list, sizes, seconds, runs, snap, slots):
    rows = []
    for size in sizes:
        for pps in pps_list:
            base = None
            for mode in modes:
                results = [run_once(rig, mode, pps, size, seconds, snap, slots) for _ in range(runs)]

                def med(key):
                    return statistics.median(r.get(key, 0.0) for r in results)

                sent, recv, captured = med("sent"), med("recv"), med("captured")
                # Everything the host spent except the load generator and the sink: the forwarding path, the hook and the sniffer
                host_us = (med("busy_ms") - med("flood_cpu_ms") - med("sink_cpu_ms")) * 1000.0 / max(sent, 1)
                if mode == "baseline":
                    base = host_us
                rows.append((mode, pps, size, sent, recv, captured, med("dropped"), med("cpu_ms") * 1000.0 / captured if captured else 0.0,
                             host_us, host_us - base if base is not None else float("nan")))
    print("| mode | pps | size | sent | forwarded | captured | captured/sent | dropped | sniffer CPU us/captured pkt | forwarding+sniffing CPU us/pkt | vs baseline us/pkt |")
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    for mode, pps, size, sent, recv, captured, dropped, sniff_us, host_us, delta in rows:
        ratio = f"{100.0 * captured / sent:.1f}%" if mode != "baseline" and sent else "-"
        print(f"| {mode} | {pps} | {size} | {int(sent)} | {int(recv)} | {int(captured)} | {ratio} | {int(dropped)} | "
              f"{sniff_us:.2f} | {host_us:.2f} | {delta:+.2f} |")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--modes", default="baseline,afpacket,nfq,swdiv")
    parser.add_argument("--pps", default="20000,100000")
    parser.add_argument("--sizes", default="64,1200", help="UDP payload bytes")
    parser.add_argument("--seconds", type=int, default=5)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--snap", type=int, default=224, help="bytes of each packet that are copied (all modes)")
    parser.add_argument("--slots", type=int, default=16384)
    parser.add_argument("--check", action="store_true", help="functional check only (every mode must capture exactly what was sent)")
    parser.add_argument("--swbench")
    args = parser.parse_args()

    if os.environ.get("SWBENCH_INNER") != "1":
        reexec_in_namespaces()

    modes = args.modes.split(",")
    if "swdiv" in modes and not os.path.exists("/dev/swdivert"):
        print("note: /dev/swdivert not found, skipping swdiv (load the module first)", file=sys.stderr)
        modes.remove("swdiv")
    if "swdiv" in modes and os.geteuid() != 0:
        print("note: swdiv needs real root, skipping it", file=sys.stderr)
        modes.remove("swdiv")

    rig = Rig(find_swbench(args.swbench))
    try:
        rig.start()
        if args.check:
            sys.exit(1 if check(rig, modes, args.snap) else 0)
        bench(rig, modes, [int(x) for x in args.pps.split(",")], [int(x) for x in args.sizes.split(",")], args.seconds, args.runs, args.snap, args.slots)
    finally:
        rig.stop()


if __name__ == "__main__":
    main()
