#!/usr/bin/env python3
"""WinDivert side of the packet-backend benchmark. Counterpart of pocs/linux_kernel_module_backend/bench.py: both run the scenarios,
take the measurements and print the report defined in pocs/bench_common.py (see research/benchmark_strategy.md).

Needs an elevated shell:

    xmake build wdbench
    python pocs/windivert_benchmark/bench.py
    python pocs/windivert_benchmark/bench.py --pps 20000 --sizes 64 --runs 1 --seconds 3 --dst 192.168.1.20

Traffic is UDP from wdbench flood to wdbench sink on loopback (or a local interface address with --dst), diverted at the network
layer. Read it like this:
  lat_*  hold scenarios minus baseline   total cost of diverting a packet
  cap_*                                  driver latency (stack -> WinDivertRecv)
  send_*                                 driver re-injection time
  over_p99 (hold2ms)                     our own scheduling jitter
  reordered / lost                       reordering and loss introduced by diverting
"""
import argparse
import glob
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import bench_common as common  # noqa: E402

ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))


def is_elevated():
    import ctypes

    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def find_wdbench(explicit):
    if explicit:
        return explicit
    found = sorted(glob.glob(os.path.join(ROOT, "build", "windows", "**", "wdbench.exe"), recursive=True), key=os.path.getmtime)
    if not found:
        sys.exit("wdbench.exe not found; run: xmake build wdbench")
    return found[-1]


def log(text):
    print(time.strftime("[%H:%M:%S] ") + text, file=sys.stderr, flush=True)


def start(exe, *args):
    return subprocess.Popen([exe] + [str(a) for a in args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def wait_ready(proc, what):
    line = proc.stdout.readline().strip()
    if line != "ready":
        sys.exit(f"{what} did not start: {line!r} {proc.stderr.read().strip()}")


def reader_args(scenario):
    spec = common.SCENARIOS[scenario]
    if not spec["hold"]:
        return ["--sniff", "yes"]
    return ["--delay-ms", spec["delay_ms"], "--batch", common.BATCH if spec["batch"] else 1]


def run_once(exe, scenario, pps, size, seconds, dst):
    sink = start(exe, "sink", "--port", common.PORT, "--seconds", seconds + 3)
    wait_ready(sink, "sink")
    reader = None
    if common.SCENARIOS[scenario]["reader"]:
        reader = start(exe, "hold", "--port", common.PORT, "--seconds", seconds + 2, *reader_args(scenario))
        time.sleep(0.8)  # WinDivertOpen has no ready signal
    busy0 = common.host_busy_ms()
    flood = subprocess.run([exe, "flood", "--dst", dst, "--port", str(common.PORT), "--pps", str(pps), "--seconds", str(seconds), "--size", str(size)],
                           capture_output=True, text=True)
    busy1 = common.host_busy_ms()
    if flood.returncode != 0:
        sys.exit("flood failed: " + flood.stderr.strip())
    sent = common.parse_kv(flood.stdout)
    out = {"sent": sent.get("sent", 0), "flood_cpu_ms": sent.get("cpu_ms", 0.0), "busy_ms": busy1 - busy0}
    if reader is not None:
        text, err = reader.communicate()
        if reader.returncode != 0:
            sys.exit("hold reader failed: " + err.strip())
        values = common.parse_kv(text)
        out.update({k: v for k, v in values.items() if k.startswith(("cap_", "over_", "send_"))})
        out["captured"] = values.get("captured", 0)
        out["reader_cpu_ms"] = values.get("cpu_ms", 0.0)
    text, err = sink.communicate()
    values = common.parse_kv(text)
    out["received"] = values.get("received", 0)
    out["sink_cpu_ms"] = values.get("cpu_ms", 0.0)
    out.update({k: v for k, v in values.items() if k.startswith("lat_") or k in ("dups", "reordered", "corrupt")})
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    common.add_common_arguments(parser)
    parser.add_argument("--dst", default="127.0.0.1", help="loopback by default; a local interface address exercises the NIC path")
    parser.add_argument("--exe", help="path of wdbench.exe")
    args = parser.parse_args()
    if not is_elevated():
        sys.exit("WinDivert needs an elevated shell")
    exe = find_wdbench(args.exe)
    pps_list = [int(v) for v in args.pps.split(",")]
    sizes = [int(v) for v in args.sizes.split(",")]
    scenarios = [s for s in common.SCENARIOS if s in common.parse_scenarios(args.scenarios)]  # baseline first: the others are read against it

    log(f"using {exe}; checking that WinDivert can be opened (1 s) ...")
    probe = subprocess.run([exe, "hold", "--port", str(common.PORT), "--seconds", "1"], capture_output=True, text=True)
    if probe.returncode != 0:
        sys.exit("WinDivert could not be opened by wdbench:\n" + probe.stderr)

    rows = []
    total = len(pps_list) * len(sizes) * len(scenarios)
    n = 0
    for size in sizes:
        for pps in pps_list:
            base = None
            for scenario in scenarios:
                n += 1
                log(f"scenario {n}/{total}: {scenario} at {pps} pps, {size} B, {args.runs} run(s) of {args.seconds} s")
                results = [run_once(exe, scenario, pps, size, args.seconds, args.dst) for _ in range(args.runs)]
                backend = "none" if scenario == "baseline" else "windivert"
                row = common.summarize("windows", backend, scenario, pps, size, results, base)
                if scenario == "baseline":
                    base = row["host_cpu_us"]
                    row["host_vs_base_us"] = 0.0
                rows.append(row)
    details = common.machine_details()
    details["parameters"] = dict(pps=pps_list, sizes=sizes, seconds=args.seconds, runs=args.runs, scenarios=scenarios, dst=args.dst)
    print(common.render(rows, [details]))
    if args.json:
        common.write_json(args.json, details, rows)


if __name__ == "__main__":
    main()
