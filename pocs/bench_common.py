#!/usr/bin/env python3
"""The one definition of the packet-backend benchmark, shared by every platform driver.

Every backend is run through the same scenarios, with the same traffic, the same measurements and the same report, so that rows
from different backends and operating systems can be put side by side. A driver (pocs/windivert_benchmark/bench.py,
pocs/linux_kernel_module_backend/bench.py) only decides HOW to start a scenario for its backend; WHAT is run and measured, and how
it is summarized and printed, lives here. See research/benchmark_strategy.md for the rationale.

Combine result files of several machines into one report:

    python pocs/bench_common.py report build/benchmarks/*.json
"""
import argparse
import datetime
import json
import os
import platform
import re
import statistics
import sys

PORT = 9000

# ---- traffic: identical for all backends --------------------------------------------------------------------------------
DEFAULT_PPS = [20000, 100000]  # 20 kpps is game scale, 100 kpps saturates (a stress row, not a game-relevant one)
DEFAULT_SIZES = [64, 1200]  # UDP payload bytes
DEFAULT_SECONDS = 5
DEFAULT_RUNS = 3  # every cell is the median of this many runs
BATCH = 16  # packets per receive/verdict call in the *-batch scenario
HOLD_MS = 2  # delay of the hold2ms scenario

# ---- scenarios: identical for all backends ------------------------------------------------------------------------------
# reader: a backend is attached; hold: packets are stolen and need a verdict; delay_ms: verdict this long after capture;
# batch: verdicts/receives are grouped (BATCH packets on Windows, everything that one receive returned on Linux)
SCENARIOS = {
    "baseline": dict(reader=False, hold=False, delay_ms=0, batch=False, what="traffic only, no backend attached"),
    "sniff": dict(reader=True, hold=False, delay_ms=0, batch=False, what="copy of each packet, original is not held"),
    "hold0": dict(reader=True, hold=True, delay_ms=0, batch=False, what="hold, verdict at once, one call per packet"),
    "hold0-batch": dict(reader=True, hold=True, delay_ms=0, batch=True, what="hold, verdict at once, calls batched"),
    "hold2ms": dict(reader=True, hold=True, delay_ms=HOLD_MS, batch=False, what=f"hold, verdict {HOLD_MS} ms after capture"),
}

# Which scenarios each backend can run; a missing one is reported as n/a with the reason, never silently skipped
BACKENDS = {
    "none": dict(os=None, scenarios=["baseline"]),
    "windivert": dict(os="windows", scenarios=["sniff", "hold0", "hold0-batch", "hold2ms"]),
    "nfqueue": dict(os="linux", scenarios=["hold0", "hold0-batch", "hold2ms"], na={"sniff": "NFQUEUE has no copy-only mode: every queued packet needs a verdict"}),
    "swdivert": dict(os="linux", scenarios=["sniff", "hold0", "hold0-batch", "hold2ms"]),
    "afpacket": dict(os="linux", scenarios=["sniff"], na={s: "AF_PACKET cannot hold packets" for s in ("hold0", "hold0-batch", "hold2ms")}),
}

# ---- measurements: identical for all backends ---------------------------------------------------------------------------
# Raw keys every driver must hand to summarize() per run (a missing key counts as 0):
#   flood:  sent, cpu_ms                                  sink: received, dups, reordered, corrupt, cpu_ms, lat_{p50,p99,p999,max}_us
#   reader: captured, cpu_ms, cap_/over_/send_{p50,p99,p999,max}_us
#   host:   busy_ms (host-wide CPU used during the flood)
# Latency timestamps come from the sender, the reader and the sink on ONE machine (CLOCK_MONOTONIC / QueryPerformanceCounter).
COLUMNS = [
    # key, header, meaning
    ("os", "os", "operating system"),
    ("backend", "backend", "none = no backend attached"),
    ("scenario", "scenario", "see SCENARIOS"),
    ("pps", "pps", "offered packets per second, one flow"),
    ("size", "size", "UDP payload bytes"),
    ("sent", "sent", "packets the sender wrote"),
    ("received", "recv", "packets the sink got"),
    ("lost", "lost", "sent - received: what the backend or the machine dropped"),
    ("dups", "dups", "packets the sink got twice"),
    ("reordered", "reord", "packets that arrived after a later one"),
    ("missed", "missed", "sent - captured: packets the backend never saw (n/a for baseline)"),
    ("lat_p50_us", "lat p50", "sender stamp -> sink, us: the end-to-end cost, read against baseline"),
    ("lat_p99_us", "lat p99", ""),
    ("lat_p999_us", "lat p99.9", ""),
    ("lat_max_us", "lat max", "worst of the runs"),
    ("cap_p50_us", "cap p50", "sender stamp -> backend reader saw the packet, us: kernel/driver side"),
    ("cap_p99_us", "cap p99", ""),
    ("over_p99_us", "over p99", "verdict due -> verdict call made, us: our scheduling (hold2ms only)"),
    ("send_p99_us", "send p99", "duration of one verdict call, us: re-injection"),
    ("reader_cpu_us", "reader cpu us/pkt", "backend reader process CPU per captured packet"),
    ("host_cpu_us", "host cpu us/pkt", "host-wide CPU minus sender and sink, per sent packet"),
    ("host_vs_base_us", "vs baseline", "host cpu us/pkt minus the baseline's for the same os, pps and size"),
]
MEDIAN_KEYS = ["sent", "received", "dups", "reordered", "captured", "lat_p50_us", "lat_p99_us", "lat_p999_us", "cap_p50_us", "cap_p99_us",
               "over_p99_us", "send_p99_us"]


def parse_kv(text):
    """`key=value` pairs of one tool output; later values win, so several lines are merged."""
    return {k: float(v) for k, v in re.findall(r"(\w+)=([0-9.]+)", text)}


def host_busy_ms():
    """Host-wide busy CPU time in ms, summed over all CPUs (everything that is not idle)."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        idle, kernel, user = wintypes.FILETIME(), wintypes.FILETIME(), wintypes.FILETIME()
        ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user))

        def ticks(f):
            return (f.dwHighDateTime << 32) | f.dwLowDateTime

        return (ticks(kernel) + ticks(user) - ticks(idle)) / 10000.0  # kernel time includes idle; 100 ns units
    with open("/proc/stat") as f:
        fields = [int(x) for x in f.readline().split()[1:]]
    user, nice, system, idle, iowait, irq, softirq, steal = fields[:8]
    return (user + nice + system + irq + softirq + steal) * 10.0


def machine_details():
    return {
        "time": datetime.datetime.now().isoformat(timespec="seconds"),
        "host": platform.node(),
        "os": "windows" if os.name == "nt" else "linux",
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpus": os.cpu_count(),
    }


def add_common_arguments(parser):
    parser.add_argument("--pps", default=",".join(map(str, DEFAULT_PPS)))
    parser.add_argument("--sizes", default=",".join(map(str, DEFAULT_SIZES)), help="UDP payload bytes")
    parser.add_argument("--seconds", type=int, default=DEFAULT_SECONDS)
    parser.add_argument("--runs", type=int, default=DEFAULT_RUNS)
    parser.add_argument("--scenarios", default=",".join(SCENARIOS), help="comma separated subset of: " + ", ".join(SCENARIOS))
    parser.add_argument("--json", help="also write the rows and the machine details to this file (see the `report` command)")


def parse_scenarios(text):
    names = [n for n in text.split(",") if n]
    for name in names:
        if name not in SCENARIOS:
            sys.exit(f"unknown scenario {name}: use {', '.join(SCENARIOS)}")
    return names


def summarize(os_name, backend, scenario, pps, size, runs, base_host_us=None):
    """One row from the per-run raw dicts: the median over the runs, except lat_max (the worst) and the host cost (median of ratios)."""
    def med(key):
        return statistics.median(r.get(key, 0.0) for r in runs)

    row = {"os": os_name, "backend": backend, "scenario": scenario, "pps": pps, "size": size, "runs": len(runs), "status": "ok"}
    for key in MEDIAN_KEYS:
        row[key] = med(key)
    row["lat_max_us"] = max(r.get("lat_max_us", 0.0) for r in runs)
    sent, captured = row["sent"], row["captured"]
    row["lost"] = sent - row["received"]
    row["missed"] = None if backend == "none" else sent - captured
    row["reader_cpu_us"] = None if backend == "none" or not captured else med("reader_cpu_ms") * 1000.0 / captured
    row["host_cpu_us"] = statistics.median((r.get("busy_ms", 0.0) - r.get("flood_cpu_ms", 0.0) - r.get("sink_cpu_ms", 0.0)) * 1000.0 / max(r.get("sent", 0.0), 1.0) for r in runs)
    row["host_vs_base_us"] = None if base_host_us is None else row["host_cpu_us"] - base_host_us
    return row


def na_row(os_name, backend, scenario, pps, size, reason):
    return {"os": os_name, "backend": backend, "scenario": scenario, "pps": pps, "size": size, "status": "n/a: " + reason}


def fmt(value, key):
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.2f}" if key in ("reader_cpu_us", "host_cpu_us", "host_vs_base_us") else f"{value:.0f}"
    return str(value)


def render(rows, details=None):
    """The one report format: a header, one markdown table with COLUMNS, then the n/a reasons and the column legend."""
    order = list(BACKENDS)
    scenarios = list(SCENARIOS)
    rows = sorted(rows, key=lambda r: (r["size"], r["pps"], r["os"], order.index(r["backend"].split("@")[0]), r["backend"], scenarios.index(r["scenario"])))
    lines = []
    for d in details or []:
        lines.append(f"# {d.get('host')} {d.get('platform')} {d.get('cpus')} cpus, {d.get('time')}")
    lines.append("| " + " | ".join(c[1] for c in COLUMNS) + " |")
    lines.append("|" + "---|" * len(COLUMNS))
    reasons = {}
    for r in rows:
        if r["status"] != "ok":
            reasons[(r["backend"], r["scenario"])] = r["status"][5:]
            cells = [r["os"], r["backend"], r["scenario"], str(r["pps"]), str(r["size"])] + ["n/a"] * (len(COLUMNS) - 5)
        else:
            cells = [fmt(r.get(c[0]), c[0]) for c in COLUMNS]
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")
    lines.append("Each cell is the median of the runs (lat max: the worst). Latencies in microseconds; hold2ms adds %d ms (%d us) by design." % (HOLD_MS, HOLD_MS * 1000))
    for (backend, scenario), reason in sorted(reasons.items()):
        lines.append(f"n/a: {backend} {scenario}: {reason}")
    lines.append("Columns: " + "; ".join(f"{c[1]} = {c[2]}" for c in COLUMNS if c[2]))
    return "\n".join(lines)


def write_json(path, details, rows):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"details": details, "rows": rows}, f, indent=1)


def load_rows(paths):
    rows, details = [], []
    for path in paths:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        details.append(data["details"])
        rows.extend(data["rows"])
    return rows, details


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    report = sub.add_parser("report", help="print the unified table for one or more --json result files")
    report.add_argument("files", nargs="+")
    args = parser.parse_args()
    rows, details = load_rows(args.files)
    print(render(rows, details))


if __name__ == "__main__":
    main()
