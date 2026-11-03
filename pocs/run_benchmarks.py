#!/usr/bin/env python3
"""Runs every packet-backend benchmark that applies to the current system and saves one combined log, so the same command
covers both ends (see research/packet_backend_comparison.md):

    Windows (elevated shell):  python pocs/run_benchmarks.py
    Linux:                     python3 pocs/run_benchmarks.py        (sudo for the swdivert kernel module rows)

Windows runs pocs/windivert_benchmark/bench.ps1 (WinDivert). Linux runs pocs/linux_kernel_module_backend/bench.py
(baseline, AF_PACKET, NFQUEUE and, when run as root with swdivert.ko loaded, the kernel module). The sweep matches the
Linux defaults: rates 20000,100000, payloads 64,1200, 5 s per run, 3 runs.

    python3 pocs/run_benchmarks.py --quick        # 20000 pps, 64 B, 1 run: a short check of the whole chain
    python3 pocs/run_benchmarks.py --dry-run      # only print what would run
    python3 pocs/run_benchmarks.py --no-build     # use the binaries that are already built

The log goes to build/benchmarks/<host>-<os>-<time>.log, with the machine details at the top so two logs can be compared.
"""
import argparse
import ctypes
import datetime
import os
import platform
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
IS_WINDOWS = os.name == "nt"


class Log:
    def __init__(self, path):
        self.file = open(path, "w", encoding="utf-8")

    def write(self, text):
        sys.stdout.write(text)
        sys.stdout.flush()
        self.file.write(text)
        self.file.flush()

    def line(self, text=""):
        self.write(text + "\n")


def is_elevated():
    if IS_WINDOWS:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return os.geteuid() == 0


def module_loaded():
    try:
        with open("/proc/modules") as modules:
            return any(line.startswith("swdivert ") for line in modules)
    except OSError:
        return False


def machine_details():
    details = [
        ("time", datetime.datetime.now().isoformat(timespec="seconds")),
        ("host", platform.node()),
        ("os", platform.platform()),
        ("machine", platform.machine()),
        ("cpus", str(os.cpu_count())),
        ("python", platform.python_version()),
        ("elevated", str(is_elevated())),
    ]
    if not IS_WINDOWS:
        details.append(("kernel", platform.release()))
        details.append(("swdivert loaded", str(module_loaded())))
    return details


def run(log, command, dry_run, cwd=ROOT):
    log.line("$ " + " ".join(command))
    if dry_run:
        return 0
    started = time.time()
    process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
    for text in process.stdout:
        log.write(text)
    process.wait()
    log.line(f"[exit {process.returncode} after {time.time() - started:.0f} s]")
    return process.returncode


def build(log, targets, dry_run):
    if shutil.which("xmake") is None:
        log.line("xmake not found; skipping the build and using existing binaries")
        return True
    return run(log, ["xmake", "build"] + targets, dry_run) == 0


def windows_suite(log, args):
    if not is_elevated() and not args.dry_run:
        log.line("This shell is not elevated: WinDivert cannot be opened. Start an administrator shell and run again.")
        return 1
    if not args.no_build and not build(log, ["wdbench"], args.dry_run):
        log.line("build of wdbench failed")
        return 1
    script = os.path.join(ROOT, "pocs", "windivert_benchmark", "bench.ps1")
    failed = 0
    for size in args.sizes:
        for repeat in range(1, args.runs + 1):
            log.line(f"\n=== WinDivert: payload {size} B, run {repeat}/{args.runs} ===")
            command = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script, "-Pps", ",".join(map(str, args.pps)), "-Size", str(size), "-Seconds", str(args.seconds)]
            failed += run(log, command, args.dry_run) != 0
    return failed


def linux_suite(log, args):
    if not args.no_build:
        targets = ["swbench"] + (["swdivert"] if is_elevated() else [])
        if not build(log, targets, args.dry_run):
            log.line("build failed")
            return 1
    script = os.path.join(ROOT, "pocs", "linux_kernel_module_backend", "bench.py")
    modes = ["baseline", "afpacket", "nfq"]
    if is_elevated() and module_loaded():
        modes.append("swdiv")
    elif is_elevated():
        log.line("swdivert.ko is not loaded (sudo insmod build/linux/x86_64/<mode>/swdivert.ko): skipping the kernel module rows")
    else:
        log.line("not root: skipping the kernel module rows (they need real root and the module loaded)")
    log.line("modes: " + ",".join(modes))
    command = [sys.executable, script, "--modes", ",".join(modes), "--pps", ",".join(map(str, args.pps)), "--sizes", ",".join(map(str, args.sizes)), "--seconds", str(args.seconds), "--runs", str(args.runs)]
    log.line("\n=== Linux: functional check ===")
    failed = run(log, command[:2] + ["--check", "--modes", ",".join(modes)], args.dry_run) != 0
    log.line("\n=== Linux: benchmark ===")
    failed += run(log, command, args.dry_run) != 0
    return failed


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pps", default="20000,100000")
    parser.add_argument("--sizes", default="64,1200", help="UDP payload bytes")
    parser.add_argument("--seconds", type=int, default=5)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--quick", action="store_true", help="20000 pps, 64 B, 1 run, 3 s")
    parser.add_argument("--egress", action="store_true", help="also probe the latency of every egress interface (pocs/egress_benchmark/egress.py), with the diverter when elevated")
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--out", help="log file (default build/benchmarks/<host>-<os>-<time>.log)")
    args = parser.parse_args()
    if args.quick:
        args.pps, args.sizes, args.runs, args.seconds = "20000", "64", 1, 3
    args.pps = [int(v) for v in str(args.pps).split(",")]
    args.sizes = [int(v) for v in str(args.sizes).split(",")]

    out = args.out
    if not out:
        folder = os.path.join(ROOT, "build", "benchmarks")
        os.makedirs(folder, exist_ok=True)
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        out = os.path.join(folder, f"{platform.node()}-{'windows' if IS_WINDOWS else 'linux'}-{stamp}.log")
    log = Log(out)
    log.line("# packet backend benchmarks")
    for key, value in machine_details():
        log.line(f"{key}: {value}")
    log.line(f"parameters: pps={args.pps} sizes={args.sizes} seconds={args.seconds} runs={args.runs}")

    failed = windows_suite(log, args) if IS_WINDOWS else linux_suite(log, args)
    if args.egress:
        log.line("\n=== Egress latency per interface ===")
        egress = [sys.executable, os.path.join(HERE, "egress_benchmark", "egress.py"), "probe", "--count", "50" if args.quick else "200"]
        if is_elevated():
            egress += ["--hold", "0", "--hold", "2"]
        failed += run(log, egress, args.dry_run) != 0
    log.line(f"\nlog: {out}")
    log.line("all benchmarks finished" if not failed else f"{failed} step(s) failed, see above")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
