#!/usr/bin/env python3
"""Latency per egress interface (ethernet, wlan, ProtonVPN, ...), with and without a packet diverter in the path.
Works on Windows and Linux; compares with research/packet_backend_comparison.md.

  list                       the interfaces that can be used as an egress
  probe                      round-trip time of UDP queries sent out of each egress (this machine's own traffic)
  hold                       run the diverter on the FORWARD path of this host while a client behind it is probed
  echo                       a UDP echo server, for --target echo:HOST:PORT
  compare                    print saved result files together

Probe (needs no privileges; --hold needs an elevated shell / root and the diverter built: `xmake build wdbench` or `swbench`):
    python pocs/egress_benchmark/egress.py list
    python pocs/egress_benchmark/egress.py probe                         # every interface that has an IPv4 address
    python pocs/egress_benchmark/egress.py probe --egress wlan="WiFi 2" --egress proton=ProtonVPN --egress eth=Ethernet
    python pocs/egress_benchmark/egress.py probe --hold 0 --hold 2       # also with a verdict after 0 ms and after 2 ms

Forwarded traffic (a client behind this host, whose traffic leaves through whatever egress the host routes it to):
  1. on the host, per egress:   python pocs/egress_benchmark/egress.py hold --egress ProtonVPN --seconds 60 [--client-ip 192.168.137.2]
  2. on the client, at once:    python pocs/egress_benchmark/egress.py probe --default via-proton --count 400
  3. repeat 1-2 after switching the host's egress (wlan, ethernet, proton); `compare` merges the saved results.
  `hold` prints how many packets the diverter captured: 0 means the client's traffic never took the forward path.
  On Windows the forward filter selects the egress with `ifIdx`; the Linux filter has no interface field, so there it
  matches the client's address (and the egress is whatever the host routes it to).

The probe sends DNS A queries (default `dns:1.1.1.1`) so that no server of your own is needed; a reply is matched by its id,
and no reply within --timeout counts as lost. With `--target echo:HOST:PORT` it uses `echo` instead (payload: timestamp
and sequence number). The egress is forced per socket: IP_UNICAST_IF on Windows, SO_BINDTODEVICE on Linux (root).
"""
import argparse
import datetime
import glob
import json
import os
import platform
import re
import socket
import statistics
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
IS_WINDOWS = os.name == "nt"
OUT_DIR = os.path.join(ROOT, "build", "benchmarks")


class Iface:
    def __init__(self, name, index, ip):
        self.name, self.index, self.ip = name, index, ip

    @property
    def kind(self):
        lowered = self.name.lower()
        if re.search(r"proton|wireguard|wg\d|tun\d|tap|ppp|vpn", lowered):
            return "vpn"
        if re.search(r"wi-?fi|wlan|wl[a-z0-9]+|wireless", lowered):
            return "wlan"
        return "ethernet" if re.search(r"eth|^en|local area", lowered) else "other"


def interfaces():
    found = []
    if IS_WINDOWS:
        script = "Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,InterfaceIndex,IPAddress | ConvertTo-Json"
        out = subprocess.run(["powershell", "-NoProfile", "-Command", script], capture_output=True, text=True).stdout
        rows = json.loads(out) if out.strip() else []
        for row in rows if isinstance(rows, list) else [rows]:
            found.append(Iface(row["InterfaceAlias"], int(row["InterfaceIndex"]), row["IPAddress"]))
    else:
        out = subprocess.run(["ip", "-j", "-4", "addr", "show", "up"], capture_output=True, text=True).stdout
        for row in json.loads(out) if out.strip() else []:
            for addr in row.get("addr_info", []):
                found.append(Iface(row["ifname"], int(row["ifindex"]), addr["local"]))
    return [i for i in found if not i.ip.startswith(("127.", "169.254."))]


def find_interface(wanted):
    for iface in interfaces():
        if wanted.lower() in (iface.name.lower(), iface.ip, str(iface.index)):
            return iface
    sys.exit(f"interface '{wanted}' not found or has no usable IPv4 address (see: egress.py list)")


def open_socket(iface):
    """A UDP socket whose traffic leaves through `iface`, or one on the default route when iface is None."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if iface is not None:
        if IS_WINDOWS:
            sock.setsockopt(socket.IPPROTO_IP, 31, socket.htonl(iface.index))  # IP_UNICAST_IF, network byte order
        else:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.name.encode())
        sock.bind((iface.ip, 0))
    return sock


def dns_query(ident):
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)


def probe_once(sock, target, seq, timeout):
    kind, host, port = target
    if kind == "dns":
        payload, key = dns_query(seq & 0xFFFF), seq & 0xFFFF
    else:
        payload, key = struct.pack("!QQ", time.perf_counter_ns(), seq) + b"x" * 48, seq
    start = time.perf_counter()
    sock.sendto(payload, (host, port))
    deadline = start + timeout
    while True:
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            return None
        sock.settimeout(remaining)
        try:
            data, _ = sock.recvfrom(2048)
        except (socket.timeout, OSError):
            return None
        if kind == "dns":
            got = struct.unpack("!H", data[:2])[0] if len(data) >= 2 else -1
        else:
            got = struct.unpack("!Q", data[8:16])[0] if len(data) >= 16 else -1
        if got == key:
            return (time.perf_counter() - start) * 1000.0


def run_probe(iface, target, count, interval, timeout):
    sock = open_socket(iface)
    samples, lost = [], 0
    started = time.perf_counter()
    for seq in range(count):
        rtt = probe_once(sock, target, seq, timeout)
        if rtt is None:
            lost += 1
        else:
            samples.append(rtt)
        slack = (seq + 1) * interval - (time.perf_counter() - started)
        if slack > 0:
            time.sleep(slack)
    sock.close()
    return summarize(samples, lost, count)


def summarize(samples, lost, count):
    result = {"sent": count, "lost": lost}
    if samples:
        ordered = sorted(samples)

        def pct(p):
            return ordered[min(len(ordered) - 1, int(p * (len(ordered) - 1)))]

        jitter = statistics.mean(abs(a - b) for a, b in zip(samples, samples[1:])) if len(samples) > 1 else 0.0
        result.update(p50=pct(0.50), p95=pct(0.95), p99=pct(0.99), max=ordered[-1], mean=statistics.mean(samples), jitter=jitter)
    return result


def parse_target(text):
    parts = text.split(":")
    if parts[0] == "dns" and len(parts) >= 2:
        return ("dns", parts[1], int(parts[2]) if len(parts) > 2 else 53)
    if parts[0] == "echo" and len(parts) == 3:
        return ("echo", parts[1], int(parts[2]))
    sys.exit("--target must be dns:IP[:PORT] or echo:HOST:PORT")


def find_binary(name):
    pattern = os.path.join(ROOT, "build", "windows" if IS_WINDOWS else "linux", "**", name + (".exe" if IS_WINDOWS else ""))
    found = sorted(glob.glob(pattern, recursive=True), key=os.path.getmtime)
    return found[-1] if found else None


def is_elevated():
    if IS_WINDOWS:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return os.geteuid() == 0


def diverter_command(filter_text, delay_ms, seconds, layer):
    """The diverter that matches this OS: wdbench hold (WinDivert) or `swbench backend` (the real kmod/NFQUEUE backend)."""
    if IS_WINDOWS:
        exe = find_binary("wdbench")
        if not exe:
            sys.exit("wdbench not found: xmake build wdbench")
        return [exe, "hold", "--layer", layer, "--filter", filter_text, "--delay-ms", str(delay_ms), "--seconds", str(seconds)]
    exe = find_binary("swbench")
    if not exe:
        sys.exit("swbench not found: xmake build swbench")
    command = [exe, "backend", "--filter", filter_text, "--delay-ms", str(delay_ms), "--seconds", str(seconds)]
    return command + (["--forward", "yes"] if layer == "forward" else [])


def parse_pairs(text):
    return {k: float(v) for k, v in re.findall(r"(\w+)=([\d.]+)", text)}


def start_diverter(filter_text, delay_ms, seconds, layer):
    command = diverter_command(filter_text, delay_ms, seconds, layer)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
    time.sleep(1.5 if IS_WINDOWS else 3.0)  # no ready signal while it opens
    if process.poll() is not None:
        sys.exit("the diverter exited at once:\n" + process.stdout.read())
    return process


def finish_diverter(process):
    try:
        out, _ = process.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        process.kill()
        out, _ = process.communicate()
    return parse_pairs(out), out


def fmt(value, digits=2):
    return "-" if value is None else f"{value:.{digits}f}"


def print_table(rows):
    header = ["egress", "kind", "variant", "sent", "lost", "p50 ms", "p95 ms", "p99 ms", "max ms", "jitter ms", "diverted", "cap p99 us"]
    table = [header]
    for r in rows:
        table.append([r["egress"], r.get("kind", ""), r["variant"], str(r["sent"]), str(r["lost"]), fmt(r.get("p50")), fmt(r.get("p95")),
                      fmt(r.get("p99")), fmt(r.get("max")), fmt(r.get("jitter")), fmt(r.get("diverted"), 0), fmt(r.get("cap_p99_us"), 0)])
    widths = [max(len(row[i]) for row in table) for i in range(len(header))]
    for row in table:
        print("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))


def save(rows, label):
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, f"egress-{platform.node()}-{label}-{datetime.datetime.now():%Y%m%d-%H%M%S}.json")
    with open(path, "w") as out:
        json.dump({"host": platform.node(), "os": platform.platform(), "time": datetime.datetime.now().isoformat(), "rows": rows}, out, indent=1)
    print(f"saved {path}")


def cmd_list(_args):
    print(f"{'name':32} {'index':>5}  {'ipv4':15}  kind")
    for iface in interfaces():
        print(f"{iface.name:32} {iface.index:>5}  {iface.ip:15}  {iface.kind}")


def cmd_probe(args):
    target = parse_target(args.target)
    targets = []  # (label, iface or None)
    if args.egress:
        for spec in args.egress:
            label, sep, name = spec.partition("=")
            targets.append((label if sep else spec, find_interface(name if sep else spec)))
    elif not args.default:
        targets = [(i.name, i) for i in interfaces()]
    for label in args.default or []:
        targets.append((label, None))
    delays = [int(v) for v in args.hold or []]
    if delays and not is_elevated():
        sys.exit("--hold needs an elevated shell / root")

    duration = args.count * args.interval / 1000.0 + args.timeout + 2
    rows = []
    for label, iface in targets:
        kind = iface.kind if iface else "default route"
        print(f"[probe] {label}: {iface.name + ' ' + iface.ip if iface else 'default route'} -> {args.target}, {args.count} queries", flush=True)
        variants = [("baseline", None)] + ([(f"hold{d}ms", d) for d in delays] if iface else [])
        for variant, delay in variants:
            if variant != "baseline" and rows and rows[-1]["egress"] == label and rows[-1]["variant"] == "baseline" and rows[-1]["lost"] == rows[-1]["sent"]:
                print(f"  {variant}: skipped, the baseline reached nothing through this egress")
                break
            process = None
            if delay is not None:
                filt = f"outbound and udp.DstPort == {target[2]} and ip.SrcAddr == {iface.ip}"
                process = start_diverter(filt, delay, int(duration) + 2, "network")
            result = run_probe(iface, target, args.count, args.interval / 1000.0, args.timeout)
            extra = {}
            if process:
                stats, _ = finish_diverter(process)
                extra = {"diverted": stats.get("captured"), "cap_p99_us": stats.get("cap_p99_us"), "send_p99_us": stats.get("send_p99_us")}
            rows.append({"egress": label, "kind": kind, "variant": variant, **result, **extra})
            print(f"  {variant}: p50 {fmt(result.get('p50'))} ms, p99 {fmt(result.get('p99'))} ms, lost {result['lost']}/{result['sent']}", flush=True)
            if result["lost"] == result["sent"]:
                print("  warning: every query was lost: no route from this interface to the target, a VPN kill switch or firewall blocking traffic outside the tunnel, or the network drops UDP/53 (try --target dns:IP of another resolver)")
            if process and not extra.get("diverted"):
                print("  warning: the diverter captured no packets; this variant says nothing about it")
    print()
    print_table(rows)
    save(rows, "probe")


def cmd_hold(args):
    if not is_elevated():
        sys.exit("hold needs an elevated shell / root")
    if args.filter:
        filter_text = args.filter
    else:
        clauses = ["outbound"] if IS_WINDOWS else []
        if args.egress and IS_WINDOWS:
            clauses.append(f"ifIdx == {find_interface(args.egress).index}")
        if args.client_ip:
            clauses.append(f"ip.SrcAddr == {args.client_ip}")
        clauses.append(f"udp.DstPort == {args.port}")
        filter_text = " and ".join(clauses)
    print(f"[hold] forward layer, filter: {filter_text}, verdict after {args.delay_ms} ms, {args.seconds} s: start the client probe now", flush=True)
    process = start_diverter(filter_text, args.delay_ms, args.seconds, "forward")
    stats, raw = finish_diverter(process)
    print(raw.strip())
    if not stats.get("captured"):
        print("captured 0 packets: the client's traffic did not take the forward path under this filter (routing, filter, or no traffic)")


def cmd_echo(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", args.port))
    print(f"echo on udp/{args.port}", flush=True)
    while True:
        data, peer = sock.recvfrom(2048)
        sock.sendto(data, peer)


def cmd_compare(args):
    rows = []
    for path in args.files:
        with open(path) as handle:
            doc = json.load(handle)
        for row in doc["rows"]:
            rows.append({**row, "egress": f"{doc['host']}:{row['egress']}"})
    print_table(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list").set_defaults(func=cmd_list)

    probe = sub.add_parser("probe")
    probe.add_argument("--egress", action="append", metavar="[LABEL=]INTERFACE", help="name, index or IPv4 of the interface; repeatable; default: all")
    probe.add_argument("--default", action="append", metavar="LABEL", help="also probe the default route under this label (what a client behind the host does)")
    probe.add_argument("--target", default="dns:1.1.1.1", help="dns:IP[:PORT] or echo:HOST:PORT")
    probe.add_argument("--count", type=int, default=200)
    probe.add_argument("--interval", type=float, default=50.0, help="ms between queries")
    probe.add_argument("--timeout", type=float, default=1.0, help="seconds before a query counts as lost")
    probe.add_argument("--hold", action="append", metavar="MS", help="also run with the diverter holding each packet MS ms (local path, network layer); repeatable")
    probe.set_defaults(func=cmd_probe)

    hold = sub.add_parser("hold")
    hold.add_argument("--egress", help="interface the forwarded traffic leaves through (Windows only: ifIdx filter)")
    hold.add_argument("--client-ip", help="the client's address")
    hold.add_argument("--port", type=int, default=53, help="destination UDP port of the probe traffic")
    hold.add_argument("--filter", help="WinDivert-style filter, replaces the generated one")
    hold.add_argument("--delay-ms", type=int, default=0)
    hold.add_argument("--seconds", type=int, default=60)
    hold.set_defaults(func=cmd_hold)

    echo = sub.add_parser("echo")
    echo.add_argument("--port", type=int, default=9100)
    echo.set_defaults(func=cmd_echo)

    compare = sub.add_parser("compare", help="print saved result files together")
    compare.add_argument("files", nargs="+")
    compare.set_defaults(func=cmd_compare)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
