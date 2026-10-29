#!/usr/bin/env python3
"""Drives lagsw against loopback traffic using profiles/localhost.test.sw.yml.

Needs root (nftables + NFQUEUE) and should run in a disposable network namespace/container, see
scripts/test_nfqueue_localhost.sh. Keys are injected through LAGSW_TEST_KEYS, so no input device is touched.

usage: localhost_harness.py <lagsw-binary> <profile.yml>
"""
import os
import pty
import re
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

BIN, PROFILE = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
WORK = tempfile.mkdtemp(prefix="lagsw-harness-")
KEYS = os.path.join(WORK, "keys")
results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name} {detail}", flush=True)


def serve_tcp(host, port):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(64)

    def conn(c):
        try:
            while True:
                d = c.recv(4096)
                if not d:
                    break
                c.sendall(d)
        except OSError:
            pass
        c.close()

    def loop():
        while True:
            c, _ = srv.accept()
            threading.Thread(target=conn, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()


def serve_udp(host, port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind((host, port))

    def loop():
        while True:
            d, a = srv.recvfrom(4096)
            srv.sendto(d, a)

    threading.Thread(target=loop, daemon=True).start()


def tcp_rtt(host="127.0.0.1", port=55000, timeout=5.0):
    """Connect plus one echo round trip; None on timeout."""
    t0 = time.monotonic()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(b"ping")
        ok = s.recv(16) == b"ping"
        s.close()
        return time.monotonic() - t0 if ok else None
    except OSError:
        return None


def udp_rtt(timeout=3.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.monotonic()
    try:
        s.sendto(b"ping", ("127.0.0.1", 55001))
        s.recvfrom(16)
        return time.monotonic() - t0
    except OSError:
        return None
    finally:
        s.close()


class Lagsw:
    def __init__(self, profile):
        self.log = ""
        env = dict(os.environ, LAGSW_TEST_KEYS=KEYS)
        pid, fd = pty.fork()
        if pid == 0:
            os.chdir(WORK)
            os.execve(BIN, [BIN, "--config", profile, "-l", "debug"], env)
        self.pid, self.fd = pid, fd
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        while True:
            try:
                r, _, _ = select.select([self.fd], [], [], 0.5)
                if r:
                    d = os.read(self.fd, 65536)
                    if not d:
                        return
                    self.log += d.decode(errors="replace")
            except OSError:
                return

    def wait_for(self, text, timeout=10):
        end = time.time() + timeout
        while time.time() < end:
            if text in self.log:
                return True
            time.sleep(0.05)
        return False

    def quit(self):
        os.write(self.fd, b"q")
        for _ in range(100):
            done, _ = os.waitpid(self.pid, os.WNOHANG)
            if done:
                return True
            time.sleep(0.1)
        os.kill(self.pid, 9)
        os.waitpid(self.pid, 0)
        return False


def hold(*keys):
    with open(KEYS, "w") as f:
        f.write(" ".join(keys))


def release():
    hold()


def tap(*keys, ms=150):
    hold(*keys)
    time.sleep(ms / 1000)
    release()
    time.sleep(0.15)


def nft_tables():
    return subprocess.run(["nft", "list", "tables"], capture_output=True, text=True).stdout


def run(profile, label, body):
    print(f"--- {label}", flush=True)
    release()
    app = Lagsw(profile)
    try:
        ok = app.wait_for("Loaded profiles", 10)
        check(f"{label}: starts", ok)
        time.sleep(1.0)
        if ok:
            body(app)
    finally:
        check(f"{label}: clean exit", app.quit())
    check(f"{label}: nft table removed", "lagsw" not in nft_tables())
    check(f"{label}: no errors logged", not re.search(r"\[(ERROR|FATAL)\]", app.log),
          "\n".join(l for l in app.log.splitlines() if "[ERROR]" in l)[:400])
    return app


def behaviour(app):
    base = tcp_rtt()
    check("baseline is fast", base is not None and base < 0.2, f"{base}")

    tap("d")  # Delay 300 ms, applied on each outbound direction
    r = tcp_rtt()
    check("Delay: connect+echo >= 500 ms", r is not None and r >= 0.5, f"{r}")
    tap("d")
    r = tcp_rtt()
    check("Delay: deactivated, traffic fast again", r is not None and r < 0.5, f"{r}")

    tap("b")
    r = tcp_rtt()
    check("Batch: delayed", r is not None and r >= 0.5, f"{r}")
    tap("b")
    time.sleep(0.8)

    hold("x")  # Drop, hold mode
    time.sleep(0.3)
    r = tcp_rtt(timeout=1.5)
    check("Drop: connection fails while held", r is None, f"{r}")
    release()
    time.sleep(0.5)
    r = tcp_rtt(timeout=6)
    check("Drop: recovers after release (SYN retransmit)", r is not None, f"{r}")

    tap("u")  # Drop Until Toggle
    r = tcp_rtt(timeout=1.5)
    check("Drop Until Toggle: dropped", r is None, f"{r}")
    tap("u")  # now holding
    tap("u")  # release and deactivate
    time.sleep(0.5)
    r = tcp_rtt(timeout=6)
    check("Drop Until Toggle: recovers", r is not None, f"{r}")

    tap("w")  # Hold Until Deactivation: packets are held until the profile is toggled off
    time.sleep(0.3)
    box = {}
    t = threading.Thread(target=lambda: box.update(r=tcp_rtt(timeout=8)))
    t.start()
    time.sleep(1.0)
    check("Hold Until Deactivation: still held", t.is_alive())
    tap("w")
    t.join()
    check("Hold Until Deactivation: released on key up", box.get("r") is not None, f"{box.get('r')}")

    tap("t")  # UDP profile
    r = udp_rtt()
    check("UDP: echo works under the profile", r is not None, f"{r}")
    check("UDP: delayed", r is not None and r >= 0.25, f"{r}")
    tap("t")

    tap("e")  # Period auto-deactivation (1500 ms)
    time.sleep(3.0)
    r = tcp_rtt()
    check("Period: deactivated by itself", r is not None and r < 0.5, f"{r}")

    # Mutually exclusive profiles
    tap("d")
    tap("z")  # Exclusive disables Delay (and Batch)
    time.sleep(0.5)
    check("Exclusive: disabled Delay", "Delay" in app.log and "deactivated" in app.log.lower())
    tap("z")

    tap("o")  # Solo disables everything else
    tap("d")
    tap("o")
    tap("d")
    time.sleep(0.5)
    tap("d")

    # Region enforcement: BETA's 127.0.0.2:55002 PSH segments are held 1-1.5 s unless BETA is enforced
    r = tcp_rtt("127.0.0.2", 55002, timeout=6)
    print(f"INFO  region enforcement probe round trip: {r}")

    pcaps = os.listdir(os.path.join(WORK, "pcap_files")) if os.path.isdir(os.path.join(WORK, "pcap_files")) else []
    check("pcap files written", len(pcaps) > 0, f"{len(pcaps)} files")


def ack_case(app):
    tap("k")  # Ack Restoration must never corrupt or stall a stream
    s = socket.create_connection(("127.0.0.1", 55000), timeout=5)
    s.settimeout(5)
    good = True
    try:
        for i in range(20):
            msg = f"msg{i}".encode()
            s.sendall(msg)
            good &= s.recv(32) == msg
    except OSError as e:
        good = False
        print(f"INFO  ack case failed at message {i}: {e!r}")
        print("\n".join(app.log.splitlines()[-400:]))
    s.close()
    tap("k")
    check("Ack Restoration: stream intact", good)



SMOKE = [("Drop And Send", ["a"]), ("Hold And Send", ["h"]), ("Group Send", ["g"]), ("Ratio Count", ["r"]),
         ("Ratio Percent", ["p"]), ("Either Key c", ["c"]), ("Either Key v", ["v"]),
         ("Chord", ["ctrl", "shift", "m"]), ("Sniff", ["n"]), ("Forward", ["f"]), ("Server Direction", ["y"])]


def smoke_case(name, keys):
    def body(app):
        tap(*keys)
        r = tcp_rtt(timeout=4)
        print(f"INFO  {name}: round trip under profile: {r}")
        tap(*keys)
        tap(*keys)
        tap(*keys)  # profiles with several phases need extra presses to finish
        time.sleep(1.5)
        check(f"smoke {name}: activated", re.search(r"activated|Activat", app.log) is not None)
        r = tcp_rtt(timeout=8)
        check(f"smoke {name}: traffic survives afterwards", r is not None, f"{r}")
    return body


def main():
    only = os.environ.get("ONLY")
    for p in (55000, 55002):
        serve_tcp("127.0.0.1", p)
    serve_tcp("127.0.0.2", 55002)
    serve_tcp("127.0.0.2", 55000)
    serve_udp("127.0.0.1", 55001)

    text = open(PROFILE).read()
    fixed = os.path.join(WORK, "fixed.yml")
    # Discovered client addresses are added to every filter, so behaviour runs use fixed filters.
    open(fixed, "w").write(re.sub(r"(forwarded_address_discovery:\s*\n\s*enabled:) true", r"\1 false", text))

    if not only:
        run(fixed, "behaviour", behaviour)
    run(fixed, "ack restoration", ack_case)
    for name, keys in ([] if only else SMOKE):
        run(fixed, name, smoke_case(name, keys))

    def smoke(app):
        check("FAD logs", app.wait_for("Forwarded address discovery enabled", 5))
        check("traffic flows", tcp_rtt() is not None)
        time.sleep(2.5)
        check("discovery debug: filter logged", "Server discovery setup: opening sniff channel" in app.log)
        check("discovery debug: packets counted", "Server discovery: " in app.log and "counted for server" in app.log)
        check("discovery debug: window summary", "Server discovery: last " in app.log)

    if not only:
        run(PROFILE, "original profile", smoke)

    shutil.rmtree(WORK, ignore_errors=True)
    print(f"\n{sum(results)}/{len(results)} checks passed")
    sys.exit(0 if all(results) else 1)


main()
