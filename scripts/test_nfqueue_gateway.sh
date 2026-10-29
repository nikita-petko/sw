#!/usr/bin/env bash
# Phase 4 checks for the NFQUEUE backend inside a throwaway privileged container: the forward hook on a
# gateway between two network namespaces, SIGTERM cleanup, and fail-open after SIGKILL.
# usage: scripts/test_nfqueue_gateway.sh [path-to-lagsw]   (build with `xmake -y` first)
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
bin="${1:-$(find "$root/build/linux" -name lagsw -type f -path '*debug*' | head -1)}"
[ -x "$bin" ] || { echo "lagsw binary not found; run xmake -y" >&2; exit 1; }

docker run --rm --privileged -v "$root:/src:ro" -v "$(dirname "$bin"):/bin-dir:ro" archlinux:latest bash -c '
set -u
pacman -Sy --noconfirm --needed nftables libnetfilter_queue python iproute2 >/dev/null 2>&1
fail=0
check() { if [ "$2" = 0 ]; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }
BIN=/bin-dir/'"$(basename "$bin")"'
PROFILE=/src/profiles/gateway.test.sw.yml
KEYS=/tmp/keys; : > $KEYS

ip netns add cli; ip netns add srv
ip link add vc type veth peer name vc0; ip link set vc0 netns cli
ip link add vs type veth peer name vs0; ip link set vs0 netns srv
ip addr add 10.1.0.1/24 dev vc; ip addr add 10.2.0.1/24 dev vs; ip link set vc up; ip link set vs up
ip -n cli addr add 10.1.0.2/24 dev vc0; ip -n cli link set vc0 up; ip -n cli link set lo up
ip -n srv addr add 10.2.0.2/24 dev vs0; ip -n srv link set vs0 up; ip -n srv link set lo up
ip -n cli route add default via 10.1.0.1; ip -n srv route add default via 10.2.0.1
sysctl -qw net.ipv4.ip_forward=1
# Offloads would hand the queue oversized segments; keep the test about forwarding.
cat > /tmp/echo.py <<P
import socket,threading,sys
s=socket.socket(); s.setsockopt(1,2,1); s.bind(("0.0.0.0",8080)); s.listen(8)
def h(c):
    while (d:=c.recv(4096)): c.sendall(d)
    c.close()
while True:
    c,_=s.accept(); threading.Thread(target=h,args=(c,),daemon=True).start()
P
ip netns exec srv python /tmp/echo.py & srvpid=$!
cat > /tmp/rtt.py <<P
import socket,time,sys
t=time.monotonic()
try:
    s=socket.create_connection(("10.2.0.2",8080),timeout=float(sys.argv[1])); s.sendall(b"x"*3000); n=0
    while n<3000: n+=len(s.recv(4096))
    print(time.monotonic()-t)
except OSError: print("timeout")
P
rtt() { ip netns exec cli python /tmp/rtt.py "$1"; }

r=$(rtt 5); echo "baseline $r"
python -c "import sys; sys.exit(0 if float(\"$r\")<0.3 else 1)"; check "gateway forwards without lagsw" $?

LAGSW_TEST_KEYS=$KEYS $BIN --config $PROFILE -l debug </dev/null >/tmp/lagsw.log 2>&1 & pid=$!
sleep 2
r=$(rtt 5); python -c "import sys; sys.exit(0 if float(\"$r\")<0.3 else 1)"; check "idle profile is transparent ($r)" $?
sleep 2.5
grep -q "counted for server 10.2.0.2" /tmp/lagsw.log; check "discovery counts forwarded packets for the server address" $?
grep -q "counted for server 10.1.0.2" /tmp/lagsw.log; [ $? -ne 0 ]; check "discovery never mistakes the client for the server" $?
echo d > $KEYS; sleep 0.5
nft list table inet lagsw | grep -q "hook forward"; check "table has a forward hook chain" $?
r=$(rtt 10); python -c "import sys; sys.exit(0 if float(\"$r\")>=0.5 else 1)"; check "forwarded traffic is delayed ($r)" $?
echo > $KEYS; sleep 0.5
r=$(rtt 5); python -c "import sys; sys.exit(0 if float(\"$r\")<0.3 else 1)"; check "released ($r)" $?
echo d > $KEYS; sleep 0.5
kill -TERM $pid; for i in $(seq 50); do kill -0 $pid 2>/dev/null || break; sleep 0.1; done
kill -0 $pid 2>/dev/null; [ $? -ne 0 ]; check "SIGTERM exits" $?
nft list table inet lagsw >/dev/null 2>&1; [ $? -ne 0 ]; check "SIGTERM removed the table" $?
echo > $KEYS
r=$(rtt 5); python -c "import sys; sys.exit(0 if float(\"$r\")<0.3 else 1)"; check "traffic fine after SIGTERM ($r)" $?

LAGSW_TEST_KEYS=$KEYS $BIN --config $PROFILE </dev/null >/tmp/lagsw2.log 2>&1 & pid=$!
sleep 2; echo d > $KEYS; sleep 0.5
kill -9 $pid; wait $pid 2>/dev/null; echo > $KEYS
r=$(rtt 5); python -c "import sys; sys.exit(0 if float(\"$r\")<0.3 else 1)"; check "fail-open after SIGKILL ($r)" $?
nft delete table inet lagsw 2>/dev/null
grep -qi "error" /tmp/lagsw.log && { echo "log errors:"; grep -i error /tmp/lagsw.log; fail=1; }
kill $srvpid
exit $fail
'
