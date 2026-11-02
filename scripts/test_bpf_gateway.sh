#!/usr/bin/env bash
# Checks for the eBPF egress tier inside a throwaway privileged container (kernel 6.6+ with tcx, sch_fq, cls_bpf): a gateway between two
# network namespaces whose veth devices carry the egress program. Covers delay accuracy, drop, batches, the passive-latency models,
# ordering, mode routing and fallback, qdisc restoration, SIGTERM/SIGKILL and unprivileged operation.
# usage: scripts/test_bpf_gateway.sh [path-to-lagsw]   (build with `xmake -y` first; a debug build gives the log messages some checks read)
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
bin="${1:-$(find "$root/build/linux" -name lagsw -type f -path '*debug*' | head -1)}"
[ -x "$bin" ] || { echo "lagsw binary not found; run xmake -y" >&2; exit 1; }

docker run --rm --privileged -e ONLY="${ONLY:-}" -v "$root:/src:ro" -v "$(dirname "$bin"):/bin-dir:ro" archlinux:latest bash -c '
set -u
pacman -Sy --noconfirm --needed nftables libnftnl libnetfilter_queue libbpf python iproute2 libcap util-linux bpf >/dev/null 2>&1
fail=0
check() { if [ "$2" = 0 ]; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }
BIN=/bin-dir/'"$(basename "$bin")"'
PROFILE=/src/profiles/bpf.test.sw.yml
KEYS=/tmp/keys; : > $KEYS; chmod 666 $KEYS
within() { python -c "import sys; v=float(sys.argv[1]); sys.exit(0 if float(sys.argv[2])<=v<=float(sys.argv[3]) else 1)" "$1" "$2" "$3"; }

ip netns add cli; ip netns add srv
ip link add vc type veth peer name vc0; ip link set vc0 netns cli
ip link add vs type veth peer name vs0; ip link set vs0 netns srv
ip addr add 10.1.0.1/24 dev vc; ip addr add 10.2.0.1/24 dev vs; ip link set vc up; ip link set vs up
ip -n cli addr add 10.1.0.2/24 dev vc0; ip -n cli link set vc0 up; ip -n cli link set lo up
ip -n srv addr add 10.2.0.2/24 dev vs0; ip -n srv link set vs0 up; ip -n srv link set lo up
ip -n cli route add default via 10.1.0.1; ip -n srv route add default via 10.2.0.1
sysctl -qw net.ipv4.ip_forward=1

cat > /tmp/echo.py <<P
import socket,threading
s=socket.socket(); s.setsockopt(1,2,1); s.bind(("0.0.0.0",8080)); s.listen(8)
def h(c):
    while (d:=c.recv(4096)): c.sendall(d)
    c.close()
while True:
    c,_=s.accept(); threading.Thread(target=h,args=(c,),daemon=True).start()
P
# UDP echo that also tells the client in what order the datagrams reached the server
cat > /tmp/udp_echo.py <<P
import socket,struct,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("0.0.0.0",int(sys.argv[1]))); n=0
while True:
    d,a=s.recvfrom(64); s.sendto(d[:4]+struct.pack("!I",n),a); n+=1
P
cat > /tmp/rtt.py <<P
import socket,time,sys
t=time.monotonic()
try:
    s=socket.create_connection(("10.2.0.2",8080),timeout=float(sys.argv[1])); s.sendall(b"x"*3000); n=0
    while n<3000: n+=len(s.recv(4096))
    print(time.monotonic()-t)
except OSError: print("timeout")
P
# udp_probe.py <port> <count> <interval_ms>: prints "mean sd min max inversions replies" (milliseconds; inversions in server arrival order)
cat > /tmp/udp_probe.py <<P
import socket,struct,sys,time,threading,statistics
port,count,gap=int(sys.argv[1]),int(sys.argv[2]),float(sys.argv[3])/1000
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("0.0.0.0",0)); s.settimeout(3)
sent={}; got=[]
def rx():
    try:
        while len(got)<count:
            d,_=s.recvfrom(64); seq,order=struct.unpack("!II",d[:8]); got.append((seq,order,time.monotonic()))
    except OSError: pass
t=threading.Thread(target=rx); t.start()
for i in range(count):
    sent[i]=time.monotonic(); s.sendto(struct.pack("!I",i),("10.2.0.2",port)); time.sleep(gap)
t.join()
rtts=[(r-sent[q])*1000 for q,_,r in got]
by_order=[q for q,_,_ in sorted(got,key=lambda x:x[1])]
inv=sum(1 for a,b in zip(by_order,by_order[1:]) if b<a)
print("%.1f %.1f %.1f %.1f %d %d"%(statistics.mean(rtts),statistics.pstdev(rtts),min(rtts),max(rtts),inv,len(got)) if rtts else "0 0 0 0 0 0")
P
# batch_probe.py: three datagrams 100 ms apart; prints the spread of their arrival times at the server side (via the echo)
cat > /tmp/batch_probe.py <<P
import socket,struct,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("0.0.0.0",0)); s.settimeout(5)
t0=time.monotonic()
for i in range(3):
    s.sendto(struct.pack("!I",i),("10.2.0.2",9001)); time.sleep(0.1)
times=[]
try:
    while len(times)<3:
        s.recvfrom(64); times.append(time.monotonic()-t0)
except OSError: pass
print("%d %.3f %.3f"%(len(times),times[0] if times else 0,(times[-1]-times[0]) if times else 0))
P
ip netns exec srv python /tmp/echo.py & srvpid=$!
ip netns exec srv python /tmp/udp_echo.py 9000 & u0=$!
ip netns exec srv python /tmp/udp_echo.py 9001 & u1=$!
rtt() { ip netns exec cli python /tmp/rtt.py "$1"; }
probe() { ip netns exec cli python /tmp/udp_probe.py "$@"; }
start() { # start <profile> [user-prefix]  -> sets $pid, log in /tmp/lagsw.log
    : > $KEYS; : > /tmp/lagsw.log
    LAGSW_TEST_KEYS=$KEYS ${2:-} $BIN --config "$1" -l debug </dev/null >/tmp/lagsw.log 2>&1 & pid=$!
    sleep 1.5
}
stop() { kill -TERM $pid 2>/dev/null; for i in $(seq 60); do kill -0 $pid 2>/dev/null || break; sleep 0.1; done; kill -0 $pid 2>/dev/null; [ $? -ne 0 ]; }
root_kind() { tc qdisc show dev "$1" | head -1 | awk "{print \$2}"; }
tcx_links() { bpftool net show 2>/dev/null | grep -c "tcx/egress"; }
tap() { echo "$1" > $KEYS; sleep 0.2; : > $KEYS; sleep 0.4; }
queued() { grep -c "^[0-9]" /proc/net/netfilter/nfnetlink_queue 2>/dev/null; }

echo "kernel: $(uname -r)"
[ "$(root_kind vc)" = noqueue ]; check "veth starts with the noqueue root qdisc" $?
r=$(rtt 5); within "$r" 0 0.3; check "baseline gateway is fast ($r)" $?

# ---- 1. profile in the kernel: delay -----------------------------------------------------------------------------------------------
start $PROFILE
[ "$(root_kind vc)" = noqueue ]; check "nothing is installed while no profile needs the kernel" $?
echo d > $KEYS; sleep 0.7
[ "$(root_kind vc)" = fq ] && [ "$(root_kind vs)" = fq ]; check "activation installs fq on both interfaces" $?
[ "$(tcx_links)" = 2 ]; check "the egress program is attached with tcx to both interfaces" $?
tc qdisc show dev vc | grep -q "horizon 900s horizon_cap"; check "fq horizon covers the longest delay and caps instead of dropping" $?
grep -q "runs in the kernel" /tmp/lagsw.log; check "log says the profile runs in the kernel" $?
r=$(rtt 10); within "$r" 1.15 1.45; check "forwarded traffic is delayed in the kernel: 4 x 300 ms ($r)" $?
[ "$(queued)" = 0 ]; check "no NFQUEUE queue is bound" $?
nft list table inet lagsw >/dev/null 2>&1; [ $? -ne 0 ]; check "no nftables rules exist for a kernel profile" $?
sleep 0.5; grep -aqE "bpf: 1 stage\(s\) on 2 iface\(s\), matched [1-9][0-9]* delayed [1-9][0-9]* dropped 0" /tmp/lagsw.log; check "the monitor status line shows the kernel counters" $?
echo > $KEYS; sleep 0.7
r=$(rtt 5); within "$r" 0 0.3; check "released: traffic is fast again ($r)" $?
grep -qE "deactivated: [1-9][0-9]* matched, [1-9][0-9]* delayed, 0 dropped" /tmp/lagsw.log; check "counters report matched and delayed packets" $?
echo d > $KEYS; sleep 0.5; r=$(rtt 10); within "$r" 1.15 1.45; check "reactivation works ($r)" $?; echo > $KEYS; sleep 0.5

# ---- 2. drop ------------------------------------------------------------------------------------------------------------------------
echo x > $KEYS; sleep 0.5
r=$(rtt 2); [ "$r" = timeout ]; check "Drop: connection fails while held" $?
echo > $KEYS; sleep 0.5
r=$(rtt 8); within "$r" 0 5; check "Drop: recovers after release ($r)" $?
grep -qE "deactivated: [1-9][0-9]* matched, 0 delayed, [1-9][0-9]* dropped" /tmp/lagsw.log; check "Drop: counters report dropped packets" $?

# ---- 3. batch (send_all_after_delay) -----------------------------------------------------------------------------------------------
echo b > $KEYS; sleep 0.5
read -r n first spread <<< "$(ip netns exec cli python /tmp/batch_probe.py)"
echo "batch: replies=$n first=$first spread=$spread"
[ "$n" = 3 ]; check "Batch: all three datagrams arrive" $?
within "$first" 1.1 1.5; check "Batch: the first one waits for the deadline in each direction ($first)" $?
within "$spread" 0 0.35; check "Batch: the batch leaves together, not 100 ms apart ($spread)" $?
echo > $KEYS; sleep 0.5

# ---- 4. fallback to NFQUEUE for a mode that needs the packets -----------------------------------------------------------------------
tap h
grep -q "using NFQUEUE, not kernel shaping: delay mode hold_until_deactivation" /tmp/lagsw.log; check "Hold: logged why it uses NFQUEUE" $?
nft list table inet lagsw 2>/dev/null | grep -q "hook forward"; check "Hold: runs on an NFQUEUE channel" $?
r=$(rtt 1.5); [ "$r" = timeout ]; check "Hold: packets are held in user space" $?
tap h; sleep 0.5
r=$(rtt 8); within "$r" 0 5; check "Hold: released ($r)" $?
# stacking: the NFQUEUE hold releases packets into the egress program, which then adds its own delay
echo "d h" > $KEYS; sleep 0.2; echo d > $KEYS; sleep 0.4
( rtt 12 > /tmp/mixed.txt ) & mixed=$!
sleep 1.0
echo "d h" > $KEYS; sleep 0.2; echo d > $KEYS
wait $mixed; r=$(cat /tmp/mixed.txt); within "$r" 2.0 3.6; check "mixed tiers: the NFQUEUE hold and the kernel delay stack ($r)" $?
: > $KEYS; sleep 0.8
stop; check "SIGTERM exits" $?
[ "$(root_kind vc)" = noqueue ] && [ "$(root_kind vs)" = noqueue ]; check "SIGTERM restores the previous root qdisc" $?
[ "$(tcx_links)" = 0 ]; check "SIGTERM detaches the programs" $?
r=$(rtt 5); within "$r" 0 0.3; check "traffic is fine after SIGTERM ($r)" $?

# ---- 5. SIGKILL: tcx links go away with the process; fq stays and is harmless ----------------------------------------------------------
start $PROFILE
echo d > $KEYS; sleep 0.7
r=$(rtt 10); within "$r" 1.15 1.45; check "delayed again in a fresh process ($r)" $?
kill -9 $pid; wait $pid 2>/dev/null; : > $KEYS; sleep 0.3
[ "$(tcx_links)" = 0 ]; check "SIGKILL: the kernel detaches the programs" $?
[ "$(root_kind vc)" = fq ]; check "SIGKILL: the fq qdisc stays (documented, harmless)" $?
r=$(rtt 5); within "$r" 0 0.3; check "SIGKILL: traffic is not delayed afterwards ($r)" $?
tc qdisc del dev vc root; tc qdisc del dev vs root

# ---- 6. root qdiscs lagsw does not own are left alone ---------------------------------------------------------------------------------
tc qdisc add dev vc root tbf rate 10gbit burst 1mb latency 50ms
start $PROFILE
echo d > $KEYS; sleep 0.7
grep -q "uses the root qdisc .tbf., which lagsw will not replace" /tmp/lagsw.log; check "a foreign root qdisc is refused with an explanation" $?
[ "$(root_kind vc)" = tbf ]; check "the foreign qdisc is untouched" $?
grep -q "runs in the kernel" /tmp/lagsw.log; [ $? -ne 0 ]; check "the profile fell back to NFQUEUE instead" $?
echo > $KEYS; stop
tc qdisc del dev vc root

# ---- 7. forced tier: refuse instead of falling back ------------------------------------------------------------------------------------
sed "s/tier: auto/tier: bpf/" $PROFILE > /tmp/bpf_forced.yml
start /tmp/bpf_forced.yml
echo h > $KEYS; sleep 0.7
grep -q "kernel shaping is required (linux_bpf tier bpf) but unavailable: delay mode hold_until_deactivation" /tmp/lagsw.log; check "tier bpf refuses a profile that needs user space" $?
nft list table inet lagsw 2>/dev/null | grep -q "hook forward"; [ $? -ne 0 ]; check "tier bpf installed no NFQUEUE rules" $?
echo > $KEYS; stop
sed "s/tier: auto/tier: nfqueue/" $PROFILE > /tmp/bpf_off.yml
start /tmp/bpf_off.yml
echo d > $KEYS; sleep 0.7
[ "$(root_kind vc)" = noqueue ]; check "tier nfqueue never touches the qdisc" $?
r=$(rtt 10); within "$r" 1.15 1.45; check "tier nfqueue still delays through NFQUEUE ($r)" $?
echo > $KEYS; stop
sed "/interfaces:/d" $PROFILE > /tmp/bpf_noif.yml
start /tmp/bpf_noif.yml
echo d > $KEYS; sleep 0.7
grep -q "no interfaces are configured for kernel shaping" /tmp/lagsw.log; check "without interfaces the profile uses NFQUEUE (reason logged)" $?
echo > $KEYS; stop

# ---- 8. passive latency models -----------------------------------------------------------------------------------------------------------
passive() { # passive <name> <mode> <delay> <jitter> <max> <preserve_order>
    cat > /tmp/passive_$1.yml <<P
global_filter: "tcp.DstPort == 8080 or tcp.SrcPort == 8080"
features:
  linux_bpf:
    tier: bpf
    interfaces: [vc, vs]
  passive_latency:
    enabled: true
    mode: $2
    delay_ms: $3
    jitter_ms: $4
    max_delay_ms: $5
    direction: outbound
    preserve_order: $6
    filter: "udp.DstPort == 9000 or udp.SrcPort == 9000"
profiles:
  - name: "A"
    key: a
    mode: hold
P
}
passive fixed fixed 100 0 0 true
start /tmp/passive_fixed.yml
grep -q "Passive latency active in the kernel" /tmp/lagsw.log; check "passive latency runs in the kernel" $?
[ "$(root_kind vc)" = fq ]; check "passive latency installs fq when lagsw starts" $?
read -r mean sd min max inv n <<< "$(probe 9000 100 20)"
echo "fixed 100: rtt mean=$mean sd=$sd min=$min max=$max inversions=$inv replies=$n"
within "$mean" 195 215; check "fixed: RTT is two baseline delays ($mean)" $?
within "$sd" 0 6; check "fixed: no jitter (sd $sd)" $?
[ "$n" = 100 ]; check "fixed: no packet lost" $?
r=$(rtt 5); within "$r" 0 0.3; check "traffic outside the passive filter is untouched ($r)" $?
stop

# without preserve_order the per-packet draws are independent, so the RTT follows the model exactly (two independent directions)
passive uniform uniform 100 40 140 false
start /tmp/passive_uniform.yml
read -r mean sd min max inv n <<< "$(probe 9000 400 15)"
echo "uniform 100+-40 (max 140), unordered: rtt mean=$mean sd=$sd min=$min max=$max inversions=$inv"
within "$mean" 192 208; check "uniform: mean RTT, expected 200 ($mean)" $?
within "$sd" 26 40; check "uniform: RTT standard deviation, expected 32.7 ($sd)" $?
within "$min" 118 150; check "uniform: shortest RTT stays near 2 x 60 ms ($min)" $?
within "$max" 0 282; check "uniform: the clamp keeps every RTT below 2 x max ($max)" $?
stop
passive normal normal 100 20 200 false
start /tmp/passive_normal.yml
read -r mean sd min max inv n <<< "$(probe 9000 400 15)"
echo "normal 100/20, unordered: rtt mean=$mean sd=$sd min=$min max=$max"
within "$mean" 192 208; check "normal: mean RTT, expected 200 ($mean)" $?
within "$sd" 23 34; check "normal: RTT standard deviation, expected 28.3 ($sd)" $?
stop
passive clamp normal 100 40 110 false
start /tmp/passive_clamp.yml
read -r mean sd min max inv n <<< "$(probe 9000 300 15)"
within "$max" 0 222; check "max_delay_ms clamps every sample: no RTT above 2 x 110 ms ($max)" $?
stop
# with preserve_order a packet never overtakes an earlier one; the price is a higher mean (a running maximum of the draws)
passive ordered uniform 100 40 140 true
start /tmp/passive_ordered.yml
read -r mean sd min max inv n <<< "$(probe 9000 300 5)"
echo "uniform ordered: rtt mean=$mean inversions=$inv"
[ "$inv" = 0 ] && [ "$n" = 300 ]; check "preserve_order: packets reach the server in order (inversions $inv)" $?
within "$mean" 200 290; check "preserve_order: mean RTT is not below the unordered mean ($mean)" $?
stop
passive unordered uniform 100 40 140 false
start /tmp/passive_unordered.yml
read -r mean sd min max inv n <<< "$(probe 9000 300 5)"
[ "$inv" -gt 0 ]; check "without preserve_order packets are reordered (inversions $inv)" $?
stop

# stages add up: a kernel profile on the same packets as the kernel baseline
passive stack fixed 100 0 0 true
cat >> /tmp/passive_stack.yml <<P
  - name: "Stack"
    key: s
    mode: hold
    delay_mode: from_timestamp
    delay_ms: 150
    filter: "udp.DstPort == 9000 or udp.SrcPort == 9000"
    capture_options:
      forward: true
P
start /tmp/passive_stack.yml
echo s > $KEYS; sleep 0.7
read -r mean sd min max inv n <<< "$(probe 9000 50 30)"
echo "stacked: baseline 100 + profile 150, rtt mean=$mean sd=$sd"
within "$mean" 495 515; check "stages add up: (100 + 150) ms in each direction ($mean)" $?
echo > $KEYS; sleep 0.7
read -r mean sd min max inv n <<< "$(probe 9000 20 30)"
within "$mean" 195 215; check "after the profile ends only the baseline remains ($mean)" $?
stop

# an inbound delay needs the user-space queue, so the baseline falls back (with tier auto) and stays correct
sed "s/tier: bpf/tier: auto/; s/direction: outbound/direction: both/" /tmp/passive_fixed.yml > /tmp/passive_both.yml
start /tmp/passive_both.yml
grep -q "Passive latency uses NFQUEUE, not kernel shaping: the baseline also delays inbound packets" /tmp/lagsw.log; check "an inbound baseline falls back to NFQUEUE" $?
stop

# ---- 9. unprivileged: file capabilities only ----------------------------------------------------------------------------------------------
mkdir -p /opt/lagsw; cp $BIN /opt/lagsw/lagsw-caps; cp $BIN /opt/lagsw/lagsw-net; chmod 755 /opt/lagsw/*
setcap cap_net_admin,cap_bpf,cap_perfmon+ep /opt/lagsw/lagsw-caps
setcap cap_net_admin+ep /opt/lagsw/lagsw-net
cp $PROFILE /tmp/profile_user.yml; chmod 644 /tmp/profile_user.yml
UNPRIV="setpriv --reuid=65534 --regid=65534 --clear-groups"
: > /tmp/lagsw.log; chmod 666 /tmp/lagsw.log
cd /tmp
LAGSW_TEST_KEYS=$KEYS $UNPRIV /opt/lagsw/lagsw-net --config /tmp/profile_user.yml -l debug </dev/null >/tmp/lagsw-net.log 2>&1 & netpid=$!
sleep 1.5
echo d > $KEYS; sleep 1; : > $KEYS
grep -qE "CAP_BPF|cannot load the eBPF program|operation not permitted" /tmp/lagsw-net.log; check "cap_net_admin alone cannot load the program and says which capabilities are missing" $?
kill -TERM $netpid; for i in $(seq 40); do kill -0 $netpid 2>/dev/null || break; sleep 0.1; done
LAGSW_TEST_KEYS=$KEYS $UNPRIV /opt/lagsw/lagsw-caps --config /tmp/profile_user.yml -l debug </dev/null >/tmp/lagsw-caps.log 2>&1 & pid=$!
sleep 1.5
echo d > $KEYS; sleep 1
grep -q "Uid:.*65534" /proc/$pid/status; check "unprivileged: really runs as uid 65534" $?
r=$(rtt 10); within "$r" 1.15 1.45; check "unprivileged with cap_net_admin,cap_bpf,cap_perfmon: delayed in the kernel ($r)" $?
grep -q "runs in the kernel" /tmp/lagsw-caps.log; check "unprivileged: the profile ran in the kernel" $?
: > $KEYS; stop
[ "$(root_kind vc)" = noqueue ]; check "unprivileged: qdisc restored on exit" $?

# informational: is cap_perfmon needed on this kernel?
cp $BIN /opt/lagsw/lagsw-noperf; setcap cap_net_admin,cap_bpf+ep /opt/lagsw/lagsw-noperf
LAGSW_TEST_KEYS=$KEYS $UNPRIV /opt/lagsw/lagsw-noperf --config /tmp/profile_user.yml -l debug </dev/null >/tmp/lagsw-noperf.log 2>&1 & pid=$!
sleep 1.5; echo d > $KEYS; sleep 1; : > $KEYS; stop
if grep -q "runs in the kernel" /tmp/lagsw-noperf.log; then echo "INFO  cap_net_admin,cap_bpf is enough on this kernel (cap_perfmon not needed)"; else echo "INFO  cap_perfmon is needed on this kernel: $(grep -m1 -o "cannot load the eBPF program[^:]*" /tmp/lagsw-noperf.log)"; fi

kill $srvpid $u0 $u1 2>/dev/null
exit $fail
'
