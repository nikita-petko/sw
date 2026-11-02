#!/usr/bin/env bash
# Phase 3 tests of the swdivert module (pocs/linux_kernel_module_backend.md): holding packets, resuming and dropping them, and
# what happens when the reader dies, stalls or a device disappears. It builds a client - gateway - server rig out of network
# namespaces (the script re-runs itself in a new network namespace, so the host's networking is not touched), loads the module,
# runs the scenarios and unloads it again.
#
# usage: test_kmod_hold.sh SWDIVERT.KO SWBENCH [test-name ...]       (as root; scripts/test_kmod_hold_vm.sh runs it in a VM)
# Env:   SWT_NFQ=0 skips the NFQUEUE comparison.
set -u

ko="$1"; swbench="$2"; shift 2
only=("$@")

if [ -z "${SWT_INNER:-}" ]; then
	exec env SWT_INNER=1 unshare -n "$0" "$ko" "$swbench" "${only[@]}"
fi

PORT=9000
TCP_PORT=9100
tmp="$(mktemp -d /tmp/swt.XXXXXX)"
pass=0
fail=0
CLIENT_PID=""
SERVER_PID=""
BG_PIDS=()

cleanup() {
	for pid in "${BG_PIDS[@]:-}"; do [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null; done
	[ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null
	[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
	rm -rf "$tmp"
}
trap cleanup EXIT

ok() { pass=$((pass + 1)); echo "ok   $*"; }
bad() { fail=$((fail + 1)); echo "FAIL $*"; }
check() { # check DESCRIPTION CONDITION-COMMAND...
	local desc="$1"; shift
	if "$@"; then ok "$desc"; else bad "$desc"; fi
}
eq() { [ "$1" = "$2" ]; }
ge() { [ "$1" -ge "$2" ] 2>/dev/null; }
le() { [ "$1" -le "$2" ] 2>/dev/null; }
gt() { [ "$1" -gt "$2" ] 2>/dev/null; }

kv() { # kv FILE KEY: the last value of key=value in a swbench output file
	grep -o "(^| )$2=[^ ]*" -E "$1" 2>/dev/null | tail -1 | sed 's/^ *[^=]*=//'
}

ns() { local who="$1"; shift; local pid="${who^^}_PID"; nsenter -t "${!pid}" -n "$@"; }

rig_up() {
	ip link set lo up
	local own pid
	own="$(readlink /proc/self/ns/net)"
	unshare -n sleep infinity & CLIENT_PID=$!
	unshare -n sleep infinity & SERVER_PID=$!
	for pid in "$CLIENT_PID" "$SERVER_PID"; do
		until [ "$(readlink "/proc/$pid/ns/net" 2>/dev/null)" != "$own" ]; do sleep 0.02; done
	done
	local who gw_dev peer_dev gw_ip peer_ip
	for who in client server; do
		if [ "$who" = client ]; then gw_dev=vc peer_dev=c0 gw_ip=10.10.1.1 peer_ip=10.10.1.2 pid=$CLIENT_PID
		else gw_dev=vs peer_dev=s0 gw_ip=10.10.2.1 peer_ip=10.10.2.2 pid=$SERVER_PID; fi
		ip link add "$gw_dev" type veth peer name "$peer_dev" || return 1
		ip link set "$peer_dev" netns "$pid"
		ip addr add "$gw_ip/24" dev "$gw_dev"
		ip link set "$gw_dev" up
		ns "$who" ip link set lo up
		ns "$who" ip addr add "$peer_ip/24" dev "$peer_dev"
		ns "$who" ip link set "$peer_dev" up
		ns "$who" ip route add default via "$gw_ip"
	done
	echo 1 > /proc/sys/net/ipv4/ip_forward
	# Prime ARP so the first packets of a measurement are not delayed by neighbour resolution
	ns client "$swbench" flood --dst 10.10.2.2 --port 9999 --pps 20 --seconds 1 --size 64 > /dev/null
}

rig_down() {
	kill "$CLIENT_PID" "$SERVER_PID" 2>/dev/null
	wait "$CLIENT_PID" "$SERVER_PID" 2>/dev/null
	CLIENT_PID="" SERVER_PID=""
	ip link del vc 2>/dev/null
	ip link del vs 2>/dev/null
	nft flush ruleset 2>/dev/null
	return 0
}

# start_bg NAME [ns] COMMAND...: runs a swbench process in the background with its output in $tmp/NAME.out and waits until it says "ready"
start_bg() {
	local name="$1"; shift
	local who=""
	if [ "$1" = client ] || [ "$1" = server ]; then who="$1"; shift; fi
	if [ -n "$who" ]; then ns "$who" "$@" > "$tmp/$name.out" 2> "$tmp/$name.err" & else "$@" > "$tmp/$name.out" 2> "$tmp/$name.err" & fi
	local pid=$!
	eval "PID_$name=$pid"
	BG_PIDS+=("$pid")
	local i
	for i in $(seq 1 200); do
		grep -q '^ready' "$tmp/$name.out" 2>/dev/null && return 0
		kill -0 "$pid" 2>/dev/null || { echo "  $name exited early: $(cat "$tmp/$name.err")"; return 1; }
		sleep 0.025
	done
	echo "  $name did not become ready"
	return 1
}
pid_of() { local v="PID_$1"; echo "${!v}"; }
stop_bg() { # stop_bg NAME [SIGNAL]
	local pid; pid="$(pid_of "$1")"
	kill "-${2:-INT}" "$pid" 2>/dev/null
	wait "$pid" 2>/dev/null
}

flood() { # flood PPS SECONDS SIZE [DST_PORT]
	ns client "$swbench" flood --dst 10.10.2.2 --port "${4:-$PORT}" --pps "$1" --seconds "$2" --size "$3" > "$tmp/flood.out" 2>&1
}
flood_bg() {
	ns client "$swbench" flood --dst 10.10.2.2 --port "${4:-$PORT}" --pps "$1" --seconds "$2" --size "$3" > "$tmp/flood.out" 2>&1 &
	FLOOD_PID=$!
	BG_PIDS+=("$FLOOD_PID")
}

set_param() { echo "$2" > "/sys/module/swdivert/parameters/$1"; }
module_refs() { lsmod | awk '$1 == "swdivert" {print $3}'; }
want_test() {
	[ "${#only[@]}" -eq 0 ] && return 0
	local t
	for t in "${only[@]}"; do [ "$t" = "$1" ] && return 0; done
	return 1
}

# ---- tests ----

t_resume_now() {
	rig_up || return
	start_bg sink server "$swbench" sink --port $PORT --verify yes
	start_bg reader "$swbench" sniff --mode swdiv-hold --port $PORT --delay-ms 0
	flood 2000 2 200
	sleep 0.4
	stop_bg reader; stop_bg sink
	local sent recv; sent="$(kv "$tmp/flood.out" sent)"; recv="$(kv "$tmp/sink.out" received)"
	check "resume at once: everything sent was delivered ($sent sent, $recv received)" eq "$recv" "$sent"
	check "resume at once: every packet was held and resumed once" eq "$(kv "$tmp/reader.out" held)/$(kv "$tmp/reader.out" resumed)" "$sent/$sent"
	check "resume at once: no duplicates, no corruption, no reordering" eq "$(kv "$tmp/sink.out" dups)/$(kv "$tmp/sink.out" corrupt)/$(kv "$tmp/sink.out" reordered)" "0/0/0"
	check "resume at once: no verdict failed" eq "$(kv "$tmp/reader.out" enoent)/$(kv "$tmp/reader.out" verr)" "0/0"
	rig_down
}

t_delay() {
	rig_up || return
	start_bg sink server "$swbench" sink --port $PORT --verify yes
	start_bg reader "$swbench" sniff --mode swdiv-hold --port $PORT --delay-ms 20
	flood 1000 2 300
	sleep 0.4
	stop_bg reader; stop_bg sink
	local sent recv p50; sent="$(kv "$tmp/flood.out" sent)"; recv="$(kv "$tmp/sink.out" received)"; p50="$(kv "$tmp/sink.out" lat_p50_us)"
	check "20 ms hold: everything delivered ($sent sent, $recv received)" eq "$recv" "$sent"
	check "20 ms hold: median latency is at least the hold (p50 ${p50} us)" ge "$p50" 20000
	check "20 ms hold: median latency is not much more than the hold (p50 ${p50} us)" le "$p50" 40000
	check "20 ms hold: order kept, no duplicates, no corruption" eq "$(kv "$tmp/sink.out" reordered)/$(kv "$tmp/sink.out" dups)/$(kv "$tmp/sink.out" corrupt)" "0/0/0"
	rig_down
}

t_drop_verdict() {
	rig_up || return
	start_bg sink server "$swbench" sink --port $PORT
	start_bg reader "$swbench" sniff --mode swdiv-hold --port $PORT --delay-ms 0 --drop-every 4
	flood 2000 2 200
	sleep 0.4
	stop_bg reader; stop_bg sink
	local sent recv vdrop; sent="$(kv "$tmp/flood.out" sent)"; recv="$(kv "$tmp/sink.out" received)"; vdrop="$(kv "$tmp/reader.out" vdropped)"
	check "drop verdicts: some packets were dropped ($vdrop)" gt "$vdrop" 0
	check "drop verdicts: delivered = sent - dropped ($recv = $sent - $vdrop)" eq "$recv" "$((sent - vdrop))"
	rig_down
}

tcp_through_hold() { # tcp_through_hold LABEL
	start_bg sink server "$swbench" tcpsink --port $TCP_PORT
	start_bg reader "$swbench" sniff --mode swdiv-hold --port $TCP_PORT --proto tcp --delay-ms 2
	ns client "$swbench" tcpsend --dst 10.10.2.2 --port $TCP_PORT --bytes 4194304 --seed 12345 > "$tmp/send.out" 2>&1
	sleep 0.3
	stop_bg reader; stop_bg sink
	check "$1: all 4 MiB arrived" eq "$(kv "$tmp/sink.out" bytes)" 4194304
	check "$1: the data is intact (hash)" eq "$(kv "$tmp/sink.out" hash)" "$(kv "$tmp/send.out" hash)"
	check "$1: TCP segments were held and every one resumed ($(kv "$tmp/reader.out" held) held, $(kv "$tmp/reader.out" resumed) resumed, $(kv "$tmp/send.out" elapsed_ms) ms)" \
		eq "$(kv "$tmp/reader.out" held)/$(kv "$tmp/reader.out" resumed)/$(kv "$tmp/reader.out" enoent)" "$(kv "$tmp/reader.out" held)/$(kv "$tmp/reader.out" held)/0"
	# 4 MiB is about 2900 full-size segments; far fewer held would mean super-packets went through unheld
	check "$1: the data segments were held (not only the handshake): $(kv "$tmp/reader.out" held) held, $(kv "$tmp/reader.out" pass_unsupported) passed unheld" ge "$(kv "$tmp/reader.out" held)" 2500
}

t_tcp() {
	rig_up || return
	tcp_through_hold "tcp through a 2 ms hold"
	rig_down
}

t_tcp_nat() {
	rig_up || return
	modprobe nf_tables nft_chain_nat nft_masq nf_nat nf_conntrack 2>/dev/null
	nft -f - <<'RULES' 2>"$tmp/nft.err"
table ip swt_nat {
	chain post {
		type nat hook postrouting priority 100; policy accept;
		oifname "vs" masquerade
	}
}
RULES
	if [ -s "$tmp/nft.err" ]; then bad "tcp+nat: could not set up NAT: $(cat "$tmp/nft.err")"; rig_down; return; fi
	tcp_through_hold "tcp through a 2 ms hold with masquerade"
	check "tcp+nat: the server saw the gateway's address (NAT applied after a resume)" eq "$(kv "$tmp/sink.out" peer)" 10.10.2.1
	rig_down
}

t_sigkill_hold() {
	rig_up || return
	start_bg sink server "$swbench" sink --port $PORT
	start_bg reader "$swbench" sniff --mode swdiv-hold --port $PORT --delay-ms 3000
	flood_bg 1000 2 200
	sleep 1
	kill -9 "$(pid_of reader)"; wait "$(pid_of reader)" 2>/dev/null
	wait "$FLOOD_PID"
	sleep 0.4
	stop_bg sink
	local sent recv; sent="$(kv "$tmp/flood.out" sent)"; recv="$(kv "$tmp/sink.out" received)"
	check "reader SIGKILLed with packets held: not one packet lost ($sent sent, $recv received)" eq "$recv" "$sent"
	check "reader SIGKILLed: no duplicates" eq "$(kv "$tmp/sink.out" dups)" 0
	local i refs=""
	for i in $(seq 1 40); do refs="$(module_refs)"; [ "$refs" = 0 ] && break; sleep 0.05; done
	check "reader SIGKILLed: nothing references the module afterwards" eq "$refs" 0
	rig_down

	[ "${SWT_NFQ:-1}" = 0 ] && return
	# The same on NFQUEUE, for comparison (information only: it is what the module replaces)
	rig_up || return
	modprobe nfnetlink_queue nf_tables nft_queue 2>/dev/null
	nft -f - <<RULES 2>"$tmp/nft.err"
table ip swt_q {
	chain f {
		type filter hook forward priority -150; policy accept;
		udp dport $PORT queue flags bypass num 0
	}
}
RULES
	if [ -s "$tmp/nft.err" ]; then echo "info NFQUEUE comparison skipped: $(cat "$tmp/nft.err")"; rig_down; return; fi
	start_bg sink server "$swbench" sink --port $PORT
	start_bg reader "$swbench" sniff --mode nfq-hold --port $PORT --delay-ms 3000
	flood_bg 1000 2 200
	sleep 1
	kill -9 "$(pid_of reader)"; wait "$(pid_of reader)" 2>/dev/null
	wait "$FLOOD_PID"
	sleep 0.4
	stop_bg sink
	sent="$(kv "$tmp/flood.out" sent)"; recv="$(kv "$tmp/sink.out" received)"
	echo "info same test on NFQUEUE: $sent sent, $recv received: $((sent - recv)) packets lost when the listener died while holding them"
	rig_down
}

t_graceful_stop() {
	rig_up || return
	start_bg sink server "$swbench" sink --port $PORT
	start_bg reader "$swbench" sniff --mode swdiv-hold --port $PORT --delay-ms 3000
	flood 1000 1 200
	sleep 0.3
	stop_bg reader INT
	sleep 0.3
	stop_bg sink
	local sent recv; sent="$(kv "$tmp/flood.out" sent)"; recv="$(kv "$tmp/sink.out" received)"
	check "reader stopped (SIGINT) with packets held: all delivered ($sent sent, $recv received)" eq "$recv" "$sent"
	check "reader stopped: the held packets were resumed by the flush ($(kv "$tmp/reader.out" flushed) flushed)" gt "$(kv "$tmp/reader.out" flushed)" 0
	rig_down
}

t_hold_timeout() {
	rig_up || return
	set_param hold_ms 300
	start_bg sink server "$swbench" sink --port $PORT
	start_bg reader "$swbench" sniff --mode swdiv-hold --port $PORT --delay-ms -1
	flood 500 1 200
	sleep 1
	stop_bg sink
	stop_bg reader
	set_param hold_ms 2000
	local sent recv p50; sent="$(kv "$tmp/flood.out" sent)"; recv="$(kv "$tmp/sink.out" received)"; p50="$(kv "$tmp/sink.out" lat_p50_us)"
	check "reader that never answers: packets were released by the timeout ($sent sent, $recv received)" eq "$recv" "$sent"
	check "reader that never answers: released after hold_ms (p50 ${p50} us >= 300 ms)" ge "$p50" 300000
	check "reader that never answers: not much later than hold_ms (p50 ${p50} us)" le "$p50" 600000
	check "reader that never answers: counted as expired, not flushed ($(kv "$tmp/reader.out" expired) expired)" eq "$(kv "$tmp/reader.out" expired)" "$sent"
	rig_down
}

t_max_held() {
	rig_up || return
	set_param max_held 50
	set_param hold_ms 1500
	start_bg sink server "$swbench" sink --port $PORT
	start_bg reader "$swbench" sniff --mode swdiv-hold --port $PORT --delay-ms -1
	flood 2000 1 200
	sleep 0.1
	stop_bg reader
	sleep 0.3
	stop_bg sink
	set_param max_held 4096
	set_param hold_ms 2000
	local sent recv held limit; sent="$(kv "$tmp/flood.out" sent)"; recv="$(kv "$tmp/sink.out" received)"; held="$(kv "$tmp/reader.out" held)"; limit="$(kv "$tmp/reader.out" pass_limit)"
	check "hold limit: no more than about max_held were held ($held, limit 50)" le "$held" 60
	check "hold limit: the rest passed unheld ($limit)" ge "$limit" "$((sent - 60))"
	check "hold limit: nothing lost ($sent sent, $recv received)" eq "$recv" "$sent"
	rig_down
}

t_device_removal() {
	rig_up || return
	set_param hold_ms 5000
	start_bg sink server "$swbench" sink --port $PORT
	start_bg reader "$swbench" sniff --mode swdiv-hold --port $PORT --delay-ms -1
	flood_bg 1000 1 200
	sleep 0.5
	local t0 t1 rc
	t0=$(date +%s%N)
	timeout 15 ip link del vs
	rc=$?
	t1=$(date +%s%N)
	check "device removed while packets were held: ip link del returned ($rc) in $(((t1 - t0) / 1000000)) ms" eq "$rc" 0
	check "device removed while packets were held: it did not wait for the hold timeout" le "$(((t1 - t0) / 1000000))" 2500
	wait "$FLOOD_PID"
	stop_bg reader
	stop_bg sink
	check "device removed while packets were held: held packets of that device were dropped ($(kv "$tmp/reader.out" dev_dropped))" gt "$(kv "$tmp/reader.out" dev_dropped)" 0
	set_param hold_ms 2000
	rig_down
}

t_rate() {
	rig_up || return
	start_bg sink server "$swbench" sink --port $PORT --verify yes
	start_bg reader "$swbench" sniff --mode swdiv-hold --port $PORT --delay-ms 0
	flood 20000 2 200
	sleep 0.5
	stop_bg reader; stop_bg sink
	local sent recv; sent="$(kv "$tmp/flood.out" sent)"; recv="$(kv "$tmp/sink.out" received)"
	check "20 kpps through hold and resume: nothing lost ($sent sent, $recv received)" eq "$recv" "$sent"
	check "20 kpps: no duplicates, no corruption" eq "$(kv "$tmp/sink.out" dups)/$(kv "$tmp/sink.out" corrupt)" "0/0"
	check "20 kpps: every packet held and resumed ($(kv "$tmp/reader.out" held) held, $(kv "$tmp/reader.out" pass_limit) passed over the limit)" \
		eq "$(kv "$tmp/reader.out" held)" "$sent"
	rig_down
}

# Phase 2 still works after the Phase 3 changes of the slot layout and the statistics: sniff-only handles copy and let packets go
t_sniff() {
	rig_up || return
	start_bg sink server "$swbench" sink --port $PORT --verify yes
	start_bg reader "$swbench" sniff --mode swdiv --port $PORT
	# Fast enough that packets arrive closer together than wake_us: batching cannot show at lower rates
	flood 100000 1 400
	sleep 0.4
	stop_bg reader; stop_bg sink
	local sent recv; sent="$(kv "$tmp/flood.out" sent)"; recv="$(kv "$tmp/sink.out" received)"
	check "sniff only: everything forwarded untouched ($sent sent, $recv received)" eq "$recv" "$sent"
	check "sniff only: everything captured ($(kv "$tmp/reader.out" captured))" eq "$(kv "$tmp/reader.out" captured)" "$sent"
	check "sniff only: nothing was held or dropped" eq "$(kv "$tmp/sink.out" dups)/$(kv "$tmp/sink.out" corrupt)/$(kv "$tmp/reader.out" dropped)" "0/0/0"
	check "sniff only: the wake-up is batched at 100 kpps ($(kv "$tmp/reader.out" wakeups) wake-ups for $sent packets)" le "$(kv "$tmp/reader.out" wakeups)" "$((sent / 2))"
	rig_down
}

# Exactly-once under races: two parallel flows, so the hook runs on several CPUs; a reader whose delay equals hold_ms, so the timeout
# and the verdict of the same packet collide; and a reader killed in the middle of it all, so the flush races the hook as well.
t_race() {
	rig_up || return
	set_param hold_ms 3
	start_bg sink server "$swbench" sink --port $PORT --verify yes
	start_bg reader "$swbench" sniff --mode swdiv-hold --port $PORT --delay-ms 3
	ns client "$swbench" flood --dst 10.10.2.2 --port $PORT --pps 20000 --seconds 2 --size 200 --stream 0 > "$tmp/flood0.out" 2>&1 &
	local f0=$!
	ns client "$swbench" flood --dst 10.10.2.2 --port $PORT --pps 20000 --seconds 2 --size 200 --stream 1 > "$tmp/flood1.out" 2>&1 &
	local f1=$!
	BG_PIDS+=("$f0" "$f1")
	sleep 1
	kill -9 "$(pid_of reader)"; wait "$(pid_of reader)" 2>/dev/null
	wait "$f0" "$f1"
	sleep 0.5
	stop_bg sink
	set_param hold_ms 2000
	local sent recv; sent=$(($(kv "$tmp/flood0.out" sent) + $(kv "$tmp/flood1.out" sent))); recv="$(kv "$tmp/sink.out" received)"
	check "races (timeout vs verdict vs kill, two flows): nothing lost ($sent sent, $recv received)" eq "$recv" "$sent"
	check "races: nothing delivered twice, nothing corrupted" eq "$(kv "$tmp/sink.out" dups)/$(kv "$tmp/sink.out" corrupt)" "0/0"
	rig_down
}

# Divert-and-resume compared with NFQUEUE doing the same job (every matching packet is held, then released at once). Not part of the
# default run: `test_kmod_hold.sh KO SWBENCH bench`. Env: BENCH_PPS="20000 100000" BENCH_SECS=3 BENCH_SIZE=200.
bench_row() { # bench_row LABEL PPS ; the sink and reader are running, the rig is up
	local label="$1" pps="$2" sent recv captured cpu
	# A row without a reader must not pick up the numbers of the previous row's reader
	[ -n "${PID_reader:-}" ] || rm -f "$tmp/reader.out"
	flood "$pps" "${BENCH_SECS:-3}" "${BENCH_SIZE:-200}"
	sleep 0.5
	[ -n "${PID_reader:-}" ] && stop_bg reader
	stop_bg sink
	sent="$(kv "$tmp/flood.out" sent)"; recv="$(kv "$tmp/sink.out" received)"
	captured="$(kv "$tmp/reader.out" captured)"; cpu="$(kv "$tmp/reader.out" cpu_ms)"
	printf '| %s | %s | %s | %s | %s.%s %% | %s | %s | %s | %s |\n' "$label" "$pps" "$sent" "$recv" \
		"$(( (sent - recv) * 100 / sent ))" "$(( ((sent - recv) * 1000 / sent) % 10 ))" \
		"$(kv "$tmp/sink.out" lat_p50_us)" "$(kv "$tmp/sink.out" lat_p99_us)" "$(kv "$tmp/sink.out" lat_max_us)" \
		"$([ -n "$captured" ] && [ "$captured" != 0 ] && awk -v c="$cpu" -v n="$captured" 'BEGIN{printf "%.2f", c*1000/n}' || echo -)"
	unset PID_reader
}

t_bench() {
	echo "| mode | pps | sent | delivered | lost | latency p50 us | p99 us | max us | reader CPU us/packet |"
	echo "|---|---|---|---|---|---|---|---|---|"
	local pps
	for pps in ${BENCH_PPS:-20000 100000}; do
		rig_up || return
		start_bg sink server "$swbench" sink --port $PORT
		bench_row "no hold (baseline)" "$pps"
		rig_down

		rig_up || return
		modprobe nfnetlink_queue nf_tables nft_queue 2>/dev/null
		nft -f - <<RULES 2>/dev/null
table ip swt_q {
	chain f {
		type filter hook forward priority -150; policy accept;
		udp dport $PORT queue flags bypass num 0
	}
}
RULES
		start_bg sink server "$swbench" sink --port $PORT
		start_bg reader "$swbench" sniff --mode nfq-hold --port $PORT --delay-ms 0
		bench_row "NFQUEUE hold, one verdict per packet" "$pps"
		rig_down

		rig_up || return
		modprobe nfnetlink_queue nf_tables nft_queue 2>/dev/null
		nft -f - <<RULES 2>/dev/null
table ip swt_q {
	chain f {
		type filter hook forward priority -150; policy accept;
		udp dport $PORT queue flags bypass num 0
	}
}
RULES
		start_bg sink server "$swbench" sink --port $PORT
		start_bg reader "$swbench" sniff --mode nfq-hold --port $PORT --delay-ms 0 --batch yes
		bench_row "NFQUEUE hold, batched verdicts" "$pps"
		rig_down

		local wake
		for wake in 0 50 250; do
			rig_up || return
			set_param hold_wake_us "$wake"
			start_bg sink server "$swbench" sink --port $PORT
			start_bg reader "$swbench" sniff --mode swdiv-hold --port $PORT --delay-ms 0
			bench_row "swdivert hold, verdict at once, hold_wake_us=$wake" "$pps"
			rig_down
		done
		set_param hold_wake_us 0
	done
}

# ---- run ----

echo "module: $ko"
insmod "$ko" || { echo "insmod failed"; exit 1; }
dmesg_before="$(dmesg | wc -l)"
[ -c /dev/swdivert ] || { echo "/dev/swdivert did not appear"; exit 1; }

default_tests=(sniff resume_now delay drop_verdict tcp tcp_nat sigkill_hold graceful_stop hold_timeout max_held device_removal rate race)
[ "${#only[@]}" -eq 0 ] && only=("${default_tests[@]}")
for t in sniff resume_now delay drop_verdict tcp tcp_nat sigkill_hold graceful_stop hold_timeout max_held device_removal rate race bench; do
	want_test "$t" || continue
	echo "== $t"
	"t_$t"
	BG_PIDS=()
done

echo "== module"
for i in $(seq 1 40); do refs="$(module_refs)"; [ "$refs" = 0 ] && break; sleep 0.05; done
check "no reference to the module is left" eq "$refs" 0
rmmod swdivert 2> "$tmp/rmmod.err" && ok "rmmod succeeded" || bad "rmmod failed: $(cat "$tmp/rmmod.err")"
if dmesg | tail -n +"$((dmesg_before + 1))" | grep -E 'BUG[: ]|WARNING:|Oops|KASAN|lockdep|Call Trace|general protection|kmem_cache_destroy|Slab cache|Poison|Redzone|refcount_t|use-after-free' > "$tmp/dmesg.txt"; then
	bad "the kernel log shows a problem:"; head -20 "$tmp/dmesg.txt"
else
	ok "no BUG/WARNING/Oops/slab error in the kernel log"
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
