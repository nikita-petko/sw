#!/usr/bin/env bash
# Phase 3 tests of the swdivert module (pocs/linux_kernel_module_backend.md): holding packets, resuming and dropping them, and
# what happens when the reader dies, stalls or a device disappears. It builds a client - gateway - server rig out of network
# namespaces (the script re-runs itself in a new network namespace, so the host's networking is not touched), loads the module,
# runs the scenarios and unloads it again.
#
# usage: test_kmod_hold.sh SWDIVERT.KO SWBENCH [test-name ...]       (as root; scripts/tests/test_kmod_hold_vm.sh runs it in a VM)
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
ALT_PID=""
BG_PIDS=()

cleanup() {
	for pid in "${BG_PIDS[@]:-}"; do [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null; done
	[ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null
	[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
	[ -n "$ALT_PID" ] && kill "$ALT_PID" 2>/dev/null
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

# A third host on its own link (10.10.3.0/24), for the test that re-routes packets
rig_alt_up() {
	local own; own="$(readlink /proc/self/ns/net)"
	unshare -n sleep infinity & ALT_PID=$!
	until [ "$(readlink "/proc/$ALT_PID/ns/net" 2>/dev/null)" != "$own" ]; do sleep 0.02; done
	ip link add va type veth peer name a0 || return 1
	ip link set a0 netns "$ALT_PID"
	ip addr add 10.10.3.1/24 dev va
	ip link set va up
	ns alt ip link set lo up
	ns alt ip addr add 10.10.3.2/24 dev a0
	ns alt ip link set a0 up
	ns alt ip route add default via 10.10.3.1
}

rig_down() {
	kill "$CLIENT_PID" "$SERVER_PID" $ALT_PID 2>/dev/null
	wait "$CLIENT_PID" "$SERVER_PID" $ALT_PID 2>/dev/null
	CLIENT_PID="" SERVER_PID="" ALT_PID=""
	ip link del vc 2>/dev/null
	ip link del vs 2>/dev/null
	ip link del va 2>/dev/null
	nft flush ruleset 2>/dev/null
	return 0
}

# start_bg NAME [ns] COMMAND...: runs a swbench process in the background with its output in $tmp/NAME.out and waits until it says "ready"
start_bg() {
	local name="$1"; shift
	local who=""
	if [ "$1" = client ] || [ "$1" = server ] || [ "$1" = alt ]; then who="$1"; shift; fi
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

# ---- Phase 4: modify, chain, inject ----

SNAP=1520	# a whole 1500-byte packet fits a slot (slot_bytes is a multiple of 16)
MODREADER=("$swbench" sniff --mode swdiv-hold --snap $SNAP --slots 2048)

t_mod_payload() {
	rig_up || return
	start_bg sink server "$swbench" sink --port $PORT --verify yes --fill y
	start_bg pk server "$swbench" pktcheck --port $PORT --iface s0
	start_bg reader "${MODREADER[@]}" --port $PORT --delay-ms 0 --modify payload
	flood 2000 2 200
	sleep 0.4
	stop_bg reader; stop_bg pk; stop_bg sink
	local sent recv; sent="$(kv "$tmp/flood.out" sent)"; recv="$(kv "$tmp/sink.out" received)"
	check "modified payload: everything delivered ($sent sent, $recv received)" eq "$recv" "$sent"
	check "modified payload: every packet carries the new bytes (corrupt = bytes that are not 'y')" eq "$(kv "$tmp/sink.out" corrupt)/$(kv "$tmp/sink.out" dups)" "0/0"
	check "modified payload: every packet was resumed with new bytes ($(kv "$tmp/reader.out" modified) modified, $(kv "$tmp/reader.out" mod_dropped) dropped)" eq "$(kv "$tmp/reader.out" modified)/$(kv "$tmp/reader.out" mod_dropped)" "$sent/0"
	check "modified payload: IP and UDP checksums verified on the wire at the receiver ($(kv "$tmp/pk.out" pk_good) good, $(kv "$tmp/pk.out" pk_bad_ip) bad IP, $(kv "$tmp/pk.out" pk_bad_l4) bad UDP)" \
		eq "$(kv "$tmp/pk.out" pk_good)/$(kv "$tmp/pk.out" pk_bad_ip)/$(kv "$tmp/pk.out" pk_bad_l4)/$(kv "$tmp/pk.out" pk_partial)" "$sent/0/0/0"
	rig_down
}

mod_len_case() { # mod_len_case MODE EXPECTED_UDP_PAYLOAD_LEN
	rig_up || return
	start_bg sink server "$swbench" sink --port $PORT
	start_bg pk server "$swbench" pktcheck --port $PORT --iface s0
	start_bg reader "${MODREADER[@]}" --port $PORT --delay-ms 0 --modify "$1"
	flood 1000 2 200
	sleep 0.4
	stop_bg reader; stop_bg pk; stop_bg sink
	local sent recv; sent="$(kv "$tmp/flood.out" sent)"; recv="$(kv "$tmp/sink.out" received)"
	check "$1: everything delivered ($sent sent, $recv received)" eq "$recv" "$sent"
	check "$1: the packets have the new length ($(kv "$tmp/sink.out" len_min)..$(kv "$tmp/sink.out" len_max) bytes, expected $2)" eq "$(kv "$tmp/sink.out" len_min)/$(kv "$tmp/sink.out" len_max)" "$2/$2"
	check "$1: checksums verified at the receiver ($(kv "$tmp/pk.out" pk_good) good)" eq "$(kv "$tmp/pk.out" pk_good)/$(kv "$tmp/pk.out" pk_bad_ip)/$(kv "$tmp/pk.out" pk_bad_l4)" "$sent/0/0"
	rig_down
}
t_mod_grow() { mod_len_case grow 300; }
t_mod_shrink() { mod_len_case shrink 64; }

t_mod_tcp() {
	rig_up || return
	start_bg sink server "$swbench" tcpsink --port $TCP_PORT
	start_bg reader "${MODREADER[@]}" --port $TCP_PORT --proto tcp --delay-ms 0 --modify tcp-flip
	ns client "$swbench" tcpsend --dst 10.10.2.2 --port $TCP_PORT --bytes 1048576 --seed 777 > "$tmp/send.out" 2>&1
	sleep 0.3
	stop_bg reader; stop_bg sink
	check "TCP with a modified byte per segment: the whole 1 MiB arrived (so the TCP checksum was right)" eq "$(kv "$tmp/sink.out" bytes)" 1048576
	check "TCP: the segments really were modified (the stream differs from what was sent)" test "$(kv "$tmp/sink.out" hash)" != "$(kv "$tmp/send.out" hash)"
	check "TCP: modified segments ($(kv "$tmp/reader.out" modified)), none dropped" eq "$(kv "$tmp/reader.out" mod_dropped)" 0
	check "TCP: some segments were modified" gt "$(kv "$tmp/reader.out" modified)" 500
	rig_down
}

t_mod_bad() {
	rig_up || return
	set_param hold_ms 250
	start_bg sink server "$swbench" sink --port $PORT
	start_bg reader "${MODREADER[@]}" --port $PORT --delay-ms 0 --modify bad
	flood 500 1 200
	sleep 0.8
	stop_bg reader; stop_bg sink
	set_param hold_ms 2000
	local sent recv; sent="$(kv "$tmp/flood.out" sent)"; recv="$(kv "$tmp/sink.out" received)"
	check "bad bytes in RESUME_MOD: refused for every packet ($(kv "$tmp/reader.out" verr) EINVAL)" eq "$(kv "$tmp/reader.out" verr)" "$sent"
	check "bad bytes: the packets stayed held and the timeout released them unmodified ($recv of $sent, $(kv "$tmp/reader.out" expired) expired)" eq "$recv/$(kv "$tmp/reader.out" expired)" "$sent/$sent"
	check "bad bytes: nothing was modified" eq "$(kv "$tmp/reader.out" modified)" 0
	rig_down
}

t_mod_dst() {
	rig_up || return
	rig_alt_up || { bad "could not set up the third host"; rig_down; return; }
	start_bg sink server "$swbench" sink --port $PORT
	start_bg altsink alt "$swbench" sink --port $PORT
	start_bg pk alt "$swbench" pktcheck --port $PORT --iface a0
	start_bg reader "${MODREADER[@]}" --port $PORT --delay-ms 0 --modify dst --to-ip 10.10.3.2
	flood 1000 2 200
	sleep 0.4
	stop_bg reader; stop_bg pk; stop_bg altsink; stop_bg sink
	local sent alt orig; sent="$(kv "$tmp/flood.out" sent)"; alt="$(kv "$tmp/altsink.out" received)"; orig="$(kv "$tmp/sink.out" received)"
	check "destination rewritten: the packets were routed again, to the third host ($sent sent, $alt received there)" eq "$alt" "$sent"
	check "destination rewritten: none reached the original server ($orig)" eq "$orig" 0
	check "destination rewritten: checksums right at the new destination ($(kv "$tmp/pk.out" pk_good) good, $(kv "$tmp/pk.out" pk_bad_l4) bad)" eq "$(kv "$tmp/pk.out" pk_good)/$(kv "$tmp/pk.out" pk_bad_ip)/$(kv "$tmp/pk.out" pk_bad_l4)" "$sent/0/0"
	check "destination rewritten: the 5-tuple change was noted ($(kv "$tmp/reader.out" ct_detached))" eq "$(kv "$tmp/reader.out" ct_detached)" "$sent"
	rig_down
}

# Two handles form a chain by priority: the higher priority is served first, and what it resumes continues to the next handle
# (with its modifications): WinDivert's "injected and resumed packets are diverted to the next priority handle".
chain_case() { # chain_case LABEL PRIO_A PRIO_B EXPECTED_B_HELD(sent|0)
	rig_up || return
	start_bg sink server "$swbench" sink --port 9001 --verify yes
	start_bg readerA "${MODREADER[@]}" --port $PORT --delay-ms 0 --prio "$2" --modify dport --to-port 9001
	start_bg readerB "$swbench" sniff --mode swdiv-hold --port 9001 --delay-ms 0 --prio "$3"
	flood 2000 2 200 $PORT
	sleep 0.4
	stop_bg readerB; stop_bg readerA; stop_bg sink
	local sent recv; sent="$(kv "$tmp/flood.out" sent)"; recv="$(kv "$tmp/sink.out" received)"
	check "$1: delivered ($sent sent to port $PORT, $recv received on 9001)" eq "$recv" "$sent"
	check "$1: A held and rewrote every packet" eq "$(kv "$tmp/readerA.out" held)/$(kv "$tmp/readerA.out" modified)" "$sent/$sent"
	local want_b="$4"; [ "$want_b" = sent ] && want_b="$sent"
	check "$1: B (filter: port 9001) held $(kv "$tmp/readerB.out" held), expected $want_b" eq "$(kv "$tmp/readerB.out" held)" "$want_b"
	rig_down
}
t_chain_order() {
	chain_case "A served first (100) then B (50): B sees what A rewrote" 100 50 sent
	chain_case "B served first (100) then A (50): B never sees the rewritten packets" 50 100 0
}

# Handles of equal priority coexist and are served in the order they were started (the engine opens several handles at its default priority)
t_priority_equal() {
	rig_up || return
	start_bg sink server "$swbench" sink --port $PORT --verify yes
	start_bg readerA "$swbench" sniff --mode swdiv-hold --port $PORT --delay-ms 0 --prio 7
	start_bg readerB "$swbench" sniff --mode swdiv --port $PORT --prio 7
	start_bg readerC "$swbench" sniff --mode swdiv --port $PORT --prio 7
	flood 2000 1 200
	sleep 0.4
	stop_bg readerA; stop_bg readerB; stop_bg readerC; stop_bg sink
	local sent recv; sent="$(kv "$tmp/flood.out" sent)"; recv="$(kv "$tmp/sink.out" received)"
	check "equal priority: three handles are started side by side" test -z "$(cat "$tmp/readerA.err" "$tmp/readerB.err" "$tmp/readerC.err")"
	check "equal priority: the holding handle held every packet ($(kv "$tmp/readerA.out" held) of $sent)" eq "$(kv "$tmp/readerA.out" held)" "$sent"
	check "equal priority: the handles started after it saw every packet once it resumed them ($(kv "$tmp/readerB.out" captured), $(kv "$tmp/readerC.out" captured))" eq "$(kv "$tmp/readerB.out" captured)/$(kv "$tmp/readerC.out" captured)" "$sent/$sent"
	check "equal priority: everything arrived ($recv of $sent)" eq "$recv" "$sent"
	rig_down
}

t_inject_twin() {
	rig_up || return
	start_bg sink server "$swbench" sink --port $PORT --verify yes
	start_bg pk server "$swbench" pktcheck --port $PORT --iface s0
	start_bg reader "${MODREADER[@]}" --port $PORT --delay-ms 0 --twin yes --inject-if vc
	flood 1000 2 200
	sleep 0.5
	stop_bg reader; stop_bg pk; stop_bg sink
	local sent recv; sent="$(kv "$tmp/flood.out" sent)"; recv="$(kv "$tmp/sink.out" received)"
	check "inject: the originals and one injected twin of each reached the server ($sent sent, $recv received)" eq "$recv" "$((2 * sent))"
	check "inject: no duplicates, no corruption (originals and twins have separate sequence numbers)" eq "$(kv "$tmp/sink.out" dups)/$(kv "$tmp/sink.out" corrupt)" "0/0"
	check "inject: loop avoidance: the handle held only the originals, never its own injected twins ($(kv "$tmp/reader.out" held) held)" eq "$(kv "$tmp/reader.out" held)" "$sent"
	check "inject: every injection succeeded ($(kv "$tmp/reader.out" injected) injected, $(kv "$tmp/reader.out" inject_failed) failed)" eq "$(kv "$tmp/reader.out" injected)/$(kv "$tmp/reader.out" inject_failed)" "$sent/0"
	check "inject: the injected packets have valid checksums on the wire ($(kv "$tmp/pk.out" pk_bad_ip) bad IP, $(kv "$tmp/pk.out" pk_bad_l4) bad UDP)" eq "$(kv "$tmp/pk.out" pk_bad_ip)/$(kv "$tmp/pk.out" pk_bad_l4)" "0/0"
	rig_down
}

t_inject_chain() {
	rig_up || return
	start_bg sink server "$swbench" sink --port $PORT
	start_bg readerA "${MODREADER[@]}" --port $PORT --delay-ms 0 --twin yes --inject-if vc --prio 100
	start_bg readerB "$swbench" sniff --mode swdiv-hold --port $PORT --delay-ms 0 --prio 50
	flood 1000 2 200
	sleep 0.5
	stop_bg readerB; stop_bg readerA; stop_bg sink
	local sent recv; sent="$(kv "$tmp/flood.out" sent)"; recv="$(kv "$tmp/sink.out" received)"
	check "inject + chain: everything delivered ($sent sent, $recv received)" eq "$recv" "$((2 * sent))"
	check "inject + chain: A held only the originals ($(kv "$tmp/readerA.out" held))" eq "$(kv "$tmp/readerA.out" held)" "$sent"
	check "inject + chain: B (served after A) held the originals and A's injected twins ($(kv "$tmp/readerB.out" held))" eq "$(kv "$tmp/readerB.out" held)" "$((2 * sent))"
	rig_down
}

t_mod_tcp_nat() {
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
	if [ -s "$tmp/nft.err" ]; then bad "could not set up NAT: $(cat "$tmp/nft.err")"; rig_down; return; fi
	start_bg sink server "$swbench" tcpsink --port $TCP_PORT
	start_bg reader "${MODREADER[@]}" --port $TCP_PORT --proto tcp --delay-ms 0 --modify tcp-flip
	ns client "$swbench" tcpsend --dst 10.10.2.2 --port $TCP_PORT --bytes 1048576 --seed 777 > "$tmp/send.out" 2>&1
	sleep 0.3
	stop_bg reader; stop_bg sink
	check "modified TCP segments through masquerade: the whole 1 MiB arrived" eq "$(kv "$tmp/sink.out" bytes)" 1048576
	check "modified TCP segments through masquerade: the server saw the gateway's address (connection tracking survived the modification)" eq "$(kv "$tmp/sink.out" peer)" 10.10.2.1
	check "modified TCP segments through masquerade: the tuple did not change, so no tracking entry was detached ($(kv "$tmp/reader.out" ct_detached))" eq "$(kv "$tmp/reader.out" ct_detached)" 0
	rig_down
}

# Modification, timeout, injection and a kill racing each other: nothing may be lost, delivered twice or crash anything
t_race_mod() {
	rig_up || return
	set_param hold_ms 3
	start_bg sink server "$swbench" sink --port $PORT
	start_bg reader "${MODREADER[@]}" --port $PORT --delay-ms 3 --modify payload --twin yes --inject-if vc
	ns client "$swbench" flood --dst 10.10.2.2 --port $PORT --pps 15000 --seconds 2 --size 200 --stream 0 > "$tmp/flood0.out" 2>&1 &
	local f0=$!
	ns client "$swbench" flood --dst 10.10.2.2 --port $PORT --pps 15000 --seconds 2 --size 200 --stream 1 > "$tmp/flood1.out" 2>&1 &
	local f1=$!
	BG_PIDS+=("$f0" "$f1")
	sleep 1
	kill -9 "$(pid_of reader)"; wait "$(pid_of reader)" 2>/dev/null
	wait "$f0" "$f1"
	sleep 0.5
	stop_bg sink
	set_param hold_ms 2000
	local sent recv; sent=$(($(kv "$tmp/flood0.out" sent) + $(kv "$tmp/flood1.out" sent))); recv="$(kv "$tmp/sink.out" received)"
	check "modify + inject + timeout + kill racing: every original arrived, plus injected twins ($sent sent, $recv received)" ge "$recv" "$sent"
	check "modify + inject + timeout + kill racing: nothing delivered twice" eq "$(kv "$tmp/sink.out" dups)" 0
	rig_down
}

# Garbage into INJECT and RESUME_MOD: must neither crash nor wedge anything
t_fuzz() {
	rig_up || return
	start_bg sink server "$swbench" sink --port $PORT
	"$swbench" fuzz --iterations 30000 --seed 1 > "$tmp/fuzz.out" 2>&1
	local rc=$?
	check "fuzz: 30000 malformed INJECT/RESUME_MOD calls completed ($(tail -1 "$tmp/fuzz.out" | cut -c1-150))" eq "$rc" 0
	check "fuzz: nothing ended in an unexpected error code ($(kv "$tmp/fuzz.out" fuzz_other))" eq "$(kv "$tmp/fuzz.out" fuzz_other)" 0
	check "fuzz: some calls were refused as invalid and some were valid" test "$(kv "$tmp/fuzz.out" fuzz_einval)" -gt 1000 -a "$(kv "$tmp/fuzz.out" inject_failed)" -ge 0
	# The path still works afterwards
	start_bg reader "${MODREADER[@]}" --port $PORT --delay-ms 0 --modify payload
	flood 1000 1 200
	sleep 0.3
	stop_bg reader; stop_bg sink
	check "fuzz: traffic still flows and can still be modified afterwards ($(kv "$tmp/flood.out" sent) sent, $(kv "$tmp/sink.out" received) received)" eq "$(kv "$tmp/sink.out" received)" "$(kv "$tmp/flood.out" sent)"
	rig_down
}

# ---- Phase 5: filter programs ----

# Floods three ports one after the other and leaves "sent_PORT" in $tmp/sent.PORT
flood_ports() { # flood_ports PPS SECONDS PORT...
	local pps="$1" secs="$2"; shift 2
	local port
	for port in "$@"; do
		flood "$pps" "$secs" 200 "$port"
		kv "$tmp/flood.out" sent > "$tmp/sent.$port"
	done
}

t_filter_string() {
	rig_up || return
	start_bg sink9000 server "$swbench" sink --port 9000
	start_bg sink9001 server "$swbench" sink --port 9001
	start_bg sink9002 server "$swbench" sink --port 9002
	start_bg reader "$swbench" sniff --mode swdiv-hold --delay-ms 0 --filter "udp and (udp.DstPort == 9000 or udp.DstPort == 9001) and ip.DstAddr == 10.10.2.2"
	flood_ports 1000 1 9000 9001 9002
	sleep 0.3
	stop_bg reader; stop_bg sink9000; stop_bg sink9001; stop_bg sink9002
	local s0 s1 s2; s0="$(cat "$tmp/sent.9000")"; s1="$(cat "$tmp/sent.9001")"; s2="$(cat "$tmp/sent.9002")"
	check "filter string: the packets of the two ports it names were held ($(kv "$tmp/reader.out" held) held of $((s0 + s1)))" eq "$(kv "$tmp/reader.out" held)" "$((s0 + s1))"
	check "filter string: the third port was left alone and everything arrived ($(kv "$tmp/sink9000.out" received)/$s0, $(kv "$tmp/sink9001.out" received)/$s1, $(kv "$tmp/sink9002.out" received)/$s2)" \
		eq "$(kv "$tmp/sink9000.out" received)/$(kv "$tmp/sink9001.out" received)/$(kv "$tmp/sink9002.out" received)" "$s0/$s1/$s2"
	rig_down

	# Negation: a negated port test still needs the protocol (a field of an absent protocol never matches)
	rig_up || return
	start_bg sink9000 server "$swbench" sink --port 9000
	start_bg sink9002 server "$swbench" sink --port 9002
	start_bg reader "$swbench" sniff --mode swdiv-hold --delay-ms 0 --filter "udp.DstPort != 9002"
	flood_ports 1000 1 9000 9002
	sleep 0.3
	stop_bg reader; stop_bg sink9000; stop_bg sink9002
	check "negated port: held the other port only ($(kv "$tmp/reader.out" held) held, $(cat "$tmp/sent.9000") sent to 9000)" eq "$(kv "$tmp/reader.out" held)" "$(cat "$tmp/sent.9000")"
	check "negated port: everything arrived" eq "$(kv "$tmp/sink9000.out" received)/$(kv "$tmp/sink9002.out" received)" "$(cat "$tmp/sent.9000")/$(cat "$tmp/sent.9002")"
	rig_down
}

t_filter_set() {
	local list="ip.DstAddr == 10.10.9.1" i
	for i in $(seq 2 200); do list="$list or ip.DstAddr == 10.10.9.$i"; done
	# A server list of 200 addresses is one sorted set in the program, and 10.10.2.2 is in it
	rig_up || return
	start_bg sink server "$swbench" sink --port $PORT
	start_bg reader "$swbench" sniff --mode swdiv-hold --delay-ms 0 --filter "udp and ($list or ip.DstAddr == 10.10.2.2)"
	flood 2000 1 200
	sleep 0.3
	stop_bg reader; stop_bg sink
	check "address set of 201 entries: the packets to the address in it were held ($(kv "$tmp/reader.out" held) held, $(kv "$tmp/flood.out" sent) sent)" eq "$(kv "$tmp/reader.out" held)" "$(kv "$tmp/flood.out" sent)"
	check "address set: everything arrived" eq "$(kv "$tmp/sink.out" received)" "$(kv "$tmp/flood.out" sent)"
	rig_down
	# ... and without it nothing is held
	rig_up || return
	start_bg sink server "$swbench" sink --port $PORT
	start_bg reader "$swbench" sniff --mode swdiv-hold --delay-ms 0 --filter "udp and ($list)"
	flood 2000 1 200
	sleep 0.3
	stop_bg reader; stop_bg sink
	check "address set without the destination: nothing was held ($(kv "$tmp/reader.out" held))" eq "$(kv "$tmp/reader.out" held)" 0
	check "address set without the destination: everything arrived untouched" eq "$(kv "$tmp/sink.out" received)" "$(kv "$tmp/flood.out" sent)"
	rig_down
	# A negated list: everything but the listed addresses
	rig_up || return
	start_bg sink server "$swbench" sink --port $PORT
	start_bg reader "$swbench" sniff --mode swdiv-hold --delay-ms 0 --filter "udp and not ($list)"
	flood 2000 1 200
	sleep 0.3
	stop_bg reader; stop_bg sink
	check "negated address set: the destination is not in it, so everything was held ($(kv "$tmp/reader.out" held))" eq "$(kv "$tmp/reader.out" held)" "$(kv "$tmp/flood.out" sent)"
	rig_down
}

# The filter is replaced while traffic flows: a packet sees the old or the new program, never a mixture, and nothing is lost
t_filter_swap() {
	rig_up || return
	start_bg sink9000 server "$swbench" sink --port 9000
	start_bg sink9001 server "$swbench" sink --port 9001
	start_bg reader "$swbench" sniff --mode swdiv-hold --delay-ms 0 --filter "udp.DstPort == 9000" --filter2 "udp.DstPort == 9001" --swap-ms 1000
	ns client "$swbench" flood --dst 10.10.2.2 --port 9000 --pps 2000 --seconds 2 --size 200 > "$tmp/flood0.out" 2>&1 &
	local f0=$!
	ns client "$swbench" flood --dst 10.10.2.2 --port 9001 --pps 2000 --seconds 2 --size 200 > "$tmp/flood1.out" 2>&1 &
	local f1=$!
	BG_PIDS+=("$f0" "$f1")
	wait "$f0" "$f1"
	sleep 0.3
	stop_bg reader; stop_bg sink9000; stop_bg sink9001
	local s0 s1 held; s0="$(kv "$tmp/flood0.out" sent)"; s1="$(kv "$tmp/flood1.out" sent)"; held="$(kv "$tmp/reader.out" held)"
	check "filter replaced under traffic: nothing lost ($(kv "$tmp/sink9000.out" received)/$s0 and $(kv "$tmp/sink9001.out" received)/$s1)" eq "$(kv "$tmp/sink9000.out" received)/$(kv "$tmp/sink9001.out" received)" "$s0/$s1"
	# About one second of one port before the swap and one second of the other after it: roughly 4000 of the 8000 packets
	check "filter replaced under traffic: the old program held its port before the swap and the new one its port after it ($held held of $((s0 + s1)))" test "$held" -gt 2500 -a "$held" -lt 5500
	check "filter replaced under traffic: no program was refused" test -z "$(cat "$tmp/reader.err")"
	rig_down
}

t_filter_bad() {
	rig_up || return
	"$swbench" sniff --mode swdiv-hold --filter 'udp.Nope == 1' > "$tmp/bad.out" 2> "$tmp/bad.err"
	local rc=$?
	check "an unsupported filter term is refused by the compiler with a message and a position (exit $rc: $(head -c 100 "$tmp/bad.err"))" eq "$rc" 2
	check "the message names the term" grep -q 'unsupported filter term' "$tmp/bad.err"
	"$swbench" sniff --mode swdiv-hold --filter 'tcp.DstPort == 99999' > "$tmp/bad.out" 2> "$tmp/bad.err"
	check "a port out of range is refused" eq "$?" 2
	rig_down
}

# What the kernel decides on real packets against the reference evaluator: random filters, compiled and installed, random packets
# injected through the rig. Both directions of the comparison are checked (kernel against reference, user-space VM against reference).
t_vmcheck() {
	rig_up || return
	# The server must not answer (ICMP errors, echo replies, resets): an answer would cross the hook too and be counted as a second packet
	ns server nft add table ip quiet
	ns server nft 'add chain ip quiet input { type filter hook input priority 0 ; policy drop ; }'
	local seed
	for seed in 3 4; do
		"$swbench" vmcheck --filters 50 --packets 100 --seed "$seed" > "$tmp/vmcheck.out" 2> "$tmp/vmcheck.err"
		local rc=$?
		check "kernel against the reference, seed $seed: $(kv "$tmp/vmcheck.out" vmcheck_filters) filters, $(kv "$tmp/vmcheck.out" vmcheck_visited) packets reached the hook, $(kv "$tmp/vmcheck.out" vmcheck_matched) matched, $(kv "$tmp/vmcheck.out" vmcheck_mismatches) mismatches" eq "$rc/$(kv "$tmp/vmcheck.out" vmcheck_mismatches)" "0/0"
		[ "$rc" != 0 ] && { head -5 "$tmp/vmcheck.err"; cat "$tmp/vmcheck.out"; }
		check "kernel against the reference, seed $seed: enough packets reached the hook to mean something" ge "$(kv "$tmp/vmcheck.out" vmcheck_visited)" 1500
		check "kernel against the reference, seed $seed: some matched and some did not" test "$(kv "$tmp/vmcheck.out" vmcheck_matched)" -gt 100 -a "$(kv "$tmp/vmcheck.out" vmcheck_matched)" -lt "$(kv "$tmp/vmcheck.out" vmcheck_visited)"
	done
	rig_down
}

t_progcheck() {
	rig_up || return
	"$swbench" progcheck > "$tmp/progcheck.out" 2> "$tmp/progcheck.err"
	local rc=$?
	check "SET_PROGRAM accepts what it must and refuses the rest ($(kv "$tmp/progcheck.out" progcheck_cases) cases, $(kv "$tmp/progcheck.out" progcheck_failed) wrong)" eq "$rc/$(kv "$tmp/progcheck.out" progcheck_failed)" "0/0"
	[ "$rc" != 0 ] && cat "$tmp/progcheck.err"
	rig_down
}

# ---- Phase 6: the lagsw backend (backends/kmod) ----
# `swbench backend` is the real backend::open()/recv()/send() driven like the engine drives it. This script is the gateway: traffic it
# sends is LOCAL_OUT, traffic sent to its addresses is LOCAL_IN, traffic between client and server is FORWARD.

backend_reader() { # backend_reader NAME ARGS...: starts `swbench backend` in the gateway namespace
	local name="$1"; shift
	start_bg "$name" "$swbench" backend "$@"
}

flood_gw() { # flood_gw PPS SECONDS SIZE DST PORT: sent by this host
	"$swbench" flood --dst "$4" --port "$5" --pps "$1" --seconds "$2" --size "$3" > "$tmp/flood.out" 2>&1
}

t_backend_api() {
	rig_up || return
	"$swbench" backend-api > "$tmp/api.out" 2> "$tmp/api.err"
	local rc=$?
	check "the backend contract without traffic: $(kv "$tmp/api.out" backend_api_cases) cases, $(kv "$tmp/api.out" backend_api_failed) failed" eq "$rc/$(kv "$tmp/api.out" backend_api_failed)" "0/0"
	[ "$rc" != 0 ] && cat "$tmp/api.err"
	rig_down
}

# check_privileges() loads the module when the device is missing: by modprobe when the module is installed, else by insmod of the .ko
# named in LAGSW_KMOD_PATH; it unloads it again on exit when asked to, and only when it loaded it.
t_backend_load() {
	local release extra
	release="$(uname -r)"
	rmmod swdivert 2> /dev/null
	check "the module is not loaded (precondition)" test ! -e /dev/swdivert

	LAGSW_KMOD_PATH="$ko" LAGSW_KMOD_UNLOAD_ON_EXIT=1 "$swbench" backend-load > "$tmp/load.out" 2> "$tmp/load.err"
	check "insmod path: check_privileges loaded the module and a channel opened ($(cat "$tmp/load.out") $(head -c 120 "$tmp/load.err"))" eq "$?/$(kv "$tmp/load.out" backend_opened)" "0/1"
	check "unload on exit: the module this process loaded is gone again" test -z "$(lsmod | awk '$1 == "swdivert"')"

	LAGSW_KMOD_PATH="$ko" "$swbench" backend-load > "$tmp/load.out" 2> "$tmp/load.err"
	check "without the unload request the module stays loaded" test -n "$(lsmod | awk '$1 == "swdivert"')"
	LAGSW_KMOD_UNLOAD_ON_EXIT=1 "$swbench" backend-load > "$tmp/load.out" 2> "$tmp/load.err"
	check "a module somebody else loaded is never unloaded, even when asked to" test -n "$(lsmod | awk '$1 == "swdivert"')"
	rmmod swdivert 2> /dev/null

	extra="/usr/lib/modules/$release/extra"
	[ -d "/usr/lib/modules/$release" ] || extra="/lib/modules/$release/extra"
	mkdir -p "$extra" && cp "$ko" "$extra/swdivert.ko" && depmod "$release" 2> /dev/null
	"$swbench" backend-load > "$tmp/load.out" 2> "$tmp/load.err"
	check "modprobe path: an installed module is loaded without any path ($(cat "$tmp/load.out") $(head -c 120 "$tmp/load.err"))" eq "$?/$(kv "$tmp/load.out" backend_opened)" "0/1"
	rmmod swdivert 2> /dev/null
	rm -f "$extra/swdivert.ko"; depmod "$release" 2> /dev/null

	# An explicit path is used alone: swdivert.ko sits next to swbench here, and must not be loaded instead of the one asked for
	LAGSW_KMOD_PATH=/nonexistent/swdivert.ko "$swbench" backend-load > "$tmp/load.out" 2> "$tmp/load.err"
	local rc=$?
	check "a module that cannot be loaded is a startup error (exit $rc) that says what to run" eq "$rc" 3
	check "... and the message names modprobe and insmod ($(kv "$tmp/load.out" backend_privileges): $(grep -o 'backend_error=.*' "$tmp/load.out" | head -c 160))" grep -q 'modprobe swdivert.*insmod' "$tmp/load.out"
	insmod "$ko" 2> "$tmp/load.err" || bad "could not load the module again: $(cat "$tmp/load.err")"
}

# The loader the embedded module goes through (init_module(2) from memory), on variants of the module that test_kmod_hold_vm.sh prepares next
# to swbench: as the build embeds it (stripped), signed with a key this kernel has never heard of, built for another kernel release, cut
# short, and not a module at all. Nothing but the first two may load, and a refusal must leave no module behind.
t_backend_image() {
	local dir loaded v
	dir="$(dirname "$swbench")"
	loaded() { lsmod | awk '$1 == "swdivert" {found = 1} END {exit !found}'; }
	rmmod swdivert 2> /dev/null
	check "the module is not loaded (precondition)" test ! -e /dev/swdivert

	if [ -f "$dir/stripped.ko" ]; then
		"$swbench" backend-image "$dir/stripped.ko" > "$tmp/image.out" 2> "$tmp/image.err"
		check "stripped module (what the build embeds): loaded from memory ($(cat "$tmp/image.out"))" eq "$?/$(kv "$tmp/image.out" image_status)" "0/loaded"
		for v in $(seq 1 60); do [ -c /dev/swdivert ] && break; sleep 0.05; done
		check "... and its device appears" test -c /dev/swdivert
		"$swbench" backend-image "$dir/stripped.ko" > "$tmp/image.out" 2> "$tmp/image.err"
		check "loading it again is reported as already loaded, not as a failure" eq "$?/$(kv "$tmp/image.out" image_status)" "0/already"
		"$swbench" backend-load > "$tmp/load.out" 2> "$tmp/load.err"
		check "the loaded module works: a channel opens through the backend" eq "$?/$(kv "$tmp/load.out" backend_opened)" "0/1"
		rmmod swdivert 2> "$tmp/rmmod.err" || bad "rmmod failed: $(cat "$tmp/rmmod.err")"
	else
		bad "no stripped module variant prepared"
	fi

	if [ -f "$dir/signed.ko" ]; then
		"$swbench" backend-image "$dir/signed.ko" > "$tmp/image.out" 2> "$tmp/image.err"
		check "module signed with an unknown key: loads where signatures are not enforced ($(kv "$tmp/image.out" image_status): $(kv "$tmp/image.out" image_error))" eq "$?/$(kv "$tmp/image.out" image_status)" "0/loaded"
		rmmod swdivert 2> /dev/null
	else
		echo "  (no signed variant: the host has no kernel signing tool or openssl)"
	fi

	for v in other_kernel truncated not_a_module; do
		[ -f "$dir/$v.ko" ] || { bad "no $v module variant prepared"; continue; }
		"$swbench" backend-image "$dir/$v.ko" > "$tmp/image.out" 2> "$tmp/image.err"
		local rc=$?
		check "$v: refused with an explanation ($(kv "$tmp/image.out" image_status): $(grep -o 'image_error=.*' "$tmp/image.out" | head -c 150))" eq "$rc/$(kv "$tmp/image.out" image_status)" "1/failed"
		check "$v: nothing was left loaded" test ! -e /dev/swdivert -a -z "$(lsmod | awk '$1 == "swdivert"')"
	done
	"$swbench" backend-image "$dir/other_kernel.ko" > "$tmp/image.out" 2> /dev/null
	check "a module built for another kernel says so and where to look" grep -q 'built for kernel .*not for the running kernel.*dmesg' "$tmp/image.out"
	check "... and the image's own release is shown next to the kernel's ($(kv "$tmp/image.out" image_release) against $(kv "$tmp/image.out" kernel_release))" test -n "$(kv "$tmp/image.out" image_release)" -a "$(kv "$tmp/image.out" image_release)" != "$(kv "$tmp/image.out" kernel_release)"
	"$swbench" backend-image "$dir/not_a_module.ko" > "$tmp/image.out" 2> /dev/null
	check "something that is not a module is called that" grep -q 'not a kernel module' "$tmp/image.out"
	insmod "$ko" 2> "$tmp/load.err" || bad "could not load the module again: $(cat "$tmp/load.err")"
}

# Loading a module takes CAP_SYS_MODULE, not root: a lagsw with `setcap cap_net_admin,cap_sys_module+ep` loads the module it carries and
# runs as an ordinary user. Tested with setpriv standing in for file capabilities. The kernel creates /dev/swdivert root-only and the udev
# rule (scripts/package/linux/70-swdivert.rules) gives it to a group a moment later; there is no udev in the VM, so a background loop does
# what the rule does (chgrp, chmod 0660) a little after the node appears, which is also the race lagsw has to wait out.
t_backend_caps() {
	local user_in_group=(setpriv --reuid=1000 --regid=1500 --clear-groups) user_outside=(setpriv --reuid=1001 --regid=1001 --clear-groups) rc started elapsed
	local caps=(--inh-caps=+net_admin,+sys_module --ambient-caps=+net_admin,+sys_module)
	rmmod swdivert 2> /dev/null
	chmod 755 "$(dirname "$swbench")" 2> /dev/null

	( for _ in $(seq 1 600); do [ -c /dev/swdivert ] && break; sleep 0.01; done; sleep 0.4; chgrp 1500 /dev/swdivert; chmod 0660 /dev/swdivert ) &
	local udev_pid=$!
	"${user_in_group[@]}" "${caps[@]}" env LAGSW_KMOD_PATH="$ko" LAGSW_KMOD_UNLOAD_ON_EXIT=1 "$swbench" backend-load > "$tmp/caps.out" 2> "$tmp/caps.err"
	rc=$?
	wait "$udev_pid" 2> /dev/null
	check "a member of the device's group with CAP_NET_ADMIN and CAP_SYS_MODULE, not root, loads the module and opens a channel although the node only gets its group 0.4 s after it appears (exit $rc: $(cat "$tmp/caps.out") $(head -c 120 "$tmp/caps.err"))" eq "$rc/$(kv "$tmp/caps.out" backend_opened)" "0/1"
	check "... and unloads it again on exit, which needs the same capability" test -z "$(lsmod | awk '$1 == "swdivert"')"

	# Not in the group: the node stays root-only for this user, and the refusal comes after the bounded wait with the way out
	( for _ in $(seq 1 600); do [ -c /dev/swdivert ] && break; sleep 0.01; done; sleep 0.4; chgrp 1500 /dev/swdivert; chmod 0660 /dev/swdivert ) &
	udev_pid=$!
	started=$(date +%s.%N)
	"${user_outside[@]}" "${caps[@]}" env LAGSW_KMOD_PATH="$ko" "$swbench" backend-load > "$tmp/caps.out" 2> "$tmp/caps.err"
	rc=$?
	elapsed="$(awk -v a="$started" -v b="$(date +%s.%N)" 'BEGIN{printf "%.1f", b - a}')"
	wait "$udev_pid" 2> /dev/null
	check "a user outside the group is refused (exit $rc after $elapsed s)" eq "$rc" 3
	check "... with the udev rule and the script that installs it named ($(grep -o 'backend_error=.*' "$tmp/caps.out" | head -c 150))" grep -q 'udev rule.*setup_kmod_access.sh' "$tmp/caps.out"
	check "... after waiting for udev, but not for ever ($elapsed s)" test "${elapsed%.*}" -ge 1 -a "${elapsed%.*}" -le 6
	rmmod swdivert 2> /dev/null

	"${user_in_group[@]}" --inh-caps=+net_admin --ambient-caps=+net_admin env LAGSW_KMOD_PATH="$ko" "$swbench" backend-load > "$tmp/caps.out" 2> "$tmp/caps.err"
	rc=$?
	check "a user without CAP_SYS_MODULE is told what is missing and nothing is loaded (exit $rc)" eq "$rc" 3
	check "... the message names the capability and how to grant it ($(grep -o 'backend_error=.*' "$tmp/caps.out" | head -c 170))" grep -q 'CAP_SYS_MODULE.*setcap' "$tmp/caps.out"
	check "... and the module is still not loaded" test -z "$(lsmod | awk '$1 == "swdivert"')"

	# Root whose bounding set lacks the capability (a container, a hardened service): the kernel's refusal is explained
	setpriv --bounding-set=-sys_module env LAGSW_KMOD_PATH="$ko" "$swbench" backend-load > "$tmp/caps.out" 2> "$tmp/caps.err"
	rc=$?
	check "root without CAP_SYS_MODULE in its bounding set: refused with the reason (exit $rc: $(grep -o 'backend_error=.*' "$tmp/caps.out" | head -c 200))" eq "$rc" 3
	check "... which names the missing capability" grep -q 'CAP_SYS_MODULE' "$tmp/caps.out"
	check "... and nothing was loaded" test -z "$(lsmod | awk '$1 == "swdivert"')"
	insmod "$ko" 2> "$tmp/load.err" || bad "could not load the module again: $(cat "$tmp/load.err")"
}

# The interface is declared stable (ABI version 1): what is reserved or unused has to be zero, unknown flags, verdicts and ioctls are refused with the
# errno that says so, and the answers carry no garbage. The sizes and ioctl numbers are asserted at compile time; this is the kernel's side of the rules.
t_abi() {
	rig_up || return
	"$swbench" abicheck > "$tmp/abi.out" 2> "$tmp/abi.err"
	local rc=$?
	check "the rules of the stable interface hold in the kernel ($(kv "$tmp/abi.out" abicheck_cases) cases, $(kv "$tmp/abi.out" abicheck_failed) wrong)" eq "$rc/$(kv "$tmp/abi.out" abicheck_failed)" "0/0"
	[ "$rc" != 0 ] && cat "$tmp/abi.err"
	dmesg | grep swdivert > "$tmp/abi.dmesg"
	check "the module reports ABI version 1 when it loads ($(head -c 100 "$tmp/abi.dmesg"))" grep -q 'ready (abi 1)' "$tmp/abi.dmesg"
	check "its metadata says what it is (modinfo): version 1, no spike label" test "$(modinfo -F version "$ko")" = 1 -a -z "$(modinfo -F description "$ko" | grep -i spike)"
	rig_down
}

t_backend_local_out() {
	rig_up || return
	start_bg sink server "$swbench" sink --port $PORT --verify yes
	backend_reader reader --filter "udp.DstPort == $PORT" --delay-ms 20
	flood_gw 1000 2 200 10.10.2.2 $PORT
	sleep 0.4
	stop_bg reader; stop_bg sink
	local sent recv p50; sent="$(kv "$tmp/flood.out" sent)"; recv="$(kv "$tmp/sink.out" received)"; p50="$(kv "$tmp/sink.out" lat_p50_us)"
	check "output hook: every packet this host sent was seen by the engine, as outbound ($(kv "$tmp/reader.out" backend_seen) seen, $(kv "$tmp/reader.out" backend_outbound) outbound, $sent sent)" \
		eq "$(kv "$tmp/reader.out" backend_seen)/$(kv "$tmp/reader.out" backend_outbound)" "$sent/$sent"
	check "output hook: all of it arrived and was sent back by the engine ($recv received, $(kv "$tmp/reader.out" backend_sent) sent back)" eq "$recv/$(kv "$tmp/reader.out" backend_sent)" "$sent/$sent"
	check "output hook: the engine's 20 ms delay was applied (median latency $p50 us)" test "$p50" -ge 20000 -a "$p50" -le 40000
	check "output hook: nothing corrupt, duplicated or reordered" eq "$(kv "$tmp/sink.out" corrupt)/$(kv "$tmp/sink.out" dups)/$(kv "$tmp/sink.out" reordered)" "0/0/0"
	check "output hook: the channel listened at input and output ($(kv "$tmp/reader.out" backend_layers))" eq "$(kv "$tmp/reader.out" backend_layers)" "input_+_output_hooks"
	rig_down
}

t_backend_local_in() {
	rig_up || return
	start_bg sink "$swbench" sink --port $PORT --verify yes
	backend_reader reader --filter "udp.DstPort == $PORT" --delay-ms 20
	ns client "$swbench" flood --dst 10.10.1.1 --port $PORT --pps 1000 --seconds 2 --size 200 > "$tmp/flood.out" 2>&1
	sleep 0.4
	stop_bg reader; stop_bg sink
	local sent recv p50; sent="$(kv "$tmp/flood.out" sent)"; recv="$(kv "$tmp/sink.out" received)"; p50="$(kv "$tmp/sink.out" lat_p50_us)"
	check "input hook: every packet for this host was seen by the engine, as inbound ($(kv "$tmp/reader.out" backend_seen) seen, $(kv "$tmp/reader.out" backend_inbound) inbound, $sent sent)" \
		eq "$(kv "$tmp/reader.out" backend_seen)/$(kv "$tmp/reader.out" backend_inbound)" "$sent/$sent"
	check "input hook: all of it was delivered to the local socket ($recv of $sent)" eq "$recv" "$sent"
	check "input hook: the 20 ms delay was applied (median latency $p50 us)" test "$p50" -ge 20000 -a "$p50" -le 40000
	check "input hook: nothing corrupt, duplicated or reordered" eq "$(kv "$tmp/sink.out" corrupt)/$(kv "$tmp/sink.out" dups)/$(kv "$tmp/sink.out" reordered)" "0/0/0"
	rig_down
}

t_backend_forward() {
	rig_up || return
	start_bg sink server "$swbench" sink --port $PORT --verify yes
	# A local filter does not see routed packets ...
	backend_reader local --filter "udp.DstPort == $PORT" --delay-ms 20
	flood 1000 1 200
	sleep 0.3
	stop_bg local; stop_bg sink
	check "a local filter does not see forwarded traffic ($(kv "$tmp/local.out" backend_seen) seen)" eq "$(kv "$tmp/local.out" backend_seen)" 0
	check "... which was not delayed or lost either ($(kv "$tmp/sink.out" received) of $(kv "$tmp/flood.out" sent))" eq "$(kv "$tmp/sink.out" received)" "$(kv "$tmp/flood.out" sent)"
	# ... a forward filter does
	start_bg sink server "$swbench" sink --port $PORT --verify yes
	backend_reader reader --forward yes --filter "udp.DstPort == $PORT" --delay-ms 20
	flood 1000 2 200
	sleep 0.4
	stop_bg reader; stop_bg sink
	local sent recv p50; sent="$(kv "$tmp/flood.out" sent)"; recv="$(kv "$tmp/sink.out" received)"; p50="$(kv "$tmp/sink.out" lat_p50_us)"
	check "forward: every routed packet was seen, as outbound ($(kv "$tmp/reader.out" backend_seen) seen, $(kv "$tmp/reader.out" backend_outbound) outbound, $sent sent)" \
		eq "$(kv "$tmp/reader.out" backend_seen)/$(kv "$tmp/reader.out" backend_outbound)" "$sent/$sent"
	check "forward: all of it arrived after the 20 ms delay ($recv of $sent, median $p50 us)" test "$recv" = "$sent" -a "$p50" -ge 20000 -a "$p50" -le 40000
	check "forward: the channel listened at forward only ($(kv "$tmp/reader.out" backend_layers))" eq "$(kv "$tmp/reader.out" backend_layers)" "forward_hook"
	rig_down
}

# include_forward: one channel for local and routed traffic, as a gateway's sniffers and profiles open it
t_backend_all() {
	rig_up || return
	start_bg sink_out server "$swbench" sink --port 9000
	start_bg sink_fwd server "$swbench" sink --port 9001
	start_bg sink_in "$swbench" sink --port 9002
	backend_reader reader --include-forward yes --filter "udp.DstPort == 9000 or udp.DstPort == 9001 or udp.DstPort == 9002" --delay-ms 10
	"$swbench" flood --dst 10.10.2.2 --port 9000 --pps 500 --seconds 2 --size 200 > "$tmp/f_out.out" 2>&1 &
	local a=$!
	ns client "$swbench" flood --dst 10.10.2.2 --port 9001 --pps 500 --seconds 2 --size 200 > "$tmp/f_fwd.out" 2>&1 &
	local b=$!
	ns client "$swbench" flood --dst 10.10.1.1 --port 9002 --pps 500 --seconds 2 --size 200 > "$tmp/f_in.out" 2>&1 &
	local c=$!
	BG_PIDS+=("$a" "$b" "$c")
	wait "$a" "$b" "$c"
	sleep 0.4
	stop_bg reader; stop_bg sink_out; stop_bg sink_fwd; stop_bg sink_in
	local so sf si; so="$(kv "$tmp/f_out.out" sent)"; sf="$(kv "$tmp/f_fwd.out" sent)"; si="$(kv "$tmp/f_in.out" sent)"
	check "all three kinds at once: the engine saw each ($(kv "$tmp/reader.out" backend_seen) seen of $((so + sf + si)); $(kv "$tmp/reader.out" backend_outbound) outbound, $(kv "$tmp/reader.out" backend_inbound) inbound)" \
		eq "$(kv "$tmp/reader.out" backend_seen)/$(kv "$tmp/reader.out" backend_outbound)/$(kv "$tmp/reader.out" backend_inbound)" "$((so + sf + si))/$((so + sf))/$si"
	check "all three kinds at once: everything arrived ($(kv "$tmp/sink_out.out" received)/$so, $(kv "$tmp/sink_fwd.out" received)/$sf, $(kv "$tmp/sink_in.out" received)/$si)" \
		eq "$(kv "$tmp/sink_out.out" received)/$(kv "$tmp/sink_fwd.out" received)/$(kv "$tmp/sink_in.out" received)" "$so/$sf/$si"
	check "all three kinds at once: one channel listened at all three hooks ($(kv "$tmp/reader.out" backend_layers))" eq "$(kv "$tmp/reader.out" backend_layers)" "input_+_output_+_forward_hooks"
	rig_down
}

# "outbound" and "inbound" in the filter pick the direction on the host, as the NFQUEUE backend's compiler does
t_backend_direction() {
	rig_up || return
	start_bg sink_out server "$swbench" sink --port 9000
	start_bg sink_in "$swbench" sink --port 9000
	backend_reader outbound --filter "outbound and udp.DstPort == 9000" --delay-ms 5
	backend_reader inbound --filter "inbound and udp.DstPort == 9000" --delay-ms 5
	"$swbench" flood --dst 10.10.2.2 --port 9000 --pps 500 --seconds 1 --size 200 > "$tmp/f_out.out" 2>&1
	ns client "$swbench" flood --dst 10.10.1.1 --port 9000 --pps 500 --seconds 1 --size 200 > "$tmp/f_in.out" 2>&1
	sleep 0.3
	stop_bg outbound; stop_bg inbound; stop_bg sink_out; stop_bg sink_in
	check "outbound filter: saw what the host sent and nothing else ($(kv "$tmp/outbound.out" backend_seen) of $(kv "$tmp/f_out.out" sent); layers $(kv "$tmp/outbound.out" backend_layers))" \
		eq "$(kv "$tmp/outbound.out" backend_seen)/$(kv "$tmp/outbound.out" backend_outbound)/$(kv "$tmp/outbound.out" backend_layers)" "$(kv "$tmp/f_out.out" sent)/$(kv "$tmp/f_out.out" sent)/output_hook"
	check "inbound filter: saw what the host received and nothing else ($(kv "$tmp/inbound.out" backend_seen) of $(kv "$tmp/f_in.out" sent); layers $(kv "$tmp/inbound.out" backend_layers))" \
		eq "$(kv "$tmp/inbound.out" backend_seen)/$(kv "$tmp/inbound.out" backend_inbound)/$(kv "$tmp/inbound.out" backend_layers)" "$(kv "$tmp/f_in.out" sent)/$(kv "$tmp/f_in.out" sent)/input_hook"
	check "direction filters: everything arrived ($(kv "$tmp/sink_out.out" received), $(kv "$tmp/sink_in.out" received))" eq "$(kv "$tmp/sink_out.out" received)/$(kv "$tmp/sink_in.out" received)" "$(kv "$tmp/f_out.out" sent)/$(kv "$tmp/f_in.out" sent)"
	rig_down
}

# The engine rewrites a packet and recomputes its checksums with backend::calc_checksums() before it sends it back. At the input hook the
# stack verifies the checksum itself, so a wrong one would be dropped; at the output hook it is checked on the wire at the receiver.
t_backend_modify() {
	rig_up || return
	start_bg sink_old "$swbench" sink --port $PORT
	start_bg sink_new "$swbench" sink --port 9005
	backend_reader reader --filter "udp.DstPort == $PORT" --delay-ms 0 --modify dport --to-port 9005
	ns client "$swbench" flood --dst 10.10.1.1 --port $PORT --pps 1000 --seconds 1 --size 200 > "$tmp/flood.out" 2>&1
	sleep 0.3
	stop_bg reader; stop_bg sink_old; stop_bg sink_new
	local sent; sent="$(kv "$tmp/flood.out" sent)"
	check "rewrite at the input hook: the stack accepted the engine's checksums ($(kv "$tmp/sink_new.out" received) arrived on the new port of $sent, $(kv "$tmp/sink_old.out" received) on the old)" \
		eq "$(kv "$tmp/sink_new.out" received)/$(kv "$tmp/sink_old.out" received)" "$sent/0"
	rig_down

	rig_up || return
	start_bg sink_new server "$swbench" sink --port 9005
	start_bg pk server "$swbench" pktcheck --port 9005 --iface s0
	backend_reader reader --filter "udp.DstPort == $PORT" --delay-ms 0 --modify dport --to-port 9005
	flood_gw 1000 1 200 10.10.2.2 $PORT
	sleep 0.3
	stop_bg reader; stop_bg pk; stop_bg sink_new
	sent="$(kv "$tmp/flood.out" sent)"
	check "rewrite at the output hook: all arrived on the new port ($(kv "$tmp/sink_new.out" received) of $sent)" eq "$(kv "$tmp/sink_new.out" received)" "$sent"
	check "rewrite at the output hook: the checksums are right on the wire ($(kv "$tmp/pk.out" pk_bad_ip) bad IP, $(kv "$tmp/pk.out" pk_bad_l4) bad UDP of $(kv "$tmp/pk.out" pk_total))" eq "$(kv "$tmp/pk.out" pk_bad_ip)/$(kv "$tmp/pk.out" pk_bad_l4)" "0/0"
	rig_down
}

# Traffic of this host to itself crosses the output and the input hook. The engine must see (and delay) each packet once, not once per hook.
t_backend_loopback() {
	rig_up || return
	start_bg sink "$swbench" sink --port $PORT --verify yes
	backend_reader reader --filter "udp.DstPort == $PORT" --delay-ms 100
	"$swbench" flood --dst 127.0.0.1 --port $PORT --pps 500 --seconds 2 --size 200 > "$tmp/flood.out" 2>&1
	sleep 0.5
	stop_bg reader; stop_bg sink
	local sent recv p50; sent="$(kv "$tmp/flood.out" sent)"; recv="$(kv "$tmp/sink.out" received)"; p50="$(kv "$tmp/sink.out" lat_p50_us)"
	check "loopback: every packet was held once, not once per hook ($(kv "$tmp/reader.out" backend_seen) seen for $sent sent)" eq "$(kv "$tmp/reader.out" backend_seen)" "$sent"
	check "loopback: the delay applied once (median latency $p50 us, not twice 100 ms)" test "$p50" -ge 100000 -a "$p50" -lt 150000
	check "loopback: everything arrived intact ($recv of $sent)" eq "$recv/$(kv "$tmp/sink.out" corrupt)" "$sent/0"
	rig_down
}

# A real TCP connection of this host (socket-owned packets, segmentation offload, TCP small queues) through a held output and input path
t_backend_tcp() {
	rig_up || return
	start_bg sink server "$swbench" tcpsink --port $TCP_PORT
	backend_reader reader --filter "tcp.DstPort == $TCP_PORT or tcp.SrcPort == $TCP_PORT" --delay-ms 2
	"$swbench" tcpsend --dst 10.10.2.2 --port $TCP_PORT --bytes 4194304 --seed 777 > "$tmp/send.out" 2>&1
	sleep 0.3
	stop_bg reader; stop_bg sink
	check "tcp from this host (output hook, acks at input): all 4 MiB arrived intact ($(kv "$tmp/sink.out" bytes) bytes, $(kv "$tmp/send.out" elapsed_ms) ms)" \
		eq "$(kv "$tmp/sink.out" bytes)/$(kv "$tmp/sink.out" hash)" "4194304/$(kv "$tmp/send.out" hash)"
	check "tcp from this host: the segments in both directions went through the engine ($(kv "$tmp/reader.out" backend_seen) seen, $(kv "$tmp/reader.out" backend_inbound) of them inbound)" test "$(kv "$tmp/reader.out" backend_outbound)" -ge 2500 -a "$(kv "$tmp/reader.out" backend_inbound)" -ge 100
	check "tcp from this host: every packet the engine saw it sent back ($(kv "$tmp/reader.out" backend_sent) of $(kv "$tmp/reader.out" backend_seen), $(kv "$tmp/reader.out" backend_errors) errors)" eq "$(kv "$tmp/reader.out" backend_sent)/$(kv "$tmp/reader.out" backend_errors)" "$(kv "$tmp/reader.out" backend_seen)/0"
	stop_bg sink 2> /dev/null
	rig_down

	# ... and the other way: the data arrives at this host (input hook), the acks leave it
	rig_up || return
	start_bg sink "$swbench" tcpsink --port $TCP_PORT
	backend_reader reader --filter "tcp.DstPort == $TCP_PORT or tcp.SrcPort == $TCP_PORT" --delay-ms 2
	ns server "$swbench" tcpsend --dst 10.10.2.1 --port $TCP_PORT --bytes 4194304 --seed 778 > "$tmp/send.out" 2>&1
	sleep 0.3
	stop_bg reader; stop_bg sink
	check "tcp to this host (input hook, acks at output): all 4 MiB arrived intact ($(kv "$tmp/sink.out" bytes) bytes)" eq "$(kv "$tmp/sink.out" bytes)/$(kv "$tmp/sink.out" hash)" "4194304/$(kv "$tmp/send.out" hash)"
	check "tcp to this host: every packet the engine saw it sent back ($(kv "$tmp/reader.out" backend_sent) of $(kv "$tmp/reader.out" backend_seen))" eq "$(kv "$tmp/reader.out" backend_sent)/$(kv "$tmp/reader.out" backend_errors)" "$(kv "$tmp/reader.out" backend_seen)/0"
	rig_down
}

# Fail-open with socket-owned packets: the engine dies while it holds what this host sends; the module lets the packets go, and the
# sockets they belong to (closed meanwhile) are released exactly once
t_backend_sigkill() {
	rig_up || return
	start_bg sink server "$swbench" sink --port $PORT
	backend_reader reader --filter "udp.DstPort == $PORT" --delay-ms 3000
	"$swbench" flood --dst 10.10.2.2 --port $PORT --pps 1000 --seconds 2 --size 200 > "$tmp/flood.out" 2>&1 &
	local f=$!
	BG_PIDS+=("$f")
	sleep 1
	stop_bg reader KILL
	wait "$f"
	sleep 0.5
	stop_bg sink
	local sent recv; sent="$(kv "$tmp/flood.out" sent)"; recv="$(kv "$tmp/sink.out" received)"
	check "the engine killed while holding outgoing packets: nothing was lost ($recv of $sent arrived)" eq "$recv" "$sent"
	rig_down

	# The same for a sender that exits while its packets are still held: the socket is closed, the packets are not
	rig_up || return
	start_bg sink server "$swbench" sink --port $PORT
	backend_reader reader --filter "udp.DstPort == $PORT" --delay-ms 400
	flood_gw 1000 1 200 10.10.2.2 $PORT
	sleep 1
	stop_bg reader; stop_bg sink
	sent="$(kv "$tmp/flood.out" sent)"; recv="$(kv "$tmp/sink.out" received)"
	check "packets still held when their sender's socket is closed are delivered ($recv of $sent)" eq "$recv" "$sent"
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
	printf '| %s | %s | %s | %s | %s.%s %% | %s | %s | %s | %s | %s | %s |\n' "$label" "$pps" "$sent" "$recv" \
		"$(( (sent - recv) * 100 / sent ))" "$(( ((sent - recv) * 1000 / sent) % 10 ))" \
		"$(kv "$tmp/sink.out" lat_p50_us)" "$(kv "$tmp/sink.out" lat_p99_us)" "$(kv "$tmp/sink.out" lat_max_us)" \
		"$([ -n "$captured" ] && [ "$captured" != 0 ] && awk -v c="$cpu" -v n="$captured" 'BEGIN{printf "%.2f", c*1000/n}' || echo -)" \
		"$([ -n "${BENCH_FILL:-}" ] && echo "$(kv "$tmp/sink.out" corrupt)" || echo -)" \
		"$([ -n "$captured" ] && echo "$(kv "$tmp/reader.out" dropped)" || echo -)"
	unset PID_reader
}

t_bench() {
	echo "| mode | pps | sent | delivered | lost | latency p50 us | p99 us | max us | reader CPU us/packet | wrong bytes | ring full / ENOBUFS |"
	echo "|---|---|---|---|---|---|---|---|---|---|---|"
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

		# The real lagsw backend (backend::open/recv/send, as the engine drives it) doing the same job. The tool copies every packet into a
		# heap buffer before it sends it back, as the engine does, so this row includes that.
		rig_up || return
		start_bg sink server "$swbench" sink --port $PORT
		start_bg reader "$swbench" backend --forward yes --filter "udp.DstPort == $PORT" --delay-ms 0
		bench_row "lagsw backend (swdivert), verdict at once" "$pps"
		rig_down

		# The same without the tool's own per-packet copies and allocations: the cost of the backend alone
		rig_up || return
		start_bg sink server "$swbench" sink --port $PORT
		start_bg reader "$swbench" backend --forward yes --filter "udp.DstPort == $PORT" --delay-ms 0 --inline yes
		bench_row "lagsw backend (swdivert), verdict at once, no tool copies" "$pps"
		rig_down

		# The same with every packet modified (payload bytes rewritten, checksums fixed): NFQUEUE sends the whole packet back and
		# the engine recomputes the checksums; the module takes the bytes and a flag. Both read the whole packet.
		export BENCH_FILL=y
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
		start_bg sink server "$swbench" sink --port $PORT --verify yes --fill y
		start_bg reader "$swbench" sniff --mode nfq-hold --port $PORT --delay-ms 0 --snap $SNAP --modify payload
		bench_row "NFQUEUE, modify every packet (checksums in user space)" "$pps"
		rig_down

		rig_up || return
		set_param hold_wake_us 0
		start_bg sink server "$swbench" sink --port $PORT --verify yes --fill y
		start_bg reader "${MODREADER[@]}" --port $PORT --delay-ms 0 --modify payload
		bench_row "swdivert, modify every packet (RESUME_MOD, checksums in the kernel)" "$pps"
		rig_down
		unset BENCH_FILL
	done
}

# ---- run ----

echo "module: $ko"
insmod "$ko" || { echo "insmod failed"; exit 1; }
dmesg_before="$(dmesg | wc -l)"
[ -c /dev/swdivert ] || { echo "/dev/swdivert did not appear"; exit 1; }

default_tests=(sniff filter_string filter_set filter_swap filter_bad vmcheck progcheck abi backend_api backend_load backend_image backend_caps backend_local_out backend_local_in backend_forward backend_all backend_direction backend_modify backend_loopback backend_tcp backend_sigkill mod_payload mod_grow mod_shrink mod_tcp mod_tcp_nat mod_bad mod_dst chain_order priority_equal inject_twin inject_chain race_mod fuzz resume_now delay drop_verdict tcp tcp_nat sigkill_hold graceful_stop hold_timeout max_held device_removal rate race)
[ "${#only[@]}" -eq 0 ] && only=("${default_tests[@]}")
for t in sniff filter_string filter_set filter_swap filter_bad vmcheck progcheck abi backend_api backend_load backend_image backend_caps backend_local_out backend_local_in backend_forward backend_all backend_direction backend_modify backend_loopback backend_tcp backend_sigkill mod_payload mod_grow mod_shrink mod_tcp mod_tcp_nat mod_bad mod_dst chain_order priority_equal inject_twin inject_chain race_mod fuzz resume_now delay drop_verdict tcp tcp_nat sigkill_hold graceful_stop hold_timeout max_held device_removal rate race bench; do
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
