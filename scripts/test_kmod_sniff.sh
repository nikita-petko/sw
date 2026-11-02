#!/usr/bin/env bash
# Loads the swdivert Phase 2 module into the RUNNING kernel, checks that it captures exactly what is forwarded through a
# throw-away veth gateway (and survives a SIGKILLed reader), optionally benchmarks it against AF_PACKET and NFQUEUE, and unloads it.
# Needs root and touches the host kernel (modules are host-wide, so no container). The traffic stays inside new network namespaces.
# usage: sudo scripts/test_kmod_sniff.sh [--bench]    (build as your user first: xmake build swdivert swbench)
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
newest() { find "$root/build" -name "$1" -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-; }
ko="$(newest swdivert.ko)"
[ -n "$ko" ] || { echo "swdivert.ko not found; run: xmake build swdivert" >&2; exit 1; }
[ -n "$(newest swbench)" ] || { echo "swbench not found; run: xmake build swbench" >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo "loading a kernel module needs root; run with sudo" >&2; exit 1; }
[ "$(modinfo -F vermagic "$ko" | cut -d' ' -f1)" = "$(uname -r)" ] || { echo "module was built for another kernel than $(uname -r)" >&2; exit 1; }
! lsmod | grep -q '^swdivert ' || { echo "swdivert is already loaded; rmmod it first" >&2; exit 1; }

echo "module: $ko"
dmesg_before="$(dmesg | wc -l)"
insmod "$ko"
trap 'rmmod swdivert' EXIT
[ -c /dev/swdivert ] || { echo "/dev/swdivert did not appear" >&2; exit 1; }

# Keep going after a failed check: the reference-count check and the benchmark are worth having either way
status=0
python3 "$root/pocs/linux_kernel_module_backend/bench.py" --check --modes afpacket,nfq,swdiv || status=1
# Every reader is gone now: nothing may still hold the module (a leaked handle or hook would show up here and block rmmod)
used="$(lsmod | awk '$1 == "swdivert" {print $3}')"
if [ "$used" = 0 ]; then
	echo "ok   no reference to the module is left after the readers exited"
else
	echo "FAIL swdivert is still in use ($used) after all readers exited" >&2
	status=1
fi

# The kernel log must not show the module (or anything triggered by it) misbehaving. A KASAN/lockdep splat needs a debug kernel to appear at all.
if dmesg | tail -n +"$((dmesg_before + 1))" | grep -E 'BUG:|WARNING:|KASAN|Oops|lockdep|general protection|Call Trace' ; then
	echo "FAIL the kernel log shows a problem (above)" >&2
	status=1
else
	echo "ok   no BUG/WARNING/Oops in the kernel log since the module was loaded"
fi

if [ "${1:-}" = "--bench" ]; then
	# Lighter than bench.py's defaults so it finishes in a few minutes; rows are printed as they complete. swdiv@US[:BATCH] sets the
	# module's wake_us/wake_batch for that row only (swdiv@0 = wake per packet), so one run shows how batching trades latency for CPU.
	python3 "$root/pocs/linux_kernel_module_backend/bench.py" --modes baseline,afpacket,nfq,swdiv@0,swdiv@50,swdiv@250:256,swdiv@1000:256 \
		--pps 100000,200000 --sizes 64 --runs 2 --seconds 3 || status=1
fi
[ "$status" = 0 ] && echo "all checks passed" || echo "some checks FAILED" >&2
exit "$status"
