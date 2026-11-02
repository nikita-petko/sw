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
insmod "$ko"
trap 'rmmod swdivert' EXIT
[ -c /dev/swdivert ] || { echo "/dev/swdivert did not appear" >&2; exit 1; }

python3 "$root/pocs/linux_kernel_module_backend/bench.py" --check --modes afpacket,nfq,swdiv
# Every reader is gone now: nothing may still hold the module (a leaked handle or hook would show up here and block rmmod)
used="$(lsmod | awk '$1 == "swdivert" {print $3}')"
[ "$used" = 0 ] || { echo "FAIL swdivert is still in use ($used) after all readers exited" >&2; exit 1; }
echo "ok   no reference to the module is left after the readers exited"

if [ "${1:-}" = "--bench" ]; then
	python3 "$root/pocs/linux_kernel_module_backend/bench.py"
fi
