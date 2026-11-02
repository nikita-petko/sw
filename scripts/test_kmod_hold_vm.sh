#!/usr/bin/env bash
# Builds nothing: runs the Phase 3 tests of the swdivert module (scripts/test_kmod_hold.sh) inside a throw-away VM that boots the
# host's kernel (scripts/kmod_vm.sh), so no root is needed and the host kernel never loads the module.
# Build first: xmake build swdivert swbench       (the mode and architecture of `xmake f` decide which build is used)
# usage: scripts/test_kmod_hold_vm.sh [--cpus N] [--mem MB] [--slub-debug FLAGS] [test-name ...]
#        scripts/test_kmod_hold_vm.sh --slub-debug "" bench       divert-and-resume against NFQUEUE (timing: no slab debugging)
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
vm_args=()
while [ $# -gt 0 ]; do
	case "$1" in
	--cpus | --mem | --slub-debug) vm_args+=("$1" "$2"); shift 2 ;;
	*) break ;;
	esac
done
newest() { find "$root/build/linux/x86_64" -name "$1" -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-; }
ko="$(newest swdivert.ko)"; swbench="$(newest swbench)"
[ -n "$ko" ] && [ -n "$swbench" ] || { echo "build first: xmake f -a x86_64 && xmake build swdivert swbench" >&2; exit 1; }
echo "module: $ko" >&2
exec "$root/scripts/kmod_vm.sh" --cpus 8 --mem 3072 "${vm_args[@]}" --timeout 600 --file "$ko" --file "$swbench" \
	-- "$root/scripts/test_kmod_hold.sh" /opt/swdivert.ko /opt/swbench "$@"
