#!/usr/bin/env bash
# Builds nothing: runs the Phase 3 tests of the swdivert module (scripts/tests/test_kmod_hold.sh) inside a throw-away VM that boots the
# host's kernel (scripts/tests/kmod_vm.sh), so no root is needed and the host kernel never loads the module.
# Build first: xmake build swdivert swbench       (the mode and architecture of `xmake f` decide which build is used)
# usage: scripts/tests/test_kmod_hold_vm.sh [--cpus N] [--mem MB] [--slub-debug FLAGS] [test-name ...]
#        scripts/tests/test_kmod_hold_vm.sh --slub-debug "" bench       divert-and-resume against NFQUEUE (timing: no slab debugging)
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
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

# Variants of the module for the tests of the in-memory loader (the embedded module is loaded that way): stripped as embedded, signed with a
# throw-away key (a kernel that does not enforce signatures loads it and taints itself; an unknown key must not matter), built for another
# kernel release, cut short, and not a module. Prepared here because the VM has neither openssl nor the kernel's signing tool.
work="$(mktemp -d "${TMPDIR:-/tmp}/swvariants.XXXXXX")"
trap 'rm -rf "$work"' EXIT
variant_files=()
cp "$ko" "$work/stripped.ko" && strip --strip-debug "$work/stripped.ko" && variant_files+=(--file "$work/stripped.ko")
release="$(modinfo -F vermagic "$ko" | cut -d' ' -f1)"
python3 - "$work/stripped.ko" "$work/other_kernel.ko" "$work/truncated.ko" "$work/not_a_module.ko" "$release" <<'PY'
import sys
src, other, cut, junk, release = sys.argv[1:6]
data = open(src, "rb").read()
magic = ("vermagic=" + release).encode()
assert data.count(magic) == 1, "vermagic not found exactly once"
open(other, "wb").write(data.replace(magic, b"vermagic=" + b"9" * len(release)))
open(cut, "wb").write(data[: len(data) // 2])
open(junk, "wb").write(b"this is not a kernel module\n" * 100)
PY
variant_files+=(--file "$work/other_kernel.ko" --file "$work/truncated.ko" --file "$work/not_a_module.ko")
sign_tool="/lib/modules/$(uname -r)/build/scripts/sign-file"
if [ -x "$sign_tool" ] && command -v openssl > /dev/null; then
	openssl req -new -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=swdivert test key/" -keyout "$work/key.pem" -outform DER -out "$work/cert.der" 2> /dev/null
	cp "$work/stripped.ko" "$work/signed.ko"
	"$sign_tool" sha256 "$work/key.pem" "$work/cert.der" "$work/signed.ko"
	variant_files+=(--file "$work/signed.ko")
fi
"$root/scripts/tests/kmod_vm.sh" --cpus 8 --mem 3072 "${vm_args[@]}" --timeout 600 --file "$ko" --file "$swbench" "${variant_files[@]}" \
	-- "$root/scripts/tests/test_kmod_hold.sh" /opt/swdivert.ko /opt/swbench "$@"
