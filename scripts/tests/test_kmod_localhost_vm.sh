#!/usr/bin/env bash
# Runs the lagsw feature harness (pocs/linux_nfqueue_backend/localhost_harness.py, the profile profiles/localhost.test.sw.yml) against the
# swdivert kernel-module backend in a throw-away VM that boots the host's kernel (scripts/tests/kmod_vm.sh): no root, no container.
#
# usage: scripts/tests/test_kmod_localhost_vm.sh [--lagsw PATH] [--ko PATH] [--cpus N] [ONLY]
#   --embedded     lagsw loads the module from its own image: no .ko file is given to the VM (the build default: `xmake f --linux_backend=kmod`)
#   lagsw has to be built for the kmod backend: `xmake f --linux_backend=kmod && xmake build lagsw swdivert`.
#   ONLY is the harness's ONLY variable: "guard" runs just the release-mark case.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
lagsw="" ko="" cpus=4 embedded=0
while [ $# -gt 0 ]; do
	case "$1" in
	--lagsw) lagsw="$2"; shift 2 ;;
	--ko) ko="$2"; shift 2 ;;
	--cpus) cpus="$2"; shift 2 ;;
	--embedded) embedded=1; shift ;;
	*) break ;;
	esac
done
newest() { find "$root/build/linux/x86_64" -name "$1" -type f -printf '%T@ %p\n' 2> /dev/null | sort -rn | head -1 | cut -d' ' -f2-; }
[ -n "$lagsw" ] || lagsw="$(newest lagsw)"
[ -n "$ko" ] || ko="$(newest swdivert.ko)"
[ -x "$lagsw" ] && { [ "$embedded" = 1 ] || [ -f "$ko" ]; } || { echo "need a built lagsw and swdivert.ko (xmake f --linux_backend=kmod && xmake build lagsw swdivert)" >&2; exit 1; }
if ldd "$lagsw" | grep -q netfilter_queue; then
	echo "$lagsw was built for the NFQUEUE backend; configure with --linux_backend=kmod" >&2
	exit 1
fi
echo "lagsw: $lagsw"
if [ "$embedded" = 1 ]; then
	echo "module: embedded in lagsw"
	ko_files=()
	ko_arg="-"
else
	echo "module: $ko"
	ko_files=(--file "$ko")
	ko_arg=/opt/swdivert.ko
fi

exec "$root/scripts/tests/kmod_vm.sh" --cpus "$cpus" --mem 3072 --timeout 900 \
	--python "os sys re pty select shutil socket subprocess tempfile threading time encodings.idna" \
	--file "$lagsw" "${ko_files[@]}" --file "$root/pocs/linux_nfqueue_backend/localhost_harness.py" --file "$root/profiles/localhost.test.sw.yml" \
	-- "$root/scripts/tests/test_kmod_localhost.sh" /opt/"$(basename "$lagsw")" /opt/localhost_harness.py /opt/localhost.test.sw.yml "$ko_arg" "${1:-}"
