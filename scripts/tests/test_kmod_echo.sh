#!/usr/bin/env bash
# Builds the swdivert_echo kernel module through xmake, loads it into the RUNNING kernel, exercises /dev/swdivert_echo and unloads it.
# Unlike the other test scripts this cannot use a container: modules are host-wide, so it needs root and touches the host kernel.
# usage: sudo scripts/tests/test_kmod_echo.sh [--build-only]   (build as your own user first with `xmake build swdivert_echo kmod_echo_test`)
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
ko="$(find "$root/build" -name swdivert_echo.ko -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)"
test_bin="$(find "$root/build" -name kmod_echo_test -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)"
[ -n "$ko" ] || { echo "swdivert_echo.ko not found; run: xmake build swdivert_echo" >&2; exit 1; }

echo "module: $ko"
modinfo "$ko" | grep -E '^(filename|license|description|vermagic):'
[ "$(modinfo -F vermagic "$ko" | cut -d' ' -f1)" = "$(uname -r)" ] || { echo "module was built for a different kernel than the running one ($(uname -r))" >&2; exit 1; }
[ "${1:-}" = "--build-only" ] && exit 0

[ "$(id -u)" = 0 ] || { echo "loading a kernel module needs root; run with sudo" >&2; exit 1; }
[ -x "$test_bin" ] || { echo "kmod_echo_test not found; run: xmake build kmod_echo_test" >&2; exit 1; }
! lsmod | grep -q '^swdivert_echo ' || { echo "swdivert_echo is already loaded; rmmod it first" >&2; exit 1; }

insmod "$ko"
trap 'rmmod swdivert_echo' EXIT
[ -c /dev/swdivert_echo ] || { echo "/dev/swdivert_echo did not appear" >&2; exit 1; }
"$test_bin"
