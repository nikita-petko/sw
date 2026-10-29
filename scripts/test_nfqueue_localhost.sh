#!/usr/bin/env bash
# Runs the localhost feature profile against the NFQUEUE backend inside a throwaway privileged container.
# The container keeps its own network namespace, so the host firewall and network are never touched.
# usage: scripts/test_nfqueue_localhost.sh [path-to-lagsw]   (build with `xmake -y` first)
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
bin="${1:-$(find "$root/build/linux" -name lagsw -type f -path '*debug*' | head -1)}"
[ -x "$bin" ] || { echo "lagsw binary not found; run xmake -y" >&2; exit 1; }

docker run --rm --privileged -e ONLY \
	-v "$root:/src:ro" -v "$(dirname "$bin"):/bin-dir:ro" \
	archlinux:latest bash -c "
		pacman -Sy --noconfirm --needed nftables libnetfilter_queue python >/dev/null 2>&1
		python /src/pocs/linux_nfqueue_backend/localhost_harness.py /bin-dir/$(basename "$bin") /src/profiles/localhost.test.sw.yml
	"
