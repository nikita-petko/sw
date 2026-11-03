#!/usr/bin/env bash
# Cross-compiles lagsw for Linux aarch64 (XMake calls it arm64) from an x86-64 Arch Linux or Ubuntu/Debian host.
# It installs the cross compiler, assembles an aarch64 sysroot with the libraries lagsw links against (without root,
# in a directory of its own) and runs xmake. Run `scripts/build/build_aarch64.sh --help` for the options.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
sysroot="$root/build/sysroot/aarch64"
mode="release"
sysroot_only=0
refresh=0
do_package=0
xmake_args=()

# Arch Linux ARM mirror for the Arch sysroot. mirror.archlinuxarm.org has no valid HTTPS certificate.
ALARM_MIRROR="${ALARM_MIRROR:-https://de3.mirror.archlinuxarm.org}"
# Ubuntu publishes arm64 packages on a separate "ports" mirror, Debian on its main one.
UBUNTU_PORTS_MIRROR="${UBUNTU_PORTS_MIRROR:-http://ports.ubuntu.com/ubuntu-ports}"
DEBIAN_MIRROR="${DEBIAN_MIRROR:-http://deb.debian.org/debian}"

usage() {
    cat <<EOF
Usage: $(basename "$0") [options] [-- extra xmake config arguments]

  --sysroot DIR     where the aarch64 sysroot is created (default: build/sysroot/aarch64)
  --mode MODE       release (default) or debug
  --refresh         rebuild the sysroot even if it already exists
  --sysroot-only    prepare the sysroot and stop
  --package         also run 'xmake package' after the build
  -h, --help        show this help

The host distribution is detected automatically: pacman (Arch Linux) or apt (Ubuntu/Debian).
Environment: ALARM_MIRROR, UBUNTU_PORTS_MIRROR, DEBIAN_MIRROR override the package mirrors.
EOF
}

die() { echo "error: $*" >&2; exit 1; }
log() { printf '\n==> %s\n' "$*"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sysroot) sysroot="$(realpath -m "${2:?--sysroot needs a directory}")"; shift 2 ;;
        --mode) mode="${2:?--mode needs a value}"; shift 2 ;;
        --refresh) refresh=1; shift ;;
        --sysroot-only) sysroot_only=1; shift ;;
        --package) do_package=1; shift ;;
        -h|--help) usage; exit 0 ;;
        --) shift; xmake_args=("$@"); break ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
done
[[ "$mode" == release || "$mode" == debug ]] || die "--mode must be release or debug"

[[ "$(uname -s)" == Linux ]] || die "this script runs on Linux hosts only"
host_arch="$(uname -m)"
[[ "$host_arch" == x86_64 ]] || die "unsupported host architecture $host_arch: this script cross-compiles from x86_64 (build natively on aarch64)"

# ---- Detect the package manager ----
distro="unknown"
if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    distro="${ID:-unknown}"
fi
if command -v pacman >/dev/null 2>&1; then
    family="arch"
elif command -v apt-get >/dev/null 2>&1; then
    family="debian"
else
    die "neither pacman nor apt-get found; only Arch Linux and Ubuntu/Debian hosts are supported"
fi
echo "Host: $distro ($family family)"

command -v xmake >/dev/null 2>&1 || die "xmake not found: install it from https://xmake.io"

run_root() {
    if [[ $EUID -eq 0 ]]; then "$@"; else sudo "$@"; fi
}

# ---- Host cross compiler ----
cross_prefix="aarch64-linux-gnu-"
if ! command -v "${cross_prefix}g++" >/dev/null 2>&1; then
    log "Installing the aarch64 cross compiler (needs root)"
    if [[ $family == arch ]]; then
        run_root pacman -S --needed --noconfirm aarch64-linux-gnu-gcc
    else
        run_root apt-get update
        run_root apt-get install -y g++-aarch64-linux-gnu
    fi
fi
bindir="$(dirname "$(command -v "${cross_prefix}g++")")"

# ---- Sysroot ----
# The sysroot holds the aarch64 headers and libraries lagsw links against, and the C library they were built for.
sysroot_arch() {
    local pkgs=(glibc linux-api-headers gcc-libs zlib curl libnetfilter_queue libmnl libnftnl libnfnetlink)
    local work="$sysroot/.work" conf
    conf="$work/pacman.conf"
    mkdir -p "$work/db" "$work/cache" "$work/gpg" "$sysroot"
    # Packages come from Arch Linux ARM. Signatures are not checked because the Arch Linux ARM keyring is not set up here;
    # the sysroot only supplies headers and libraries to link against and is never installed on the host.
    cat >"$conf" <<EOF
[options]
Architecture = aarch64
HookDir = $work/hooks
NoExtract = usr/share/libalpm/hooks/*
DisableSandbox
ParallelDownloads = 5
SigLevel = Never

[core]
Server = $ALARM_MIRROR/\$arch/\$repo

[extra]
Server = $ALARM_MIRROR/\$arch/\$repo
EOF
    command -v unshare >/dev/null 2>&1 || die "unshare (util-linux) is required"
    log "Installing ${pkgs[*]} from Arch Linux ARM into $sysroot"
    # A user namespace makes pacman believe it runs as root, so no real root is needed and files stay owned by this user.
    # The "Exec format error" pacman prints for its ldconfig call is expected: the target is aarch64.
    unshare -r pacman --config "$conf" --root "$sysroot" --dbpath "$work/db" --cachedir "$work/cache" \
        --gpgdir "$work/gpg" --noscriptlet --noconfirm -Sy --needed "${pkgs[@]}"
}

sysroot_debian() {
    local pkgs=(libc6-dev libstdc++6 zlib1g-dev libcurl4-openssl-dev libnetfilter-queue-dev libmnl-dev libnftnl-dev libnfnetlink-dev)
    local work="$sysroot/.work" codename="${VERSION_CODENAME:-}" keyring sources
    [[ -n "$codename" ]] || die "cannot determine the distribution codename from /etc/os-release"
    mkdir -p "$work/state/lists/partial" "$work/cache/archives/partial" "$sysroot"
    : >"$work/status"

    if [[ "$distro" == ubuntu ]]; then
        keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg
        sources="deb [arch=arm64 signed-by=$keyring] $UBUNTU_PORTS_MIRROR $codename main universe
deb [arch=arm64 signed-by=$keyring] $UBUNTU_PORTS_MIRROR $codename-updates main universe
deb [arch=arm64 signed-by=$keyring] $UBUNTU_PORTS_MIRROR $codename-security main universe"
    else
        keyring=/usr/share/keyrings/debian-archive-keyring.gpg
        sources="deb [arch=arm64 signed-by=$keyring] $DEBIAN_MIRROR $codename main
deb [arch=arm64 signed-by=$keyring] $DEBIAN_MIRROR $codename-updates main
deb [arch=arm64 signed-by=$keyring] http://deb.debian.org/debian-security $codename-security main"
    fi
    [[ -r "$keyring" ]] || die "archive keyring $keyring not found (install ubuntu-keyring or debian-archive-keyring)"
    printf '%s\n' "$sources" >"$work/sources.list"

    # A private apt configuration resolves the arm64 dependency closure against the arm64 mirrors, without touching the
    # host's own apt state or architecture list (so it works without `dpkg --add-architecture arm64` and without root).
    local apt=(apt-get
        -o "APT::Architecture=arm64" -o "APT::Architectures=arm64"
        -o "Dir::Etc::sourcelist=$work/sources.list" -o "Dir::Etc::sourceparts=-"
        -o "Dir::State=$work/state" -o "Dir::State::status=$work/status"
        -o "Dir::Cache=$work/cache" -o "Debug::NoLocking=1"
        -o "APT::Install-Recommends=false" -o "APT::Get::AllowUnauthenticated=false")
    log "Downloading arm64 packages for ${pkgs[*]} (not installed on this host)"
    "${apt[@]}" update
    "${apt[@]}" install --download-only --yes "${pkgs[@]}"

    log "Extracting packages into $sysroot"
    local deb
    for deb in "$work"/cache/archives/*.deb; do
        dpkg-deb -x "$deb" "$sysroot"
    done
}

marker="$sysroot/.lagsw-sysroot"
if [[ $refresh -eq 1 || ! -f "$marker" ]]; then
    rm -rf "$sysroot"
    mkdir -p "$sysroot"
    if [[ $family == arch ]]; then sysroot_arch; else sysroot_debian; fi
    rm -rf "$sysroot/.work"
    echo "$family" >"$marker"
else
    echo "Using the existing sysroot $sysroot (--refresh recreates it)"
fi
[[ -f "$sysroot/usr/include/curl/curl.h" ]] || die "sysroot is incomplete: curl/curl.h is missing"
[[ $sysroot_only -eq 0 ]] || { echo "Sysroot ready: $sysroot"; exit 0; }

# ---- Build ----
# --sysroot points the compiler and linker at the aarch64 headers and libraries; rpath-link finds their dependencies.
# Arch's cross compiler looks for headers in <sysroot>/include instead of <sysroot>/usr/include, hence the explicit paths;
# -idirafter keeps them behind libstdc++'s own wrappers of the C headers (written as -Wp, because xmake splits two-word flags).
libdirs=("$sysroot/usr/lib" "$sysroot/usr/lib/aarch64-linux-gnu" "$sysroot/lib/aarch64-linux-gnu")
sysflags="--sysroot=$sysroot -Wp,-idirafter,$sysroot/usr/include -Wp,-idirafter,$sysroot/usr/include/aarch64-linux-gnu"
ldflags="--sysroot=$sysroot"
for dir in "${libdirs[@]}"; do
    ldflags+=" -L$dir -Wl,-rpath-link,$dir"
done
ldflags+=" -B$sysroot/usr/lib -B$sysroot/usr/lib/aarch64-linux-gnu"

cd "$root"
log "Configuring xmake for linux/arm64 ($mode)"
xmake f -c -y -p linux -a arm64 --toolchain=cross --bin="$bindir" --cross="$cross_prefix" \
    --cxflags="$sysflags" --ldflags="$ldflags" --linux_bpf=n -m "$mode" "${xmake_args[@]}"

log "Building lagsw"
xmake build -y lagsw

exe="$root/build/linux/arm64/$mode/lagsw"
[[ -f "$exe" ]] || die "build finished but $exe was not produced"
if command -v readelf >/dev/null 2>&1 && ! readelf -h "$exe" | grep -q 'Machine:.*AArch64'; then
    die "$exe is not an AArch64 binary"
fi

if [[ $do_package -eq 1 ]]; then
    log "Packaging"
    xmake package -y -o "$root/dist" lagsw
fi

echo
echo "Built $exe"
