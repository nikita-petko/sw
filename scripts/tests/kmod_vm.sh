#!/usr/bin/env bash
# Runs a script as root inside a throw-away QEMU virtual machine that boots the HOST's kernel image, so kernel modules can be loaded,
# exercised and crashed without touching the host kernel and without root. Needs qemu-system-x86_64, /dev/kvm, /boot/vmlinuz-linux
# (readable), the kernel module tree of the same kernel under /usr/lib/modules and the usual host tools (bash, iproute2, util-linux,
# kmod). Everything the VM runs is copied from the host into an initramfs; nothing is installed.
#
# usage: scripts/tests/kmod_vm.sh [--mem MB] [--cpus N] [--timeout SEC] [--modules "m1 m2"] [--slub-debug FLAGS] [--keep] [--file F]... -- script [args...]
#   --file F      also copy F into the VM at /opt/<basename F> (modules, test tools; the script is copied to /opt/run.sh)
#   --modules     kernel modules (with dependencies) available to `modprobe` in the VM
#   --python MODS Python 3 with just the standard-library modules MODS (space separated, plus what they import) in the VM: a few MB instead
#                 of the whole standard library
#   --slub-debug  slub_debug= flags (default FZP: sanity checks, red zones, poisoning: catches use-after-free and overflows of slab objects;
#                 "" turns it off, which is what you want for timing)
# The VM's console output is streamed; the exit status is the script's. A kernel panic or a timeout is a failure.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
mem=2048
cpus=4
timeout_s=300
modules="veth nf_conntrack nf_nat nf_tables nft_nat nft_masq nft_chain_nat nft_ct nft_queue nfnetlink_queue nf_conntrack_netlink"
files=()
py_modules=""
keep=0
slab_debug="FZP"
while [ $# -gt 0 ]; do
	case "$1" in
	--mem) mem="$2"; shift 2 ;;
	--cpus) cpus="$2"; shift 2 ;;
	--timeout) timeout_s="$2"; shift 2 ;;
	--modules) modules="$2"; shift 2 ;;
	--file) files+=("$2"); shift 2 ;;
	--python) py_modules="$2"; shift 2 ;;
	--keep) keep=1; shift ;;
	--slub-debug) slab_debug="$2"; shift 2 ;;
	--) shift; break ;;
	*) echo "unknown option $1" >&2; exit 2 ;;
	esac
done
[ $# -ge 1 ] || { echo "usage: $0 [options] -- script [args...]" >&2; exit 2; }
script="$1"; shift
[ -f "$script" ] || { echo "no such script: $script" >&2; exit 2; }

kernel_image="${KERNEL_IMAGE:-/boot/vmlinuz-linux}"
release="$(file -b "$kernel_image" | sed -n 's/.*version \([^ ]*\).*/\1/p')"
[ -r "$kernel_image" ] || { echo "cannot read $kernel_image" >&2; exit 1; }
[ -n "$release" ] || { echo "cannot tell the version of $kernel_image" >&2; exit 1; }
modroot="/usr/lib/modules/$release"
[ -d "$modroot" ] || { echo "no module tree $modroot for the kernel image ($release)" >&2; exit 1; }
[ -w /dev/kvm ] || { echo "/dev/kvm is not writable: KVM is required" >&2; exit 1; }

work="$(mktemp -d "${TMPDIR:-/tmp}/kmodvm.XXXXXX")"
[ "$keep" = 1 ] || trap 'rm -rf "$work"' EXIT
img="$work/initramfs"
stage="$work/root"
mkdir -p "$stage"/{usr/bin,usr/lib,proc,sys,dev,tmp,run,opt,etc,var} "$stage/usr/lib/modules/$release"
ln -s usr/bin "$stage/bin"; ln -s usr/bin "$stage/sbin"; ln -s usr/lib "$stage/lib"; ln -s usr/lib "$stage/lib64"
ln -s bin "$stage/usr/sbin"

# Copies a host file to the same path in the image, following symlinks for the content (programs look libraries up by the
# soname path, so that exact path has to exist as a file).
put() {
	[ -e "$stage$1" ] && return 0
	mkdir -p "$stage$(dirname "$1")"
	cp -L "$1" "$stage$1"
}
# Copies a host program and the shared libraries it needs.
copy_bin() {
	local path
	path="$(type -P "$1" 2>/dev/null)" || return 1
	put "$path"
	copy_libs "$path"
}
copy_libs() {
	local lib loader
	while read -r lib; do
		[ -e "$lib" ] && put "$lib"
	done < <(ldd "$1" 2>/dev/null | awk '/=> \//{print $3} /^[ \t]*\//{print $1}')
	loader="$(readelf -l "$1" 2>/dev/null | sed -n 's/.*Requesting program interpreter: \(.*\)]/\1/p')"
	[ -n "$loader" ] && put "$loader"
	return 0
}

for tool in bash sh ls cat sleep echo mkdir rm cp mv ln date kill sort head tail wc tr cut sed awk grep egrep diff uniq seq true false env test \
	chmod chgrp chown mount umount dmesg sync stat id uname hostname find xargs tee timeout mktemp readlink dirname basename \
	ip nsenter unshare setpriv insmod rmmod lsmod modprobe depmod modinfo nft ping ss; do
	copy_bin "$tool" || echo "note: $tool is not a program on the host, skipped" >&2
done
# kmod's tools are symlinks to one binary: copy_bin followed them, which stored the same program under each name, so that works.
for lib in /usr/lib/libnss_files.so.2; do [ -e "$lib" ] && put "$lib"; done

# Python: the interpreter, its library, and exactly the standard-library files that importing the requested modules loads on the host
if [ -n "$py_modules" ]; then
	copy_bin python3 || { echo "python3 is not available on the host" >&2; exit 1; }
	while read -r f; do
		put "$f"
		case "$f" in *.so) copy_libs "$f" ;; esac
	done < <(python3 -c '
import importlib, os, sys
for name in sys.argv[1:]:
    importlib.import_module(name)
for module in list(sys.modules.values()):
    path = getattr(module, "__file__", None)
    if path and os.path.isfile(path):
        print(path)
' $py_modules)
fi

# Kernel modules with their dependencies, plus the metadata modprobe needs
for m in $modules; do
	modprobe -S "$release" --show-depends "$m" 2>/dev/null | awk '/^insmod/{print $2}'
done | sort -u | while read -r ko; do
	mkdir -p "$stage$(dirname "$ko")"
	cp "$ko" "$stage$ko"
done
for f in modules.order modules.builtin modules.builtin.modinfo modules.builtin.bin; do
	[ -e "$modroot/$f" ] && cp "$modroot/$f" "$stage$modroot/" || true
done
depmod -b "$stage/usr" "$release" 2>/dev/null || depmod -b "$stage" "$release"

# What to run
cp "$script" "$stage/opt/run.sh"; chmod +x "$stage/opt/run.sh"
for f in "${files[@]}"; do
	cp -L "$f" "$stage/opt/$(basename "$f")"
	case "$f" in
	*.ko) ;;
	*)
		chmod +x "$stage/opt/$(basename "$f")"
		# Only programs have libraries to bring along (scripts and data files are copied as they are)
		[ "$(head -c 4 "$f" | tail -c 3)" = ELF ] && copy_libs "$f"
		;;
	esac
done
# nsswitch/hosts so tools do not stall on lookups
echo "root:x:0:0:root:/:/bin/bash" > "$stage/etc/passwd"
echo "hosts: files" > "$stage/etc/nsswitch.conf"
echo "127.0.0.1 localhost" > "$stage/etc/hosts"

args=""
for a in "$@"; do args="$args '${a//\'/\'\\\'\'}'"; done
cat > "$stage/init" <<EOF
#!/bin/bash
export PATH=/usr/bin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
mount -t tmpfs tmp /tmp
mount -t tmpfs run /run
mkdir -p /dev/pts /sys/fs/cgroup
echo 0 > /proc/sys/kernel/printk 2>/dev/null || true
ip link set lo up
cd /opt
set +e
/opt/run.sh$args
code=\$?
echo "VM-EXIT:\$code"
sync
echo o > /proc/sysrq-trigger
sleep 5
EOF
chmod +x "$stage/init"

( cd "$stage" && find . | cpio -o -H newc --quiet | gzip -1 > "$img" )
echo "== initramfs $(du -h "$img" | cut -f1), kernel $release, ${mem} MB, ${cpus} CPUs" >&2

log="$work/console.log"
set +e
timeout "$timeout_s" qemu-system-x86_64 -enable-kvm -cpu host -smp "$cpus" -m "$mem" -nographic -no-reboot \
	-kernel "$kernel_image" -initrd "$img" \
	-append "console=ttyS0 panic=-1 oops=panic rdinit=/init loglevel=4 net.ifnames=0 ${slab_debug:+slub_debug=$slab_debug}" \
	-nic none 2>&1 | tee "$log" | sed -u 's/\r$//'
set -e
code="$(sed -n 's/.*VM-EXIT:\([0-9]*\).*/\1/p' "$log" | tail -1)"
if [ -z "$code" ]; then
	echo "== the VM ended without running the script to the end (kernel panic, oops or timeout after ${timeout_s}s)" >&2
	[ "$keep" = 1 ] && echo "== kept: $work" >&2
	exit 125
fi
[ "$keep" = 1 ] && echo "== kept: $work" >&2
exit "$code"
