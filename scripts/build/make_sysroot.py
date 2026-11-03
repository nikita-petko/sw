#!/usr/bin/env python3
"""Creates a Linux sysroot (headers and libraries lagsw links against) from Debian or Ubuntu packages.

It runs on any host (Windows, Linux, macOS) with only the Python standard library, needs no root and never installs
anything on the host. Use it to cross-compile lagsw for Linux with clang from a machine that is not that Linux, e.g.:

    python scripts/build/make_sysroot.py --arch x86_64 --dest build/sysroot/x86_64
    xmake f -p linux -a x86_64 --toolchain=clang --sysroot=build/sysroot/x86_64

The package indexes and packages are downloaded over HTTPS and verified against the SHA-256 sums of the release file
(its GPG signature is not checked). Run with --help for the options.
"""
import argparse
import hashlib
import io
import lzma
import gzip
import os
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request

# Packages lagsw needs: the C and C++ runtimes and headers, the libraries of the Linux packet backend, libcurl and zlib
# for the HTTPS region lookups, and libbpf for the optional eBPF egress tier. Their runtime dependencies are added.
ROOTS = [
    "libc6-dev", "linux-libc-dev", "libcrypt-dev", "libgcc-s1", "libstdc++6",
    "zlib1g-dev", "libcurl4-openssl-dev",
    "libnetfilter-queue-dev", "libmnl-dev", "libnftnl-dev", "libnfnetlink-dev",
    "libbpf-dev",
]
# Host tools and data a sysroot has no use for
SKIP = {"libc-dev-bin", "rpcsvc-proto", "debconf", "dpkg", "perl-base", "tzdata", "ca-certificates", "install-info",
        "pkg-config", "pkgconf", "pkgconf-bin", "libpkgconf3"}

DISTROS = {
    # name: (default release, {arch: (mirror, components)}, suites derived from the release)
    "debian": ("bookworm", lambda arch: ("https://deb.debian.org/debian", ["main"]), lambda rel: [rel, rel + "-updates"]),
    "ubuntu": ("noble",
               lambda arch: ("https://archive.ubuntu.com/ubuntu" if arch == "amd64" else "https://ports.ubuntu.com/ubuntu-ports", ["main", "universe"]),
               lambda rel: [rel, rel + "-updates"]),
}
# Packages taken from another suite of the release: the kernel headers and libbpf of Debian 12 (6.1, 1.1) are older than
# what the eBPF tier uses (TCX needs kernel headers 6.6+ and libbpf 1.3+)
PINNED = {"debian": {name: (lambda rel: rel + "-backports") for name in ("linux-libc-dev", "libbpf-dev", "libbpf1")}}
ARCHS = {"x86_64": "amd64", "x64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}


def log(message):
    print("==> " + message, flush=True)


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "lagsw-make-sysroot"})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def parse_paragraphs(text):
    for block in text.split("\n\n"):
        fields, key = {}, None
        for line in block.split("\n"):
            if not line:
                continue
            if line[0] in " \t":
                if key:
                    fields[key] += "\n" + line.strip()
            else:
                key, _, value = line.partition(":")
                fields[key] = value.strip()
        if fields:
            yield fields


def load_index(mirror, suite, component, arch):
    """Downloads Packages for one suite/component, checked against the sums of InRelease."""
    release = fetch(f"{mirror}/dists/{suite}/InRelease").decode("utf-8", "replace")
    sums = {}
    in_sha256 = False
    for line in release.splitlines():
        if line.startswith("SHA256:"):
            in_sha256 = True
        elif in_sha256 and line.startswith(" "):
            digest, _, name = line.split(None, 2)
            sums[name] = digest
        elif in_sha256 and not line.startswith(" "):
            in_sha256 = False
    for ext, opener in ((".xz", lzma.decompress), (".gz", gzip.decompress)):
        name = f"{component}/binary-{arch}/Packages{ext}"
        if name in sums:
            data = fetch(f"{mirror}/dists/{suite}/{name}")
            if hashlib.sha256(data).hexdigest() != sums[name]:
                raise SystemExit(f"error: checksum mismatch for {suite}/{name}")
            return opener(data).decode("utf-8", "replace")
    raise SystemExit(f"error: {suite}/{component} has no Packages index for {arch} on {mirror}")


class Repository:
    def __init__(self, mirror, suites, components, arch, pinned):
        self.mirror = mirror
        self.packages = {}
        self.provides = {}
        # Earlier suites are overridden by later ones (the -updates pocket carries newer versions)
        for suite in suites:
            for component in components:
                log(f"reading the package index of {suite}/{component}")
                for fields in parse_paragraphs(load_index(mirror, suite, component, arch)):
                    self.packages[fields["Package"]] = fields
        for suite in sorted(set(pinned.values())):
            for component in components:
                log(f"reading the package index of {suite}/{component} for {', '.join(n for n, s in pinned.items() if s == suite)}")
                for fields in parse_paragraphs(load_index(mirror, suite, component, arch)):
                    if pinned.get(fields["Package"]) == suite:
                        self.packages[fields["Package"]] = fields
        for name, fields in self.packages.items():
            for provided in fields.get("Provides", "").split(","):
                provided = provided.strip().split(" ")[0]
                if provided:
                    self.provides.setdefault(provided, name)

    def lookup(self, name):
        if name in self.packages:
            return self.packages[name]
        if name in self.provides:
            return self.packages[self.provides[name]]
        return None

    def dependencies(self, fields):
        """Names of the runtime dependencies; the first available alternative of each is used."""
        result = []
        for group in fields.get("Depends", "").split(","):
            for alternative in group.split("|"):
                name = re.split(r"[ (:]", alternative.strip(), 1)[0]
                if name and self.lookup(name):
                    result.append(self.lookup(name)["Package"])
                    break
        return result

    def resolve(self, roots):
        wanted, queue = {}, list(roots)
        while queue:
            name = queue.pop()
            fields = self.lookup(name)
            if fields is None:
                raise SystemExit(f"error: package '{name}' not found")
            name = fields["Package"]
            if name in wanted or name in SKIP:
                continue
            wanted[name] = fields
            for dependency in self.dependencies(fields):
                # Headers of other -dev packages are not needed unless asked for (the roots list has the ones that are)
                if name.endswith("-dev") and dependency.endswith("-dev") and dependency not in roots:
                    continue
                queue.append(dependency)
        return wanted

    def download(self, fields):
        data = fetch(f"{self.mirror}/{fields['Filename']}")
        if hashlib.sha256(data).hexdigest() != fields["SHA256"]:
            raise SystemExit(f"error: checksum mismatch for {fields['Package']}")
        return data


def deb_data_tar(deb):
    """Returns the decompressed data.tar of a .deb (an ar archive)."""
    if deb[:8] != b"!<arch>\n":
        raise SystemExit("error: not a .deb file")
    position = 8
    while position < len(deb):
        header = deb[position:position + 60]
        name, size = header[:16].decode().strip(), int(header[48:58])
        body = deb[position + 60:position + 60 + size]
        position += 60 + size + (size & 1)
        if name.startswith("data.tar"):
            if name.endswith(".xz"):
                return lzma.decompress(body)
            if name.endswith(".gz"):
                return gzip.decompress(body)
            if name.endswith(".zst"):
                return decompress_zstd(body)
            if name.endswith(".tar"):
                return body
            raise SystemExit(f"error: unsupported package compression {name}")
    raise SystemExit("error: .deb without data.tar")


def decompress_zstd(data):
    try:
        from compression import zstd  # Python 3.14+
        return zstd.decompress(data)
    except ImportError:
        pass
    try:
        import zstandard
        return zstandard.ZstdDecompressor().decompressobj().decompress(data)
    except ImportError:
        pass
    program = shutil.which("zstd")
    if program:
        return subprocess.run([program, "-d", "-c"], input=data, stdout=subprocess.PIPE, check=True).stdout
    raise SystemExit("error: this package uses zstd; use Python 3.14+, `pip install zstandard`, install zstd, or pick --distro debian")


def can_symlink(directory):
    probe = os.path.join(directory, ".symlink_probe")
    try:
        os.symlink("target", probe)
        os.remove(probe)
        return True
    except (OSError, NotImplementedError):
        return False


def strip_dot(name):
    return name[2:] if name.startswith("./") else ("" if name == "." else name)


def extract(data_tar, dest, links):
    """Extracts regular files and directories; symbolic links are collected into `links` (path -> target)."""
    with tarfile.open(fileobj=io.BytesIO(data_tar)) as archive:
        for member in archive:
            relative = strip_dot(member.name)
            if not relative or relative.startswith(("usr/share/doc", "usr/share/man", "usr/share/info", "usr/share/locale", "usr/bin", "usr/sbin", "bin/", "sbin/", "etc/")):
                continue
            path = os.path.join(dest, *relative.split("/"))
            if member.isdir():
                os.makedirs(path, exist_ok=True)
            elif member.issym():
                links[relative] = member.linkname
            elif member.islnk():
                links[relative] = "/" + strip_dot(member.linkname)
            elif member.isfile():
                os.makedirs(os.path.dirname(path), exist_ok=True)
                if os.path.lexists(path):
                    os.remove(path)
                with archive.extractfile(member) as source, open(path, "wb") as target:
                    shutil.copyfileobj(source, target)


def resolve_link(relative, target):
    """The sysroot-relative POSIX path a link points to (absolute targets are relative to the sysroot)."""
    import posixpath
    if target.startswith("/"):
        return posixpath.normpath(target.lstrip("/"))
    return posixpath.normpath(posixpath.join(posixpath.dirname(relative), target))


def materialise_links(dest, links):
    symlinks = can_symlink(dest)
    if not symlinks:
        log("symbolic links are not available here; copying their targets instead")
    pending = dict(links)
    for _ in range(8):  # links to links
        failed = {}
        for relative, target in pending.items():
            path = os.path.join(dest, *relative.split("/"))
            source = os.path.join(dest, *resolve_link(relative, target).split("/"))
            if os.path.lexists(path):
                continue
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if symlinks:
                import posixpath
                os.symlink(posixpath.relpath(resolve_link(relative, target), posixpath.dirname(relative) or "."), path)
            elif os.path.isdir(source):
                shutil.copytree(source, path)
            elif os.path.isfile(source):
                shutil.copy2(source, path)
            else:
                failed[relative] = target
        if not failed or failed == pending:
            break
        pending = failed
    # A merged-/usr distribution has no lib/ of its own, but linker scripts such as libc.so refer to /lib/<triple>/...
    for name in ("lib", "lib64"):
        top, merged = os.path.join(dest, name), os.path.join(dest, "usr", name)
        if not os.path.lexists(top) and os.path.isdir(merged):
            if symlinks:
                os.symlink(os.path.join("usr", name), top)
            elif os.name == "nt":
                subprocess.run(["cmd", "/c", "mklink", "/J", top, merged], check=True, stdout=subprocess.DEVNULL)
            else:
                shutil.copytree(merged, top)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--arch", default="x86_64", choices=sorted(ARCHS), help="target architecture (xmake: x86_64 or arm64)")
    parser.add_argument("--dest", help="sysroot directory (default: build/sysroot/<arch> below the repository)")
    parser.add_argument("--distro", default="debian", choices=sorted(DISTROS), help="package source (default: debian)")
    parser.add_argument("--release", help="distribution release (default: bookworm for debian, noble for ubuntu)")
    parser.add_argument("--mirror", help="override the package mirror")
    parser.add_argument("--package", action="append", default=[], help="additional package to include (repeatable)")
    parser.add_argument("--refresh", action="store_true", help="recreate the sysroot if it exists")
    args = parser.parse_args()

    arch = ARCHS[args.arch]
    default_release, mirrors, suites_of = DISTROS[args.distro]
    release = args.release or default_release
    mirror, components = mirrors(arch)
    mirror = (args.mirror or mirror).rstrip("/")
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    dest = os.path.abspath(args.dest or os.path.join(root, "build", "sysroot", "x86_64" if arch == "amd64" else "aarch64"))
    stamp = os.path.join(dest, ".lagsw-sysroot")

    if os.path.exists(stamp) and not args.refresh:
        log(f"{dest} already exists (use --refresh to recreate it)")
        return
    if os.path.isdir(dest):
        if not os.path.exists(stamp) and os.listdir(dest):
            raise SystemExit(f"error: {dest} exists and is not a lagsw sysroot; refusing to delete it")
        shutil.rmtree(dest)
    os.makedirs(dest)

    pinned = {name: suite_of(release) for name, suite_of in PINNED.get(args.distro, {}).items()}
    repository = Repository(mirror, suites_of(release), components, arch, pinned)
    roots = list(ROOTS) + args.package
    # The newest libstdc++/libgcc development packages of the release
    versions = sorted((int(m.group(1)) for name in repository.packages if (m := re.fullmatch(r"libstdc\+\+-(\d+)-dev", name))
                       and f"libgcc-{m.group(1)}-dev" in repository.packages), reverse=True)
    if not versions:
        raise SystemExit("error: no libstdc++ development package found")
    roots += [f"libstdc++-{versions[0]}-dev", f"libgcc-{versions[0]}-dev"]
    wanted = repository.resolve(roots)
    log(f"{len(wanted)} packages for {args.distro} {release} {arch}")

    links = {}
    for index, (name, fields) in enumerate(sorted(wanted.items()), 1):
        print(f"  [{index}/{len(wanted)}] {name} {fields['Version']}", flush=True)
        extract(deb_data_tar(repository.download(fields)), dest, links)
    materialise_links(dest, links)
    with open(stamp, "w") as handle:
        handle.write(f"{args.distro} {release} {arch}\n")
    log(f"sysroot ready: {dest}")
    print(f"Next: xmake f -p linux -a {'x86_64' if arch == 'amd64' else 'arm64'} --toolchain=clang --sysroot={dest}")


if __name__ == "__main__":
    sys.exit(main())
