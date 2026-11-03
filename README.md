# lagsw

[![tests](https://github.com/nikita-petko/sw/actions/workflows/tests.yml/badge.svg)](https://github.com/nikita-petko/sw/actions/workflows/tests.yml)
[![build](https://github.com/nikita-petko/sw/actions/workflows/build.yml/badge.svg)](https://github.com/nikita-petko/sw/actions/workflows/build.yml)
[![release](https://github.com/nikita-petko/sw/actions/workflows/release.yml/badge.svg)](https://github.com/nikita-petko/sw/actions/workflows/release.yml)

### Windows (WinDivert)

![](https://share.cdn.vmminfra.dev/petko-new/2026/11/WindowsTerminal_yHf9JumhnV.png)

### Linux (nftables + NFQUEUE)

![](https://share.cdn.vmminfra.dev/petko-linux/261102_16h28m13s_screenshot.png)

`lagsw` is a console utility that temporarily delays matching network
packets. On Windows it uses the embedded [WinDivert](win_divert/README) driver
to capture packets, hold them in memory, and reinject them after the configured
delay. On Linux it uses nftables and NFQUEUE for the same purpose (see
[Linux](#linux)). Other platforms use a stub backend that does not capture or
delay traffic.

Profiles define which key or key combination activates packet capture, which
packets are captured, and how those packets are released. This makes it useful
for testing network-sensitive software and for manually simulating latency.

> **Warning:** Delaying or reinjecting packets can disrupt network connections.
> Use this only on systems and networks where you are authorized to intercept
> traffic. Start with a narrow filter and keep a way to terminate the program.

## Requirements

- Windows 10 or newer, or Windows Server with WinDivert support
- Visual Studio C++ tools with C++20 support
- [XMake](https://xmake.io/)
- Administrator privileges at runtime

WinDivert binaries and headers are included in [`win_divert/`](win_divert/).
The executable is built with a Windows administrator manifest because WinDivert
needs permission to open its capture handle. The project currently targets
64-bit Windows through the checked-in WinDivert runtime resources.

## Build

From a Visual Studio developer PowerShell or command prompt:

```powershell
xmake f -p windows -a x64 -m release
xmake
```

For a debug build:

```powershell
xmake f -p windows -a x64 -m debug
xmake
```

The executable is generated under XMake's build directory, typically
`build/windows/x64/release/lagsw.exe` or
`build/windows/x64/debug/lagsw.exe`.

To remove generated build output:

```powershell
xmake clean
```

### Cross-compiling from Linux (MinGW-w64)

The Windows executable can also be built on Linux (or any host) with [MinGW-w64](https://www.mingw-w64.org/) instead of
Visual Studio. It is built and tested with [llvm-mingw](https://github.com/mstorsjo/llvm-mingw) (`xmake require llvm-mingw`
downloads it); GCC-based MinGW-w64 (`x86_64-w64-mingw32-g++`, Debian/Ubuntu `g++-mingw-w64-x86-64-posix`) uses the same settings:

```sh
xmake f -p mingw -a x86_64 -m release                 # MinGW found on PATH or in /usr
xmake f -p mingw -a x86_64 --mingw=/opt/llvm-mingw    # or give the toolchain directory
xmake build lagsw
xmake package lagsw            # dist/lagsw-v*-x86_64-release.zip (needs zip or 7z)
```

The result is a self-contained `build/mingw/x86_64/release/lagsw.exe` (libstdc++ and libgcc are linked statically) with
the same embedded WinDivert runtime and administrator manifest as the Visual Studio build. The checked-in WinDivert
files are x64, so only the `x86_64` architecture is functional. The unit tests build for MinGW too (`xmake test` on a
Windows machine, or under Wine); the `windivert` benchmark and proof-of-concept programs are Visual Studio only.

### Optional features

Each section of the profiles `features:` block is a compile-time feature. A
disabled feature is not compiled into the binary at all, and its section in a
profiles file is skipped with a warning. Toggle them when configuring:

| Feature | xmake flag | Default |
| --- | --- | --- |
| `server_discovery` | `--server_discovery=y\|n` | `y` |
| `region_enforcement` | `--region_enforcement=y\|n` | `y` |
| `passive_latency` | `--passive_latency=y\|n` | `y` |
| `pcap_files` | `--pcap_files=y\|n` | `n` |
| `desync_countdown` | `--desync_countdown=y\|n` | `y` |
| `forwarded_address_discovery` | `--forwarded_address_discovery=y\|n` | `y` |
| `backend_monitor` | `--backend_monitor=y\|n` | `y` |
| `net_monitor` | `--net_monitor=y\|n` | `y` |
| `config_tui` | `--config_tui=y\|n` | `y` |

```powershell
xmake f -m release --pcap_files=y --region_enforcement=n
xmake
```

Each feature defines `LAGSW_FEATURE_<NAME>` (for example `LAGSW_FEATURE_PCAP_FILES`)
while it is enabled.

### Unit tests

```sh
xmake test                    # builds and runs every suite
xmake test packet_test        # one suite
xmake build packet_test && xmake run packet_test visible   # only cases whose name contains "visible"
```

| Suite | Covers |
| --- | --- |
| `options_test` | profiles YAML loader and validation (`src/options/`) |
| `packet_test` | IPv4/IPv6/TCP/UDP header parsing and packet formatting helpers |
| `modes_test` | packet scheduling modes (`src/packet_mode/`) driven with a fake clock, plus ACK restoration and retransmission filtering |
| `region_test` | region lookup helpers: response parsing, server naming, the on-disk cache and rate-limit retries (HTTPS, sleep and data directory are faked) |
| `engine_test` | `PacketEngine` with its real worker threads against an in-memory capture backend: profile lifecycle, packet release and flushing, server selection, server and forwarded-address discovery, region resolution, desync countdown and the state report |
| `region_enforcement_test` | region enforcement on the same in-memory backend: enforced-region cycle, which servers are delayed, delayed release and flushing, probe detection (only built with `--region_enforcement=y`) |
| `passive_latency_test` | passive latency on the same in-memory backend: channel setup and priority, delayed release, ordering, overflow fail-open, teardown flushing (only built with `--passive_latency=y`) |
| `config_tui_test` | config TUI: recent-files list and markers, YAML outline, form and raw editing, safe save with `.bak`, discard/invalid-save prompts |
| `net_monitor_test` | net monitor on the same in-memory backend: sniff channel setup, passive RTT and retransmission measurement, pause/reset, ports, packet sizes, handshakes, TCP health, flows, chart and frame rendering |
| `format_test` | text formatting of profile options |
| `nfqueue_filter_test` | capture-filter to nftables compiler (not built on Windows) |
| `shaper_plan_test` | the egress-tier planner: which stages the eBPF program can serve and the exact data it receives, plus the normal-distribution table (not built on Windows) |
| `verdict_tracker_test` | which waiting NFQUEUE packets one batch verdict may release, including id wraparound (not built on Windows) |
| `nft_batch_test` | nf_tables netlink batches built by the Linux backend, decoded with libnftnl and compared with the expected tables, chains, sets and expressions (not built on Windows) |

Suites are plain executables without external dependencies; the shared helpers are in
[`tests/support/`](tests/support). The tests honour the compile-time feature flags above, so run them
with different `xmake f` feature settings too. CI ([`.github/workflows/tests.yml`](.github/workflows/tests.yml))
does exactly that on Windows and Linux (default features, all optional features off, PCAP files on), and
also runs the suites under AddressSanitizer/UndefinedBehaviorSanitizer and ThreadSanitizer on Linux:

```sh
xmake f -m debug --policies=build.sanitizer.address,build.sanitizer.undefined
xmake test -v
```

## Linux

### Requirements

- Linux with nf_tables and NFQUEUE support (`nf_tables`, `nft_queue`, `nfnetlink_queue`). The `nft` binary is not
  needed: rules are programmed in-process over netlink. Linux 5.12+ is recommended (see [How it behaves](#how-it-behaves))
- A C++20 compiler, [XMake](https://xmake.io/), and the development packages for
  `libnetfilter_queue`, `libmnl`, `libnftnl`, `libnfnetlink` and `libcurl`
  (Debian/Ubuntu: `libnetfilter-queue-dev libmnl-dev libnftnl-dev libnfnetlink-dev libcurl4-openssl-dev`;
  Arch: `libnetfilter_queue libmnl libnftnl libnfnetlink curl`)
- For the optional [kernel shaping](#kernel-shaping-ebpf) tier: `libbpf` (Debian/Ubuntu `libbpf-dev`, Arch `libbpf`) and,
  at build time only, `clang` with the bpf target. Without them the build continues without that tier and prints a warning;
  `xmake f --linux_bpf=n` leaves it out deliberately
- At runtime: `CAP_NET_ADMIN` (root, or a file capability, see below) and read access to `/dev/input/event*`
  (root or the `input` group), because hotkeys are read from evdev rather than the terminal

### Build

```sh
xmake f -m release
xmake
```

The binary is `build/linux/x86_64/release/lagsw`.

#### Cross-compiling for ARM64

[`scripts/build/build_aarch64.sh`](scripts/build/build_aarch64.sh) builds an `aarch64`
(XMake: `arm64`) binary on an x86-64 Arch Linux or Ubuntu/Debian host. It
detects `pacman` or `apt`, installs the cross compiler if it is missing (one
`sudo` call), assembles an aarch64 sysroot, and runs XMake:

```sh
scripts/build/build_aarch64.sh                 # build/linux/arm64/release/lagsw
scripts/build/build_aarch64.sh --mode debug
scripts/build/build_aarch64.sh --package       # also create dist/lagsw-v*-arm64-release.tar.gz
scripts/build/build_aarch64.sh --sysroot-only  # just prepare the sysroot
scripts/build/build_aarch64.sh -- --pcap_files=y   # extra `xmake f` arguments after --
```

The sysroot (default `build/sysroot/aarch64`, change it with `--sysroot`,
recreate it with `--refresh`) is created without root and never installed on
the host:

| | Arch Linux host | Ubuntu/Debian host |
| --- | --- | --- |
| Cross compiler | `aarch64-linux-gnu-gcc` | `g++-aarch64-linux-gnu` |
| Sysroot source | Arch Linux ARM (`ALARM_MIRROR`), via `pacman` in a user namespace; packages are not signature-checked | arm64 packages of your release (`UBUNTU_PORTS_MIRROR` / `DEBIAN_MIRROR`), resolved with a private `apt` setup and extracted with `dpkg-deb -x`; signatures are checked |
| Libraries | `glibc linux-api-headers gcc-libs zlib curl libnetfilter_queue libmnl libnftnl libnfnetlink` | `libc6-dev libstdc++6 zlib1g-dev libcurl4-openssl-dev libnetfilter-queue-dev libmnl-dev libnftnl-dev libnfnetlink-dev` |

Dependencies of these (for example OpenSSL) are pulled in automatically. The
sysroot is also the C library the binary is linked against, so build with the
distribution `lagsw` will run on: an Ubuntu sysroot for Ubuntu/Debian
targets, an Arch Linux ARM one for Arch Linux ARM targets.

The script does what you would do by hand: it configures XMake with
`-p linux -a arm64 --toolchain=cross --bin=<compiler dir> --cross=aarch64-linux-gnu-`
and passes `--sysroot` plus the sysroot's `usr/include` and `usr/lib`
directories as compiler and linker flags (Arch's cross compiler does not look
in `<sysroot>/usr/include` by itself). `--linux_bpf=n` leaves out the optional
eBPF tier, and cross builds link `libcurl` and `zlib` from the sysroot
(`-lcurl -lz`) instead of building them from source, which fails with cross
toolchains. The script reconfigures XMake (`xmake f -c`), so run `xmake f`
again afterwards to go back to a native build.

#### Cross-compiling from Windows (clang)

A Linux binary (`x86_64` or `arm64`) can be built on Windows, or on any other host, with clang and lld plus a Linux
sysroot. [`scripts/build/make_sysroot.py`](scripts/build/make_sysroot.py) creates the sysroot from Debian (default,
bookworm) or Ubuntu packages with only the Python standard library: no root, no WSL, nothing is installed on the host. It
downloads the C/C++ runtime and headers and the libraries lagsw links against (`libnetfilter_queue`, `libmnl`, `libnftnl`,
`libnfnetlink`, `libcurl`, `zlib`, `libbpf`) over HTTPS and checks every download against the SHA-256 sums of the release
file (the release file's GPG signature is not checked). On Windows the targets of symbolic links are copied instead of
linking them (rerun with `--refresh` to recreate a sysroot made by an older version of the script).

```powershell
python scripts/build/make_sysroot.py --arch x86_64 --dest build/sysroot/x86_64     # or --arch arm64; --distro ubuntu
xmake f -p linux -a x86_64 --toolchain=clang --sysroot=build/sysroot/x86_64 -m release
xmake build lagsw
xmake package lagsw          # dist/lagsw-v*-x86_64-release.tar.gz
```

To package every platform at once, `xmake package-all` builds Windows x86_64 (`.zip`), Linux x86_64 and Linux arm64
(`.tar.gz`) into `dist/`. It uses its own configuration directory (your `xmake f` settings stay untouched), Visual Studio
for Windows on a Windows host and MinGW-w64 elsewhere (`--mingw=<dir>`), the native toolchain for a Linux target of the
host's own architecture, and clang with an automatically created `build/sysroot/<arch>` otherwise. Options: `--targets=`
(`windows-x86_64,linux-x86_64,linux-arm64`), `-m debug`, `-o <dir>`.

Requirements: clang 16+ with lld and the target (`clang --print-targets` lists `x86-64` / `aarch64`), **found on `PATH`**
(`clang --version` must work in the shell that runs `xmake f`; `--sdk`/`--bin` are not enough). For example install LLVM
(`winget install LLVM.LLVM`, then reopen the terminal) or put the `bin` directory of `xmake require llvm-mingw` (whose
clang also builds Linux targets) on `PATH`. If `xmake f` ends with `toolchain not found!`, the configuration was not
changed: a following `xmake build` or `xmake package` silently builds for the previous platform (for example Windows), so
fix `PATH` and rerun `xmake f` first. The eBPF tier is built when that
clang also has the `bpf` target and the sysroot has `libbpf` (the script includes it), and skipped with a warning
otherwise; `--linux_bpf=n` leaves it out deliberately. The binary runs on distributions with a glibc at least as new as the
sysroot's (Debian 12: 2.36), so the default sysroot suits most current distributions. For Debian the kernel headers and
`libbpf` come from `bookworm-backports` because the eBPF tier needs 6.6+ and 1.3+ (the target then needs a `libbpf1` that new
as well, or `--linux_bpf=n`). Notes:

- The kernel modules (`xmake build -g kmod`) and their tests need the kernel headers of a running Linux and are only
  available on Linux hosts; the unit tests cannot run on the build host.
- Packaging on a Windows host cannot record executable bits in the `.tar.gz`: run `chmod +x lagsw bootstrap.sh` after
  extracting it.
- Settings of the sysroot are passed as `--sysroot`, `--target=<triple>` and `-fuse-ld=lld` (and `-stdlib=libstdc++`
  because LLVM builds for MinGW default to libc++); see [`modules/toolchain.lua`](modules/toolchain.lua).
- `xmake f` overwrites the project configuration. To keep a native and a cross configuration side by side, give the cross
  one its own directories: set `XMAKE_CONFIGDIR=<dir>` and pass `-o <build dir>` to `xmake f`.

### Running

Run as root:

```sh
sudo ./lagsw --config profiles/div1.sw.yml
```

or grant the binary the one capability it needs and run it as a normal user:

```sh
sudo setcap cap_net_admin+ep ./lagsw
./lagsw --config profiles/div1.sw.yml
```

Rules are programmed over netlink by lagsw itself (no helper process is spawned), so a file
capability is enough. Hotkeys still need read access to `/dev/input/event*` (the `input` group).
lagsw checks for `CAP_NET_ADMIN` right after parsing the options and exits with an explanatory
error if it is missing (`--help` and option errors still work unprivileged). It never re-executes
itself under `sudo`. A warning is logged when `/dev/input/event*` is not readable, since hotkeys
would not work. Re-run `setcap` after every rebuild, because replacing the file removes it.

`scripts/package/linux/bootstrap.sh` re-executes itself with `sudo` and runs `lagsw` with preset arguments.

### How it behaves

- All capture rules live in the `inet lagsw` nftables table and use `queue ... bypass`, so
  traffic keeps flowing if lagsw crashes or is killed. A stale table is replaced on the next start.
- On Linux 5.12+ the table is created with the `owner` flag: it belongs to lagsw's netlink socket and the
  kernel deletes it whenever the process ends, including after SIGKILL or a crash, so nothing is left behind.
  Older kernels get an ordinary table (a warning is logged); it is removed on a normal exit, and after a
  SIGKILL `sudo nft delete table inet lagsw` removes the leftover (pass-through) rules.
- Only one lagsw can own the table at a time: a second instance fails to start with an error instead of
  replacing the running one's rules.
- The table is removed on `q`/backspace, SIGTERM and SIGHUP. Ctrl+C is ignored, as on Windows.
- Only the `inet lagsw` table is ever touched. Queue numbers are `10 + channel id`. Server address lists
  with several members are installed as named sets (`ch<id>_a<n>`) instead of one rule per address.
- `nft list table inet lagsw` shows the installed rules while lagsw runs. At `-l debug` the `nft.script` log group shows every
  batch and rule that is sent to the kernel.
- `forward: true` profiles capture routed traffic (gateway use). Loopback traffic crosses the
  output and input hooks. A channel that holds packets sets a reserved bit in the netfilter mark of every
  packet it releases and skips marked packets at its other hook, so a loopback packet is held once, not
  once per hook (sniff channels still observe it at both). The bits are `0xFF000000`, one per live channel,
  and the released packet keeps its other mark bits; avoid using the top mark byte for other purposes on a
  host that runs lagsw. `outbound: true` still restricts a profile to one direction.
- Packets that a profile releases together (a flush, a `hold_until_deactivation` release, deactivation) are
  accepted with one batch verdict when they are the oldest packets waiting in the queue, unmodified, and carry
  the same mark; anything else is released one packet at a time, in order.
- Filter terms outside the supported subset are rejected at startup with the position of the error.

### Setting up a gateway

`scripts/package/linux/setup_gateway.sh` configures the host as a router between two interfaces, which is what
`forward: true` profiles need. For example, share the wired uplink `eth0` with clients on a `wlan0`
access point:

```sh
# Give wlan0 the address 192.168.50.1/24, hand out leases with DHCP, forward + NAT to eth0:
sudo scripts/package/linux/setup_gateway.sh up --wan eth0 --lan wlan0 --lan-address 192.168.50.1/24 --dhcp
sudo scripts/package/linux/setup_gateway.sh status                      # also reprints the client network settings
sudo scripts/package/linux/setup_gateway.sh down                        # undo everything `up` did
```

`up` enables `net.ipv4.ip_forward`, allows `--lan` to `--wan` traffic (and the established replies back)
in the `FORWARD` chain, and masquerades traffic leaving `--wan`. All rules live in the `LAGSW_FWD`,
`LAGSW_NAT` and `LAGSW_IN` iptables chains, so `up` is repeatable and `down` removes exactly what was
added: the rules, the DHCP server, an address `up` assigned, and it restores the previous sysctl values.

- `--lan-address ADDRESS/PREFIX` assigns the gateway address to `--lan`. If omitted, the IPv4 address
  already on `--lan` is used (and `up` fails if there is none).
- `--dhcp` starts `dnsmasq` (must be installed) as a DHCP-only server on `--lan`. It leases
  `.100`-`.199` of a /24 (the whole subnet minus the gateway for smaller ones) and advertises this host as
  the gateway and `--dns` (default `1.1.1.1,8.8.8.8`) as DNS. DNS itself is not served, so it never
  clashes with a local resolver.
- Without `--dhcp`, assign addresses to clients yourself. `up` and `status` print the values to use:

  ```text
  LAN network 192.168.50.0/24 on wlan0:
    Gateway:  192.168.50.1
    Netmask:  255.255.255.0 (/24)
    DNS:      1.1.1.1, 8.8.8.8
    DHCP:     off
    Static client example: address 192.168.50.2, netmask 255.255.255.0, gateway 192.168.50.1, DNS 1.1.1.1, 8.8.8.8
  ```

- `--no-nat` forwards without masquerading, `--ipv6` also configures `ip6tables` (forwarding only: no
  DHCPv6 or router advertisements), `--dry-run` prints the commands.

The script does not create the access point itself (use hostapd, or your desktop's hotspot feature, which
may fight over the interface and its address), and it does not persist across reboots.

### Kernel shaping (eBPF)

By default every delayed packet makes a round trip through user space (NFQUEUE) and is held in the kernel while it waits.
For behaviours that only need a release time or a drop, lagsw can instead stamp the packet in an eBPF program on the egress
of chosen interfaces and let the `fq` qdisc send it at that time, so the packet never reaches user space, there is no queue
length to overflow, and the delay is exact. It is off until you name interfaces:

```yaml
features:
  linux_bpf:
    tier: auto            # auto (default) | nfqueue (never use it) | bpf (require it)
    interfaces: [lan0, wan0]   # the gateway's LAN and WAN devices; both directions of forwarded traffic are covered
```

What runs in the kernel (everything else keeps using NFQUEUE, and `auto` logs the reason for each fallback at debug level):

| Feature | Kernel shaping when |
|---|---|
| Profile `delay_mode: from_timestamp`, `drop`, `send_all_after_delay` | `delay_ms > 0` (a delay of 0 holds packets until deactivation), no `ack_restoration`, `retransmission_mode: none`, not `sniff`, no PCAP files, and the filter matches only forwarded (`forward: true`) or locally generated (`outbound: true`) traffic |
| `passive_latency` (fixed, uniform and normal; `preserve_order`, `max_delay_ms`) | no inbound delay (`direction: outbound`, or `inbound_delay_ms: 0`) |

Only egress traffic is shaped, so local inbound delays, sniffing, discovery, PCAP and every verb that decides per packet in
user space (`hold_and_send`, `hold_until_deactivation`, `ratio`, `drop_and_send`, `drop_until_toggle`, `packet_group_send`,
region enforcement) stay on NFQUEUE. A kernel profile and an NFQUEUE profile can be active together; their delays add up.
`tier: bpf` refuses instead of falling back.

Requirements and behaviour:

- Linux 6.6+ (tcx), the `sch_fq` and `cls_bpf` modules, `CAP_NET_ADMIN`, `CAP_BPF` and `CAP_PERFMON`. With file
  capabilities: `sudo setcap cap_net_admin,cap_bpf,cap_perfmon+ep ./lagsw` (hotkeys still need `/dev/input` access).
- The first profile that needs it loads the program, replaces each interface's root qdisc with `fq` and attaches the
  program. Only `noqueue`, `pfifo_fast`, `fq_codel`, `mq` and `fq` are replaced; any other root qdisc is left alone and the
  profile falls back (or fails with `tier: bpf`). On an orderly exit (`q`, SIGTERM, SIGHUP) lagsw waits up to 2 seconds for
  queued packets, detaches the program and puts the previous qdisc kind back with default parameters.
- After SIGKILL or a crash the kernel detaches the program by itself; the `fq` qdisc stays, which is harmless without
  timestamps (`sudo tc qdisc del dev <if> root` restores the default).
- `fq` limits: 262144 packets in total and 65536 per flow, so *delay × packet rate* must fit; a delay may be up to
  600000 ms and the total stamped delay is capped at 890 s (`fq`'s horizon is 900 s and caps instead of dropping).
- Pausing the passive latency stops delaying new packets at once; packets already stamped still leave on their schedule.
- With `backend_monitor` enabled the extra status line also shows the kernel counters (stages, packets matched, delayed and
  dropped).

### Kernel module backend (experimental)

A third Linux backend replaces nftables + NFQUEUE with an out-of-tree kernel module, `swdivert` (`kmod/`; design, measurements
and caveats in [`pocs/linux_kernel_module_backend.md`](pocs/linux_kernel_module_backend.md)). The module matches packets with a
filter program, copies them into a ring shared with `lagsw` and holds the originals until the engine sends or drops them,
so a held packet costs no netlink round trip. The filter language, the engine and the profiles are the same as with NFQUEUE. It is
chosen when `lagsw` is built:

```sh
xmake f -m release --linux_backend=kmod       # the default is nfqueue
xmake build lagsw swdivert                    # the module needs the kernel headers of the running kernel
sudo ./build/linux/x86_64/release/lagsw --config profiles/localhost.test.sw.yml
```

This build needs none of the netfilter libraries. At startup, as root, `lagsw` loads the module when `/dev/swdivert` is missing:
`modprobe swdivert` for an installed module, else `insmod` of `swdivert.ko` from `$LAGSW_KMOD_PATH` or from next to the
executable (copy it there, or set the variable, for a development build). It never unloads the module,
since closing the handles already releases everything it held; `LAGSW_KMOD_UNLOAD_ON_EXIT=1` unloads it on a normal exit
when this process loaded it. Without root nothing is loaded and the error says which command to run. A module of another ABI
version is refused.

What is different from the NFQUEUE backend: a packet nobody answered for 60 s is released by the module itself (a stuck or
killed `lagsw` never blackholes traffic, as with `bypass`), so a delay beyond that is not applied; up to 16384 packets are held
per channel; packets larger than about 4000 bytes (loopback, jumbo frames) are let through undelayed; IPv4 only; there is no kernel
shaping tier (profiles run through the channel as usual); no nftables table is created. Loopback traffic is held once, not once
per hook. The module is GPL, host-wide and needs to be rebuilt for each kernel; a Secure Boot system needs it signed.

Its tests run in a throw-away VM that boots the host's kernel, without root (`/dev/kvm` and QEMU needed):
`scripts/tests/test_kmod_hold_vm.sh` (module and backend contract) and `scripts/tests/test_kmod_localhost_vm.sh` (the real
`lagsw` binary against the localhost feature profile).

### Testing

`scripts/tests/test_nfqueue_localhost.sh`, `scripts/tests/test_nfqueue_gateway.sh` and `scripts/tests/test_bpf_gateway.sh` run end to end in a
throwaway privileged Docker container (see [Included profiles](#included-profiles)).

## Usage

The configuration file must be supplied explicitly:

```powershell
lagsw.exe --config profiles/div1.sw.yml
```

To discover the busiest server on a port while the program runs, enable the
`server_discovery` feature (see [Features](#features)):

```yaml
features:
  server_discovery:
    enabled: true
    port: 55000
    interval: 5000
```

```powershell
lagsw.exe --config profiles/div1.sw.yml
```

Options:

| Option | Description |
| --- | --- |
| `--config <file>` | Load profiles from a YAML file. Optional: without it, an interactive terminal opens the config TUI to pick, create or edit a profile file (see [`pocs/config_tui.md`](pocs/config_tui.md)). |
| `--log-level <level>`, `-l <level>` | Set the minimum log level: `error`, `warn`, `info`, or `debug`. |
| `--log-group <rules>`, `-g <rules>` | Mute or unmute log groups, a comma-separated list such as `-discovery.packet,-packet.recv`. A bare or `+` name enables a group, a `-` prefix disables it, and `all` matches every group and discards earlier rules. The most specific rule wins and a parent such as `discovery` covers its children. Only debug and info messages are muted; warnings and errors always show. Every group is on by default except the chatty per-packet groups (`packet.recv`, `packet.send`, `packet.drop`, `discovery.packet`, `forwarded.packet`, `enforcement.packet`, `nfq.packet`), which are marked `[off by default]` in `--print-log-groups`; enable them with e.g. `-g +discovery.packet`. Naming a parent such as `+discovery` also enables its children, and `all` enables every group. |
| `--show-log-groups` | Prefix each log line with its group, e.g. `[DEBUG] [discovery.packet] ...`. Off by default. |
| `--print-log-groups` | List every log group with a description and exit. |
| `--server <server>`, `-s <server>` | Select the initial configured server by name or address. Unknown values warn and use `none`. |
| `--client-address <address>` | Set both the client source and destination addresses. |
| `--client-source-address <address>` | Set the client source address. |
| `--client-destination-address <address>` | Set the client destination address. |
| `--resolve-region` | Resolve the geographic region of discovered servers. Successful lookups are cached locally for 30 days. |
| `--help`, `-h` | Print command help and exit. |

While the program is running:

- Activate a `toggle` profile by pressing its configured key or key combination.
  Press it again to deactivate the profile.
- Activate a `hold` profile by holding its configured key or combination.
  Releasing the key deactivates it.
- Press `I` (fixed; profiles that use it as an activation key, `send_key` or net monitor/passive latency key fail to
  load while the `config_tui` build feature is on) to return to the config TUI, edit or
  switch profile files and resume without restarting the app. The engine is restarted from the chosen file; if it
  fails to load, the previous configuration stays active.
- Press the configured `net_monitor` key (when the feature is enabled) to open
  the net monitor, a full-screen view with live network statistics and charts
  for the configured servers (see [`pocs/net_monitor.md`](pocs/net_monitor.md)).
  Measuring only happens while the view is open: `Space` pauses/resumes, `r`
  resets, the same key closes it. Log output is held back while it is open and
  printed when it closes.
- Press `Tab` to print packet and activation statistics.
  When discovery is enabled, it also prints the current authoritative server
  and a packet-ranked list for the active discovery window. A final `log groups`
  section shows how many error, warn, info, and debug messages each log group
  has written and how many were muted by `--log-group`.
- Press Page Up or Page Down to cycle the configured server filter, including
  `none` (which applies no server filter).
- When region enforcement is enabled, press Left or Right to cycle the enforced
  server group.
- Press `q`, `Q`, or Backspace to quit.

Multiple profiles can be active at the same time. Profiles may share keys; a
key press enables every matching toggle profile when the group is only partly
active, and deactivates the group only when every matching profile is active.
Hold profiles follow the key state independently. Each active profile has its
own capture handle and packet queue. `Tab` is reserved for displaying state
and cannot be used as a profile key.

When discovery is enabled (`features.server_discovery` in the configuration),
lagsw opens a sniff-only handle and counts packets to and from the selected
port without delaying them. At the end of each window, the remote address with
the highest packet count is logged as authoritative and added to the server
list. If that address is already in the list, lagsw warns and reuses the
existing entry. Discovery switches to the authoritative server when no
concrete server was selected. Both an omitted `--server` argument and explicit
`--server none` request automatic selection. A concrete `--server` selection is
never replaced by discovery. Discovery is temporarily paused while any profile
is active and resumes with a fresh window after all profiles are deactivated.
Profiles with `server_direction` use the selected server when they are next
activated.

Alongside discovery, lagsw detects disconnects. It averages the packets counted
in the last six windows and warns when a window drops by `disconnect_drop_percent`
(default 80%) or more below that average, then logs when the traffic recovers.
It needs three prior windows averaging at least 10 packets, so quiet links do
not trigger it, and windows in which a profile paused discovery reset its history.

Linux builds use the nftables + NFQUEUE backend (`backends/nfqueue/`, see
[`pocs/linux_nfqueue_backend.md`](pocs/linux_nfqueue_backend.md) and
[`pocs/linux_ebpf_netlink_backend.md`](pocs/linux_ebpf_netlink_backend.md)). It needs
`libnetfilter_queue`/`libmnl`/`libnftnl` at build time and `CAP_NET_ADMIN` at
runtime (it cannot modify packets from a rootless user namespace); rules are
programmed over netlink, so no `nft` binary is required. Capture rules
live in a dedicated `inet lagsw` table that is removed on exit (by the kernel on
Linux 5.12+, even after SIGKILL); they use `bypass`,
so traffic keeps flowing if the process dies. Profile filters are translated from
the WinDivert subset (`tcp.*` flags, `ip.*Addr`, `tcp|udp.*Port`, `ifIdx`,
`inbound`/`outbound`, `and`/`or`/`not`). Other platforms use the stub backend.

## Configuration

The parser accepts the YAML-shaped subset used by the examples in
[`profiles/`](profiles/). A configuration contains a global filter and one or
more profiles:

```yaml
global_filter: "tcp.DstPort == 55000 or tcp.SrcPort == 55000"

servers:
  - "34.90.202.108:game server"
  - "203.0.113.10:backup server"

profiles:
  - name: "Example"
    key: space
    mode: toggle
    disables: "Other profile"
    disable_wait_percent: 50
    respect_disable_wait: true
    delay_mode: from_timestamp
    retransmission_mode: both
    delay_ms: 500
    capture_options:
      forward: false
      server_direction: destination
```

Servers can be grouped by region or another label. Selecting any server in a
group applies the profile filter to every server in that group. A server
configuration can combine named groups and an `addresses` list:

```yaml
servers:
  addresses:
    - "104.155.45.25:BRU-EUC-25"
    - "34.76.248.132:BRU-EUC-132"
  EU:
    - "34.13.202.203:GR-EUC-203"
    - "34.90.202.108:GR-EUC-108"
```

### Top-level fields

| Field | Required | Description |
| --- | --- | --- |
| `global_filter` | No | Capture filter used by profiles that do not define `filter`. Defaults to `tcp.DstPort == 55000 or tcp.SrcPort == 55000`. |
| `default_view` | No | View shown at startup: `log` (default) or `net_monitor`. `net_monitor` opens the full-screen network statistics view and requires `features.net_monitor.enabled: true`; otherwise loading fails. |
| `servers` | No | A list of server addresses, or a mapping of server groups with an optional `addresses` list. |
| `features` | No | Optional feature configuration, including server discovery, PCAP capture, desynchronization countdown, forwarded-address discovery, and region enforcement. |
| `profiles` | Yes | A non-empty list of profile definitions. |

`servers` as a list is a set of known server addresses. An entry may use
`address:name` to provide the status-bar name:

```yaml
servers:
  - "34.90.202.108:game server"
  - "203.0.113.10:backup server"
```

Server discovery is configured in the `features` block, not in `servers` (see
[Features](#features)).

### Features

Every feature is optional at build time (see [Optional features](#optional-features));
settings for a feature that was left out of the build are ignored with a warning.

The `server_discovery` feature observes the traffic on a port and selects the
remote address that receives the most packets in each window as the
authoritative server (see [Usage](#usage) for how it interacts with `--server`).
Without it, servers come only from the `servers` block.

```yaml
features:
  server_discovery:
    enabled: true
    port: 55000
    interval: 5000
```

| Field | Required | Description |
| --- | --- | --- |
| `enabled` | No | Enables server discovery. Defaults to `false`. |
| `port` | Yes when enabled | Port (1-65535) to observe TCP and UDP traffic on. |
| `interval` | No | Discovery window length in milliseconds. Defaults to `5000`. |
| `disconnect_drop_percent` | No | Reports a disconnect when a window's packet count falls this many percent below the average of the last windows. Defaults to `80`; `0` disables. |

PCAP output is a debugging feature and is disabled by default, both in the
build (`--pcap_files=n`) and in the profiles file. When enabled,
each activation of a selected profile writes every packet received by that
profile's capture thread to a separate PCAP file. The file name and the
deactivation log share a GUID. PCAP files contain raw IP packets (`DLT_RAW`)
and can be opened by Wireshark.

```yaml
features:
  pcap_files:
    enabled: true
    output_dir: pcap_files
    enabled_for: "*"
```

| Field | Required | Description |
| --- | --- | --- |
| `enabled` | No | Enables PCAP output. Defaults to `false`. A warning is logged at startup when enabled. |
| `output_dir` | No | Destination directory. Defaults to `pcap_files` beneath the current working directory. |
| `enabled_for` | Yes when enabled | `"*"` for every profile, or a non-empty list of configured profile names. |

The optional `desync_countdown` feature displays an approximate status-line
countdown after selected profiles are deactivated. The estimate is 80% of the
profile's most recent active duration, based on preliminary observations; it
is not a measurement of server state or a guarantee that desync ends at that
time. It is disabled by default.

```yaml
features:
  desync_countdown:
    enabled: true
    duration_percent: 80
    enabled_for:
      - "RPM"
```

| Field | Required | Description |
| --- | --- | --- |
| `enabled` | No | Enables the approximate countdown. Defaults to `false`. |
| `display` | No | `alongside` (default) shows the countdown next to profile activations; `override` shows it instead of the profile's activation status; `until_reactivated` hides it once the profile is reactivated. |
| `duration_percent` | No | Estimated desync duration as a percentage of the selected profile's active duration. Defaults to `80`; valid values are `1`-`100`. |
| `enabled_for` | Yes when enabled | `"*"` for every profile, or a non-empty list of configured profile names. |

The optional `backend_monitor` feature shows an extra status line, below the
main one, with the health of the packet backend. The stub backend shows nothing.

- **nfqueue (Linux):** for each bound queue the packets waiting in the kernel,
  the kernel-queue and netlink-socket drop counters (from
  `/proc/net/netfilter/nfnetlink_queue`), and whether the `inet lagsw` nftables
  table is still installed. The line ends with `[!]` when a queue is
  backlogged, drops increased since the last sample, or the table disappeared
  (for example after a firewall reload; capture rules use `bypass`, so traffic
  then flows unmanaged).
- **kmod (Linux):** the swdivert module's handle count and held, unheld,
  expired, passed-through and late packet counters. The line is flagged when
  packets went through unheld, expired on their own, or the held backlog
  reached the threshold.
- **WinDivert (Windows):** the number of open handles, packets received and
  sent, receive/send errors, packets waiting in user space (only non-zero when
  forwarded traffic is captured too), the longest time a packet waited in the
  driver queue since the last sample, and whether the WinDivert driver service
  is still running. The line is flagged when errors occur, the user-space
  backlog reaches the threshold, packets wait 250 ms or more in the driver
  queue (the driver drops packets that wait longer than about one second), or
  the driver stops (capture has then ended).

It is disabled by default.

```yaml
features:
  backend_monitor:
    enabled: true
    interval: 1000
    backlog_threshold: 1000
```

| Field | Required | Description |
| --- | --- | --- |
| `enabled` | No | Shows the extra status line. Defaults to `false`. |
| `interval` | No | Minimum time between samples in milliseconds. Defaults to `1000`; minimum `100`. |
| `backlog_threshold` | No | Waiting packets (in the kernel, or in user space for WinDivert) at which the line is flagged. Defaults to `1000`. |

The optional `net_monitor` feature adds a full-screen network statistics view
(packets/s and throughput up/down, latency, jitter, retransmits, per-server
table, all with mini charts). The view opens and closes with the configured key;
it only captures traffic (through its own sniff channel, which never delays
packets) while it is open, and `Space` pauses the measurement. See
[`pocs/net_monitor.md`](pocs/net_monitor.md). It is disabled by default.

```yaml
features:
  net_monitor:
    enabled: true
    key: N
    alert_rtt: 150
    alert_jitter: 30
    alert_retransmit: 2
    alert_stall: 1000
    export_directory: "netmonitor-exports"
    log_file: "netmonitor.jsonl"
```

| Field | Required | Description |
| --- | --- | --- |
| `enabled` | No | Makes the view available. Defaults to `false`. |
| `key` | No | Key that opens and closes the view. Defaults to `N`. |
| `pause_key` | No | Key that pauses/resumes the measurement. Defaults to Space. |
| `reset_key` | No | Key that resets the statistics. Defaults to `R`. |
| `flows_key` | No | Key that switches between the overview and the per-flow view. Defaults to `F`. |
| `profiles_key` | No | Key that switches between the overview and the per-profile view. Defaults to `P`. |
| `export_key` | No | Key that exports the measured window. Defaults to `E`. |
| `alert_rtt` | No | Latency in milliseconds above which a server raises an alert. Defaults to `150`; `0` disables it. |
| `alert_jitter` | No | Smoothed RTT jitter in milliseconds above which a server raises an alert. Defaults to `30`; `0` disables it. |
| `alert_retransmit` | No | Percentage of retransmitted TCP data packets over the last 10 seconds above which a server raises an alert. Defaults to `2`; `0` disables it. |
| `alert_stall` | No | Inbound silence in milliseconds from a server at or above which an alert is raised. Defaults to `1000`; `0` disables it. |
| `export_directory` | No | Directory for the CSV and JSON files written by the `e` key. Defaults to a `netmonitor` folder in the per-user data directory. |
| `log_file` | No | JSON Lines file that receives one record per server and second, plus the events, while the view is open. Disabled when empty. |

All six keys (`key`, `pause_key`, `reset_key`, `flows_key`, `profiles_key`, `export_key`) must be different from each other and must not be `q`, Backspace, Tab, Page Up/Down, an arrow key, the passive latency `pause_key` (when that feature is enabled), or a profile activation key or `send_key`; otherwise the configuration fails to load.

While the view is open, `f` switches to a per-flow view (`Up`/`Down` select a flow and show its history), `p` switches to
a per-profile view (activations, active time and the latency, retransmits and throughput measured while each profile was
active), `e` exports
the measured window and `r` resets it. A server whose alert thresholds are exceeded turns red in the table, and the
events panel lists alerts, profile activations and servers found by server discovery.

Region enforcement delays TCP PSH packets from configured servers outside the
currently selected server group. Use the Left and Right arrow keys to change
the selected group while the program is running. The configured probe port is
used to observe server-region probe traffic; the status line shows the
selected group and the next-check countdown.

```yaml
features:
  region_enforcement:
    enabled: true
    probe_port: 55002
```

| Field | Required | Description |
| --- | --- | --- |
| `enabled` | No | Enables region enforcement. Defaults to `false`. |
| `probe_port` | Yes when enabled | Port (1-65535) used to observe region-probe traffic. |

Passive latency applies an always-on baseline delay to every packet matched by
its filter, independent of any profile's activation state. It exists to
replace an external proxy client (FlClash, Clash Forge, Proton VPN, and
similar) previously used only to add artificial latency: some packet-timing
methods (see [`research/division1_lag_switch_weapon_swap_analysis.md`](research/division1_lag_switch_weapon_swap_analysis.md))
are more consistent with a bit of added delay, and a low-ping connection can
actually make them less reliable. Unlike a proxy client, the delay here is a
precise, directly configured value instead of an indirect and only loosely
tunable side effect of routing, and it has no recurring cost. It runs on its
own capture channel that is processed before profiles and region enforcement,
so a profile's own delay (if any) is added on top. The delay can be fixed or
jittered, set per direction, and is shown on the extra status line below the main one, after the backend monitor text. See
[`pocs/passive_latency.md`](pocs/passive_latency.md) for the full design and
the remaining planned work (pause key, capture options, adaptive target RTT).

```yaml
features:
  passive_latency:
    enabled: true
    mode: uniform
    delay_ms: 60
    jitter_ms: 10
    direction: both
    filter: "tcp"
```

To reach an RTT floor of 120 ms either use `delay_ms: 60` with `direction: both`
or `outbound_delay_ms: 120` with `inbound_delay_ms: 0`. Jitter never reorders
packets of the same direction unless `preserve_order` is `false`. Region-enforcement
probe traffic (the configured `probe_port`) is never delayed, so region detection is not skewed.

**Migrating from a proxy client:** remove the proxy client's latency from the path and set
`delay_ms` (or the per-direction values) to the added RTT you were getting from it, split across
both directions. Existing profile `delay_ms` values keep their meaning as extra delay beyond the baseline.
The desync countdown estimate is based on a profile's active duration and excludes the baseline.

| Field | Required | Description |
| --- | --- | --- |
| `enabled` | No | Enables passive latency. Defaults to `false`. |
| `mode` | No | `fixed` (default), `uniform` (`delay_ms` +/- `jitter_ms`), or `normal` (`delay_ms` with standard deviation `jitter_ms`). |
| `delay_ms` | Yes when enabled, unless a direction override is set | Baseline delay in milliseconds (the mean for `uniform` and `normal`); at most `600000`. |
| `jitter_ms` | Required for `uniform`/`normal` | Jitter in milliseconds; must be `0` or absent for `fixed`. |
| `max_delay_ms` | No | Upper clamp after sampling. `0` (the default) uses `delay_ms + 3 * jitter_ms` per direction; otherwise it must be at least each direction's delay. |
| `direction` | No | `both` (default), `inbound`, or `outbound`. Packets of the other direction pass through undelayed. |
| `inbound_delay_ms`, `outbound_delay_ms` | No | Override `delay_ms` for that direction. |
| `pause_key` | No | Key that pauses and resumes passive latency while running (not `q`, Backspace, Tab, Page Up/Down or the arrow keys). Pausing releases queued packets at once; the extra status line below the main one shows `passive: paused`. |
| `preserve_order` | No | Never release a packet before an earlier one of the same direction. Defaults to `true`; `false` can reorder TCP packets when jitter is used. |
| `max_queued_packets` | No | Safety bound on queued packets; packets past this bound are released immediately instead of being dropped. Defaults to `4096`. |
| `filter` | No | Capture filter in the active backend's syntax. Defaults to `global_filter` when unset. |

Forwarded address discovery dynamically finds the client addresses used to
filter packets when lagsw runs on a PC that shares its internet connection
with a client device (for example, DeviceA is hard-wired to the PC, and the
PC's Wi-Fi, Ethernet, or VPN interface has Windows Internet Connection
Sharing enabled). Packets originating from the client are translated by
Windows ICS as they leave the shared interface, so they arrive twice: once on
the client's own interface with the client's real address, and once on the
shared interface with the PC's address. This feature observes both
interfaces to keep `client_source_address` and `client_destination_address`
up to date automatically, overriding `--client-source-address` and
`--client-destination-address` while addresses are being discovered.

Like server discovery, each interface's traffic is scoped to a configured port
and tallied over a recurring window, with the most frequently observed address
per interface selected at the end of each window. Scoping to the actual
game/server port (the same way server discovery does) keeps unrelated traffic
such as broadcasts from being mistaken for the client's address.

```yaml
features:
  forwarded_address_discovery:
    enabled: true
    inbound: 12
    outbound: 21
    port: 55000
    interval: 5000
```

| Field | Required | Description |
| --- | --- | --- |
| `enabled` | No | Enables forwarded address discovery. Defaults to `false`. |
| `inbound` | Yes when enabled | Interface index of the interface DeviceA (the client) is directly connected to. Used to discover `client_destination_address`. |
| `outbound` | Yes when enabled | Interface index of the shared interface with Internet Connection Sharing enabled (Wi-Fi, Ethernet, or VPN). Used to discover `client_source_address`. |
| `port` | Yes when enabled | Port (1-65535) to observe TCP and UDP traffic on, scoping discovery to the actual game/server traffic. |
| `interval` | No | Discovery window length in milliseconds. Defaults to `5000`. |

Interface indexes can be found with `Get-NetAdapter` in PowerShell (the
`ifIndex` column) or `netsh interface ipv4 show interfaces`. `inbound` and
`outbound` must reference different interfaces. Active profiles are
automatically reconfigured whenever a discovered address changes.

### Profile fields

| Field | Required | Description |
| --- | --- | --- |
| `name` | Yes | Display name shown in logs and state output. |
| `key` | One of `key` or `keys` | One activation key. |
| `keys` | One of `key` or `keys` | A list of keys that must all be held, for example `keys: [ctrl, shift]`. A block list is also supported. |
| `send_key` | No | Optional key that releases the configured `amount` without deactivating the profile. It cannot overlap any profile activation key. |
| `key_mode` | No | `oneof` activates when any configured key is held; `combination` activates when all configured keys are held. Defaults to `combination`. |
| `mode` | No | `toggle`, `hold`, or `period`; defaults to `toggle`. `period` behaves like `toggle` but automatically deactivates after `activation_period`. |
| `activation_period` | Required for `period` | Positive activation duration in milliseconds. At expiry the profile deactivates and flushes queued packets as it does on a manual toggle-off. |
| `disables` | No | A profile name, `*`, or a list of either, to keep disabled while this profile is active. `*` disables every other profile. Named targets must be configured profiles and cannot include this profile. |
| `disable_wait_ms` | No | Time in milliseconds this profile remains active after it is disabled. Defaults to `0`. |
| `disable_wait_percent` | No | Additional wait equal to this percentage of the profile's current enabled time, from `0` to `100`. This is added to `disable_wait_ms`. Defaults to `0`. |
| `respect_disable_wait` | No | When this profile disables another profile with a configured disable wait, wait for that profile to stop before activating. Defaults to `true`; set to `false` to activate immediately. |
| `delay_mode` | No | `from_timestamp`, `send_all_after_delay`, `ratio`, `drop`, `drop_and_send`, `hold_and_send`, `drop_until_toggle`, `hold_until_deactivation`, or `packet_group_send`; defaults to `from_timestamp`.|
| `retransmission_mode` | No | `none` allows retransmissions; `only_seq` drops duplicate sequence numbers; `only_ack` drops duplicate acknowledgment numbers; `both` requires a unique `(SeqNum, AckNum)` pair. Defaults to `none`. |
| `ack_restoration` | No | Includes bare TCP ACKs in the profile filter and prevents sent PSH packets from moving the acknowledged sequence backward. Defaults to `false`. |
| `subsequent_packet_hold_mode` | No | For `hold_and_send`, `none` holds only the configured initial packet count; `seq_only`, `ack_only`, or `seq_ack` also holds subsequent TCP packets matching an initially held packet. Defaults to `none`. |
| `delay_ms` | No | Delay in milliseconds. Defaults to `0`. |
| `ratio` | For `ratio`, `drop_and_send`, or `hold_and_send` mode | Positive packet count, or a positive percentage such as `50%`. Percentage ratios also require `delay_ms > 0` and may not exceed `100%`; `hold_and_send` requires a packet count. |
| `amount` | For `hold_until_deactivation` mode | Number of deferred packets released on deactivation; `0` releases all deferred packets. Defaults to `0`. |
| `group_count` | For `packet_group_send` mode | Positive number of packet groups to capture. Activation-key presses delimit groups and then send one group per press.|
| `group_order` | No | `fifo`, `lifo`, or `random`; order in which `packet_group_send` releases captured groups. Defaults to `fifo`.|
| `ratio_selection` | No | `first`, `last`, or `random`; controls which packets a percentage-based `ratio` releases immediately: the first x, the last x, or a random x of the batch. Defaults to `first`. |
| `filter` | No | Profile-specific capture filter. Overrides `global_filter`. |
| `capture_options` | No | Capture options described below (legacy name: `windivert_options`). |

Keys may be a single printable character or one of `tab`, `space`, `alt`,
`ctrl`, and `shift`. Printable characters are case-insensitive and are stored
as their uppercase virtual-key value. Numeric virtual-key codes are also
accepted, including hexadecimal values such as `0x41`.

When two profiles list each other in `disables`, pressing either profile's key
while the other is active switches directly to the requested profile.

### Delay modes

- `from_timestamp`: Each packet is released at approximately its receive time
  plus `delay_ms`. Packets retain their receive order when release times match.
- `send_all_after_delay`: The first packet starts a batch timer. All packets
  captured in that batch are released together after `delay_ms`.
- `ratio`: Releases packets in groups. With `ratio: 3`, three packets are sent
  per delay interval. With `ratio: 50%`, half of the queued packets are sent at
  each interval, with at least one packet sent when packets are available. For
  percentage-based ratios, `ratio_selection` controls which packets in the
  batch are released immediately: `first` releases the earliest-received
  packets, `last` releases the most recently received packets, and `random`
  releases a random selection. The remaining packets are held until the next
  interval.
- `drop`: Drops every filtered packet while the profile is active.
- `drop_and_send`: Drops the configured `ratio` of each batch, then sends the
  remaining packets after `delay_ms`. Both `ratio` and a positive `delay_ms` are
  required.
- `hold_and_send`: Holds the first `ratio` packets while allowing every later
  packet through immediately. Held packets are sent when the profile is
  deactivated. With `subsequent_packet_hold_mode`, later packets matching an
  initially held TCP packet by sequence, acknowledgment, or both are held as
  well. This mode requires a positive packet-count `ratio`.
- `drop_until_toggle`: Drops packets after activation. The next toggle starts
  holding packets, and the following toggle sends the held packets and
  deactivates the profile. This mode requires `mode: toggle`.
- `hold_until_deactivation`: Holds every packet while active. On the deactivation
  key press, releases `amount` packets for normal sending and then flushes all
  remaining packets during deactivation. An `amount` of `0` releases all held
  packets at once. When `send_key` is configured, pressing it releases the
  configured amount while leaving the profile active. This mode requires
  `mode: toggle`.
- `packet_group_send`: Captures packets into `group_count` groups. The first
  activation starts capturing group 1; each subsequent activation starts the
  next group. After the final group has been captured, each activation sends
  one group in `group_order` (`fifo`, `lifo`, or `random`) order. Packets within
  each group retain their original receive order. The profile deactivates after
  its final group is sent. Group capture, send, and completion are logged, and
  the active group and stage are shown in the status bar. This mode requires
  `mode: toggle`.

When `delay_ms` is zero, queued packets wait until the profile is deactivated.
Deactivation flushes all remaining packets immediately, so this is a packet
hold rather than a permanent drop.

### Capture options

```yaml
capture_options:
  sniff: false
  forward: false
  outbound: false
  client_address_enforcement: both
  server_direction: destination
```

`windivert_options` is still accepted as a legacy alias of `capture_options`.

The `client_address_enforcement` option defaults to `both` and accepts
`none`, `source`, `destination`, or `both`. It controls which configured
client address clauses are included in the profile filter.

- `sniff`: Capture packets without diverting them from the normal network path.
  Sniffed packets are observed but are not delayed or reinjected by `lagsw`.
- `forward`: Capture routed (forwarded) traffic instead of traffic to and from
  this host (the WinDivert `NETWORK_FORWARD` layer on Windows, the netfilter
  `forward` hook on Linux).
- `outbound`: Restrict the filter to outbound packets. Internally, the capture
  filter becomes `outbound and (<filter>)`. This applies only to local
  traffic; do not combine it with `forward: true`.
- `server_direction`: When a server is selected, add an `ip.SrcAddr`,
  `ip.DstAddr`, or `ip.Addr` filter for `source`, `destination`, or `both`.
  If no server is selected, no IP server filter is added.

Filters are validated by the platform capture backend before the program starts. Invalid filters,
missing profile names or keys, invalid booleans, and invalid delay modes cause
startup to fail with an error.

## Included profiles

[`profiles/div1.sw.yml`](profiles/div1.sw.yml) is the checked-in example
configuration. It combines server discovery with named server groups and
demonstrates timestamp-based delay, percentage-based ratio handling,
deactivation waits, timed activation, and packet holding with a zero delay.
Its filters and addresses are tailored to its example game and network setup;
review and adapt them before using the configuration elsewhere.

[`profiles/localhost.test.sw.yml`](profiles/localhost.test.sw.yml) exercises every
delay mode, activation mode and feature against loopback traffic only (TCP
55000/55002, UDP 55001). `scripts/tests/test_nfqueue_localhost.sh` runs it end to end
against the Linux backend inside a throwaway privileged Docker container
(`pocs/linux_nfqueue_backend/localhost_harness.py` drives it). Setting the
`LAGSW_TEST_KEYS` environment variable to a file path makes the Linux build read
held keys (whitespace-separated names such as `d`, `ctrl`, `space`) from that
file instead of `/dev/input`; this exists for the harness. `scripts/tests/test_nfqueue_gateway.sh` additionally tests the forward hook
between two network namespaces ([`profiles/gateway.test.sw.yml`](profiles/gateway.test.sw.yml)),
SIGTERM cleanup and fail-open after SIGKILL. `scripts/tests/test_bpf_gateway.sh` does the same for the
[kernel shaping](#kernel-shaping-ebpf) tier with [`profiles/bpf.test.sw.yml`](profiles/bpf.test.sw.yml): delay accuracy,
drop, batches, the passive-latency models and ordering, fallback and forced-tier behaviour, qdisc restoration, SIGTERM,
SIGKILL and unprivileged operation.

## Troubleshooting

- **The program exits with an initialization or handle error:** Run the console
  as Administrator and confirm the WinDivert files match the target
  architecture.
- **No packets are delayed:** Check the active profile's filter, layer, and
  `outbound` setting. Use `--log-level debug` to inspect received packets.
- **The configuration is rejected:** Check that every profile has a name and
  a valid `key` or `keys` value; activation keys may be shared. Check that
  booleans are valid and that `ratio` and `drop_and_send` profiles have a
  positive ratio and `delay_ms`.
- **The console appears stuck:** This is expected while packets are being held.
  Press the active toggle key again, release a hold key, or press `q` to stop;
  queued packets are flushed during teardown.

## Project layout

| Path | Purpose |
| --- | --- |
| `src/` | Application, configuration parser (`src/options/`), packet engine, logging, and resource files |
| `include/` | Public project headers |
| `tests/` | Unit tests (`xmake test`, see [Unit tests](#unit-tests)) |
| `profiles/` | Example YAML configurations |
| `win_divert/` | Embedded WinDivert headers, libraries, drivers, and documentation |
| `xmake.lua` | Project-wide compiler and linker settings |

## License

The `lagsw` project does not currently include a root license file. WinDivert
is distributed under the terms described in [`win_divert/LICENSE`](win_divert/LICENSE).
Review the bundled WinDivert license before redistributing builds that include
its binaries or driver.
