# PoC: Linux Kernel Module Backend (a "WinDivert for Linux")

## 0. Status

- **Phase 1 (build system and echo module): done and verified end to end.** `kmod/xmake.lua` drives the kernel's kbuild from xmake and `kmod/echo/` is a minimal `/dev/swdivert_echo` module (details in §10 and §12). Verified on Linux 7.2.11 (Arch, gcc 16.2.1): `xmake build swdivert_echo` produces a `.ko` whose vermagic matches the running kernel, rebuilds are incremental, a missing kernel build tree gives an actionable error, and debug/release outputs are separate. `sudo scripts/test_kmod_echo.sh` was run as root on the same kernel: the module loads, all 9 user-space checks pass (ABI version ioctl, echo, replace, binary round-trip, second open, full-capacity write, `EMSGSIZE`, intact message after a rejected write, `ENOTTY`) and it unloads. Not covered: other kernels, Secure Boot signing, cross-compilation.
- **Everything else is design only.** Nothing from §7 on is implemented or measured. Every number in §11 is a hypothesis to be confirmed or killed by the spikes in §12.
- This PoC is the third option next to the shipped backend ([`linux_nfqueue_backend.md`](linux_nfqueue_backend.md)) and the eBPF/EDT tier ([`linux_ebpf_netlink_backend.md`](linux_ebpf_netlink_backend.md)). Those two deliberately avoid a kernel module. This one asks the opposite question: *if we accept an out-of-tree module, can Linux match WinDivert's capabilities and per-packet cost, and is the gain large enough to justify the maintenance burden?*
- Success criterion (go/no-go, §12): the module must beat **NFQUEUE with batched verdicts and fail-open (the current backend)** by a margin that the eBPF tier cannot also deliver for the verbs that need user space. If it does not, stop; the documented fallback is the existing backend.

## 1. Summary

WinDivert is a WFP callout driver. It evaluates a compiled filter in the kernel, copies matching packets once into a per-handle queue, lets user space read them in batches (`WinDivertRecvEx`), and lets user space inject any packet back (`WinDivertSendEx`) at a chosen layer, with priority chaining between handles. There is no per-packet message, no per-packet verdict call and no kernel-side queue of original packets that must be answered by id.

Linux has no equivalent. NFQUEUE is the closest, but it costs a netlink message per packet in each direction, a verdict syscall per packet (batched verdicts exist but are limited), a rigid verdict/id model, no synthetic injection, and no layer for "inject as if received on interface X". `AF_PACKET`/XDP can capture and inject but sit below IP, bypass netfilter's ordering and cannot *remove* a packet from the stack without extra rules.

This PoC specifies a module, `swdivert.ko`, that provides:

- a misc char device, `/dev/swdivert`, one open file = one "handle" (WinDivert-style);
- an in-kernel filter VM (bytecode compiled in user space from the existing WinDivert-style filter strings; verified and bounded in the kernel);
- netfilter hooks that run filters, then **divert** (steal and copy to a shared-memory ring), **sniff** (copy, let the original continue) or **drop**;
- mmap'd lock-free rx/tx rings with batch read/write and one wakeup per batch;
- injection of synthetic packets at the network layer (inbound/outbound/forward) and "resume the original packet" by id;
- priority chaining of handles, loop avoidance and a fail-open guarantee when the process dies.

It plugs into the existing seam (`include/packet_backend.h`) as a third Linux backend, `backends/kmod/`, without engine changes.

## 2. Terminology

- **Handle**: an open `/dev/swdivert` file with a filter, layer, priority and flags (WinDivert `HANDLE`).
- **Layer**: `NETWORK` (local in/out) or `NETWORK_FORWARD` (routed). Flow, socket and reflect layers are out of scope (§5).
- **Divert**: take the packet out of the stack and hand it to a handle.
- **Resume**: give a diverted packet back to the stack at the point where it was taken (`NF_ACCEPT` equivalent), optionally with new bytes.
- **Inject**: create a new packet that never existed in the stack (`WinDivertSend` of a synthetic packet).
- **Slot**: one fixed-size entry in a ring.

## 3. Motivation

- **Per-packet cost.** The engine delays, batches, drops and rewrites game traffic. At gateway scale or under bursts, the NFQUEUE netlink round trip is the dominant cost (§11 lists what to measure; the eBPF tier already removes it for pure time-shaping verbs, so the module only has to win on the verbs that must see bytes).
- **Capability gaps of NFQUEUE** relative to WinDivert (all used or plausibly used by the engine):

| Need | WinDivert | NFQUEUE today |
|---|---|---|
| Read many packets per syscall | `WinDivertRecvEx` batch up to 255 | one netlink datagram can carry several messages, but each still needs its own verdict |
| Release many packets per syscall | `WinDivertSendEx` batch | batched verdicts (`send_batch`) only within one socket and still one message per packet |
| Inject packets that were never captured | yes | no (only verdicts on queued packets) |
| Inject inbound as if received on an interface | yes (`IfIdx`, `Outbound=0`) | no |
| Sniff without a verdict | `WINDIVERT_FLAG_SNIFF` | emulated: accept in callback, still pays the round trip |
| Priority chaining incl. injected packets | yes | per-table nft priority only; injected packets cannot be chained |
| Filter on payload bytes, TCP flags, ports, sets, in one program | yes | nft expressions, one rule per DNF clause (see `filter_compiler.cc`) |
| Fail-open on process death | handle close removes the filter | `queue ... bypass` flag |
| Packet timestamp from capture | `Timestamp` | `NFQA_TIMESTAMP` (optional) |
| Hold a packet in the kernel for N ms with no user-space hop | no | no (eBPF/EDT tier does this) |

- **Single dependency story on Linux.** One ABI (ioctl + mmap rings) instead of nftables netlink + nfnetlink_queue + eBPF/tc + fq.

## 4. Goals

1. Capability parity with the WinDivert subset the engine uses today: `NETWORK` and `NETWORK_FORWARD` layers, IPv4 TCP/UDP (IPv6 designed for, tested later), filter strings, priority, sniff, drop, recv/send (single and batch), `shutdown(RECV)`, queue length/time/size parameters, checksum recalculation, `PacketMeta` fields (`outbound`, `if_index`, `timestamp`).
2. Per-packet CPU and latency at least as good as WinDivert-class designs: one copy kernel→user, one copy user→kernel, no per-packet syscall in steady state.
3. Safe by construction: filters cannot hang or crash the kernel; a dead process never blackholes traffic (§9).
4. Coexist with nftables, conntrack, NAT and the other backends: the module must not require disabling them.
5. Ship behind `PacketBackend`; no engine changes except what the other backends already needed (`send_batch`, `discard`, `ShapeSpec`).

## 5. Non-goals

- Windows flow/socket/reflect layers and WinDivert's `WINDIVERT_ADDRESS` ABI compatibility. The module has its own ABI; a thin userland shim (§8.4) maps it to `PacketMeta`.
- Upstreaming. This is an out-of-tree, GPL-compatible module (§10).
- Layer 2 (Ethernet) capture and injection. The module works at the IP layer, like WinDivert's network layer.
- A general-purpose firewall. The filter VM is deliberately smaller than nft/BPF.
- Replacing the shipped backend in this phase. It is opt-in (`--backend=kmod`, §8.4) until §12 says otherwise.

## 6. Why a module and not something else

| Option | Verdict |
|---|---|
| NFQUEUE (shipped) | Works everywhere, no module, but pays a netlink hop per packet and has no injection. This is the baseline to beat. |
| eBPF tc + EDT (see its PoC) | Best for verbs that only need a release time or a drop. Cannot hand bytes to user space and back without a ring-buffer copy path that cannot *resume* an original skb. |
| `AF_PACKET` + `PACKET_TX_RING` / TPACKET_V3 | Fast capture and send, but sees frames after routing/NAT and cannot remove the original; needs rules to drop and then re-inject, losing conntrack/route state. |
| AF_XDP | Driver-level, great speed, but requires driver/XDP support, bypasses netfilter, no locally generated traffic hook, awkward with virtual devices. |
| TPROXY / TUN | Terminates flows, changes TCP semantics. See [`tcp_tls_proxy.md`](tcp_tls_proxy.md) for that path. |
| Module with rings (this PoC) | Only option that can both **steal and resume** an skb with full stack metadata and **inject** synthetic packets with a WinDivert-like cost model. Cost: out-of-tree kernel code. |

## 7. Architecture

```
                   user space                                        kernel
  engine ─ PacketChannel (backends/kmod)                  swdivert.ko
              │   mmap                                       ┌────────────────────────────┐
              ├── rx ring (SPSC, kernel→user) ◄──────────────┤ per-handle rx ring + stats │
              ├── tx ring (SPSC, user→kernel) ───────────────►│ per-handle tx ring         │
              └── ioctl: OPEN / SET_FILTER / SET_PARAM /      │                            │
                         KICK_TX / SHUTDOWN / STATS           │  hook ──► filter VM ──┐    │
                                                              │  (per layer, per prio)│    │
  netfilter hooks: PREROUTING/LOCAL_IN/FORWARD/LOCAL_OUT/POSTROUTING ◄──────────────────┘    │
                                                              │  divert / sniff / drop     │
                                                              │  held-skb table (id→skb)   │
                                                              └────────────────────────────┘
```

### 7.1 Device and handle lifecycle

- `misc_register` of `/dev/swdivert`, mode `0600 root`. `open()` creates a handle in the *calling task's network namespace* (netns of the opener; document that a handle in the init namespace does not see container-internal traffic and vice versa).
- Handle state: layer, priority (−30000..30000 like WinDivert), flags (`SNIFF`, `DROP`, `RECV_ONLY`, `SEND_ONLY`, `FRAGMENTS` reserved), compiled filter, rx ring, tx ring, params (queue length 32..16384, queue time 100..16000 ms, queue size 64 KiB..32 MiB; same bounds and defaults as WinDivert so the engine's constants carry over), counters.
- `release()` (close, process exit, SIGKILL) unlinks the handle from the hook table via RCU, then resumes or drops every packet still held by it according to the handle's *on-close policy* (§9.1). This is the fail-open path; it is synchronous with file release, so no separate watchdog is required.

### 7.2 Hooks and layers

| WinDivert layer / direction | Netfilter hook(s) | Notes |
|---|---|---|
| NETWORK inbound | `NF_INET_LOCAL_IN` | After routing decided local delivery. |
| NETWORK outbound | `NF_INET_LOCAL_OUT` | Locally generated packets just before they leave the host, as WinDivert sees them pre-send. |
| NETWORK_FORWARD | `NF_INET_FORWARD` | Routed traffic (gateway case). |
| "earliest inbound" (optional) | `NF_INET_PRE_ROUTING` | Needed when a handle must see packets before DNAT/routing; used for region enforcement drops. |

- Hooks are registered **once per netns per hook** (not per handle) at a fixed base priority, with a dispatcher that walks the handles ordered by priority. This is the same shape as WinDivert's single callout per layer and avoids hundreds of netfilter entries.
- Hook priority: by default just after `NF_IP_PRI_FIRST` (before conntrack/NAT, like the −150 chains of the shipped nft table). Whether to run before or after NAT is a real trade-off (open question §14.2), so it is a module parameter: `prio_mode=early|late`.
- Handles are matched by `(layer, direction)` first. The per-packet fast path is: read RCU pointer to the sorted handle array, evaluate filters in order, stop at the first divert/drop.
- Direction and ifindex come from `state->in`/`state->out`, `Outbound` from the hook. Loopback packets are reported with `Outbound=1` once (as WinDivert does on Windows) by diverting only at `LOCAL_OUT` and marking the later `LOCAL_IN` pass as already-seen (§7.6).

### 7.3 Filter VM

- Source language: the WinDivert-style strings the engine already produces. `backends/nfqueue/filter_{lexer,parser,compiler}.cc` already parses that subset to a DNF; the kmod backend reuses lexer/parser and emits **bytecode** instead of nft rules. The kernel never sees text.
- Program format: a flat array of fixed-size instructions, forward jumps only (no loops, so termination is structural), max 4096 instructions, max 256 bytes of packet look-ahead per instruction.
- Operand sources: IP/TCP/UDP header fields (addresses, ports, protocol, flags, TTL, length), `outbound`, `loopback`, `ifindex`, `mark`, payload bytes at constant offsets (`tcp.Payload[i]`-style), and **set lookups**.
- Sets: the engine's server lists become `ipv4_set` and `port_range_set` objects uploaded with `SET_FILTER`. Implementation: sorted array + binary search below 32 entries, `rhashtable` above. This keeps the cost of "match any of N servers" O(1) instead of the DNF clause explosion that motivated Change A of the eBPF PoC.
- Verification (`SET_FILTER` ioctl): bounds-check every jump and offset, reject unknown opcodes, reject reads past 256 bytes, copy the program into kernel memory before verifying (no TOCTOU), refuse programs larger than the limit. Fuzzed in CI (§13).
- Execution: `skb_header_pointer()` for header reads so non-linear skbs work; no allocation, no sleeping, runs in softirq/RCU read-side context.
- Optional later: JIT the VM or reuse `bpf_prog_run` on a classic-BPF program (open question §14.3). Not needed for the PoC; the VM is chosen first because it has no dependency on exported BPF symbols that vary by kernel.

### 7.4 Divert path (the hot path)

On a match with `action=divert`:

1. If the skb is cloned/shared, `skb_unshare`; if GSO, see §7.7.
2. Compute the slot size (`skb->len` + header ≤ MTU + metadata); if the rx ring has no free slot or the handle's queue-length / queue-size / queue-time limits are exceeded: apply the handle's **overflow policy** (`pass` by default so an overloaded diverter fails open; `drop` for enforcement handles). WinDivert drops the oldest queued packet instead; that is selectable as `drop_oldest`.
3. Copy the packet into a free rx slot (`skb_copy_bits`, one copy). Write slot metadata: id, timestamp (`ktime_get_real_ns`), direction, layer, ifindex, flags, checksum-valid bits, original length.
4. Choose the hold mode of the handle:
   - **`HOLD` (default for modify/delay verbs):** the original skb is stolen (`NF_STOLEN`) and parked in a per-handle table keyed by the slot id, together with the information needed to continue (`struct nf_hook_state` copy, hook index, netns/dev refs). User space later *resumes* it by id.
   - **`CONSUME`:** the skb is freed immediately (`NF_STOLEN` + `consume_skb`) and the engine re-injects a new packet (WinDivert behaviour). Cheaper in memory; loses conntrack/route/socket association and TCP small-queue accounting changes (see §7.6 and §14.4).
5. Publish the slot by advancing the ring head with `smp_store_release`; if the consumer is sleeping, wake it. Wakeups are **batched**: at most one per `wake_batch` packets or `wake_us` microseconds (module params), plus an immediate wake when the ring was empty and the consumer is blocked.

For `action=sniff`: steps 2–3 only, the original skb continues (`NF_ACCEPT`), slot flagged `SNIFFED` and not resumable. Cost is one copy and no table entry.

For `action=drop`: `kfree_skb_reason`, counters updated, no ring traffic. This is the in-kernel region-enforcement path and costs only the filter evaluation.

### 7.5 Reinjection path

The tx ring carries commands, each referencing either a held id or carrying new bytes:

| Command | Meaning | Maps to |
|---|---|---|
| `RESUME(id)` | continue the held skb unchanged | `NF_ACCEPT` / `send()` of an unmodified packet |
| `RESUME_MOD(id, bytes)` | replace headers+payload (in place if length ≤ original and the skb is writable, else `pskb_expand_head`) and continue; kernel recomputes checksums when flagged | modified `send()` + `calc_checksums` |
| `DROP(id)` | free the held skb | `PacketChannel::discard()` |
| `INJECT(bytes, dir, ifindex, layer)` | build a new skb and deliver it as inbound or outbound | `WinDivertSend` of a synthetic packet |

- **Resume mechanics.** The module records the hook ops pointer and index at divert time. On resume, it re-reads the netns hook entries under RCU, locates the same ops, and calls `nf_hook_slow()` starting at the **next** index (so lower-priority hooks still run, and the packet is not re-diverted by this module's dispatcher because the handle's own priority is already consumed); if the ops disappeared (rule set changed), it continues from the recorded index with a bounds check, and if even that is invalid it falls back to `okfn()` directly. This mirrors what `nf_reinject()` does for queued packets; the module cannot reuse `nf_reinject()` itself because that requires being the registered nf_queue handler, which would conflict with `nfnetlink_queue` and the shipped backend (§14.1).
- **Inject mechanics.** Outbound: `ip_local_out()` for locally generated direction or `dev_queue_xmit()` on `ifindex` for forward-layer output; inbound: set `skb->dev`, `skb->protocol`, call `netif_rx()`/`ip_rcv()` in softirq with `local_bh_disable()`. Route lookup is performed for outbound packets that carry no dst.
- **Batching.** User space writes N commands, then one `KICK_TX` (or the kernel polls the ring from the same wakeup path if the module param `tx_poll_us` is set). The kernel processes commands in order and writes per-command status back into the slot (`ok`, `no_such_id`, `bad_packet`, `no_route`). That status is what `PacketChannel::send_batch()` returns per item.
- **Ordering.** Commands from one handle are executed in ring order on one CPU. The ring gives the ordering guarantee the engine's delay modes rely on (the engine already treats ordering as a first-class concern for `preserve_order`).

### 7.6 Loop avoidance, priorities and chaining

- Injected and resumed packets are tagged for the duration of their synchronous traversal with a **per-CPU "current priority" register** (set around `nf_hook_slow()` / `ip_local_out()` / `netif_rx()` calls with BH disabled). The dispatcher consults it and only offers the packet to handles with priority strictly lower than the injector, which gives WinDivert's "injected packets are diverted to the next priority handle" semantics without relying on a mark bit that other software might use.
- When the traversal is *not* synchronous (e.g., `netif_rx()` defers to the backlog), the module sets a bit in a reserved skb mark range (module param `mark_mask`, default `0x40000000`; documented to not collide with the shipped backend's verdict mark in the eBPF PoC) and clears it on first sight. Both mechanisms are required: per-CPU for the common synchronous path, mark for the deferred path.
- Handles at the same priority are exclusive-filter by contract, identical to WinDivert; the module rejects `OPEN` of a second handle with identical `(layer, priority)` unless `allow_shared_priority=1`.
- Loopback: both `LOCAL_OUT` and `LOCAL_IN` see the same packet. The dispatcher marks a loopback packet as "already diverted at this handle" so it is reported once, as WinDivert does.

### 7.7 Offloads, GSO/GRO and checksums

- Default: ask netfilter hooks to see the packet after `skb_gso_segment()` for handles that can modify (`HOLD` mode), so user space always handles ≤ MTU packets; this costs a segmentation per super-packet but matches NFQUEUE's `NFQA_CFG_F_GSO` behaviour already used by the shipped backend. Sniff handles may opt in to super-packets (`SNIFF_GSO`) to avoid the segmentation cost.
- Partial checksums: the slot carries `ip_csum_ok`, `tcp_csum_ok`, `udp_csum_ok` like `WINDIVERT_ADDRESS`. For `CHECKSUM_PARTIAL` skbs the bits report "ok" (the NIC will finish it), matching what WinDivert reports for offloaded outbound packets.
- `RESUME_MOD`/`INJECT` accept flags `CALC_IP|CALC_TCP|CALC_UDP`, performed in the kernel with `csum_partial` helpers; user-space `calc_checksums()` remains available for pcap and tests.

### 7.8 Optional extension beyond WinDivert: in-kernel hold

Because the module owns held skbs, it can also offer `RESUME_AT(id, deadline_ns)` and a per-handle `hrtimer`-driven release queue. That would let delay verbs release without a user-space wake per packet and covers what the eBPF/EDT tier cannot (hold *and* inspect). It is **out of the parity scope** and only specified here so the ring ABI reserves the command (§8.2). It is evaluated as a follow-up spike if parity benchmarks pass.

## 8. Interface

### 8.1 ioctl ABI (sketch)

```
SWDIV_IOC_OPEN        { u8 layer; i16 priority; u32 flags; u32 ring_slots; u32 slot_bytes; }
SWDIV_IOC_SET_FILTER  { u32 n_insns; u64 insns; u32 n_sets; u64 sets; }       // verified, atomic swap
SWDIV_IOC_SET_PARAM   { u32 param; u64 value; }   // QUEUE_LENGTH / TIME / SIZE / OVERFLOW / HOLD_MODE / ONCLOSE
SWDIV_IOC_KICK_TX     { }                          // process tx ring
SWDIV_IOC_SHUTDOWN    { u32 how; }                 // RECV, SEND, BOTH; recv wakes with "closed"
SWDIV_IOC_STATS       { out: seen, diverted, sniffed, dropped, overflow, resumed, injected, held, errors }
SWDIV_IOC_VERSION     { out: abi, features }
```

- Two versioned ABI fields (`abi`, `features`) so the backend can refuse an incompatible module with a clear message (this mirrors how `initialize()` reports a missing WinDivert driver).
- `mmap` offsets: header page (producer/consumer indices, flags), rx slots, tx slots. Indices are cache-line separated; slots are fixed size (`slot_bytes`, default 2048 + 64 metadata) to avoid allocator work and keep prefetch friendly.

### 8.2 Slot layout

```
struct swdiv_slot_hdr {
  u64 id;            // unique per handle, wraps after 2^64
  s64 timestamp_ns;
  u32 len;           // packet bytes
  u32 ifindex;
  u16 flags;         // OUTBOUND LOOPBACK IMPOSTOR SNIFFED GSO_SEGMENT CSUM_IP_OK CSUM_TCP_OK CSUM_UDP_OK
  u8  layer, hook;
  u32 mark;
  u32 status;        // tx only: result of the command
  u32 cmd;           // tx only: RESUME | RESUME_MOD | DROP | INJECT | RESUME_AT (reserved)
  u64 deadline_ns;   // RESUME_AT only
};
```

### 8.3 Failure semantics visible to user space

- `recv` on a shut-down handle with an empty ring returns `closed`. Overflow does not error: it is counted and applied per the overflow policy; the engine reads the counters and logs them in the status line.
- `RESUME` of an id that was already resumed, dropped or timed out returns `no_such_id`; the engine treats it as "packet already gone" (same as NFQUEUE returning `ENOENT` for a verdict).
- Held packets have a **hold timeout** (WinDivert's QUEUE_TIME analogue, default 2 s, max 16 s, longer values require `CAP_SYS_ADMIN` and a module param, because held skbs pin socket send buffers). On expiry the kernel applies the on-close policy to that packet and counts it.

### 8.4 Mapping to `PacketBackend`

| `packet_backend.h` | `backends/kmod/` |
|---|---|
| `initialize()` | open `/dev/swdivert` and check `SWDIV_IOC_VERSION`; if the device is missing, load the module per §9.3; if that is not possible, an actionable error (`modprobe swdivert`, DKMS hint). A version mismatch is refused with both versions in the message. |
| `check_privileges()` | root, or `CAP_NET_ADMIN` + device node permission (a `udev` rule/group is documented; the device refuses without `CAP_NET_ADMIN` regardless of mode bits). |
| `open(OpenOptions)` | `OPEN` with layer from `forward`/`include_forward` (two handles like the WinDivert backend), `priority` → priority, `sniff` → `SNIFF`, `filter` → compile and `SET_FILTER` |
| `validate_filter()` | compile + local verifier; no kernel call needed |
| `PacketChannel::recv()` | consume rx ring; `poll()`/futex-style wait when empty; fills `PacketMeta` (`outbound`, `if_index`, `timestamp`, `native` = slot id and hold token) |
| `send()` / `send_batch()` | write tx commands, one `KICK_TX` per batch |
| `discard()` | `DROP(id)` |
| `shutdown_recv()` | `SHUTDOWN(RECV)` |
| `calc_checksums()` | reuse the NFQUEUE backend's implementation |
| `open_shape_stage()` | "unsupported" initially (engine falls back to an ordinary channel); later `RESUME_AT` (§7.8) or defer to the eBPF tier |

`PacketMeta::native[96]` is large enough for the slot id + hold token + command flags.

## 9. Lifecycle, failure and privileges

### 9.1 Fail-open is a hard requirement

- **On-close policy** per handle (`pass` default, `drop` for enforcement handles that must fail closed by explicit request). On `release()` the module resumes every held packet (`pass`) or drops it (`drop`) and unlinks the handle before the file is freed.
- **Module unload** is never done by `lagsw` unless asked (§9.3), and is refused by the kernel while handles exist (`try_module_get` by each open), and unregisters hooks only after an RCU grace period.
- **Overload** applies the handle's overflow policy; the engine's default is `pass`, so an overwhelmed engine degrades to "no shaping", not "no network".
- **Crash of the kernel module itself** is the residual risk this design cannot make go away; mitigated by §10 and §13 (fuzzing, KASAN/KCSAN CI, strict ownership rules).

### 9.2 Privileges

- Device node `0600 root:root`, plus `CAP_NET_ADMIN` checked in `open()` (so a file-capability'd binary can use it; compare with the netlink backend's capability story).
- `SET_FILTER`, `INJECT`, long hold timeouts are checked against the opener's capabilities at ioctl time, not just at open.
- Handles are per-netns; a handle cannot affect another namespace.

### 9.3 Who loads and unloads the module

`lagsw` loads the module when it is missing and **never unloads it by default**.

- **Load (in `initialize()`):** only when `/dev/swdivert` does not exist and the process is root (loading needs `CAP_SYS_MODULE`, which a file capability for `CAP_NET_ADMIN` does not give).
  1. `modprobe swdivert` (installed module, Phase 7 packaging).
  2. Otherwise `insmod <path>` for a `.ko` given with `--kmod-path` or found next to the executable, so a development build works without installing.
  3. Otherwise fail with the instructions in §8.4. Without root, never attempt a load: print the `modprobe`/`insmod` command to run instead.
  - Loading goes through the `modprobe`/`insmod` programs (`kmod` userland), not an in-process `finit_module()`, so module signing, dependencies and the system's module policy (`modprobe.d`, lockdown) apply unchanged.
  - After loading, wait for the device node (udev can lag behind `insmod`) with a short bounded retry, then run the ABI check. An already-loaded module with a different ABI is an error; `lagsw` does not try to replace it.
  - `lagsw` records whether *it* loaded the module (for the opt-in below and for the log line "loaded swdivert (abi N)").
- **Unload: not by default.** Reasons:
  - The module is host-wide. Another `lagsw` instance, a container or another tool may hold handles, and `rmmod` of a module that is in use is refused by the kernel anyway.
  - Packets are already safe on exit and on crash: closing the device (normal exit, `SIGKILL`, kernel-side process teardown) runs the handle's `release()` which applies the on-close policy (§9.1). Leaving the module loaded does not leave any traffic diverted. An unload step could not run after a crash, so it would only add a second cleanup path that is not always executed.
  - Loaded but idle costs nothing: hooks are registered only while a handle exists (§14.5).
  - This differs from the NFQUEUE backend, which removes its own `inet lagsw` nft table on exit because that table belongs to the process alone.
- **Opt-in unload:** `--kmod-unload-on-exit` makes a normal exit (not a crash) run `rmmod swdivert` **only if this process loaded it**, after all its handles are closed; `EBUSY` is logged at debug level and ignored. Default off. A normal exit includes the `SIGTERM`/`SIGHUP` path used by the NFQUEUE backend.
- **Failure handling:** a failed load is a startup error (before any profile is activated), never a mid-run surprise. If the module disappears while running (manual `rmmod` is impossible while handles are open, so this means an unexpected kernel-side failure) the channels report `error` and the engine shuts down; there is nothing to fall back to at that point, and fail-open (§9.1) has already released held packets.
- **Auto-selection (Phase 6):** the backend choice kmod → nfqueue only prefers the module when it is already loaded or loadable (root and a `.ko`/installed module found) and the ABI matches; otherwise it falls back to NFQUEUE with a log line saying why. A load is never attempted just to probe.

## 10. Build, packaging and distribution

- **Build system (Phase 1, implemented).** Modules live under `kmod/` and are built by xmake through the rule `kmod.module` ([`kmod/xmake.lua`](../kmod/xmake.lua), helpers in [`kmod/modules/kbuild.lua`](../kmod/modules/kbuild.lua)):
  - A target is `add_rules("kmod.module")` + `add_files("*.c")` + optional `add_includedirs` and `add_values("kmod.defines", ...)` (not `add_defines`, which also carries the repository-wide `DEBUG`/`NDEBUG`); its output is `build/<plat>/<arch>/<mode>/<name>.ko`. See [`kmod/echo/xmake.lua`](../kmod/echo/xmake.lua).
  - The rule does **not** compile with xmake. It stages the sources into `build/.gens/<name>/.../kbuild/`, generates a `Kbuild` file there from the target (xmake is the single source of truth; there is no checked-in Makefile, which the repo's `.gitignore` would also exclude) and runs `make -C <kdir> M=<stage> modules`. kbuild therefore owns the compiler, flags, modpost, vermagic, BTF and (if configured) signing, exactly as DKMS will later. The root-level flags (`-Werror`, C++20, LTO, mode defines) never reach kernel code. xmake's built-in `platform.linux.module` rule was evaluated and rejected: it re-implements kbuild/modpost steps by hand and refuses the global `mode.*` rules this repository applies to every target.
  - Kernel selection: `xmake f --kmod_kdir=<dir>`, else `$KDIR`, else `/lib/modules/$(uname -r)/build`. The kernel, the target's sources and the build mode are inputs of the incremental check, so a different kernel triggers a rebuild.
  - **IntelliSense.** Project generators skip phony targets and only see what xmake itself compiles, so a module would be invisible to clangd (neovim) and cpptools (VS Code) and every kernel header would be "not found". The rule therefore takes the sources out of the target's file list (xmake must not compile them with the repository's flags), keeps the target a file-less `.ko` binary, and emits an explicit `gcc -fsyntax-only` command per source from `on_buildcmd`. That command's result is ignored during a build (kbuild is the judge); it exists so `xmake project -k compile_commands` records a compile command for each module source. The flags are a curated set (kernel include paths for the target architecture, `-include kconfig.h` and friends, `-D__KERNEL__ -DMODULE`, `CONFIG_CC_MS_EXTENSIONS` from the kernel `.config`), not the kbuild command line, whose gcc-only flags make clangd report errors. Checked with `clangd --check` on `echo.c`: headers resolve and no diagnostics are reported. Without a prepared kernel tree no entries are emitted (the generator must not fail on machines without headers), so install the headers, then regenerate `compile_commands.json`. Header-only files (`kmod/include/*.h`) get no entry of their own; clangd infers one from the sources that include them.
  - Modules are **not** part of the default build (the target is `set_default(false)` and in the `kmod` group, and the headers of the target kernel may be absent). Use `xmake build swdivert_echo` or `xmake build -g kmod`. `xmake clean` removes the staging directory and the `.ko`. A missing or unprepared kernel tree is reported by a `before_build` check, so only real builds fail.
  - Integration test: `kmod/echo/echo.c` is a misc device that returns the last message written to it, with a version ioctl. [`tests/kmod_echo/`](../tests/kmod_echo/xmake.lua) is the user-space half and [`scripts/test_kmod_echo.sh`](../scripts/test_kmod_echo.sh) builds-checks, `insmod`s, runs it and `rmmod`s (root only; it cannot use a container because modules are host-wide). The shared ABI header `kmod/include/swdivert_echo_abi.h` is the pattern the real `swdivert_abi.h` follows (only `<linux/*.h>` uapi types, included by both sides).
  - Not done yet: module signing for Secure Boot (kbuild can sign with the kernel's key; DKMS/MOK flow is Phase 7), a `.clangd`/`compile_commands.json` entry for kernel sources, cross-compiling (`ARCH=`/`CROSS_COMPILE=` pass-through), and installing (`modules_install`/DKMS).
- Packaging: DKMS config for the real module (Phase 7). The kernel module is built independently of the user-space backend, which only needs the ABI header.
- License: `GPL` (required to call GPL-only netfilter symbols such as `nf_hook_slow`, `nf_register_net_hook` and to avoid tainting with a proprietary flag). The userland backend remains under the project's license; the ioctl/mmap ABI is the boundary.
- **Secure Boot / lockdown:** unsigned modules will not load on Secure Boot systems. Options: user enrolls a MOK and DKMS signs the module; or run in a VM/container host where the module is pre-installed. This is a hard adoption constraint (WinDivert ships a signed driver; this project cannot).
- Kernel support target for the PoC: the single dev kernel (7.2.11 per the other PoCs), then the current LTS series. Record exact required symbols per kernel (`nf_register_net_hook`, `nf_hook_slow`, `skb_gso_segment`, `rhashtable`). The CI matrix is part of Phase 8 (§12).
- Container use: the module is host-wide; containers need `/dev/swdivert` passed through and `CAP_NET_ADMIN`. The shipped backends remain the choice for unprivileged or locked-down environments.

## 11. Performance model and targets (hypotheses)

Where the cost is today and where the module is supposed to save it:

| Step | NFQUEUE (shipped) | `swdivert.ko` |
|---|---|---|
| Match | nft rules (set lookup or DNF clauses) | filter VM, set lookups |
| Hand to user | netlink skb alloc + attributes + copy, socket wake | one copy into ring slot, batched wake |
| Return verdict | `sendmsg` with verdict (+ payload if modified), one per packet (batched at best by message) | tx ring write; one `KICK_TX` per batch |
| Resume | `nf_reinject` | `nf_hook_slow` from recorded index |
| Memory per held packet | skb + `nf_queue_entry` + netlink skb copy | skb + table entry (ring slot recycled when copied) |

Targets to confirm (all single-flow UDP/TCP, 64 B and 1400 B payloads, one engine thread):

- Throughput with one core saturated: **≥ 2× NFQUEUE's packets/s** for divert-and-resume of unmodified packets, and **≥ 1.5×** for divert-modify-resume.
- Added latency (p50/p99) at 10 k / 50 k / 100 k pps: **≤ half** of NFQUEUE's, measured with the same netns/veth rig as `scripts/test_nfqueue_gateway.sh`.
- Idle overhead (module loaded, no handle open): **unmeasurable** against baseline (hooks registered lazily, only while handles exist; §14.5).
- CPU per packet at sniff: within **10 %** of `AF_PACKET` TPACKET_V3 on the same box.
- Maximum sustainable `delay × pps` before overflow, to compare directly with the eBPF/EDT tier's `fq` horizon limit.

WinDivert's own numbers are not a target, because they depend on Windows. The parity claim here is architectural (one copy each way, batching, in-kernel filter), and the measured claim is relative to NFQUEUE on the same hardware.

## 12. Phases and go/no-go

1. **Phase 1: kernel-module build system and echo module (done).** Add `kmod/` with the `kmod.module` xmake rule that drives kbuild, an echo module (`swdivert_echo`: a misc device that returns what was written, plus a version ioctl), a user-space test and a root-only load/test script (§10). Exit criteria: `xmake build swdivert_echo` yields a `.ko` for the selected kernel from a clean tree; incremental rebuilds are no-ops; a missing kernel tree gives a clear error; the default `xmake` build is unaffected; **and** `sudo scripts/test_kmod_echo.sh` loads the module, passes all user-space checks and unloads it cleanly (met on 7.2.11). Every later phase builds on this rule, so it is first.
2. **Phase 2, Spike A: capture-only ring.** Hook `FORWARD` on a veth netns gateway, filter by hard-coded 5-tuple, copy into an mmap ring, sniff only. Measure cost per packet against `AF_PACKET` and NFQUEUE sniff.
3. **Phase 3, Spike B: steal and resume.** Add `HOLD`, `RESUME`, `DROP`. Verify TCP continues, conntrack and NAT state unaffected, `bypass`-like fail-open on `kill -9`, and netns teardown with held packets.
4. **Phase 4, Spike C: modify and inject.** `RESUME_MOD`, `INJECT`, checksum flags, priority chaining, loop avoidance. Re-run the existing engine test profiles through a `backends/kmod` stub.
5. **Go/no-go gate.** Compare against the §11 targets. If divert-and-resume is not at least ~1.5× faster than the batched NFQUEUE backend, **stop** and keep NFQUEUE + eBPF (record the numbers here).
6. **Phase 5: filter VM and sets.** Bytecode emitter from the existing lexer/parser, verifier, fuzz harness (syzkaller-style, plus a user-space harness that runs the VM on random programs/packets under ASan).
7. **Phase 6: backend integration.** `backends/kmod/backend.cc`, xmake option, module load policy and `--kmod-path`/`--kmod-unload-on-exit` (§9.3), `--backend`/auto-selection order (kmod → nfqueue only when the module is loaded and ABI matches), README section.
8. **Phase 7: packaging.** DKMS config, module signing (MOK) and the Secure Boot story, `modules_install`.
9. **Phase 8: hardening.** KASAN/KCSAN/lockdep runs, netns churn, module reload under traffic, CPU hotplug, multiple handles with priority chains, kernel matrix.
10. **Optional:** `RESUME_AT` in-kernel hold, IPv6, multi-queue fanout (one ring per CPU/flow hash, relevant only if the engine's single-thread-per-channel model changes).

## 13. Test plan

- **Build system:** `xmake build swdivert_echo` from a clean tree, no-op rebuild, rebuild after a source change, a different `--kmod_kdir`, missing kernel headers (error text), debug and release side by side, default `xmake` build unchanged, `sudo scripts/test_kmod_echo.sh`.
- **Functional:** every existing engine verb through the real engine against the module (delay, batch, drop, hold, UDP, period, ack restoration, exclusivity, pcap, region enforcement), reusing `profiles/localhost.test.sw.yml` and the gateway scripts' structure (a `scripts/test_kmod_gateway.sh`).
- **ABI:** version mismatch, truncated ioctl, hostile ring indices written by user space (the kernel must not trust producer/consumer indices from the user-writable page; keep authoritative copies in kernel memory).
- **Filter VM:** verifier rejection tests, differential tests against the nft backend's compiled output on the same pcaps (`pcap_files/`), fuzzing.
- **Module lifecycle (§9.3):** start as root with the module absent (loaded via `insmod --kmod-path`, then `modprobe`), start without root with the module absent (clear instruction, no load attempt), already loaded with matching and with mismatching ABI, device node appearing late, `--kmod-unload-on-exit` with and without a second process holding handles (`EBUSY` ignored), the module is left loaded by default, the unload flag does not unload a module this process did not load.
- **Failure:** SIGKILL with N held packets, `rmmod` attempt with open handles, netns deletion with a handle open, ring overflow (both policies), hold timeout expiry, `RESUME` of stale id, double `RESUME`.
- **Interaction:** with nftables rules at various priorities, conntrack + NAT, GSO/GRO on/off, `CHECKSUM_PARTIAL` skbs, loopback, VLAN and non-Ethernet links (`ARPHRD_NONE`), concurrent use with the shipped NFQUEUE backend on a different profile.
- **Performance:** §11 on the same rig as the NFQUEUE and eBPF measurements so all three are comparable.

## 14. Risks and open questions

1. **Resuming a stolen skb without being the nf_queue handler.** The design uses `nf_hook_slow()` from a recorded index. Needs a spike to prove it is correct on `LOCAL_OUT` (where the hook is `NF_INET_LOCAL_OUT` and `okfn` is `dst_output`) and `FORWARD`, including when hook entries change between divert and resume. If it is not robust, the fallback is `CONSUME` + `INJECT` only (WinDivert's own model), at the cost of metadata and TCP small-queue behaviour.
2. **Hook priority vs conntrack/NAT.** Seeing the packet before or after NAT changes what addresses the engine filters on (the same issue as §7.5 of the eBPF PoC). Decide `early` vs `late` per hook after a spike with a masquerading gateway.
3. **Filter VM vs reusing BPF.** `bpf_prog_get_type()` + `bpf_prog_run` would give a JIT and a verifier for free, but the exported-symbol surface differs by kernel and config. The VM is chosen for independence; revisit if the VM is the bottleneck.
4. **TCP small queues and held skbs.** Holding an outbound skb keeps its socket's `sk_wmem_alloc`; long holds can stall the sender, which is the point for some verbs and surprising for others. `CONSUME` frees early and changes that behaviour. Needs measurement with the actual game flows (see the research notes) before choosing defaults.
5. **Lazy hook registration.** Registering netfilter hooks has a cost for *all* traffic (static key enabled). Register only while at least one handle for that layer exists; measure the idle overhead claim.
6. **Secure Boot and distribution** may make the module unusable for the likely end users (§10). Decide whether the module is only for gateway/lab deployments.
7. **Maintenance cost.** Netfilter internals change between kernel versions. The module should be small (target < 4 kLoC), have an explicit supported-kernel list, and CI against each.
8. **Security review.** Any out-of-tree kernel code that parses attacker-controlled packets and user-supplied bytecode needs a dedicated review (§15) before shipping.
9. **Multi-queue.** The engine reads each channel from one thread; per-CPU rings only help if that changes (compare the "fanout deferred" decision in the NFQUEUE PoC).

## 15. Security and correctness requirements

- Never trust anything in the shared mapping: ring indices, slot lengths, command fields. Re-validate against kernel-held state on every command.
- Bound all allocations by handle parameters (queue length/size) and a global module cap; cap held skbs per handle and globally to avoid memory exhaustion by a buggy engine.
- The filter verifier is the main attack surface. Copy-then-verify, forward-jump-only, bounded length and read offsets, no kernel pointers exposed, constant-time-bounded execution.
- No information leaks: copy only `len` bytes into slots and zero the remainder and padding of slot headers.
- Respect network namespaces; never take references to another netns's devices.
- Reference-count `net_device`/`dst`/netns of held skbs and release them on every path (resume, drop, timeout, close, netns exit).
- Run under KASAN, KCSAN, lockdep and `CONFIG_DEBUG_ATOMIC_SLEEP` in CI; fuzz the ioctl surface.
- Document that loading the module taints nothing (GPL) and that the module logs through `pr_*` with a rate limit only.

## 16. Decision

Phase 1 is complete; proceed with Spikes A–C (Phases 2–4, §12) on the dev kernel and record numbers back into this document. The module is justified only if it clearly beats the batched NFQUEUE backend on divert-and-resume latency and CPU while meeting §9's fail-open guarantee; otherwise the project keeps NFQUEUE plus the eBPF/EDT tier and this PoC is closed as "not worth the out-of-tree cost".
