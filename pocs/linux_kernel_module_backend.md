# PoC: Linux Kernel Module Backend (a "WinDivert for Linux")

## 0. Status

- **Phase 1 (build system and echo module): done and verified end to end.** `kmod/xmake.lua` drives the kernel's kbuild from xmake and `kmod/echo/` is a minimal `/dev/swdivert_echo` module (details in §10 and §12). Verified on Linux 7.2.11 (Arch, gcc 16.2.1): `xmake build swdivert_echo` produces a `.ko` whose vermagic matches the running kernel, rebuilds are incremental, a missing kernel build tree gives an actionable error, and debug/release outputs are separate. `sudo scripts/tests/test_kmod_echo.sh` was run as root on the same kernel: the module loads, all 9 user-space checks pass (ABI version ioctl, echo, replace, binary round-trip, second open, full-capacity write, `EMSGSIZE`, intact message after a rejected write, `ENOTTY`) and it unloads. Not covered: other kernels, Secure Boot signing, cross-compilation.
- **Phase 2 (Spike A, capture-only ring): done and measured on 7.2.11. The ring matches AF_PACKET TPACKET_V3 on sniffer CPU when the wake-up is batched coarsely, and is ~10× cheaper than NFQUEUE.** `kmod/swdivert/` is a sniff-only `/dev/swdivert` with a FORWARD hook, one 5-tuple filter and an mmap ring; `pocs/linux_kernel_module_backend/` has the rig and the sniffers. `sudo scripts/tests/test_kmod_sniff.sh --bench` passes every check (exact capture, decoy flow ignored, SIGKILLed reader leaves forwarding intact, module reference count 0 afterwards, nothing in `dmesg`) and the ring never dropped a packet up to 200 kpps, where NFQUEUE dropped 14–26 % of the *forwarded* traffic. Sniffer CPU per packet depends on how many packets one wake-up covers: 1.8–2.1 µs at one packet per wake-up, 0.28–0.42 µs at the default `wake_us=50`, and **0.06–0.08 µs at `wake_us=1000`, `wake_batch=256`, against 0.05–0.07 µs for AF_PACKET** and 3.9–4.3 µs for NFQUEUE. The price of the coarse setting is up to `wake_us` of added delay before a sleeping reader sees a packet, which was **not measured** and is irrelevant for sniffing but decisive for Phase 3's release path. The default stays at the latency-safe 50 µs / 32 until Phase 3 has measured that latency (§12 "Phase 2 results").
- **Phase 3 (Spike B, steal and resume): implemented, verified in a VM on 7.2.11, and benchmarked once on real hardware (bare metal, same kernel).** A `HOLD` handle steals matching FORWARD packets (`NF_STOLEN`), copies them into the ring and parks the original until user space gives a verdict (`RESUME` or `DROP`, batched in one ioctl); a packet nobody answers is resumed after `hold_ms`; closing the handle, including by SIGKILL, resumes every held packet before the hook goes away. `scripts/tests/test_kmod_hold_vm.sh` boots the host's own kernel in QEMU/KVM and runs 46 checks against the real module, with slab poisoning and red zones on: all pass, three runs in a row on 8 CPUs. Results: a TCP transfer through a 2 ms hold arrives intact with all 2915 data segments held (also through a masquerading gateway, so conntrack/NAT state survives a hold); **SIGKILLing the reader with packets held loses none (NFQUEUE loses every one that was waiting: 1000 of 2000 in the same test)**; exactly-once delivery holds under racing timeouts, verdicts and kills (79,999 of 79,999, no duplicates); and divert-and-resume costs less reader CPU than batched-verdict NFQUEUE: **2.4–2.5× less at 100 kpps and 1.4–1.5× less at 20 kpps on bare metal** (2.7–3.0× and 1.6× in the VM), with no loss and a lower median latency (8 vs 17 µs at 100 kpps, 11 vs 13 µs at 20 kpps). The advantage is real but smaller than the VM suggested and at low rates sits right at the 1.5× gate. Caveats remain large (one machine, `veth` not a NIC, one flow, one run per row, no packet modification yet, one kernel); see §12 "Phase 3 results".
- **Phase 4 (Spike C, modify and inject): implemented, verified in a VM on 7.2.11, and benchmarked once on bare metal.** A held packet can be resumed with new bytes (`RESUME_MOD`, with the IP and TCP/UDP checksums recomputed in the kernel on request); a handle can inject packets of its own (`INJECT`, received as if on an interface); handles have priorities and form a chain, and injected and resumed packets continue to the handles served after the injector but are never offered to it again (loop avoidance). 92 checks pass (three runs in a row, 8 CPUs, slab poisoning on), including checksums verified on the wire at the receiver, a TCP transfer with a modified byte in every segment (with and without masquerade), a destination rewrite that is routed again through a third host, chaining in both orders, and a fuzzer (30,000 hostile `INJECT`/`RESUME_MOD` calls: no crash, no unexpected error, traffic fine afterwards). **Over four bare-metal runs (release builds, nothing lost in any), the module's reader CPU is 2.1× lower than batched NFQUEUE's at 50 kpps for a plain resume (2.07–2.19×) and 2.0× lower with every packet modified (1.85–2.31×); at 20 kpps it is 1.55× lower for a plain resume (1.39–1.67×) and 1.41× lower with modification (1.28–1.50×).** Modifying costs under about 1.2 µs per packet on top of a plain resume in either approach. The VM had suggested a much smaller advantage and an expensive modification; the bare-metal runs replace that. The §12 gate (~1.5×) is met from about 50 kpps up, is borderline for a plain resume at 20 kpps (mean 1.55×, three of four runs at or above 1.5) and not met at 20 kpps with modification (mean 1.41×, never above 1.50); the robustness results (nothing lost on a crash, exactly-once, chaining, in-kernel checksums) come on top. See §12 "Phase 4 results".
- **Phase 5 (filter VM and sets): implemented, verified in a VM on 7.2.11 and by differential and fuzz testing in user space; not yet re-benchmarked on bare metal.** A handle's filter is now a verified bytecode program (`SET_PROGRAM`), produced from the engine's own WinDivert-style strings by the existing lexer, parser and DNF conversion; the old 5-tuple filter is now just a tiny program. The verifier and interpreter are one dependency-free header ([`swdivert_vm.h`](../kmod/include/swdivert_vm.h)) compiled into both the module and the user-space tests. 3 000 random filters × 120 random packets agree with an independent reference evaluator (0 mismatches); in the kernel, 2 × 5 000 random packets injected through the rig agree with the same evaluator (0 mismatches, all 10 000 reached the hook); 1.5 M fuzz iterations under ASan+UBSan found one real bug (fixed) and then nothing. The full VM suite is 114 checks, three runs in a row, clean. A typical server filter costs about 33–45 ns per packet in user space (an address set of 2 000 entries: 43–51 ns). See §12 "Phase 5 results" for what this does not show.
- **Phase 6 (backend integration): implemented; verified in a VM on 7.2.11 through the real `lagsw` binary and benchmarked once on bare metal (three runs): the backend as first built used 1.3–1.4× less reader CPU than NFQUEUE, below the ~1.5× gate that the raw reader met; the cause was found (a slow per-packet fingerprint, 0.77 µs of it) and fixed, and the repeat on bare metal shows the gate met from about 50 kpps (1.6–1.75× less reader CPU than NFQUEUE) and borderline-to-short at 20 kpps (1.3–1.4×, with large run-to-run scatter).** `backends/kmod/` implements `packet_backend.h` and is selected when `lagsw` is built (`xmake f --linux_backend=kmod`; no netfilter libraries needed). Serving a real engine took changes in the module: a handle now attaches to any of `LOCAL_IN`, `LOCAL_OUT` and `FORWARD` (the engine's normal client case is local traffic, which Phases 2–5 never hooked), packets owned by a socket can be held (the module keeps the socket alive), a handle's fail-open horizon and hold limit are set per handle, handles of equal priority coexist (the engine opens several at its default priority), and a packet a holding handle resumed is not held again at the handle's next hook (loopback traffic is delayed once, as with the NFQUEUE backend's release mark). 158 VM checks pass (three runs in a row; the 116 earlier ones plus 42 for the backend), covering input, output and forward traffic through `backend::open()/recv()/send()`, rewrites with the engine's own checksum helper at both local hooks, TCP in both directions through a held path, `kill -9` of the engine with socket-owned packets held, and the module load policy (insmod, modprobe, failure message, unload on exit). **The unmodified `lagsw` feature harness (`localhost_harness.py`, 107 checks: delays, batch release, drop, hold-until-deactivation with three concurrent connections, UDP, period, loopback release, ack restoration, eleven smoke profiles) gives 91/107 against the kmod build and 91/107 against the NFQUEUE build in the same VM, with the same 16 checks failing in both** (the harness' expectations of log text and of a pcap feature that this build does not have; not investigated further). See §12 "Phase 6 results".
- **Driver spec (planned, §8.5): the module will most likely move to its own repository and be renamed `lindivert`.** It will ship a driver spec (device, ABI, semantics) plus a small user-space library, so consumers never write raw `ioctl`/`read`/`write` calls. The spec gives the same functions as WinDivert with Unix/Linux/POSIX semantics and calling conventions. Spec only; nothing below the existing ABI (§8.1) has changed yet. In this document `swdivert` names the current in-tree PoC module and `lindivert` its planned successor.
- **Everything from §7 on that is not listed above is design only.** Nothing there is implemented or measured. Every number in §11 is a hypothesis to be confirmed or killed by the spikes in §12.
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
              │   mmap                                        ┌────────────────────────────┐
              ├── rx ring (SPSC, kernel→user) ◄───────────────┤ per-handle rx ring + stats │
              ├── tx ring (SPSC, user→kernel) ───────────────►│ per-handle tx ring         │
              └── ioctl: OPEN / SET_FILTER / SET_PARAM /      │                            │
                         KICK_TX / SHUTDOWN / STATS           │  hook ──► filter VM ──┐    │
                                                              │  (per layer, per prio)│    │
  netfilter hooks: PREROUTING/LOCAL_IN/FORWARD/LOCAL_OUT/POSTROUTING ◄────────────────┘    │
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
- **As built (Phase 6):** there is no dispatcher; every started handle registers its own netfilter hook for each layer it asked for (`SWDIV_OPEN_LOCAL_IN | LOCAL_OUT | FORWARD`, default FORWARD), all at the handle's priority, and netfilter orders them. That is simple and was enough for the handle counts of the engine (a handful); the "hundreds of entries" argument above is untested. The filter learns which hook it runs at from `SWDIV_SRC_HOOK`, and the compiler registers only the hooks a filter can match at (`outbound and ...` is `LOCAL_OUT` alone). `PRE_ROUTING` is not hooked.
- Direction and ifindex come from `state->in`/`state->out`, `Outbound` from the hook. Loopback packets are reported with `Outbound=1` once (as WinDivert does on Windows) by diverting only at `LOCAL_OUT` and marking the later `LOCAL_IN` pass as already-seen (§7.6).

### 7.3 Filter VM

- Source language: the WinDivert-style strings the engine already produces. `backends/nfqueue/filter_{lexer,parser,compiler}.cc` already parses that subset to a DNF; the kmod backend reuses lexer/parser and emits **bytecode** instead of nft rules. The kernel never sees text.
- Program format: a flat array of fixed-size instructions, forward jumps only (no loops, so termination is structural), max 4096 instructions, max 256 bytes of packet look-ahead per instruction.
- Operand sources: IP/TCP/UDP header fields (addresses, ports, protocol, flags, TTL, length), `outbound`, `loopback`, `ifindex`, `mark`, payload bytes at constant offsets (`tcp.Payload[i]`-style), and **set lookups**.
- Sets: the engine's server lists become `ipv4_set` and `port_range_set` objects uploaded with `SET_PROGRAM`. Implemented (Phase 5): a sorted array and binary search at every size (about 11 steps for 2 000 addresses, 51 ns per packet measured); an `rhashtable` was planned above 32 entries and is deferred, since the measured cost does not call for it yet. This keeps the cost of "match any of N servers" O(1) instead of the DNF clause explosion that motivated Change A of the eBPF PoC.
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
- Handles at the same priority are exclusive-filter by contract, identical to WinDivert; the module rejects `OPEN` of a second handle with identical `(layer, priority)` unless `allow_shared_priority=1`. **As built: dropped in Phase 6.** The engine opens several handles at its default priority (discovery, probes, the profile, the net monitor), so a second started handle of an equal priority is accepted; equal priorities are served in the order the handles were started, and an injected packet skips every handle of an equal or higher priority.
- Loopback: both `LOCAL_OUT` and `LOCAL_IN` see the same packet. The dispatcher marks a loopback packet as "already diverted at this handle" so it is reported once, as WinDivert does. **As built:** a holding handle that serves more than one hook claims one bit of the `skb->mark` pool `release_marks` (default the top byte, as the NFQUEUE backend does; a handle that finds none runs without the guard), sets it on every packet it resumes and ignores packets that carry it; the bit is masked out of the mark a filter sees. A sniffing handle sees loopback packets at both hooks, as an NFQUEUE sniffer does.

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
| `initialize()` (as built: `check_privileges()`, which runs after the options are parsed so `--help` never loads a module) | open `/dev/swdivert` and check `SWDIV_IOC_VERSION`; if the device is missing, load the module per §9.3; if that is not possible, an actionable error (`modprobe swdivert`, DKMS hint). A version mismatch is refused with both versions in the message. |
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

### 8.5 `lindivert` driver spec (planned)

The PoC module will most likely be pulled out into its own repository and renamed **`lindivert`** (module `lindivert.ko`, device `/dev/lindivert`, library `liblindivert`). The ABI in §8.1/§8.2 is a PoC sketch; `lindivert` turns it into a documented, versioned driver spec. This section is the intent; the spec itself will live in the new repository, and `backends/kmod/` becomes a consumer of the library like any other program.

**Goal.** Provide every function of WinDivert, with Unix/Linux/POSIX semantics and calling conventions. **Consumers must never write raw `ioctl`s or `read`/`write` calls on the device.** Those, and the mmap ring layout, are private to the driver and library, versioned by `abi`/`features` (§8.1), and may change between major versions. The supported surface is the library (and any language bindings built on it).

**Conventions (POSIX, not Win32).**

- A handle is a plain file descriptor (`int`), created `O_CLOEXEC` by default. It works with `poll`/`epoll`/`select`, `dup`, `fork` (the handle follows the open file description) and `close`.
- Errors: functions return `-1` and set `errno` (`EINVAL`, `EPERM`, `ENOENT`, `ENODEV`, `EAGAIN`, `EMSGSIZE`, `ENOBUFS`, `ESHUTDOWN`, `EPROTONOSUPPORT` for an ABI mismatch). There is no `GetLastError`. A filter syntax error is reported with a position and message through an out-parameter, as `HelperCompileFilter` does.
- Blocking follows POSIX: blocking by default, `O_NONBLOCK`/`LINDIVERT_NONBLOCK` returns `EAGAIN`, `EINTR` is honoured and `SHUTDOWN(RECV)` wakes readers with end-of-file semantics (0 / `ESHUTDOWN`), not a Win32-style error.
- Batching uses `iovec`-style arrays (as `recvmmsg`/`sendmmsg` do) instead of WinDivert's packed buffer. No overlapped I/O; asynchronous use is `epoll` plus non-blocking calls (an `io_uring` path is a later option).
- Privileges are Linux capabilities (`CAP_NET_ADMIN`, device node permissions; §9.2), not Administrator. Handles are per network namespace (§7.1).

**Function mapping (WinDivert to `lindivert`).** Names are provisional.

| WinDivert | `lindivert` (library) | Notes |
|---|---|---|
| `WinDivertOpen(filter, layer, priority, flags)` | `int lindivert_open(const char *filter, enum lindivert_layer, int16_t priority, uint64_t flags)` | Layers: `NETWORK` (in/out/forward, selected by hook as in §7.2) and the reserved ones; flags `SNIFF`, `DROP`, `RECV_ONLY`, `SEND_ONLY`, `NONBLOCK`, `CLOEXEC`. Compiles the filter, verifies it, then `SET_PROGRAM`. |
| `WinDivertRecv` / `RecvEx` | `lindivert_recv()` / `lindivert_recvmmsg()` | Reads from the rx ring; fills a `lindivert_addr` per packet (`ifindex`, direction, timestamp, flags, `mark`, layer/hook, checksum flags, slot id). |
| `WinDivertSend` / `SendEx` | `lindivert_send()` / `lindivert_sendmmsg()` | Inject, or resume with new bytes (`RESUME_MOD`); one kernel kick per batch. |
| (no equivalent) | `lindivert_resume()`, `lindivert_drop()` | Verdicts for held packets by id (§7.8); optional extension. |
| `WinDivertShutdown` | `lindivert_shutdown(fd, how)` | `RECV`, `SEND`, `BOTH`. |
| `WinDivertClose` | `close(fd)` | Fail-open on close, SIGKILL included (§9.1). No library call needed. |
| `WinDivertSetParam` / `GetParam` | `lindivert_setparam()` / `lindivert_getparam()` | `QUEUE_LENGTH`, `QUEUE_TIME`, `QUEUE_SIZE` with WinDivert's bounds and defaults, plus `OVERFLOW`, `HOLD_MODE`, `ONCLOSE`, and read-only `VERSION`/stats. |
| `WinDivertHelperCompileFilter` / `EvalFilter` / `FormatFilter` | `lindivert_compile_filter()` / `lindivert_eval_filter()` / `lindivert_format_filter()` | Pure user space, no device needed; the same lexer, parser and verifier header as the module (`swdivert_vm.h`). |
| `WinDivertHelperParsePacket`, `CalcChecksums`, address/byte-order helpers | `lindivert_parse_packet()`, `lindivert_calc_checksums()`, `lindivert_ntoh*`/`hton*` | Pure user space. |

**What the driver spec must define** (in the new repository):

1. Device node, naming, permissions, `udev` rule and module autoload (§9.3).
2. The stable-in-major-version semantics of each operation: hook points, loop avoidance, priority chaining, hold/fail-open policy, overflow policy, reinjection position, checksum handling, offload/GSO behaviour (§7.2–§7.7).
3. The private kernel/library ABI: ioctl numbers, structs (`abi`/`features`), ring header and slot layout (§8.1–§8.2), compat rules and the `features` bits that gate optional extensions. These are explicitly *not* a public API.
4. The filter language (WinDivert-compatible grammar plus Linux fields such as `ifindex` and `mark`) and bytecode format.
5. The error model above, the security requirements (§15) and the supported-kernel list (§10).

**Consequences for this PoC.**

- `backends/kmod/` should stop using `swdivert_abi.h` directly and call `liblindivert` once it exists; until then it stays the reference consumer of the PoC ABI.
- Rename (`swdivert` to `lindivert`: module, device, symbols, header guards, test scripts) is mechanical and happens with the repository split. Phase results in §12 keep the old name because that is what was measured.
- The module and library are versioned and released independently of `lagsw`; `lagsw` pins a minimum `lindivert` ABI.
- Open questions: whether to offer a C++ wrapper or only C; whether `lindivert_recv` should expose the mmap ring zero-copy (borrowed slot, explicit release) in addition to the copying form; and `io_uring` support.

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

- **Load (as built: in `check_privileges()`, after the options are parsed, so `--help` and config errors never touch the kernel; the design said `initialize()`):** only when `/dev/swdivert` does not exist and the process is root (loading needs `CAP_SYS_MODULE`, which a file capability for `CAP_NET_ADMIN` does not give).
  1. `modprobe swdivert` (installed module, Phase 7 packaging).
  2. Otherwise `insmod <path>` for a `.ko` given with `--kmod-path` (as built: the environment variable `LAGSW_KMOD_PATH`; the engine has no command-line flags for backend settings) or found next to the executable, so a development build works without installing.
  3. Otherwise fail with the instructions in §8.4. Without root, never attempt a load: print the `modprobe`/`insmod` command to run instead.
  - Loading goes through the `modprobe`/`insmod` programs (`kmod` userland), not an in-process `finit_module()`, so module signing, dependencies and the system's module policy (`modprobe.d`, lockdown) apply unchanged.
  - After loading, wait for the device node (udev can lag behind `insmod`) with a short bounded retry, then run the ABI check. An already-loaded module with a different ABI is an error; `lagsw` does not try to replace it.
  - `lagsw` records whether *it* loaded the module (for the opt-in below and for the log line "loaded swdivert (abi N)").
- **Unload: not by default.** Reasons:
  - The module is host-wide. Another `lagsw` instance, a container or another tool may hold handles, and `rmmod` of a module that is in use is refused by the kernel anyway.
  - Packets are already safe on exit and on crash: closing the device (normal exit, `SIGKILL`, kernel-side process teardown) runs the handle's `release()` which applies the on-close policy (§9.1). Leaving the module loaded does not leave any traffic diverted. An unload step could not run after a crash, so it would only add a second cleanup path that is not always executed.
  - Loaded but idle costs nothing: hooks are registered only while a handle exists (§14.5).
  - This differs from the NFQUEUE backend, which removes its own `inet lagsw` nft table on exit because that table belongs to the process alone.
- **Opt-in unload:** `--kmod-unload-on-exit` (as built: `LAGSW_KMOD_UNLOAD_ON_EXIT=1`) makes a normal exit (not a crash) run `rmmod swdivert` **only if this process loaded it**, after all its handles are closed; `EBUSY` is logged at debug level and ignored. Default off. A normal exit includes the `SIGTERM`/`SIGHUP` path used by the NFQUEUE backend.
- **Failure handling:** a failed load is a startup error (before any profile is activated), never a mid-run surprise. If the module disappears while running (manual `rmmod` is impossible while handles are open, so this means an unexpected kernel-side failure) the channels report `error` and the engine shuts down; there is nothing to fall back to at that point, and fail-open (§9.1) has already released held packets.
- **Auto-selection (Phase 6; not built: the backend is chosen when `lagsw` is built, `xmake f --linux_backend=nfqueue|kmod`, because `packet_backend.h` is one set of free functions per binary; a run-time choice needs a dispatching layer between the engine and two backends):** the backend choice kmod → nfqueue only prefers the module when it is already loaded or loadable (root and a `.ko`/installed module found) and the ABI matches; otherwise it falls back to NFQUEUE with a log line saying why. A load is never attempted just to probe.

## 10. Build, packaging and distribution

- **Build system (Phase 1, implemented).** Modules live under `kmod/` and are built by xmake through the rule `kmod.module` ([`kmod/xmake.lua`](../kmod/xmake.lua), helpers in [`kmod/modules/kbuild.lua`](../kmod/modules/kbuild.lua)):
  - A target is `add_rules("kmod.module")` + `add_files("*.c")` + optional `add_includedirs` and `add_values("kmod.defines", ...)` (not `add_defines`, which also carries the repository-wide `DEBUG`/`NDEBUG`); its output is `build/<plat>/<arch>/<mode>/<name>.ko`. See [`kmod/echo/xmake.lua`](../kmod/echo/xmake.lua).
  - The rule does **not** compile with xmake. It stages the sources into `build/.gens/<name>/.../kbuild/`, generates a `Kbuild` file there from the target (xmake is the single source of truth; there is no checked-in Makefile, which the repo's `.gitignore` would also exclude) and runs `make -C <kdir> M=<stage> modules`. kbuild therefore owns the compiler, flags, modpost, vermagic, BTF and (if configured) signing, exactly as DKMS will later. The root-level flags (`-Werror`, C++20, LTO, mode defines) never reach kernel code. xmake's built-in `platform.linux.module` rule was evaluated and rejected: it re-implements kbuild/modpost steps by hand and refuses the global `mode.*` rules this repository applies to every target.
  - Kernel selection: `xmake f --kmod_kdir=<dir>`, else `$KDIR`, else `/lib/modules/$(uname -r)/build`. The kernel, the target's sources and the build mode are inputs of the incremental check, so a different kernel triggers a rebuild.
  - **IntelliSense.** Project generators skip phony targets and only see what xmake itself compiles, so a module would be invisible to clangd (neovim) and cpptools (VS Code) and every kernel header would be "not found". The rule therefore takes the sources out of the target's file list (xmake must not compile them with the repository's flags), keeps the target a file-less `.ko` binary, and emits an explicit `gcc -fsyntax-only` command per source from `on_buildcmd`. That command's result is ignored during a build (kbuild is the judge); it exists so `xmake project -k compile_commands` records a compile command for each module source. The flags are a curated set (kernel include paths for the target architecture, `-include kconfig.h` and friends, `-D__KERNEL__ -DMODULE`, `CONFIG_CC_MS_EXTENSIONS` from the kernel `.config`), not the kbuild command line, whose gcc-only flags make clangd report errors. Checked with `clangd --check` on every module source: headers resolve and no diagnostics are reported. cpptools (VS Code) parses with the EDG front end, which lacks `__seg_gs` (x86 per-CPU variables) and `__typeof_unqual__` (`READ_ONCE`, `smp_load_acquire`) and reported false syntax errors on `__percpu`, `READ_ONCE` and `this_cpu_ptr`. The generated command therefore force-includes [`kmod/intellisense/edg_compat.h`](../kmod/intellisense/edg_compat.h) right after `kconfig.h`, which undefines the two `CONFIG_` options that select those features so the headers take their portable paths. It is never seen by kbuild. Not verified against cpptools itself (it cannot be run here): if more false errors appear, the fix belongs in that header. Without a prepared kernel tree no entries are emitted (the generator must not fail on machines without headers), so install the headers, then regenerate `compile_commands.json`. Header-only files (`kmod/include/*.h`) get no entry of their own; clangd infers one from the sources that include them.
  - Modules are **not** part of the default build (the target is `set_default(false)` and in the `kmod` group, and the headers of the target kernel may be absent). Use `xmake build swdivert_echo` or `xmake build -g kmod`. `xmake clean` removes the staging directory and the `.ko`. A missing or unprepared kernel tree is reported by a `before_build` check, so only real builds fail.
  - Integration test: `kmod/echo/echo.c` is a misc device that returns the last message written to it, with a version ioctl. [`tests/kmod_echo/`](../tests/kmod_echo/xmake.lua) is the user-space half and [`scripts/tests/test_kmod_echo.sh`](../scripts/tests/test_kmod_echo.sh) builds-checks, `insmod`s, runs it and `rmmod`s (root only; it cannot use a container because modules are host-wide). The shared ABI header `kmod/include/swdivert_echo_abi.h` is the pattern the real `swdivert_abi.h` follows (only `<linux/*.h>` uapi types, included by both sides).
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
- Added latency (p50/p99) at 10 k / 50 k / 100 k pps: **≤ half** of NFQUEUE's, measured with the same netns/veth rig as `scripts/tests/test_nfqueue_gateway.sh`.
- Idle overhead (module loaded, no handle open): **unmeasurable** against baseline (hooks registered lazily, only while handles exist; §14.5).
- CPU per packet at sniff: within **10 %** of `AF_PACKET` TPACKET_V3 on the same box.
- Maximum sustainable `delay × pps` before overflow, to compare directly with the eBPF/EDT tier's `fq` horizon limit.

WinDivert's own numbers are not a target, because they depend on Windows. The parity claim here is architectural (one copy each way, batching, in-kernel filter), and the measured claim is relative to NFQUEUE on the same hardware.

## 12. Phases and go/no-go

1. **Phase 1: kernel-module build system and echo module (done).** Add `kmod/` with the `kmod.module` xmake rule that drives kbuild, an echo module (`swdivert_echo`: a misc device that returns what was written, plus a version ioctl), a user-space test and a root-only load/test script (§10). Exit criteria: `xmake build swdivert_echo` yields a `.ko` for the selected kernel from a clean tree; incremental rebuilds are no-ops; a missing kernel tree gives a clear error; the default `xmake` build is unaffected; **and** `sudo scripts/tests/test_kmod_echo.sh` loads the module, passes all user-space checks and unloads it cleanly (met on 7.2.11). Every later phase builds on this rule, so it is first.
2. **Phase 2, Spike A: capture-only ring (done: functionally passes and matches AF_PACKET on sniffer CPU with a coarse wake-up, see "Phase 2 results").** Hook `FORWARD` on a veth netns gateway, filter by hard-coded 5-tuple, copy into an mmap ring, sniff only. Measure cost per packet against `AF_PACKET` and NFQUEUE sniff.
3. **Phase 3, Spike B: steal and resume (done: functional tests in a VM, one bare-metal benchmark; gate provisionally met, see "Phase 3 results").** Add `HOLD`, `RESUME`, `DROP`. Verify TCP continues, conntrack and NAT state unaffected, `bypass`-like fail-open on `kill -9`, and netns teardown with held packets.
4. **Phase 4, Spike C: modify and inject (done: VM tests plus one bare-metal benchmark, see "Phase 4 results").** `RESUME_MOD`, `INJECT`, checksum flags, priority chaining, loop avoidance. Re-running the existing engine test profiles through a `backends/kmod` stub needs the backend itself (Phase 6) and was not done.
5. **Go/no-go gate.** Compare against the §11 targets. If divert-and-resume is not at least ~1.5× faster than the batched NFQUEUE backend, **stop** and keep NFQUEUE + eBPF (record the numbers here).
6. **Phase 5: filter VM and sets (done: see "Phase 5 results").** Bytecode emitter from the existing lexer/parser, verifier, fuzz harness (syzkaller-style, plus a user-space harness that runs the VM on random programs/packets under ASan).
7. **Phase 6: backend integration (done, see "Phase 6 results"; build-time backend choice, environment variables for the load policy).** `backends/kmod/backend.cc`, xmake option, module load policy and `--kmod-path`/`--kmod-unload-on-exit` (§9.3), `--backend`/auto-selection order (kmod → nfqueue only when the module is loaded and ABI matches), README section.
8. **Phase 7: packaging.** DKMS config, module signing (MOK) and the Secure Boot story, `modules_install`.
9. **Phase 8: hardening.** KASAN/KCSAN/lockdep runs, netns churn, module reload under traffic, CPU hotplug, multiple handles with priority chains, kernel matrix.
10. **Optional:** `RESUME_AT` in-kernel hold, IPv6, multi-queue fanout (one ring per CPU/flow hash, relevant only if the engine's single-thread-per-channel model changes).

### Phase 6 results (backend integration)

**What exists**
- User space: [`backends/kmod/backend.cc`](../backends/kmod/backend.cc) (`backend::open/recv/send/send_batch/discard/validate_filter/monitor_status`), [`module.cc`](../backends/kmod/module.cc) (load policy), the Phase 5 [`filter_program.cc`](../backends/kmod/filter_program.cc) (now with the layers of a filter and `SWDIV_SRC_HOOK` tests), and [`xmake.lua`](../backends/kmod/xmake.lua) (`backend.kmod` rule, option `linux_backend`). What both Linux backends need is shared, not copied: the filter builders (`backends/nfqueue/filters.cc`) and `calc_checksums` (`checksums.cc`) moved out of the NFQUEUE backend's `backend.cc`, and the lexer, parser, DNF conversion and privilege check are linked from there as they are. New log groups `kmod`, `kmod.packet`, `kmod.filter`, `kmod.monitor`.
- A channel is one `/dev/swdivert` handle: 2048 slots of 4096 bytes (8 MiB), `HOLD` unless it sniffs, 60 s fail-open horizon, at most 16384 held packets (the NFQUEUE queue's length). `recv()` copies a slot out and releases it at once; a packet that is truncated, too big for the engine's buffer or not IPv4 is resumed unchanged and never shown to the engine. `send()` of an unchanged packet is `RESUME` (a hash of the bytes decides, as in the NFQUEUE backend, so the kernel keeps its offload state); changed bytes are `RESUME_MOD` without checksum flags, because the engine recomputes them with `calc_checksums()`. `send_batch()` is one ioctl for up to 4096 verdicts, in order. A verdict for a packet the module already released (horizon passed) is counted and logged, not an error.
- Module changes this needed (all in [`kmod/swdivert`](../kmod/swdivert)): layers per handle; socket-owned packets can be held (`sock` reference kept in the entry); `ip_route_me_harder()` for a changed destination at `LOCAL_OUT`, no re-route at `LOCAL_IN`; a rewritten packet gets `CHECKSUM_NONE` whatever its state was (a `CHECKSUM_PARTIAL` locally generated packet would otherwise have its checksum overwritten by the device: found by reading what `nf_queue` does, covered by the output-hook rewrite test, which checks the checksums on the wire); `hold_ms` and `max_held` per handle in `OPEN` (the ABI is still version 0); equal priorities allowed; the release mark.
- Tests: `swbench backend`, `backend-load` and `backend-api` (the real backend driven like the engine: open, receive, hold for N ms, rewrite, drop, batch release), 11 new VM tests in [`test_kmod_hold.sh`](../scripts/tests/test_kmod_hold.sh), a unit test for programs that span hooks, and [`test_kmod_localhost_vm.sh`](../scripts/tests/test_kmod_localhost_vm.sh), which runs the real `lagsw` and the existing localhost harness in the VM (`kmod_vm.sh --python` copies Python 3 and only the standard-library files the harness imports: 25 MB initramfs). `lagsw` loads the module itself there.

**Results (VM, 8 CPUs, slab poisoning on)**
- 158 checks, three runs in a row, no kernel log warning, module unloads with no reference left. Of them, for the backend: `backend-api` (16 cases: validation with positions, bad filters refused when opening, three channels of one priority open at once, the layers each filter listens at, closed channels answer); module loading (insmod path, modprobe path with the module installed into the VM, unload on exit only for a module this process loaded, a load failure is a startup error that names `modprobe` and `insmod`); output hook (2000 of 2000 seen as outbound, delay 20 ms applied, median latency 20.2 ms); input hook (same, as inbound); forward hook (a local filter sees none of the routed traffic, a forward filter all); all three at once in one channel (3000 seen: 2000 outbound, 1000 inbound); `outbound`/`inbound` filters pick one hook each; rewrite at the input hook (the stack accepts the engine's checksums, 1000 of 1000 on the new port) and at the output hook (1000 of 1000, 0 bad checksums on the wire); loopback (1000 seen for 1000 sent, delay applied once: 100.1 ms for a 100 ms hold); TCP of 4 MiB from and to this host through a 2 ms hold (intact; 4338 and 4514 packets through the engine, every one sent back, 0 errors); `kill -9` of the engine with 3 s of socket-owned packets held (2000 of 2000 arrived) and a sender that exits while its packets are held (1000 of 1000).
- Real `lagsw` against `profiles/localhost.test.sw.yml` (`localhost_harness.py`, unchanged except that it also accepts "batch resume" as the log line of a batch release): **91 of 107 checks, the same count as the NFQUEUE build in the same VM, and the same 16 failing**: 10 "smoke ... activated" checks, "batch verdict", "Exclusive: disabled Delay", "pcap files written" and three "discovery debug" checks look for log text or a feature (`pcap_files` is off in this build) that the current `lagsw` does not produce; they were not investigated, and since they fail identically on both backends they say nothing about the module. Every behavioural check passes on both: delay (a TCP connect plus echo takes 1.20 s under a 300 ms delay), batch, drop (the connection fails while held, recovers after), drop until toggle, hold until deactivation with three concurrent connections, UDP, period auto-deactivation, loopback released once (1.20 s for 4 packets at 300 ms), ack restoration, clean exit, no errors logged. After the run the module is still loaded (a normal exit never unloads it) with no open handle.

**What this does not show**
- **The backend's cost on bare metal is lower than the raw reader's advantage, and below the ~1.5× gate.** Three bare-metal runs of the new bench row, "lagsw backend (swdivert), verdict at once" (release builds, nothing lost in any, reader CPU in µs per packet, UDP forwarded through the rig, as in Phases 3 and 4):

  | | 20 kpps | 50 kpps |
  |---|---|---|
  | NFQUEUE, one verdict per packet (what the NFQUEUE backend's `send()` does) | 4.58, 4.27, 4.23 | 3.27, 3.18, 3.15 |
  | NFQUEUE, batched verdicts | 4.68, 4.88, 4.34 | 3.24, 3.04, 3.48 |
  | swdivert raw reader (`hold_wake_us=0`) | 3.29, 2.99, 2.73 | 1.51, 1.58, 1.47 |
  | **lagsw backend on swdivert** | **3.23, 3.63, 3.40** | **2.24, 2.45, 2.32** |
  | ratio, backend against NFQUEUE one verdict / batched (of the means) | 1.27× / 1.35× | 1.37× / 1.39× |

  Median latency is 9–10 µs against NFQUEUE's 11–12 µs and the p99 is 35–57 µs against 31–46 µs (one NFQUEUE batched run had a p99 of 2.4 ms and one swdivert run 552 µs; single outliers of that kind appear in every row). So the backend costs about 0.4 µs (20 kpps) to 0.8 µs (50 kpps) per packet more than the raw reader, which is where the Phase 3/4 advantage (1.5× at 20 kpps, 2.1× at 50 kpps over batched NFQUEUE) went. The raw reader sends its verdicts in one ioctl per drain; the backend's `send()` is one ioctl per packet, because the engine releases packets one at a time (only a flush uses `send_batch()`), and the tool adds a heap copy and a few allocations per packet, as the engine does. The modification rows are unchanged from Phase 4 for the raw reader (2.0–2.3 µs against NFQUEUE's 3.8–4.0 at 50 kpps). **The gate of section 12 therefore did not hold for the backend as first built, at either rate.**

  **Where the 0.4–0.8 µs went (diagnosed after that run).** Not the verdict ioctl and not copying: the backend fingerprints every packet with a byte-at-a-time FNV-1a in `recv()` and again in `send()` (to resume an unchanged packet as it is, and only a changed one as new bytes). Timed in user space on the development host (not the bare-metal bench machine), FNV-1a takes **384 ns for the bench's 228-byte packets** (84 ns at 64 bytes, 2.3 µs at 1240), so the two calls cost about **0.77 µs per packet**, the whole gap. The slot copy is 12 ns. The engine does not release packets one by one from its reader thread as the bench tool's inline path does: it hands released packets to a writer thread that calls `send_batch()` (`transmit_packets`), so the per-packet ioctl is not what the engine pays either, and batching verdicts or handing out several packets per `recv()` would not have addressed the cost (it is also why no such change was made).

  **Fix.** [`payload_hash.h`](../backends/kmod/payload_hash.h): four independent 64-bit lanes of 8 bytes per step instead of one byte per step, **26 ns for 228 bytes (15× less)**. A change to any 8-byte word always changes its lane's state, so a single edit is always seen; `vm_test` checks that flipping any single bit at any position changes the fingerprint for 18 packet sizes around every loop boundary (empty, 8/32-byte steps and their remainders, 1500, 9000), that a shorter or longer packet differs, that 200 000 random packets do not collide, and that it stays under 150 ns. The NFQUEUE backend has the same FNV-1a in both of its paths (the NFQUEUE rows above are the bench tool's own `nfq-hold` reader, which does not hash, so they are unaffected); it was left alone, and it would gain by the same change.

  **Re-measured in the VM (slab debugging off, so only the ratios mean anything; one run).** The backend row now sits 0.1–0.4 µs above the raw reader (5.81 against 5.18 µs at 20 kpps, 2.12 against 1.72 at 100 kpps), and a new row, "lagsw backend (swdivert), verdict at once, no tool copies" (`swbench backend --inline yes`: send straight from the receive buffer, so none of the tool's own per-packet allocations and copies are included), is level with the raw reader at 20 kpps (4.78) and 1.98 at 100 kpps. **Bare metal after the fix (three runs, release builds, nothing lost in any, reader CPU in µs per packet; the machine was noisier than in the first benchmark: NFQUEUE's 20 kpps figure drifted from 4.2–4.6 then to 4.8–6.7 now, so read the ratios, not the absolute numbers).**

  | | 20 kpps | 50 kpps |
  |---|---|---|
  | NFQUEUE, one verdict per packet | 4.78, 5.70, 6.72 (mean 5.73) | 4.13, 4.36, 4.15 (4.21) |
  | NFQUEUE, batched verdicts | 4.44, 5.39, 5.74 (5.19) | 3.93, 4.35, 3.54 (3.94) |
  | swdivert raw reader | 3.10, 3.62, 4.16 (3.63) | 2.91, 2.16, 1.67 (2.25) |
  | **lagsw backend** | 3.81, 4.60, 3.58 (4.00) | 2.57, 2.29, 2.38 (2.41) |
  | lagsw backend, no tool copies | 4.27, 4.67, 3.03 (3.99) | 2.60, 2.26, 2.00 (2.29) |
  | **ratio, one-verdict NFQUEUE / backend** (per run) | **1.43×** (1.25, 1.24, 1.88) | **1.75×** (1.61, 1.90, 1.74) |
  | ratio, batched NFQUEUE / backend (per run) | 1.30× (1.17, 1.17, 1.60) | 1.63× (1.53, 1.90, 1.49) |
  | modify every packet: NFQUEUE / raw reader (RESUME_MOD) | 1.38× (6.04 / 4.36) | 1.92× (5.08 / 2.65) |

  - **The fix worked where it was measurable: at 50 kpps the backend is now 0.16 µs above the raw reader (2.41 against 2.25; it was 0.82) and the gate is met against both NFQUEUE variants (1.75× and 1.63×, every single run above 1.49×).** The "no tool copies" row is level with the backend row (2.29), so the tool's own allocations were not what was left.
  - **At 20 kpps the result is not clear.** The mean ratio is 1.43× against one verdict per packet and 1.30× against batched verdicts, short of 1.5×, and the runs scatter too much to say more (1.17× to 1.88×; the backend-minus-raw gap is +0.71, +0.98 and −0.58 µs in the three runs, mean +0.37, against +0.42 before). At low rate both sides are dominated by the wake-up of an idle reader per packet, which swdivert pays as well, so the room for a reader-side improvement is small here. The raw reader's own advantage at 20 kpps (1.43× over batched NFQUEUE here, 1.55× in Phase 4) is the ceiling for any backend.
  - Latency stays lower: median 9–15 µs for the backend and the raw reader against 11–16 µs for NFQUEUE; the p99 and maxima are noisy in every row (single multi-millisecond outliers appear in all of them, NFQUEUE's included).
  - **Reading against the gate (section 12): met from about 50 kpps up for plain resumes through the backend (1.6–1.75×); borderline-to-short at 20 kpps (1.3–1.4×). The modification row is the raw reader's (1.9× at 50 kpps): the bench has no backend row that modifies, so that path is not measured through the backend.** That is the same shape as the Phase 4 verdict for the raw reader, one notch lower at low rate. Whether it justifies the out-of-tree cost remains the decision in section 16.

  The robustness advantages (nothing lost when the engine dies, exactly once, in-kernel checksums on the raw path) are unaffected.
- Only the harness' loopback and the veth gateway rig were used: no real NIC, no engine run on a gateway with `forward: true` (the forward path is covered through `swbench backend --forward`, not through `lagsw`), no IPv6.
- `ensure_module()` for a non-root process (the message that says which command to run) and the refusal of a module with another ABI version were not exercised; both are a few lines of straight-line code. A module reload while `lagsw` is running was not tried.
- Settings that the PoC document wanted as flags (`--kmod-path`, `--kmod-unload-on-exit`) are environment variables, and the backend is chosen at build time; a `lagsw` that falls back to NFQUEUE by itself needs a dispatching layer (section 9.3).
- A packet held longer than the horizon (60 s) is released by the module; the engine's delays are not capped, so a longer delay silently does not apply. 4 KiB slots mean packets above about 4000 bytes (loopback, jumbo frames) are never shown to the engine; a sniffing channel simply does not report them. The module's memory per channel is the ring (8 MiB) plus the held packets themselves.
- Phase 7 (DKMS, signing, packaging) and Phase 8 (KASAN, lockdep, netns churn, reload under traffic, a kernel matrix) are open, as are the security review and the go/no-go decision on the out-of-tree cost.

### Phase 5 results (filter VM and sets)

**What exists**
- ABI ([`swdivert_abi.h`](../kmod/include/swdivert_abi.h)): `SWDIVERT_IOC_SET_PROGRAM` takes an array of 16-byte instructions (`op`, `fail`, `src`, `k`, `a`, `b`) plus up to 64 sets (IPv4 addresses or port ranges). Limits: 4096 instructions, 65 536 elements per set, 2^20 in total, 256 bytes of packet prefix.
- Model: a program is a disjunction of clauses (what the DNF conversion already produces). Each instruction tests one field; on failure it jumps **forward** to the next clause (`fail`), on success it falls through; `ACCEPT` ends the program. Forward-only jumps make termination structural. A field that is absent (other protocol, a later fragment, a truncated header, an offset beyond the 256-byte prefix) fails every test, including `!=`, ranges and "not in set", so `udp.DstPort != 53` never matches a TCP packet, as in WinDivert.
- Kernel: [`prog.c`](../kmod/swdivert/prog.c) copies the program from user space, then verifies the copy (no TOCTOU), then installs it with an RCU pointer swap and frees the old one with `kvfree_rcu`; the hook builds the context from the skb's first 256 bytes and runs it. A filter can be replaced while a handle is started, with no packet seeing a mixture.
- User space: [`backends/kmod/filter_program.cc`](../backends/kmod/filter_program.cc) calls `linux_shared::compile_filter` (the shared Linux parser and DNF) and emits one clause per rule; address lists become shared sorted sets; a single address becomes an `EQ`/`NE`.
- Tests: [`tests/kmod_vm`](../tests/kmod_vm) (17 unit and differential tests, plus an ASan+UBSan fuzzer) and, in the VM, `filter_string`, `filter_set`, `filter_swap`, `filter_bad`, `vmcheck` and `progcheck` in [`scripts/tests/test_kmod_hold.sh`](../scripts/tests/test_kmod_hold.sh); the `fuzz` mode of `swbench` gained two program cases.

**Results**
- Differential, user space: 2 991 random filters, 358 920 comparisons against a reference evaluator written separately over the parsed tree: 0 mismatches.
- Differential, in the kernel (`vmcheck`): two seeds × 50 random filters × 100 random packets, injected through the rig and compared with the reference through the handle's `seen`/`matched` counters; every one of the 10 000 packets reached the hook (1 700–2 200 matched per seed, so both outcomes are exercised); 0 mismatches. The user-space VM agreed with the reference on the same packets.
- Fuzz, user space (ASan+UBSan): 1.5 M iterations over four seeds, about 1.3 M random or mutated programs of which about 6.5% pass the verifier, 8+ M runs on random packets: no sanitizer report, at most about 2 200 steps for one packet. The fuzzer found one real bug early on: `in_set` on an unknown set kind read the wrong array (now returns "not in set"; the verifier also rejects it).
- Kernel, `progcheck`: 29 cases through the real ioctl, each accepted or refused with the intended errno: jumps that do not go forward or leave the program, an unknown operation or source, a read offset beyond the prefix, an empty program, the largest program (4096) and one more, a set that does not exist, unsorted, duplicated, overlapping, reversed or out-of-range set contents, an unknown set kind, the largest set (65 536) and one more, sets adding up to exactly the total limit and to more, and bad calls (reserved field set, null or wild pointers giving `EFAULT`, absurd counts).
- Behaviour: a filter string with several ports, a negated port, a 201-address set that includes and excludes the destination, a negated set, a filter replaced every second under traffic (nothing lost, each program held its own port) and a bad filter refused by the compiler with a message and position: all pass.
- Regression: the 92 earlier checks pass through the VM path (the tuple filter is now a program), so 114 checks in total, three runs in a row, 8 CPUs, slab poisoning on, no kernel log warnings. The module builds clean with `W=1`.
- Cost in user space (same interpreter, `kmod_vm_test`): 33–45 ns per packet for a typical server filter (4 instructions, one set), 43–51 ns with a 2 000-address set, on this machine, under the build's default flags.

**What this does not show**
- The VM's cost **in the kernel on bare metal** was not measured; the user-space number is the interpreter only. The hook also pays for building the context and for `skb_header_pointer`. Compare against Phase 3/4 (the same `scripts/tests/test_kmod_hold.sh bench` run) before treating the gate numbers above as unchanged; the old hand-coded 5-tuple compare was cheaper than a program, even if only by tens of nanoseconds.
- Only IPv4, only the first 256 bytes, binary-search sets only (no `rhashtable`), no IPv6 sets, no `ifindex`/`mark`/`loopback` filtering beyond what the context carries today. Overflow policy and `PATCH`/outbound injection from Phase 4 are still open.
- The kernel verifier has been exercised by the fuzzer through the *same header* in user space and by 29 ioctl cases; it has not had a syzkaller run or KASAN (Phase 8).

### Phase 4 results (Spike C)

**What exists**
- [`kmod/swdivert/inject.c`](../kmod/swdivert/inject.c) (new: packet validation, checksums, `INJECT`) and additions to `hold.c` (`RESUME_MOD`, priority claim), `hook.c`, `main.c`; ABI in [`swdivert_abi.h`](../kmod/include/swdivert_abi.h): `SWDIV_V_RESUME_MOD` (the verdict item gained `data`, `len`, `flags`), `SWDIV_CALC_IP`/`SWDIV_CALC_L4`, `SWDIVERT_IOC_INJECT`, `swdiv_open_args.priority`, new statistics.
- Tools: `swbench` gained modification modes for the hold reader (`--modify payload|grow|shrink|dport|dst|tcp-flip|bad`), `--prio`, `--twin` (inject a copy of every held packet), `pktcheck` (verifies IP and UDP checksums of the packets as they arrive at the receiver; needed because veth can mark a received packet as already verified, so a UDP socket cannot tell) and `fuzz`. Tests: 26 new checks in [`scripts/tests/test_kmod_hold.sh`](../scripts/tests/test_kmod_hold.sh), run with `scripts/tests/test_kmod_hold_vm.sh`.

**How it works**
- **RESUME_MOD.** The user gives a whole IPv4 packet (up to 64 KiB); the kernel validates it (version 4, header and total length consistent; bytes beyond the IP total length are ignored) *before* taking the held packet, so bad bytes answer `EINVAL` and the packet stays held (and the timeout still releases it). The skb is linearised, un-cloned, resized and overwritten in place, checksums are recomputed on request (`CALC_L4` also resets offload state to `CHECKSUM_NONE`), and the packet continues after the handle's own hook. Receive-side checksum state that no longer describes the bytes is cleared.
- **What the new bytes contradict is adjusted, nothing more.** A changed **destination address** is routed again (`ip_route_input`) and the hooks after this one are told the new outgoing device; a changed **5-tuple detaches the connection-tracking entry** (`nf_reset_ct`), because its NAT mapping and state were made for the old tuple, so the rest of the path treats the packet as untracked (counted as `ct_detached`). A payload-only change keeps tracking and NAT intact. A failure here (no memory, no route) drops the packet (`mod_dropped`).
- **Priorities and chaining.** A handle has a priority in −30000…30000, higher served first, mapped to the netfilter priority (`INT_MIN + 30000 − priority`, ahead of every other FORWARD hook); two started handles of one namespace cannot share one (`EEXIST`). A resumed packet continues after the resuming handle's hook, so it reaches the lower-priority handles, with the modifications applied: handle B (served after A) held every packet A rewrote, and handle B served *before* A held none of them.
- **INJECT.** Builds an skb from the bytes, computes the checksums asked for and delivers it with `netif_receive_skb()` as if received on `ifindex`: PREROUTING, routing and, when it is forwarded, the FORWARD hooks. A per-CPU marker naming the injecting handle is set around that synchronous call; hooks of that handle and of handles served before it skip the packet, handles served after it see it. This is the loop avoidance, and it is **per CPU**: with receive packet steering the packet could be queued to another CPU, where the marker is not set. It was tested with receive steering off only.

**Test results (VM, 7.2.11, KVM, 8 vCPUs, `slub_debug=FZP`; 92 checks, three consecutive runs all green)**

| scenario | result |
|---|---|
| payload rewritten (every packet) | 4000/4000 delivered, all with the new bytes, **4000 verified good at the receiver**: 0 bad IP, 0 bad UDP checksums |
| grown (+100 bytes) / shrunk (to 64) | all delivered at the new length (300 / 64), all checksums good |
| TCP, 1 MiB, one byte per segment flipped | all bytes arrive (so the TCP checksum was right) and the stream differs; 736 segments modified, none dropped |
| the same through masquerade | arrives, the server sees the gateway's address, no tracking entry detached |
| destination rewritten to a third host | 2000/2000 routed again to the new host, 0 at the original, checksums good, tuple change counted |
| bad bytes in `RESUME_MOD` | refused (`EINVAL`) for every packet, packets stayed held and were released unmodified by the timeout |
| chain: A (100) rewrites the port, B (50) filters the new port | B held all 4000 rewritten packets; with the priorities swapped B held 0 |
| second handle with the same priority | refused with `EEXIST`; a different priority accepted |
| inject a twin of each held packet (matches the handle's own filter) | 2000 originals + 2000 twins delivered (4000), no duplicates, **the handle held only the 2000 originals** (loop avoidance), 2000 injections, 0 failed, checksums good |
| inject + chain | B (served after A) held the originals and A's twins: 4000 |
| modify + inject + timeout + kill racing (2 flows × 15 kpps, `hold_ms` = delay = 3 ms, reader SIGKILLed) | every original arrived, no duplicates |
| fuzz: 30,000 hostile `INJECT`/`RESUME_MOD`/verdict calls | 7656 accepted, 16484 `EINVAL`, 3864 `ENOENT`, 1996 `EFAULT`, **0 other**; no crash, nothing wedged, traffic and modification still work afterwards |
| unload / kernel log | reference count 0, `rmmod` succeeds, no BUG/WARNING/Oops/slab error |

**Cost with modification on bare metal** (the host the module is developed on, 8 CPUs, Linux 7.2.11, `veth`, 3 s per row, **release builds** of the module and of `swbench` (the earlier bare-metal tables used debug builds, so compare ratios within a table, not absolute CPU across tables), **four runs** (the first is the table below; the ratios and ranges that follow cover all four); UDP, 200-byte packets, one flow; every packet's payload rewritten and the checksums fixed; NFQUEUE hands the whole packet back and the engine recomputes the checksums in user space as `lagsw` does, the module takes the new bytes and a checksum flag; "reader CPU" is the reader process only and includes building the new packet, which is the same work in both). Run as root: `BENCH_PPS="20000 50000" scripts/tests/test_kmod_hold.sh KO SWBENCH bench`.

| mode | 20 kpps: p50 / p99 latency, reader CPU | 50 kpps: p50 / p99 latency, reader CPU |
|---|---|---|
| no hold (baseline) | 4 / 24 µs | 4 / 17 µs |
| NFQUEUE, one verdict per packet | 11 / 32 µs, 4.32 µs | 12 / 49 µs, 3.26 µs |
| NFQUEUE, batched verdicts | 12 / 36 µs, 4.58 µs | 13 / 66 µs, 3.42 µs |
| **swdivert, plain resume (`hold_wake_us=0`)** | **10 / 38 µs, 2.87 µs** | **8 / 57 µs, 1.56 µs** |
| swdivert, `hold_wake_us=50` | 58 / 87 µs, 2.25 µs | 57 / 92 µs, 1.22 µs |
| swdivert, `hold_wake_us=250` | 115 / 288 µs, 1.22 µs | 138 / 299 µs, 0.82 µs |
| **NFQUEUE, modify every packet** | 13 / 35 µs, **5.27 µs** | 16 / 44 µs, **4.29 µs** |
| **swdivert, modify every packet (`RESUME_MOD`)** | **11 / 55 µs, 4.11 µs** | **9 / 49 µs, 2.11 µs** |

The table is run 1. **In all four runs no row lost a packet, none of the eight modified rows delivered a packet with the wrong bytes, and the ring never filled.** Reader CPU of swdivert against NFQUEUE (the NFQUEUE figure is the batched-verdict variant; the one-verdict variant is within a few percent of it), ratio of NFQUEUE to swdivert over the four runs:

| | 20 kpps | 50 kpps |
|---|---|---|
| plain resume (`hold_wake_us=0`) | mean **1.55×**, 1.39–1.67 (sd 0.12) | mean **2.12×**, 2.07–2.19 (sd 0.05) |
| modify every packet (`RESUME_MOD`) | mean **1.41×**, 1.28–1.50 (sd 0.09) | mean **2.01×**, 1.85–2.31 (sd 0.22) |

Absolute reader CPU per packet in the four runs: swdivert plain 2.66–3.71 µs at 20 kpps and 1.56–1.68 µs at 50 kpps; NFQUEUE batched 4.41–5.14 and 3.37–3.56 µs; swdivert modify 3.47–4.11 and 1.99–2.24 µs; NFQUEUE modify 5.19–5.33 and 4.08–4.60 µs. Median latency (p50) over the four runs: plain resume 8–12 µs (swdivert) against 11–13 µs (NFQUEUE) at 20 kpps and 8 against 12–13 µs at 50 kpps; modify 10–11 against 12–13 µs at 20 kpps and 9–10 against 15–17 µs at 50 kpps.

- **Modification is cheap on bare metal**: it adds 0.4–1.2 µs to the module's plain resume in three of four runs at 20 kpps (the fourth run's plain-resume row was a slow outlier, 3.71 µs, which makes its difference negative) and 0.39–0.58 µs at 50 kpps, against 0.05–1.23 µs for NFQUEUE. The 4–5 µs the VM showed was VM overhead in the user-space work both sides share; discard the VM modify figures.
- **The advantage is largest at moderate rates and smallest at 20 kpps**, for plain resume as for modification: at low rates both spend most of their time in the sleep, wake-up and system-call cycle of one packet per round trip. Median latency is level to slightly lower at 20 kpps and about 35–45 % lower at 50 kpps.
- **Noise.** The 20 kpps rows move by up to 30 % between runs (run 3's plain resume was 3.71 µs against 2.66–2.87 in the others); the 50 kpps rows are tight. The p99 and max columns are dominated by single outliers and say nothing either way. Still one machine, `veth` rather than a NIC, one flow.
- **The overload behaviour seen in the VM was not reached here** (the ring never filled at 50 kpps). The VM result stands as a description of what the policy does when it does fill (packets pass unheld, i.e. unmodified: 3–4 % at 100 kpps in the VM, against NFQUEUE's 13–41 % loss and 180–300 ms of queueing), not as a measurement of where bare metal saturates.

Earlier, in the VM (4 vCPUs, no slab debugging; two runs, kept only for the overload behaviour above): modifying cost 4–5 µs more than a plain resume, the module was 1.14–1.46× cheaper than NFQUEUE at 20 kpps with modification, and at 100 kpps both overloaded.

**The go/no-go gate (§12 item 5), as it stands.** "At least ~1.5× faster than the batched NFQUEUE backend", measured as reader CPU on bare metal over four runs: **met at 50 kpps for both plain (2.12×) and modified (2.01×) resume with a clear margin; borderline at 20 kpps for plain resume (mean 1.55×, range 1.39–1.67, three of four runs at or above 1.5); not met at 20 kpps with modification (mean 1.41×, range 1.28–1.50)**, with median latency equal or lower everywhere. Whether the engine's real rates fall above or below the 20–50 kpps line is the open question: the profiles' packet rates were not measured here. On top of speed the module demonstrates, all measured: no held packet lost when the reader dies (NFQUEUE lost 1000 of 2000), exactly-once delivery under races, checksums fixed in the kernel, a priority chain, injection with loop avoidance, bounded behaviour under a fuzzer, and a defined overflow behaviour where NFQUEUE queues and drops. Still outstanding for a final decision: a real NIC and several flows, host-wide CPU including softirq (the reader-CPU figure leaves out the hook's own work), NFQUEUE as the real backend configures it, the engine's actual packet rates, and the costs of an out-of-tree module (Secure Boot, §10; maintenance, §14.7; a security review, §14.8, which this code has not had). **The evidence supports continuing; it does not show the module is faster at every rate. A user whose traffic is mostly below about 20 kpps per flow gets roughly a 1.4–1.6× CPU advantage plus the robustness properties, not a large speed-up.**

**Not done, known gaps**
- **A `PATCH` verdict** (offset, length, new bytes) that avoids sending and copying the whole packet both ways would remove most of the work NFQUEUE cannot avoid; it is the obvious way to make modification cheaper than the table above, and it is not built or measured.
- **Outbound injection** (leaving through an interface without PREROUTING and the FORWARD hooks) and every hook other than FORWARD; injection is inbound only.
- **Overflow policy `drop`**, the tx ring, GSO-aware injection (a super-packet injected as one is not segmented), IPv6.
- **The engine test profiles through a `backends/kmod` stub** (the plan's last item for this phase) need the backend, which is Phase 6 (done: the localhost harness runs through it, see "Phase 6 results").
- **Connection tracking after a 5-tuple change is detached, not rebuilt**: a packet whose tuple the engine rewrites loses NAT for the rest of the path. That is a deliberate, tested and counted choice, but it differs from WinDivert, which works below connection tracking and has no such interaction; an engine that rewrites addresses behind a NAT gateway must know.
- Loop avoidance with receive packet steering, several handles injecting at once, and routes that change while a packet is held are untested. The fuzzer ran one seed. Still VM only, no KASAN/KCSAN/lockdep, one kernel.

### Phase 3 results (Spike B)

**What exists**
- [`kmod/swdivert/hold.c`](../kmod/swdivert/hold.c) (new) plus changes in `hook.c`, `ring.c`, `main.c`; ABI additions in [`swdivert_abi.h`](../kmod/include/swdivert_abi.h) (`SWDIV_OPEN_HOLD`, `SWDIVERT_IOC_VERDICT`, slot `id`, more statistics; the slot header is now 48 bytes and `slot_bytes` a multiple of 16).
- Tools: [`swbench.cc`](../pocs/linux_kernel_module_backend/swbench.cc) gained `sniff --mode swdiv-hold|nfq-hold` (delay, drop-every-N, never-answer, batched verdicts for NFQUEUE), timestamped and sequence-numbered packets with latency, duplicate, reorder and corruption detection in the sink, and TCP send/sink tools. [`scripts/tests/test_kmod_hold.sh`](../scripts/tests/test_kmod_hold.sh) is the test driver (it builds its own client–gateway–server namespaces and can run on a real kernel as root), [`scripts/tests/kmod_vm.sh`](../scripts/tests/kmod_vm.sh) runs a script as root in a throw-away QEMU/KVM VM that boots the host's kernel image with an initramfs built from host binaries (no root, nothing installed, a panic is contained; boots in about 3 s), and [`scripts/tests/test_kmod_hold_vm.sh`](../scripts/tests/test_kmod_hold_vm.sh) ties them together: `xmake build swdivert swbench && scripts/tests/test_kmod_hold_vm.sh`.

**How it works (and where it differs from §7)**
- **Steal and resume.** The hook copies the packet into the ring and returns `NF_STOLEN`; the entry owns the skb, a copy of the `nf_hook_state` and a reference on each device. A resume runs the hooks that sort after this handle's (found by scanning the hook entries for this handle's hook; by priority if the hook is already gone) and then the original `okfn` (`ip_forward_finish`), under `local_bh_disable()` + `rcu_read_lock()`, which is what `nf_hook()` would have done. `nf_reinject()` is not usable because it needs the packet to have gone through `nf_queue()` and the one queue handler belongs to `nfnetlink_queue`. This answers §14.1 for the FORWARD hook (LOCAL_OUT and the others are not covered).
- **Exactly once.** Every exit (verdict, timeout, flush, device removal) goes through one function that removes the entry from an xarray under its lock, so a packet is resumed or dropped by exactly one party. An entry is marked `ready` under the ring lock just before its slot becomes visible and the hook never touches it or the skb afterwards, which makes it safe for another CPU to resume the packet while the hook is still returning. Entries that are not ready are never taken (a reader guessing an id gets `ENOENT`).
- **Fail-open.** Stop and close set a `closing` flag under the table lock (so no later packet can be held), resume everything while the hook is still registered, and only then unregister the hook. A reader that stops answering (hung, not dead) is covered by `hold_ms` (default 2000) and a limit `max_held` (default 4096) makes further packets pass unheld.
- **Devices.** A held packet pins its devices; a netdevice notifier drops the held packets of a device that is being unregistered instead of stalling the unregistration.
- **GSO.** Super-packets are segmented first (`skb_gso_segment`, as nf_queue does) and each segment is held on its own. The first version let them through unheld, which the TCP test caught: only 4 of about 2900 data packets of a 4 MiB transfer were held.
- **Verdicts by ioctl, not a tx ring.** `SWDIVERT_IOC_VERDICT` takes an array of up to 4096 `(id, verdict)` pairs and returns a status per item; the tx ring of §7.5 is deferred (an ioctl per drain was enough for the measurements below).
- **Wake policy.** Held handles do not batch the wake-up by default (`hold_wake_us=0`): batching adds its delay to every held packet one for one, and per-packet wake-up already costs 2–3× less CPU than NFQUEUE. Sniff-only handles keep the batched wake (`wake_us`, `wake_batch`). This answers the open question of Phase 2.
- Not held, passed through (counted): packets owned by a socket, packets without a refcounted route, segmentation failures. A segment that cannot be held while its siblings were (limit, full ring) continues at once, which can reorder a connection but loses nothing.

**Test results (VM: 7.2.11, KVM, 4–8 vCPUs, `slub_debug=FZP`; 46 checks, three consecutive runs all green)**

| scenario | result |
|---|---|
| resume at once | 4000/4000 delivered, every packet held and resumed once, no duplicates, no corruption, no reordering |
| 20 ms hold | 2000/2000 delivered, median latency 20.1 ms, order kept |
| drop verdicts (every 4th) | delivered = sent − dropped exactly |
| TCP, 4 MiB, 2 ms hold | intact (hash), 2915 segments held and resumed, 0 passed unheld |
| same through masquerade | intact, 2905 segments held, the server sees the gateway's address |
| reader SIGKILLed, packets held | **2000/2000 delivered**, no duplicates, module reference count 0 afterwards. Same test on NFQUEUE: **1000 of 2000 lost** |
| reader stopped (SIGINT), packets held | 1000/1000 delivered, 1000 counted as flushed |
| reader never answers, `hold_ms=300` | 500/500 delivered, median 318 ms, all counted as expired |
| `max_held=50`, reader never answers | 50 held, 1950 passed unheld, 2000/2000 delivered |
| device removed while packets held | `ip link del` returned in 14 ms, 503 held packets of that device dropped |
| 20 kpps hold and resume | 40,000/40,000, no duplicates, no corruption |
| races: 2 flows × 20 kpps, `hold_ms` = reader delay = 3 ms, reader killed mid-stream | 79,999/79,999 delivered, 0 duplicates, 0 corrupt |
| sniff-only handle (Phase 2 regression) | 99,998/99,998 captured and forwarded, 13,582 wake-ups for 99,998 packets |
| module unload / kernel log | reference count 0, `rmmod` succeeds, no BUG/WARNING/Oops/slab error (the slab cache is destroyed on unload, which reports leaked entries) |

**Divert-and-resume against NFQUEUE (the §11 comparison), first in the VM**: UDP, 200-byte packets, every matching packet held and released at once, one flow, 3 s per row, VM with 4 vCPUs and no slab debugging, two runs. "Reader CPU" is the user+system time of the reader process per packet; the resume itself runs in that process for both (in the verdict ioctl or in `sendmsg`), so the figures are comparable, but softirq time of the hook is not in them.

| mode | 20 kpps: p50 latency / reader CPU | 100 kpps: p50 latency / reader CPU / loss |
|---|---|---|
| no hold (baseline) | 8–9 µs | 4–6 µs |
| NFQUEUE, one verdict per packet | 23–33 µs / 6.6–9.0 µs | 63–384 µs / 5.4–6.0 µs / 0–0.43 % |
| NFQUEUE, batched verdicts (the shipped backend's way) | 22–24 µs / 6.5–6.7 µs | 85–3066 µs / 5.3–5.8 µs / 0 |
| **swdivert, `hold_wake_us=0`** | **19 µs / 3.98–4.09 µs** | **15–19 µs / 1.8–2.1 µs / 0** |
| swdivert, `hold_wake_us=50` | 67 µs / 3.3 µs | 63 µs / 1.3 µs / 0 |
| swdivert, `hold_wake_us=250` | 149–154 µs / 2.0–2.1 µs | 114–121 µs / 1.0–1.1 µs / 0 |

- **Reader CPU: 1.6× lower than batched NFQUEUE at 20 kpps and 2.7–3.0× lower at 100 kpps.** Median latency is similar at 20 kpps and far lower at 100 kpps, where NFQUEUE's median and tail rise (at 100 kpps its p99 was 8.8–101 ms in every row; swdivert's was 0.1–1.9 ms in four rows and 15–16 ms in two). **The tail figures of this VM are too noisy to use** (single outliers of milliseconds show up in every mode, the no-hold baseline included); medians and CPU are repeatable, tails are not.
- The batched-wake rows show the cost of batching on a held path: each 50 µs of `hold_wake_us` adds about 50 µs of median latency for a CPU saving of well under 1 µs per packet, hence the default of 0.

**The same benchmark on bare metal** (the host the module is developed on: 8 CPUs, Linux 7.2.11, `veth`, 3 s per row, **one run per row**, `sudo scripts/tests/test_kmod_hold.sh KO SWBENCH bench`; the VM is not involved):

| mode | 20 kpps: p50 / p99 latency, reader CPU | 100 kpps: p50 / p99 latency, reader CPU |
|---|---|---|
| no hold (baseline) | 5 / 96 µs | 4 / 40 µs |
| NFQUEUE, one verdict per packet | 13 / 62 µs, 5.43 µs | 18 / 70 µs, 3.28 µs |
| NFQUEUE, batched verdicts | 13 / 46 µs, 5.27 µs | 17 / 547 µs, 3.36 µs |
| **swdivert, `hold_wake_us=0`** | **11 / 101 µs, 3.65 µs** | **8 / 51 µs, 1.36 µs** |
| swdivert, `hold_wake_us=50` | 60 / 105 µs, 2.94 µs | 56 / 105 µs, 0.91 µs |
| swdivert, `hold_wake_us=250` | 122 / 302 µs, 1.72 µs | 119 / 300 µs, 0.64 µs |

Nothing was lost in any row (NFQUEUE did not lose packets at 100 kpps on this machine, unlike in the VM). Reader CPU of swdivert against batched NFQUEUE: **1.44× lower at 20 kpps, 2.47× lower at 100 kpps** (1.49× and 2.41× against one verdict per packet). Median latency: 11 vs 13 µs at 20 kpps (level), 8 vs 17 µs at 100 kpps (about half). The p99 columns are within each other's noise at this sample size (one NFQUEUE row has a 547 µs p99, the rest are 46–105 µs) and say nothing either way.

- The bare-metal ratios are **lower than the VM's** (NFQUEUE is cheaper here: 5.3 against 6.5 µs at 20 kpps and 3.3 against 5.5 at 100 kpps) but point the same way. Trust these over the VM figures.
- At 20 kpps both approaches spend most of their time in the sleep, wake-up and system-call cycle of one packet per round trip, which is why the advantage shrinks there: the module removes the netlink encode/decode and the second system call per packet, not the wake-up of the reader. A lower-rate advantage would need a different wake mechanism (for example the reader spinning briefly before it sleeps); this was not tried.
- The batching rows repeat the Phase 2 lesson on this machine: every 50 µs of `hold_wake_us` adds about 50 µs of median latency (60 and 122 µs against 11) for a saving of 0.7 and 1.9 µs of CPU per packet at 20 kpps. Default 0 stands.

**Against the §12 gate** ("if divert-and-resume is not at least ~1.5× faster than the batched NFQUEUE backend, stop"): **met at 100 kpps (2.5×), at the threshold at 20 kpps (1.44×, below 1.5 by a hair on a single run), and met on median latency.** That is enough to continue to Phase 4, not enough to call the gate passed. Still missing: (a) repeated runs and a spread (this is one run per row), (b) a real NIC and several flows, (c) the cost with **modification**, which Phase 4 has since measured on bare metal (modification adds under 1.3 µs and the advantage holds: 1.28× at 20 kpps, 2.03× at 50 kpps), (d) host-wide CPU including softirq, which this rig cannot separate from background load, and (e) NFQUEUE as the real backend uses it (`bypass`, fanout, GSO flags), not as `swbench` does. Also note that "reader CPU" excludes the softirq work of the hook itself (copy into the ring versus building a netlink message); that is the half of the cost the rig cannot see.

**Not covered / known gaps**
- Only the FORWARD hook. LOCAL_IN/OUT/PRE/POSTROUTING, locally generated packets (`skb->sk`, TCP small queues, §14.4), IPv6, bridged traffic and fragments are untested; sockets are simply not held.
- The module keeps a reference on the namespace of every open handle, so a namespace cannot be torn down while a reader keeps the device open (the "netns teardown with held packets" item of the plan is therefore only covered as "closing the handle releases them", not as a teardown race).
- NAT was tested for masquerade (SNAT) only, not DNAT; conntrack was only used by NAT, not inspected.
- Memory: held skbs are bounded by `max_held` per handle, not globally.
- The functional tests ran in the VM only (the real-hardware run covers the benchmark, the module reference count, unload and the kernel log, not the 46 checks; `sudo scripts/tests/test_kmod_hold.sh KO SWBENCH` runs those on the host too). One kernel, no KASAN/KCSAN/lockdep (the Arch kernel has none; `slub_debug` poisons and red-zones slab objects but not the vmalloc ring or page-level bugs). A KASAN/lockdep kernel run is still to do (Phase 8).
- The IntelliSense compat header was not re-checked in cpptools for the new file; clangd is clean on all four sources.

### Phase 2 results (Spike A)

**What exists**
- [`kmod/swdivert/`](../kmod/swdivert/xmake.lua) (`main.c` device/ioctl/mmap/poll, `ring.c` ring, `hook.c` hook and match, `swdivert.h`), target `swdivert`, built by the Phase 1 rule (the first multi-file module, which needed the rule to add the target directory to the include path). ABI: [`kmod/include/swdivert_abi.h`](../kmod/include/swdivert_abi.h), version 0 (not stable). User-space consumer: [`kmod/include/swdivert_ring.h`](../kmod/include/swdivert_ring.h).
- Flow: `OPEN` (ring sizing) → `SET_FILTER` (proto/addresses/ports, 0 = wildcard) → `mmap` ring (read-only) and consumer page (writable) → `START` (registers a FORWARD hook in the opener's netns at `NF_IP_PRI_FIRST`) → `poll()` + drain → `STATS` → `STOP`/close. Closing the file, including by SIGKILL, unregisters the hook (`nf_unregister_net_hook` waits for running callbacks) and frees the ring.
- Rig and tools: [`bench.py`](../pocs/linux_kernel_module_backend/bench.py) builds client, gateway and server as throw-away namespaces (rootless via `unshare -Urn`, or real root for `swdiv`), [`swbench.cc`](../pocs/linux_kernel_module_backend/swbench.cc) is the paced UDP sender, the sink and the three sniffers (swdivert ring, AF_PACKET TPACKET_V3 with an equivalent cBPF filter, NFQUEUE with an immediate `NF_ACCEPT` verdict). All three copy at most the same number of bytes per packet (`--snap`, default 224) from the IP header on and touch the data. Unit tests: `xmake test kmod_ring_test`. Root-side script: [`scripts/tests/test_kmod_sniff.sh`](../scripts/tests/test_kmod_sniff.sh).

**Deviations from the design (§7, §8)**
- The ring has **one lock-serialised producer side**, not SPSC: the FORWARD hook runs on every CPU, so concurrent producers must be serialised (`spin_lock_bh` around reserve, copy and publish). The reader side is still a single consumer. If the lock shows up in the profile, per-CPU rings are the next step.
- The consumer index is on its **own writable page**; the slots and producer count are mapped **read-only** (`VM_MAYWRITE` cleared). The kernel treats the consumer index as untrusted (a value beyond the producer count reads as "full"). This is the §13 "hostile ring indices" requirement implemented early.
- Wake-up: the first measured version woke the reader once per published packet (when it was asleep). The measurements below confirmed that was the main cost, so it was replaced by the batched wake of §7.4: the reader is woken after `wake_batch` packets (default 32) or `wake_us` microseconds (default 50) after the first unannounced one, whichever comes first, using one `hrtimer` per handle that is armed once (restarting it per packet would postpone the wake for as long as traffic keeps coming). A reader that is busy draining never sleeps and is not delayed. Both are module parameters, writable at runtime in `/sys/module/swdivert/parameters/`; `wake_us=0` gives the old wake per packet, which `bench.py` uses as `swdiv_legacy` for an A/B comparison. Cost of batching: a packet can wait up to `wake_us` before a *sleeping* reader sees it. That is irrelevant for sniffing but not for Phase 3, where held packets are released after a verdict: that path needs its own low-latency mode (or `wake_us=0`) and its latency must be measured.
- Only the IP packet is captured (no L2), truncated to `slot_bytes - 32`; `len` keeps the original length and a flag marks truncation. GSO super-packets are not segmented (§7.7 is not built).
- The handle holds a reference to the opener's network namespace, so a namespace with an open handle is not torn down until the handle is closed.
- No `HOLD`, no verdicts, no reinjection: this is the sniff path only, by design of the spike.

**Numbers (all sniffers, `sudo scripts/tests/test_kmod_sniff.sh --bench`: 8 CPUs, Linux 7.2.11, UDP, 3 s per run, median of 2, 224 bytes copied per packet; `swdiv_legacy` = wake per packet (`wake_us=0`), `swdiv` = batched wake at the defaults `wake_us=50`, `wake_batch=32`)**

Run 2, with the batched wake. The last column is not usable at this resolution: the baseline itself moves between 6.7 and 15.2 µs/pkt from row to row on this desktop machine (background load divided by the packet count), so deltas of ±5 µs are noise (several come out negative). Read the sniffer-CPU and batching columns, which are measured inside the sniffer and the module.

| mode | pps | payload | captured/sent | forwarded/sent | sniffer CPU µs per captured pkt | packets per `poll()` | packets per kernel wake-up |
|---|---|---|---|---|---|---|---|
| afpacket | 100k | 64 | 100 % | 100 % | 0.08 | 99.9 | - |
| nfq | 100k | 64 | 100 % | 100 % | 3.67 | 1.0 | - |
| swdiv_legacy | 100k | 64 | 100 % | 100 % | 1.80 | 1.1 | 1.1 |
| **swdiv** | 100k | 64 | 100 % | 100 % | **0.42** | 6.1 | 6.4 |
| afpacket | 200k | 64 | 100 % | 100 % | 0.07 | 200.5 | - |
| nfq | 200k | 64 | 74.1 % | 74.1 % | 4.82 | 1.0 | - |
| swdiv_legacy | 200k | 64 | 100 % | 100 % | 2.17 | 1.2 | 1.1 |
| **swdiv** | 200k | 64 | 100 % | 100 % | **0.28** | 12.2 | 13.0 |
| afpacket | 100k | 1200 | 100 % | 100 % | 0.09 | 99.9 | - |
| nfq | 100k | 1200 | 100 % | 100 % | 4.30 | 1.0 | - |
| swdiv_legacy | 100k | 1200 | 100 % | 100 % | 1.88 | 1.1 | 1.1 |
| **swdiv** | 100k | 1200 | 100 % | 100 % | **0.42** | 6.2 | 6.4 |
| afpacket | 200k | 1200 | 100 % | 100 % | 0.06 | 200.0 | - |
| nfq | 200k | 1200 | 85.6 % | 85.6 % | 4.17 | 1.0 | - |
| swdiv_legacy | 200k | 1200 | 100 % | 100 % | 2.12 | 1.1 | 1.1 |
| **swdiv** | 200k | 1200 | 100 % | 100 % | **0.29** | 12.2 | 12.7 |

(Run 1, per-packet wake only, gave swdiv 1.84–2.11 µs, the same as `swdiv_legacy` here, which shows the two runs are consistent. An earlier rootless run of AF_PACKET and NFQUEUE alone gave NFQUEUE 4.2–4.6 µs and 20–22 % forwarded-traffic loss at 200 kpps.)

What these say, and do not say:
- **Cause confirmed.** Wake-ups per packet went from ~1 to 6–13 packets per wake-up and sniffer CPU fell 5–7× (about 2.0 → 0.28–0.42 µs). The ring is now ~10× cheaper than the NFQUEUE sniffer in process CPU (0.3–0.4 vs 3.7–4.8 µs).
- **At the default `wake_us=50` it is still 4–5× AF_PACKET (0.06–0.09 µs), short of the "within ~2×" target; the sweep below shows the setting that closes it.** The batch is far below `wake_batch=32`: at 100 kpps a packet arrives every 10 µs, so the 50 µs timer collects ~5–6 of them (observed 6.4), and at 200 kpps ~10–13 (observed 13). The timer, not the batch size, sets the batch. TPACKET_V3 batches 100–200 packets per `poll()` here.
- **A simple model fits all four data points.** Reader CPU per packet ≈ 0.1 µs + 2 µs / N, with N the packets per wake-up: N=1.1 → 1.9 (observed 1.8–2.2); N=6.4 → 0.41 (0.42); N=12.7 → 0.26 (0.28–0.29); and N=200 (AF_PACKET's batch) → 0.11 (observed 0.07). That is a fit of two constants to four points, not a validated model, but it makes a testable prediction: to get within 2× of AF_PACKET (≲ 0.15 µs) the ring needs about **50 or more packets per wake-up**, i.e. `wake_us` of roughly 250 µs at 200 kpps and 500 µs at 100 kpps, with `wake_batch` raised accordingly (the default 32 would cap it). The cost is added latency for a sleeping reader of up to `wake_us`, which is fine for sniffing and is exactly the latency question Phase 3 has to answer separately.
- **Against NFQUEUE the ring is clearly better** on every axis measured: ~10× less sniffer CPU, and no loss of forwarded traffic where NFQUEUE lost 14–26 % at 200 kpps (its queue overflows and the kernel drops; `bypass` only applies when no listener is bound; the `dropped` column stays 0 because that overflow is silent for the listener).
- AF_PACKET remains the sniffing benchmark: a ring-based module cannot beat it by much, and what the module adds is the verdict/resume path (Phases 3–4). The go/no-go (§12) is still decided on divert-and-resume against NFQUEUE.
- The veth rig forwards at most a few hundred kpps on this machine and its generator is one thread; it says nothing about a real NIC. The kernel-side cost (hook, lock, copy, in softirq context) is not separated out by this rig; the host-wide column was meant to show it and is too noisy. `perf` or a quieter machine is needed if that number matters.

**Wake-up sweep (run 3, the prediction test; same conditions, 64 B payload, `swdiv@WAKE_US[:WAKE_BATCH]`)**

| mode | pps | captured/sent | sniffer CPU µs per captured pkt | packets per `poll()` | packets per kernel wake-up |
|---|---|---|---|---|---|
| afpacket | 100k | 100 % | 0.07 | 99.8 | - |
| swdiv@0 (wake per packet) | 100k | 100 % | 1.82 | 1.1 | 1.1 |
| swdiv@50 (the default, batch 32) | 100k | 100 % | 0.42 | 6.0 | 6.3 |
| swdiv@250:256 | 100k | 100 % | 0.16 | 22.6 | 26.6 |
| **swdiv@1000:256** | 100k | 100 % | **0.08** | 87.2 | 102 |
| afpacket | 200k | 100 % | 0.05 | 200.1 | - |
| swdiv@0 | 200k | 100 % | 2.09 | 1.1 | 1.0 |
| swdiv@50 | 200k | 100 % | 0.28 | 12.1 | 12.9 |
| swdiv@250:256 | 200k | 100 % | 0.10 | 46.0 | 53.1 |
| **swdiv@1000:256** | 200k | 100 % | **0.06** | 168 | 202 |

- **The prediction held.** More packets per wake-up gave proportionally less sniffer CPU, and at about 100–200 packets per wake-up the ring is level with AF_PACKET (0.08 vs 0.07 µs at 100 kpps, 0.06 vs 0.05 at 200 kpps). Within 2× of AF_PACKET (the acceptance target) is reached at `wake_us=250` / `wake_batch=256` at 200 kpps (0.10 vs 0.05, exactly 2×) and needs `wake_us=1000` at 100 kpps (0.16 at 250 µs is 2.3×).
- **The fitted model was slightly off.** Refitting two constants to the whole sweep gives about 0.05 µs + 2.0 µs / N (N = packets per wake-up); it under-predicts the middle of the range by up to ~0.06 µs (for example 0.37 predicted against 0.42 observed at N = 6.3) and fits the ends. It is an explanation of where the time goes (a fixed ~2 µs per sleep/wake/`poll()` cycle plus a small per-packet part), not a tool to extrapolate with.
- **Batches are limited by the timer when the batch size is large**: `wake_us` × packet rate gives the packets per wake-up (1000 µs at 200 kpps = 200, observed 202). Both parameters have to be raised together; the default `wake_batch=32` would cap a long `wake_us`.
- The host-wide column (not shown) was within its ±2–3 µs noise of the baseline for `swdiv@1000:256` at both rates, which is consistent with the kernel-side cost (hook, lock, copy) being small but cannot prove it on this rig.
- **Latency was not measured.** A sniffing reader that is asleep sees a packet up to `wake_us` late (up to 1 ms at the coarse setting). Nothing here says what that does to a path where a held packet waits for a verdict.

**Finding: NFQUEUE loses in-flight packets when its listener dies.** The SIGKILL check showed NFQUEUE forwarding 5999 of 6000 (reproduced rootless: 0–2 packets lost in about half of the runs, at 2 kpps). The kernel destroys the queue instance when the listener's socket closes and drops the packets still waiting for a verdict; `bypass` only covers packets that arrive afterwards. So the "fail-open" the shipped backend relies on has a small hole at the moment of a crash, which `AF_PACKET` and the swdivert sniff path do not have (they never hold the original). The held-packet path of Phase 3 must close this by design (§9.1: resume or drop every held packet on `release()`), and Phase 3's SIGKILL test should count exactly how many held packets are released. `bench.py` therefore allows up to 5 lost in-flight packets for NFQUEUE only and prints the number.

**Acceptance for Phase 2: met.**
- Functional: `swdiv` captured = sent and the decoy flow was not captured; SIGKILL of the reader left forwarding intact; the module reference count was 0 afterwards (`rmmod` works); no `dropped_full` at 200 kpps with 16384 slots; no BUG/WARNING/Oops in `dmesg` (this kernel has no KASAN/lockdep, so that says little about memory-safety bugs).
- Cost: clearly below NFQUEUE (about 10× lower sniffer CPU at the default, ~50× at `wake_us=1000`, and no loss of forwarded traffic) and within 2× of AF_PACKET at `wake_us ≥ 250` (level with it at 1000 µs). The default `wake_us=50` is 4–6× AF_PACKET; a sniffing user should raise `wake_us`/`wake_batch` together.
- **Open for Phase 3, not Phase 2:** the latency a sleeping reader sees (bounded by `wake_us`), and whether the release path of held packets needs its own wake policy (`wake_us=0` or an explicit "wake now" when a verdict is waiting). The default stays at 50 µs / 32 until that is measured.
- **Not covered by Phase 2:** other kernels, a real NIC, multi-flow traffic and several handles at once (one lock-serialised producer side is assumed to be uncontended in a single-flow rig; it is the first suspect if multi-flow throughput disappoints), GSO super-packets, and IPv6.

**Risk note.** The module is unreviewed kernel code. It has now run through the checks above without incident, but that is a few minutes of traffic on one kernel; keep running it in a VM or on a machine where a panic is acceptable. Phase 3 steals and re-injects real packets, which is riskier than sniffing: `scripts/tests/test_kmod_hold_vm.sh` exists so that it never has to be tried on a host first. It only sniffs (always `NF_ACCEPT`), so a logic bug should not break forwarding, but a memory-safety bug can.

## 13. Test plan

- **Build system:** `xmake build swdivert_echo` from a clean tree, no-op rebuild, rebuild after a source change, a different `--kmod_kdir`, missing kernel headers (error text), debug and release side by side, default `xmake` build unchanged, `sudo scripts/tests/test_kmod_echo.sh`.
- **Functional:** every existing engine verb through the real engine against the module (delay, batch, drop, hold, UDP, period, ack restoration, exclusivity, pcap, region enforcement), reusing `profiles/localhost.test.sw.yml` and the gateway scripts' structure (a `scripts/tests/test_kmod_gateway.sh`).
- **ABI:** version mismatch, truncated ioctl, hostile ring indices written by user space (the kernel must not trust producer/consumer indices from the user-writable page; keep authoritative copies in kernel memory).
- **Filter VM:** verifier rejection tests, differential tests against the nft backend's compiled output on the same pcaps (`pcap_files/`), fuzzing.
- **Module lifecycle (§9.3):** start as root with the module absent (loaded via `insmod --kmod-path`, then `modprobe`), start without root with the module absent (clear instruction, no load attempt), already loaded with matching and with mismatching ABI, device node appearing late, `--kmod-unload-on-exit` with and without a second process holding handles (`EBUSY` ignored), the module is left loaded by default, the unload flag does not unload a module this process did not load.
- **Failure:** SIGKILL with N held packets, `rmmod` attempt with open handles, netns deletion with a handle open, ring overflow (both policies), hold timeout expiry, `RESUME` of stale id, double `RESUME`.
- **Interaction:** with nftables rules at various priorities, conntrack + NAT, GSO/GRO on/off, `CHECKSUM_PARTIAL` skbs, loopback, VLAN and non-Ethernet links (`ARPHRD_NONE`), concurrent use with the shipped NFQUEUE backend on a different profile.
- **Performance:** §11 on the same rig as the NFQUEUE and eBPF measurements so all three are comparable.

## 14. Risks and open questions

1. **Resuming a stolen skb without being the nf_queue handler. Answered for FORWARD by Phase 3** (resume from the position after the handle's own hook, with a priority-based fallback; works with GSO segments, NAT and TCP, and holds up under timeout/verdict/kill races). Still open for the other hooks, in particular `LOCAL_OUT` (original text follows). The design uses `nf_hook_slow()` from a recorded index. Needs a spike to prove it is correct on `LOCAL_OUT` (where the hook is `NF_INET_LOCAL_OUT` and `okfn` is `dst_output`) and `FORWARD`, including when hook entries change between divert and resume. If it is not robust, the fallback is `CONSUME` + `INJECT` only (WinDivert's own model), at the cost of metadata and TCP small-queue behaviour.
2. **Hook priority vs conntrack/NAT.** Seeing the packet before or after NAT changes what addresses the engine filters on (the same issue as §7.5 of the eBPF PoC). Decide `early` vs `late` per hook after a spike with a masquerading gateway.
3. **Filter VM vs reusing BPF.** `bpf_prog_get_type()` + `bpf_prog_run` would give a JIT and a verifier for free, but the exported-symbol surface differs by kernel and config. The VM is chosen for independence; revisit if the VM is the bottleneck.
4. **TCP small queues and held skbs (reached in Phase 6: `LOCAL_OUT` holds socket-owned packets, the module keeps the socket alive; a 4 MiB TCP transfer through a 2 ms hold in both directions is intact, and a sender that exits while its packets are held is fine; long holds stalling a sender were not measured).** Holding an outbound skb keeps its socket's `sk_wmem_alloc`; long holds can stall the sender, which is the point for some verbs and surprising for others. `CONSUME` frees early and changes that behaviour. Needs measurement with the actual game flows (see the research notes) before choosing defaults.
5. **Lazy hook registration.** Registering netfilter hooks has a cost for *all* traffic (static key enabled). Register only while at least one handle for that layer exists; measure the idle overhead claim.
6. **Secure Boot and distribution** may make the module unusable for the likely end users (§10). Decide whether the module is only for gateway/lab deployments.
7. **Maintenance cost.** Netfilter internals change between kernel versions. The module should be small (target < 4 kLoC), have an explicit supported-kernel list, and CI against each.
8. **Security review.** Any out-of-tree kernel code that parses attacker-controlled packets and user-supplied bytecode needs a dedicated review (§15) before shipping.
9. **Multi-queue.** The engine reads each channel from one thread; per-CPU rings only help if that changes (compare the "fanout deferred" decision in the NFQUEUE PoC).
10. **Overflow policy.** When a held handle's ring is full the packet passes unheld (unmodified); NFQUEUE instead queues and then drops. For uses where a leaked packet is a failure the design's `drop` policy has to exist; it does not (Phase 4 finding).
11. **Connection tracking and rewrites.** A changed 5-tuple detaches the tracking entry (tested); engines that rewrite addresses behind NAT lose NAT for those packets. Decide whether that is acceptable or whether the module should instead refuse tuple changes on tracked packets.

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

Phases 1–4 are implemented, verified in a VM and benchmarked on bare metal. Over four bare-metal runs the speed gate is met from about 50 kpps (2.0–2.1×) and is at or just below the line at 20 kpps (1.55× plain, 1.41× modified; §12 "Phase 4 results"); the evidence supports continuing with Phases 5–8, with the decision on the out-of-tree cost (Secure Boot, maintenance, a security review) left to the project. Before relying on the numbers, measure the engine's real packet rates and repeat the benchmark on a real NIC with several flows. The module is justified only if it clearly beats the batched NFQUEUE backend on divert-and-resume latency and CPU while meeting §9's fail-open guarantee; otherwise the project keeps NFQUEUE plus the eBPF/EDT tier and this PoC is closed as "not worth the out-of-tree cost".
