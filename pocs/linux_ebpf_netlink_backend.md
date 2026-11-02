# PoC: A Better Approach on Linux to NFQUEUE and nftables

## 0. Implementation status

- Proposal only. Nothing here has been built or run. Every kernel-behaviour claim marked **(verify)** must be confirmed in the network-namespace harness (§12) before code is written.
- This **evolves** [`linux_nfqueue_backend.md`](linux_nfqueue_backend.md) and builds on [`linux_tc_netem_backend.md`](linux_tc_netem_backend.md), replacing netem's fixed parameters with per-packet logic. It keeps the shipped NFQUEUE backend as the stateful fallback and changes how it is installed and when it is used.
- The three changes (§1) are independent. Change A is useful on its own and is the recommended first phase (§13).

## 1. Summary

The shipped backend (`backends/nfqueue/`) has two structural costs:

1. **Rules are installed by spawning the `nft` binary** (`run_nft_impl` in [nft_table.cc](../backends/nfqueue/nft_table.cc)). That forces root, because a spawned `nft` does not inherit file capabilities ([privileges.cc](../backends/nfqueue/privileges.cc)); it forks per change; and because the process that owns the table exits immediately, nothing ties the table's lifetime to `lagsw`. After `SIGKILL` the table stays (the README tells the user to run `nft delete table inet lagsw`).
2. **Every matching packet makes a user-space round trip and is pinned in the kernel while it waits.** Delay is implemented as a delayed verdict, so memory and queue length scale with *delay × packet rate*, overflow drops or fails open, and the engine reads each queue from one thread ("Fanout ... deliberately not implemented" in the NFQUEUE PoC status). Most delay modes do not need the packet contents at all, only a release time.

This PoC proposes three changes:

| | Change | Removes |
|---|---|---|
| **A** | Program nf_tables **directly over netlink** (libmnl + libnftnl, one atomic batch) into a table with the `owner` flag, using sets instead of one rule per clause | the `nft` binary, the root-only restriction, stale tables after `SIGKILL` |
| **B** | A **tc eBPF + earliest-departure-time (EDT)** data plane for verbs that only need a release time or a drop (`passive_latency`, `from_timestamp`, `drop`, `send_all_after_delay`, probabilistic `drop_and_send`), plus a ring-buffer **copy** path for sniff/pcap | the user-space hop, the queue-length limit, and the "queue and immediately `NF_ACCEPT`" sniff |
| **C** | **NFQUEUE only for stateful verbs**, installed only while such a verb is active, with batched verdicts | idle-profile user-space cost; NFQUEUE as the default path |

Unlike the netem PoC, the delay is computed **per packet in BPF**, so `preserve_order`, `max_delay_ms` and the `uniform`/`normal` models map exactly instead of being listed as gaps (§8). The kernel still holds the packet, but in a qdisc, not in an NFQUEUE entry.

## 2. Terminology

- **EDT (earliest departure time)**: the packet's `skb->tstamp` is set to a future time and a time-aware qdisc (`fq`) does not transmit it before then.
- **tc eBPF / clsact**: a BPF program attached to a network device's tc ingress or egress hook, running per `sk_buff` (direct-action mode: it returns the verdict itself).
- **tcx**: the fd-owned tc attach point (Linux 6.6+). A tcx *link* is detached by the kernel when the last reference to its fd closes.
- **Owner table**: an nf_tables table created with `NFT_TABLE_F_OWNER` (`flags owner`). Only the creating netlink socket may modify it, and the kernel deletes it when that socket closes.
- **Stateful verb**: a delay mode whose release time is not known when the packet arrives (§9).
- Other terms are as in the two existing Linux PoCs.

## 3. Motivation

- Run as a normal user with file capabilities (`cap_net_admin`, `cap_bpf`, `cap_perfmon`) instead of root, apart from hotkeys, which still need `/dev/input` access.
- Make "process died" mean "traffic is untouched" without a watchdog, for both the rules and the shaping.
- Make activation a map write or one netlink batch, not a spawn.
- Stop paying user-space cost, queue-memory cost and netlink-verdict latency for packets whose fate is a timestamp.
- Give sniff/discovery/pcap a real copy instead of a delayed accept.

## 4. Goals

1. Replace the spawned `nft` with an in-process nf_tables netlink client that produces the same `inet lagsw` ruleset semantics, while keeping the `filter_compiler` front end (§6).
2. Prove that `passive_latency` (all models, both directions, `preserve_order`, `max_delay_ms`), `from_timestamp`, `drop` and `send_all_after_delay` run with no packets in user space (§7, §8).
3. Prove that killing the process with `SIGKILL` leaves no rules and no shaping behind on supported kernels, and define the degraded behaviour on older ones (§10).
4. Keep every profile that works today working: anything the BPF tier cannot do is routed to NFQUEUE by a static check at start-up, never silently approximated (§9).
5. Quantify the gain: CPU per packet, added-latency error, and maximum sustainable delay × pps against the shipped backend (§12).

## 5. Non-goals

- Replacing NFQUEUE for payload rewrite, `ack_restoration`, `hold_and_send`, `hold_until_deactivation`, `drop_until_toggle`, `packet_group_send`, region enforcement or anything needing a user-space decision per packet. They are the reason NFQUEUE stays.
- IPv6, VLAN and non-IP in the first iteration (the BPF parser and nft expressions extend naturally later).
- XDP. It runs before the stack, cannot set a delivery time that a qdisc honours, and cannot see locally generated egress.
- A general-purpose eBPF framework. One small, fixed set of programs is shipped.
- Managing an interface whose root qdisc the user configured (same refusal rule as the netem PoC §9.1).

## 6. Change A: native nf_tables control plane

### 6.1 What changes

`nft_table.cc` keeps its public surface (`ensure_table`, `add_channel_rules`, `remove_channel_rules`, `table_present`, `remove_table`) but is implemented on a long-lived `NETLINK_NETFILTER` socket owned by the process:

- Build messages with libmnl and libnftnl and send them as one batch (`NFNL_MSG_BATCH_BEGIN` ... `END`), which the kernel commits atomically, as `nft -f -` does today. Errors come back as netlink extended acks with the failing object, replacing "parse nft's stderr".
- Create the table with `NFTA_TABLE_FLAGS = NFT_TABLE_F_OWNER`. The kernel removes it when the socket closes, including on `SIGKILL` and a crash. This replaces the `TableGuard` destructor and the README's manual cleanup step. **(verify: owner flag, introduced around Linux 5.12; the `persist` companion flag is much newer and must not be used.)**
- The socket must stay open for the life of the process, which is only possible with an in-process client. A spawned `nft` would make the table vanish as soon as it exited, so A and the owner flag are inseparable.
- No `nft` binary at runtime, so `privileges.cc` no longer needs the ambient-capability check, and `setcap cap_net_admin` works.

### 6.2 Sets instead of clause explosion

Today `filter_compiler.cc` renders one rule per DNF clause per hook with addresses inlined. The renderer instead emits expression lists (not text) and moves repeated values into sets:

```
table inet lagsw { flags owner;
  set srv_p1 { type ipv4_addr . inet_service; flags interval; }   # elements added/removed by netlink
  chain ch1_forward { type filter hook forward priority -150; policy accept;
    ip saddr . tcp sport @srv_p1 queue flags bypass,fanout to 10-13 }
}
```

- A server-list change (profile switch, discovery result) is a set-element add/delete in one batch; no chain is rebuilt.
- Because expressions are constructed as structs, no user-supplied string is ever concatenated into a command. This is the same requirement as §11 of the NFQUEUE PoC, enforced by construction.
- `nfqueue_filter_test` keeps testing the compiler; it gains a second assertion layer that decodes the generated batch and compares it with the expected expressions. The existing text renderer stays as a debug dump (`--log-group nft.script`).

### 6.3 Interaction with C

Rules that queue (§8) are added only while a stateful verb is active and deleted on deactivation, in a single batch. With `bypass` they remain fail-open if the process dies while they are installed, and with the owner table they disappear entirely.

## 7. Change B: eBPF + EDT data plane

### 7.1 Architecture

```
  egress  (local out, and forwarded packets leaving a given interface)
  packet --> [netfilter, unchanged] --> tc egress (tcx) BPF --set skb tstamp--> fq --> NIC
                                              |
                                              +--> ringbuf (copy, optional)  --> lagsw (sniff / pcap / discovery)

  ingress to this host  (see §7.4)
  NIC --> tc ingress BPF --bpf_redirect--> ifb_lagsw --fq (tstamp honoured)--> stack
```

The program is small and fixed. User space owns the maps; it never sees a packet that does not need to be seen.

| Map | Contents |
|---|---|
| `cfg[dir]` (array) | active flag, mode, base delay, jitter, max delay, `preserve_order`, drop probability, batch-timer state |
| `servers` (LPM/hash) | IPv4 + port range → direction flags, built from the same `ProfileFilter` data the engine already has |
| `normal_cdf` (array, 256) | quantile table so `normal` needs no floating point in BPF |
| `last_release[dir]` (array) | last assigned release time, for `preserve_order` |
| `events` (ring buffer) | packet copies (headers + `snaplen`) for sniff |
| `stats` (per-CPU array) | matched, delayed, dropped, clamped, overflow: feeds the status line |

Profile activation or deactivation writes `cfg[dir].active`. Activation latency is a single `bpf_map_update_elem`.

### 7.2 Per-packet logic (egress)

```
parse Ethernet/IPv4/TCP|UDP; no match -> TC_ACT_OK (untouched, no timestamp written)
if !cfg.active                         -> TC_ACT_OK
if drop mode (or drop roll hits)       -> TC_ACT_SHOT
d   = model(cfg)                       # fixed | uniform(prandom) | normal(normal_cdf[prandom & 255])
t   = ktime_get_ns() + min(d, max_delay)
if preserve_order: t = max(t, last_release[dir]); atomic update last_release[dir]
bpf_skb_set_tstamp(skb, t, BPF_SKB_TSTAMP_DELIVERY_MONO)   # or skb->tstamp = t on older kernels
if sniff: bpf_ringbuf_output(events, header + snaplen)
return TC_ACT_OK
```

`fq` releases each packet at its `tstamp` and orders equal timestamps by arrival. This is what the engine already promises for `from_timestamp` ("Packets retain their receive order when release times match", README Delay modes). **(verify: ordering of equal and out-of-order timestamps within and across fq flows.)**

### 7.3 Why this closes the netem gaps

| netem PoC gap (§8 there) | This approach |
|---|---|
| `max_delay_ms` clamp: none | explicit `min(d, max_delay)` |
| `preserve_order: true`: jitter can reorder | `max(t, last_release)` |
| `preserve_order: false` | skip the clamp |
| `max_queued_packets`: different semantics | not needed for correctness; bounded by qdisc `limit` and `flow_limit` (§11) |
| `ratio` with `%`: probabilistic | exact per-batch counters in a map for count-based `ratio`; `bpf_get_prandom_u32` for `drop_and_send` percentages |
| `send_all_after_delay`: not supported | map stores the batch deadline: the first packet sets `deadline = now + delay_ms`, every packet in the batch gets `tstamp = deadline` |
| sniff/pcap: not supported | ring-buffer copy |

### 7.4 Inbound traffic

- **Gateway (forward):** classify on the egress of the interface the traffic *leaves* (`-o lan0` for server→client, `-o wan0` for client→server). No ifb, same as netem PoC §6.3, and the primary use case in the NFQUEUE PoC §14.
- **Local host inbound:** tc ingress runs before netfilter, and delaying delivery to the stack needs a queue. The proposed path is tc ingress BPF → `bpf_redirect` to an `ifb` device with `fq` as its root qdisc. **(verify: that `fq` on an ifb honours a delivery time set at ingress; kernels differ in how `skb->tstamp` is treated when ingress sets it as monotonic.)** If it does not, fall back to `netem` on the ifb for local inbound (the netem PoC's exact mechanism), with the §9 mode limits, or keep local-inbound profiles on NFQUEUE.
- **Forwarded packets across namespaces or interfaces:** the delivery time is cleared on forward on old kernels. The `bpf_skb_set_tstamp` / `tstamp_type` support that preserves it is from Linux 5.18; below that the program must stamp at the final egress device. **(verify.)**

### 7.5 NAT and address visibility

tc egress runs after the netfilter `POSTROUTING` hook and tc ingress before `PREROUTING`. With NAT on a gateway the client address seen by BPF is the translated one on the WAN side. Server addresses are unaffected. `client_address_enforcement` is therefore resolved per attach point: LAN-side programs match LAN client addresses, WAN-side programs match the translated address (or the match is dropped and a warning logged). The nft/NFQUEUE path keeps its current semantics.

### 7.6 Sniff and discovery

The ring buffer gives a true copy with no verdict wait, replacing the NFQUEUE PoC §8.4 default (queue + immediate `NF_ACCEPT`) and the `libnetfilter_log` alternative. It carries an interface index, direction and a timestamp, so `PacketMeta` is fillable. pcap export uses the same records. Records are dropped, with a counter, if user space falls behind; sniff consumers must tolerate loss, which a WinDivert sniff handle also does.

### 7.7 Offloads

tc sees GSO/GRO super-packets and `fq` shapes them as one unit, then segmentation happens at dequeue. Delay is correct without disabling offloads. Only per-packet drop probability and the ring-buffer record size are affected by super-packets. The `ethtool -K ... gro off gso off tso off` requirement in the NFQUEUE PoC §8.5 stays only for NFQUEUE payload rewrites.

## 8. Change C: narrow and speed up NFQUEUE

1. **Install on demand.** The queue rule exists only while a stateful verb is active (§6.3). Idle profiles cost nothing. **(Confirm how the engine opens and holds channels today before committing to this.)**
2. **Pre-filter in the kernel.** The nft rule is the DNF match plus, where possible, TCP flag matches (for example excluding bare ACKs unless `ack_restoration` is on, as `ProfileFilter::include_bare_acks` already allows), so fewer packets reach the queue.
3. **Batched verdicts.** `NFQNL_MSG_VERDICT_BATCH` accepts or drops every queued packet up to an id with one message. Releases that are a plain accept (`hold_until_deactivation`, `hold_and_send` flush) become one syscall. It does not apply to packets with modified payload.
4. **Fanout, per flow.** `queue flags fanout` with a flow hash keeps per-flow order. The engine currently reads each channel from one thread and some modes depend on cross-flow order, so this stays deferred until §12 measurements justify it, as before.
5. **Verdict mark.** Reinject with `NFQA_MARK` set to a reserved value and add `meta mark ... return` to the queue chain so a released packet cannot be re-queued by a lower-priority rule of the same table.

## 9. Mode routing

Each profile and the passive-latency feature are classified at start-up. A profile runs on the BPF tier only if **every** mode and option it uses is in the "BPF" column; otherwise it uses NFQUEUE as today. Mixed profiles are not split.

| Feature | Tier | Notes |
|---|---|---|
| `passive_latency` fixed / uniform / normal, per direction, `preserve_order`, `max_delay_ms` | **BPF** | exact |
| `from_timestamp` | **BPF** | `tstamp = rx time + delay_ms` |
| `drop` | **BPF** (`TC_ACT_SHOT`) | |
| `send_all_after_delay` | **BPF** | batch deadline in a map |
| `ratio` (count) | **BPF candidate** | needs the per-interval release schedule expressed as timestamps; **(spike)** |
| `drop_and_send` | **BPF candidate** | percentage drop plus delay; batch-exact variant needs counters; **(spike)** |
| `hold_and_send`, `hold_until_deactivation`, `drop_until_toggle`, `packet_group_send` | **NFQUEUE** | release time is decided by a later key press |
| `ack_restoration`, `subsequent_packet_hold_mode`, payload rewrite | **NFQUEUE** | needs packet contents and checksums |
| Region enforcement (SYN/PSH probes) | **NFQUEUE** | per-packet user-space verdict; a later iteration can use a BPF drop flag keyed by server |
| `capture_options.sniff`, discovery, forwarded-address discovery, pcap | **BPF ring buffer** | copy, no verdict |
| `capture_options.forward` | both | forward = egress program on the outgoing interface (§7.4) |
| Desync countdown | unchanged | depends only on active duration |

A profile asking for a BPF-tier feature on a system that cannot load the program (kernel, capability, missing `fq`) falls back to NFQUEUE with a logged reason, never to an approximation. A new option, `linux_tier: auto|nfqueue|bpf` (default `auto`), allows forcing either for comparison and bug reports.

## 10. Lifecycle, failure and privileges

### 10.1 Ownership

| Object | Owner / cleanup on `SIGKILL` |
|---|---|
| nf_tables table `inet lagsw` | owner socket; **kernel deletes it** (Linux 5.12+ **(verify)**) |
| BPF maps and programs | fds held by the process; freed by the kernel |
| tcx links (Linux 6.6+) | fd-owned; **kernel detaches them** |
| `cls_bpf` filters via netlink (Linux < 6.6) | **persist** after exit: cleanup needs a watchdog (netem PoC §9.3) or documented one-line command |
| `fq` root qdisc and `ifb_lagsw` | persist; harmless when no timestamps are set, but they replaced the interface's previous root qdisc. The previous qdisc is recorded and restored on orderly exit; refuse to start if the existing root qdisc is not one of `noqueue`, `pfifo_fast`, `fq_codel`, `mq`, `fq` |

Pinning BPF objects to bpffs is **not** done, precisely so lifetime follows the process. Start-up removes any stale `inet lagsw` table and any stale `cls_bpf` filters with the program name `lagsw_*`, by name.

### 10.2 Failure behaviour compared with today

| Event | Shipped NFQUEUE backend | This proposal on Linux 6.6+ |
|---|---|---|
| Orderly exit / `SIGTERM` | table removed | table removed, links closed, qdisc restored |
| `SIGKILL` / crash | `bypass` keeps traffic flowing; empty table remains | table and links disappear; only a zero-effect `fq` remains |
| Process hangs (not dead) | packets queue, then overflow to accept | EDT packets keep being released on time; in-flight NFQUEUE packets as today |

On kernels without tcx, `SIGKILL` leaves the `cls_bpf` filter attached. The program keeps its map references, so the last `cfg` state stays in force and **delay persists** until the filter is removed. That is the same sticky behaviour netem has, and the same mitigation applies (netem PoC §9.3: a detached watchdog that removes the filters when the parent pid disappears). The alternative is to require 6.6+ for the BPF tier; the spikes weigh the two. **(open question 3.)**

### 10.3 Privileges

| Need | Capability |
|---|---|
| nf_tables, NFQUEUE, tc, ifb, `fq` | `CAP_NET_ADMIN` |
| Load BPF programs and create maps | `CAP_BPF` (5.8+), plus `CAP_PERFMON` on kernels where the verifier needs it for the helpers used **(verify)** |
| Hotkeys | `/dev/input/event*` access (`input` group or root), unchanged |

With A in place there is no spawned helper, so `check_privileges` reduces to "effective `CAP_NET_ADMIN` (+ `CAP_BPF` for the BPF tier)". Payload rewrites through NFQUEUE still need the init user namespace, as the existing status notes.

## 11. Capacity limits to document

- **fq horizon.** `fq` drops or clamps packets whose delivery time is further than its `horizon` away (default 10 s **(verify)**). Profiles allow delays up to 600000 ms ([passive_latency.md](passive_latency.md)). The attach step raises `horizon` to at least `max_delay_ms` plus margin, or rejects the profile on the BPF tier with a clear message.
- **fq limits.** `limit` (total packets, default 10000) and `flow_limit` (per flow, default 100) must be raised to cover *delay × packet rate*; overflow drops, as NFQUEUE's queue length does today. Exposed in `stats` and in the status line (where `nfqueue` health is shown now).
- **Clock.** The program uses the monotonic clock (`bpf_ktime_get_ns`); `from_timestamp` uses the packet's receive time only where the kernel provides it in monotonic form, otherwise "now".

## 12. Test plan

Reuse the privileged-container / network-namespace pattern of `scripts/test_nfqueue_localhost.sh` and `scripts/test_nfqueue_gateway.sh`, with a new `scripts/test_ebpf_*.sh`. Phase 1 (§13) is manual shell, no C++ changes.

### Functional
- **A:** `nft list ruleset` shows the table with the `owner` flag; the same localhost and gateway suites pass with `cap_net_admin` only and no `nft` in `PATH`.
- **B delay accuracy:** with `fixed 120ms` the RTT rises by 120 ms per configured direction; `uniform` and `normal` match the configured mean and stddev over 1000 samples; compare with the NFQUEUE backend and netem.
- **B ordering:** a sequence-numbered UDP stream with jitter: zero reordering with `preserve_order: true`, observed reordering with `false`.
- **B clamp:** no packet exceeds `max_delay_ms`.
- **B drop and `send_all_after_delay`:** counts and release instants.
- **B sniff:** the ring buffer sees every matched packet; counters show loss under overload; pcap output opens in Wireshark with correct timestamps.
- **Unlisted traffic:** never given a timestamp (`tcpdump` timing unchanged).

### Topology
- Host-local egress; host-local inbound through ifb; gateway with and without NAT (§7.5); forwarded traffic across veth/netns (§7.4).

### Failure
- `SIGKILL` on kernels ≥ 6.6: table and links gone, traffic unaffected. On 5.x/6.x without tcx: record whether delay persists.
- `SIGTERM`: all objects removed, previous root qdisc restored.
- Stale objects from a prior run are replaced by name.
- Overflow: lower the `fq` limits and send at high rate; counters report drops, no stall.

### Performance
- CPU per packet and added-latency error against the NFQUEUE backend and netem at 10k/50k/100k pps, and the maximum *delay × pps* before drops. This is the number that decides whether B is worth shipping.
- Activation latency: BPF map write versus an nft batch versus a spawned `nft`.

## 13. Phases

1. **Spikes (shell + `bpftool`/`tc`, no C++):** answer every **(verify)** item: fq horizon and ordering, ifb + fq inbound, `tstamp` preservation on forward, `owner` table on target kernels, tcx versus `cls_bpf` cleanup. This decides whether B proceeds.
2. **Change A:** libmnl/libnftnl client behind the existing `nft_table.h` interface, set-based renderer, owner flag, privilege-check simplification, `setcap` docs. Delivers value even if B is abandoned.
3. **Change C:** on-demand queue rules, pre-filter, batched verdicts, verdict mark.
4. **Change B (egress, gateway first):** BPF program, maps, tcx attach, `fq`, mode routing and fallback, `stats` in the status line.
5. **Change B (local inbound, sniff ring buffer, pcap).**
6. **Packaging/docs:** xmake option, README Linux section, capability and kernel-version table.

## 14. Build and packaging

- `backends/nfqueue/` gains `netlink/` (libmnl, libnftnl) and `bpf/` (`lagsw.bpf.c`, built with clang `-target bpf -O2 -g` and embedded as a skeleton via libbpf/`bpftool gen skeleton`). Linux-only; Windows sources are untouched.
- The BPF object is built at **package time** and embedded, so end users need neither clang nor kernel headers. CO-RE (BTF) is used so one object runs across kernels; kernels without BTF use the NFQUEUE tier.
- xmake: `--linux_tier=nfqueue|auto` (default `auto`; `nfqueue` omits all BPF sources and libbpf, giving today's footprint plus Change A).
- Runtime: kernel modules `nf_tables`, `nft_queue`, `nfnetlink_queue`, plus for B `sch_fq`, `cls_bpf`/tcx, `ifb`, `act_mirred`, and `CONFIG_BPF_SYSCALL`, `CONFIG_DEBUG_INFO_BTF`.
- Minimum versions (proposal, to be fixed by the spikes): A: kernel ≥ 5.12; B: ≥ 5.18, with the cleanest lifecycle at ≥ 6.6. Older kernels are served by the shipped backend unchanged.

## 15. Security and correctness requirements

- Verify every netlink and ring-buffer record length before parsing; never trust sizes from the kernel or a map.
- The BPF programs are loaded through the verifier with no `unprivileged_bpf_disabled` bypass; they hold no secrets and expose no pinned objects, so another local user cannot read or change maps.
- No shell, no `system()`, no string concatenation into nft; everything is built as typed objects (§6.2).
- Only addresses, ports and interface names that passed the existing filter validation reach the maps and expressions.
- Never touch another table, qdisc filter or BPF program not named `lagsw_*`.
- Use only on traffic the operator is authorised to intercept, as for the existing backends.

## 16. Open questions

1. Is the gateway the primary use case? If so, local-host inbound (ifb) can be dropped from B, removing the riskiest spike.
2. What is the minimum kernel? Requiring ≥ 6.6 for B gives clean `SIGKILL` semantics and one attach method; ≥ 5.18 widens support but needs a watchdog and a netlink attach path.
3. Is a keep-alive/watchdog acceptable on kernels without tcx, or is "B requires tcx" the rule?
4. Does the engine keep channels open for idle profiles today? If so, §8.1 is a larger win than assumed; if not, it only formalises current behaviour.
5. Do `ratio` (count) and `drop_and_send` map to timestamps exactly enough to stay on the BPF tier, or are they NFQUEUE-only? Decide after the §13 spike.
6. Is fq's horizon cap acceptable, or do delays above it (up to 600 s) always fall back to NFQUEUE?
7. Is fanout worth enabling for the stateful tier once idle cost is gone, or does the single-thread-per-channel read model stay?
