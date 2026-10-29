# PoC: Linux Packet Backend via nftables + NFQUEUE

## 0. Implementation status

- Phase 1 (interface extraction): done. `include/packet_backend.h` is the seam; `PacketChannel::discard()` maps engine drops to `NF_DROP`.
- Phase 3 (full verbs): done. `scripts/test_nfqueue_localhost.sh` runs `profiles/localhost.test.sw.yml` through the real engine in a privileged container (96 checks: delay, batch, drop, hold, UDP, period, ack restoration, exclusivity, pcap, every other profile, clean table removal). It found that `ack_restoration` tracked one ACK per capture direction, which on loopback mixes both directions of a connection; it is now tracked per TCP flow.
- Phase 4 (robustness): GSO + fail-open queue flags and the 16k queue length were already in place; SIGTERM/SIGHUP now request a normal quit so the `inet lagsw` table is removed (SIGINT stays ignored, SIGKILL fails open via `bypass`). `scripts/test_nfqueue_gateway.sh` verifies the forward hook on a veth/netns gateway (delay applied to forwarded traffic, transparent when idle), SIGTERM cleanup and SIGKILL fail-open. Fanout (multiple queues per channel) is deliberately not implemented: the engine reads each channel from one thread and delay modes depend on packet order, so it is deferred until throughput measurements justify it.
- Phase 5 (packaging/docs): done. xmake selects `backend.nfqueue` on Linux (Phase 2); the README has a Linux section with requirements, build, running as root (file capabilities do not reach the spawned `nft`) and lifecycle notes, and `scripts/bootstrap.sh` already wraps the run with sudo.
- Phase 2 (pass-through): done in `backends/nfqueue/`. The engine keeps passing WinDivert-style filter strings; `filter_compiler.cc` parses that subset, converts it to DNF and renders one nft rule per clause/hook (instead of the `CaptureSpec` in §7). Verified in a privileged container: pass-through, drop, payload rewrite with checksums, `kill -9` fail-open and stale-table replacement.
- Payload rewrites require the init user namespace (the kernel refuses them from user namespaces), so rootless testing covers only pass-through/drop.

## 1. Summary

The packet engine currently depends on WinDivert (`WinDivertOpen/Recv/Send`, `WinDivertHelperCalcChecksums`, WinDivert filter strings). This PoC defines a Linux backend that provides the same capabilities using **nftables** to select traffic and **NFQUEUE** (via `libnetfilter_queue`) to hand packets to user space, which then returns a verdict (accept / drop / accept-with-modified-payload).

The goal is to prove that every behaviour the engine relies on (capture, drop, delay, modify, reinject, sniff) can be reproduced on Linux without a kernel module, and to identify the seam where the engine is split into a platform-neutral core and per-OS backends.

## 2. Terminology

- **Backend**: OS-specific implementation of packet capture/reinjection.
- **Queue**: an NFQUEUE number bound by one user-space socket.
- **Verdict**: kernel instruction for a queued packet (`NF_ACCEPT`, `NF_DROP`, optionally with a replacement packet).
- **Sniff**: observe without being able to affect the packet.

## 3. Motivation

- Run on Linux hosts, routers and containers (the forward path is where this tool is most useful as a gateway).
- Avoid the Windows-only WinDivert runtime (`backends/windivert/runtime.*`) dynamic loader and driver.

## 4. Goals

1. Introduce a `PacketBackend` interface in `include/` that the engine uses instead of WinDivert types directly.
2. Implement `NfqueueBackend` for Linux, IPv4 first, TCP and UDP.
3. Generate and own the nftables ruleset from the existing profile/server/filter data.
4. Support the existing modes: normal (intercept), sniff, forward, outbound-only, region enforcement (drop), delay/reorder, payload rewrite.
5. Fail safe: if the process dies, traffic must keep flowing.

## 5. Non-goals

- Porting the WinDivert filter language verbatim (see §7).
- IPv6, VLAN, or non-IP traffic in the first iteration.
- Generating packets that never traversed the host (see §9.3 for the limited injection story).
- Supporting iptables-legacy.

## 6. Concept mapping

| WinDivert | Linux (this PoC) |
|---|---|
| `WinDivertOpen(filter, NETWORK, prio, flags)` | nft rule `queue num N` in a chain at a given hook/priority + `nfq_create_queue(N)` |
| `WINDIVERT_LAYER_NETWORK_FORWARD` | nft `forward` hook |
| `WINDIVERT_LAYER_NETWORK` | nft `input` and `output` hooks (two rules, direction known from the hook) |
| `priority` | nft chain priority (lower runs first); one chain per distinct priority |
| `WINDIVERT_FLAG_SNIFF` | verdict `NF_ACCEPT` immediately in the receive callback (copy is processed afterwards), or nft `queue ... bypass` with a `numgen`/`meta` sample; see §8.4 |
| `WinDivertRecv` | `nfq_handle_packet` callback; packet ID, hook, ifindex, mark from `nfq_get_msg_packet_hdr/indev/outdev` |
| `WinDivertSend` (reinject) | `nfq_set_verdict(qh, id, NF_ACCEPT, len, buf)` with the (modified) packet |
| Dropping (no send) | `NF_DROP` |
| `WINDIVERT_ADDRESS` (outbound, ifIdx, impostor, flags) | small `PacketMeta` struct built from queue metadata |
| `WinDivertHelperCalcChecksums` | `nfq_ip_set_checksum`, `nfq_tcp_set_checksum_ipv4`, `nfq_udp_set_checksum_ipv4` (or a local implementation) |
| `WinDivertHelperCompileFilter` (validation) | validate by building the rule struct, then `nft -c -f` (dry-run) |

## 7. Filter model

WinDivert expressions are free-form strings assembled in `PacketEngine::server_filter` and `region_enforcement_filter`. nftables cannot consume them. The PoC therefore does **not** translate strings; it introduces a structured `CaptureSpec`:

```
CaptureSpec {
  hook:       input | output | forward
  proto:      tcp | udp
  servers:    set<ipv4> and port ranges
  match_on:   source | destination | both       // WinDivertOptions::ServerDirection
  client_ip:  optional, enforced per ClientAddressEnforcement
  priority:   int
  action:     queue(N) | drop
}
```

`server_filter()` and `region_enforcement_filter()` are changed to return a `CaptureSpec`; the Windows backend renders it to a WinDivert string (preserving today's output), the Linux backend renders it to nft.

Rendered nft example (profile with two servers, both directions, outbound capture, forwarding on):

```
table inet lagsw {
  set srv_p1 { type ipv4_addr; elements = { 34.13.202.203, 34.90.202.108 } }

  chain pre_p1 { type filter hook prerouting priority -150; policy accept;
    ip saddr @srv_p1 meta l4proto { tcp, udp } queue flags bypass,fanout num 10-13 }
  chain out_p1 { type filter hook output priority -150; policy accept;
    ip daddr @srv_p1 meta l4proto { tcp, udp } queue flags bypass,fanout num 10-13 }
}
```

Notes:
- Use `prerouting` rather than `input` so the same rule catches both local and forwarded inbound traffic; use `postrouting` for the forward-and-local outbound equivalent when NAT ordering matters. Choose per profile `forward` option.
- `bypass` makes the kernel accept packets if no listener is attached (fail-open, satisfies goal 5).
- Region enforcement uses a lower priority number (WinDivert `-100`) and `drop` verdicts decided in user space.

## 8. Design

### 8.1 Interface seam

```
struct PacketMeta { bool outbound; uint32_t ifindex; uint32_t mark; uint32_t id; };
class PacketBackend {
  virtual Handle open(const CaptureSpec&, OpenFlags) = 0;
  virtual bool   recv(Handle, buf, len, &out_len, &PacketMeta) = 0;
  virtual bool   send(Handle, const buf, len, const PacketMeta&) = 0; // verdict accept
  virtual bool   drop(Handle, const PacketMeta&) = 0;
  virtual void   calc_checksums(buf, len) = 0;
  virtual void   close(Handle) = 0;
};
```

`src/packet_engine/io.cc`, `discovery.cc` and `region.cc` call these instead of `WinDivert*`. `backends/windivert/runtime.*` and `WinDivertOptions` move behind the Windows backend; the options struct is renamed (e.g. `CaptureOptions`) with the YAML keys unchanged.

### 8.2 Receive loop

One thread per queue (or per fanout member). Each opens an `nfq_handle`, binds `AF_INET`, creates the queue, sets `NFQNL_COPY_PACKET` with a copy range of 65535 and `NFQA_CFG_F_GSO`, and loops on `recv()` of the netlink socket (large `SO_RCVBUF`). The callback copies the packet into the engine's existing packet node and enqueues it, so downstream code (delay lists, region logic) is unchanged.

### 8.3 Reinjection and delay

The kernel holds a packet until a verdict is issued, so **delaying a packet == delaying its verdict**. The existing delayed-send list in `src/packet_engine/io.cc` maps directly: the "send" at release time becomes `nfq_set_verdict`. Constraints:

- Set `queue-maxlen` (`NFQNL_CFG_CMD`/`NFQA_CFG_QUEUE_MAXLEN`) high enough for the longest configured delay × packet rate; overflow drops (or accepts with `bypass`/`NFQA_CFG_F_FAIL_OPEN`). Document this limit per profile.
- Verdicts must be issued from a thread that owns the netlink socket, or serialised with a mutex.
- Unlike WinDivert, reordering is expressed by issuing verdicts out of order; this works, but is bounded by the queue length.

### 8.4 Sniff mode

NFQUEUE has no native copy mode. Options evaluated by the PoC:

1. Queue and immediately `NF_ACCEPT` in the callback (latency cost of one user-space round trip). **Default.**
2. nft `log group N` with `libnetfilter_log` (true copy, no latency, but truncated/limited metadata). Candidate for discovery/probe/FAD handles which use `WINDIVERT_FLAG_SNIFF` today.

### 8.5 Modification and checksums

Modified packets are returned in the verdict; the kernel does not recompute checksums for them. Call the checksum helper after any rewrite. Because `NFQA_CFG_F_GSO` can deliver super-packets larger than MTU when offload is on, either (a) require `ethtool -K <if> gro off gso off tso off` for the PoC, or (b) cap handling to ≤ MTU and accept GSO frames unchanged. The PoC uses (a) and documents it.

Note: if payload length changes, conntrack's sequence tracking is bypassed; use `nfq_set_verdict2` with `NFQA_CT`/conntrack info or `ct state` exemptions for rewritten flows. Prefer length-preserving rewrites first.

### 8.6 Loop avoidance

A verdict returns the packet to the next hook after the queue rule, so there is no re-capture loop (unlike a WinDivert reinjection, which relies on the impostor flag). For packets the engine itself creates (§9.3) set a distinguishing `SO_MARK` and add `meta mark 0x1c1c return` before the queue rule.

## 9. Privileges, lifecycle, injection

### 9.1 Privileges
`CAP_NET_ADMIN` (nft + nfqueue). `CAP_NET_RAW` only if §9.3 is used. Provide a `setcap` example; no need for full root.

### 9.2 Ruleset lifecycle
- Own a single table `inet lagsw`; apply atomically with `nft -f -` (or libnftables) on start, `nft delete table inet lagsw` on stop and in signal handlers.
- On crash the table remains, but `bypass` keeps traffic flowing; the next start deletes and recreates it.
- Never touch other tables.

### 9.3 Packet injection
Packets not obtained from a queue (if any engine feature needs them) are sent through an `AF_INET`/`SOCK_RAW` socket with `IP_HDRINCL` and the loop-avoidance mark.

## 10. Build and packaging

- `xmake.lua`: add a Linux target selecting `src/backend/nfqueue/*.cc`; packages `libnetfilter_queue`, `libmnl`, `libnftables` (optional). Keep WinDivert sources behind `is_plat("windows")`.
- Replace Windows-only types (`HANDLE`, `UINT`, `WINDIVERT_ADDRESS`) used in `packet_engine.h` internals with portable types.
- Platform-neutral threading/time helpers must not use Win32 APIs.

## 11. Security and correctness requirements

- Validate every netlink payload length before parsing; never trust queue metadata sizes.
- Rule generation must only interpolate validated IPv4 addresses/ports (no string concatenation of user YAML into `nft` commands); pass through the structured API.
- Always remove the ruleset on orderly exit; document fail-open behaviour.
- Do not require disabling the host firewall; use dedicated priorities and a dedicated table.

## 12. Test plan

### Functional
- UDP echo to a listed server: packets arrive at the queue, accepted unchanged, no loss.
- Drop verdict from region enforcement: target packets never reach the peer.
- Delay N ms: measure RTT increase ≈ N ms.
- Payload rewrite (length-preserving): peer observes new bytes, checksums valid (`tcpdump -vv`, no bad cksum).

### Topology
- Host-local (`output`/`prerouting`) and gateway (`forward`) using network namespaces: client ns → router ns (engine) → server ns.

### Failure
- `kill -9` the engine: traffic continues (bypass).
- Queue overflow: no deadlock, counters in `/proc/net/netfilter/nfnetlink_queue` reflect drops.
- Second instance start: ruleset replaced cleanly.

### Performance
- Compare pps and added latency against the Windows baseline with `iperf3 -u` at 10k/50k pps, with 1 vs. 4 fanout queues.

## 13. Phases

1. **Interface extraction**: `PacketBackend`, `CaptureSpec`; Windows backend keeps behaviour (existing tests/PCAPs unchanged).
2. **Pass-through**: nft ruleset generation, single queue, accept-all, IPv4 UDP.
3. **Full verbs**: drop, delay, modify + checksums, TCP.
4. **Scale/robustness**: fanout, GSO handling, fail-open, cleanup, forward hook.
5. **Packaging/docs**: xmake Linux target, README Linux section, capability instructions.

## 14. Open questions

1. Is gateway (forward) the primary Linux use case, or local host capture?
2. Accept disabling GRO/GSO as a requirement, or implement segmentation-aware handling?
3. Is sniff via `NF_ACCEPT` latency acceptable for discovery/FAD, or should `libnetfilter_log` be used?
4. Are length-changing rewrites (see `tls_segment_removal.md`) required on Linux in the first iteration? They need conntrack-aware sequence adjustment.
5. Minimum kernel/nftables version (proposal: kernel ≥ 5.10, nftables ≥ 0.9.8 for `queue flags bypass,fanout`).
