# PoC: Linux Latency Backend via iptables + tc + netem

## 0. Implementation status

- Proposal only. Nothing in this document has been run or built yet; the commands in §6 and §11 are the intended starting point and must be validated in a network-namespace harness (§11) before any code is written.
- This is an **alternative** to [`linux_nfqueue_backend.md`](linux_nfqueue_backend.md), not a replacement. The NFQUEUE backend stays the reference Linux backend because it is the only one that can implement every delay mode.

## 1. Summary

The NFQUEUE backend hands every matching packet to user space and the engine decides its fate. This PoC investigates the opposite split: **iptables classifies, the kernel delays**. Matching packets are steered into a dedicated `netem` qdisc via `tc`, and activating or deactivating a profile becomes a single `tc qdisc change` instead of a user-space packet loop.

The goal is to find out which engine features survive that split, what the cost/benefit is (no user-space hop, no per-packet syscalls, nothing in the data path if the process dies badly), and whether a reduced "kernel-shaped" backend is worth shipping for the simple delay/jitter/loss cases (`passive_latency`, `from_timestamp`, `drop`).

## 2. Terminology

- **qdisc**: a queueing discipline attached to a network interface (`tc qdisc`).
- **netem**: the network-emulator qdisc. Supports `delay` (with jitter, correlation, distribution), `loss`, `duplicate`, `corrupt`, `reorder`, `rate` and a `limit` on queued packets.
- **prio**: classful qdisc with N bands; used here only as a place to hang a `netem` child.
- **ifb**: intermediate functional block, a virtual device used to shape *ingress* traffic by redirecting it to an egress queue.
- **CLASSIFY**: iptables target that sets `skb->priority` to a `major:minor` class id, which classful qdiscs use directly.

## 3. Motivation

- No user-space packet path: no queue-length tuning, no netlink verdict latency, no per-packet CPU cost at high packet rates.
- Uses ubiquitous tooling (`iptables`, `ipset`, `iproute2`) on systems where `nft`/`libnetfilter_queue` are unavailable (older routers, OpenWrt, minimal containers).
- netem is a well-tested delay engine; jitter distributions (`uniform`, `normal`, `pareto`, `paretonormal`) and correlation are free.
- The shaping state lives in the kernel, so `tc -s qdisc show` gives drop/backlog counters without any extra monitor code.

## 4. Goals

1. Prove that iptables + tc + netem can implement `passive_latency` (fixed/uniform/normal delay, per direction) and the `from_timestamp` and `drop` delay modes on both a local host and a gateway.
2. Define the exact mapping from existing profile fields to qdisc parameters, and list the modes that cannot be mapped (§8).
3. Measure added latency accuracy and jitter against the NFQUEUE backend (§11).
4. Define a safe lifecycle that cleans up fully, and a failure story for a crashed controller (§9).

## 5. Non-goals

- Payload rewrite, region-enforcement verdicts that depend on packet contents, sniffing/pcap capture, `ack_restoration`, TCP sequence-aware holds (see §8). These need packet visibility in user space and stay on NFQUEUE.
- IPv6 in the first iteration (the same design works with `ip6tables` and `protocol ipv6` filters).
- Replacing the filter language. Profile filters that are not expressible as an iptables match (§7) are rejected at startup, exactly like unsupported terms are rejected by the NFQUEUE filter compiler.
- Managing a pre-existing, user-owned qdisc setup. If the interface already has a non-default root qdisc the backend refuses to start (§9.1).

## 6. Architecture

```
                         local host / gateway egress (per interface)

  packet --> mangle/POSTROUTING --> LAGSW chain --CLASSIFY 1:3--> prio 1: --band 1:3--> netem 30: --> NIC
                                                                      |
                                                                      +--band 1:1 (everything else, untouched)

                         inbound to this host (ingress cannot be shaped directly)

  NIC --> tc ingress (ffff:) --flower match--> mirred redirect --> ifb0 --> netem --> stack
```

### 6.1 Egress classification

Traffic that leaves an interface, whether generated locally or forwarded, passes `mangle POSTROUTING`, so a single hook covers the local-out and `forward: true` cases. Mangle runs before the `nat` table's POSTROUTING, so client-side source addresses are still the original LAN addresses when the rule is evaluated; replies are already de-NATed.

```sh
# Server list as a set so it can change without touching rules
ipset create lagsw_srv hash:ip -exist
ipset add lagsw_srv 34.13.202.203 -exist
ipset add lagsw_srv 34.90.202.108 -exist

iptables -t mangle -N LAGSW
iptables -t mangle -I POSTROUTING -j LAGSW
iptables -t mangle -A LAGSW -o eth0 -p udp -m set --match-set lagsw_srv dst -j CLASSIFY --set-class 1:3
iptables -t mangle -A LAGSW -o eth0 -p tcp -m set --match-set lagsw_srv dst -j CLASSIFY --set-class 1:3
```

Server-direction matching (`server_direction: source|destination|both`) maps to `src`, `dst` or both rules on the relevant interface. `client_address_enforcement` maps to `-s`/`-d` client matches.

### 6.2 Egress qdisc tree

```sh
# Band 1:1 receives all default traffic. 1:3 is the shaped band.
tc qdisc add dev eth0 root handle 1: prio bands 3 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
tc qdisc add dev eth0 parent 1:3 handle 30: netem delay 0ms limit 10000
```

The `netem` child is created once at start with zero delay and then only ever *changed*. `tc qdisc change` replaces parameters but leaves already queued packets in place, so toggling does not flush or reorder what is in flight.

### 6.3 Ingress (inbound to this host)

`tc` cannot delay packets on ingress, and the ingress hook runs before netfilter, so an iptables mark/classify is not available. Packets are matched with a `flower` filter and redirected to an `ifb` device that has the same prio/netem tree:

```sh
modprobe ifb numifbs=1
ip link add ifb_lagsw type ifb 2>/dev/null; ip link set ifb_lagsw up

tc qdisc add dev eth0 handle ffff: ingress
tc filter add dev eth0 parent ffff: protocol ip prio 1 flower ip_proto udp src_ip 34.13.202.203 \
    action mirred egress redirect dev ifb_lagsw

tc qdisc add dev ifb_lagsw root netem delay 0ms limit 10000
```

One `flower` filter is needed per server address (the filter language cannot reference an ipset). With large server lists use a `u32` hash table or fall back to NFQUEUE.

On a **gateway** the ifb is unnecessary: delay traffic toward the client by classifying it on the LAN-facing interface's egress (`-o lan0 -s <server>`) and traffic toward the server on the WAN-facing egress (`-o wan0 -d <server>`).

### 6.4 Activation

| Action | Command |
|---|---|
| Activate, fixed 120 ms | `tc qdisc change dev eth0 parent 1:3 handle 30: netem delay 120ms limit 10000` |
| Activate, 60 ms ± 10 ms normal | `tc qdisc change dev eth0 parent 1:3 handle 30: netem delay 60ms 10ms distribution normal limit 10000` |
| Drop everything | `tc qdisc change dev eth0 parent 1:3 handle 30: netem loss 100% limit 10000` |
| Deactivate | `tc qdisc change dev eth0 parent 1:3 handle 30: netem delay 0ms limit 10000` |

The controller issues these via netlink (`libnl-route-3` or a raw `NETLINK_ROUTE` socket) rather than spawning `tc`, to keep activation latency in the sub-millisecond range. The PoC may spawn `tc` and measure the difference.

## 7. Filter model

The WinDivert-style filter strings the engine passes today are compiled by `backends/nfqueue/filter_compiler.cc` into DNF clauses. This backend reuses the parser and AST and adds a different renderer. The grammar is the one documented in `backends/nfqueue/filter_compiler.h`. The terms that map onto iptables matches are `tcp`, `udp`, `ip.SrcAddr`/`ip.DstAddr`/`ip.Addr` (`==`/`!=`), `tcp|udp.SrcPort|DstPort` (`-p tcp --sport/--dport`), the `tcp.Fin|Syn|Rst|Psh|Ack|Urg` flags (`--tcp-flags`), `outbound`/`inbound`, `ifIdx` (`-i`/`-o` by name), and `and`/`or`/`not` composition. Terms with no iptables or `flower` equivalent (for example TCP flag matching on the `flower` ingress path, which is not reliable across kernels) are refused at startup with the error position.

- The renderer emits one iptables rule per DNF clause per direction.
- Only validated IPv4 addresses, integers and interface names are interpolated into commands; nothing from YAML is concatenated as free text (same requirement as §11 of the NFQUEUE PoC). Commands are executed with `execve` and an argument vector, never through a shell.
- `inbound` clauses become `flower` filters on the ingress device (or a LAN-egress rule on a gateway); `outbound` clauses become `mangle POSTROUTING` rules.

## 8. Feature mapping and gaps

| Engine feature | netem equivalent | Verdict |
|---|---|---|
| `passive_latency` fixed | `delay D` | Exact |
| `passive_latency` uniform (`delay ± jitter`) | `delay D J` (default distribution is uniform) | Close; netem's range is `D ± J` |
| `passive_latency` normal | `delay D J distribution normal` | Exact |
| `inbound_delay_ms` / `outbound_delay_ms` | independent netem on each direction's interface | Exact |
| `max_delay_ms` clamp | none | **Gap.** The built-in distributions are bounded by the table, but there is no explicit clamp |
| `preserve_order: true` | none directly; netem orders by release time, so jitter can reorder | **Gap.** Verify empirically (§11) and document; use fixed delay when ordering matters |
| `preserve_order: false` | jitter reordering, or `reorder P% [C%]` with `delay` | Approximate |
| `max_queued_packets` | `limit N` (overflow drops, it does not release early) | Different semantics |
| `delay_mode: from_timestamp` | `delay D` | Exact |
| `delay_mode: drop` | `loss 100%` (or an iptables `DROP`) | Exact |
| `delay_mode: ratio` with `%` | `delay D reorder P%` sends P% immediately and delays the rest | Approximate, probabilistic rather than batch-based |
| `delay_mode: drop_and_send` | `loss P% delay D` | Approximate, probabilistic rather than a batch ratio |
| `send_all_after_delay`, `ratio` (count), `hold_and_send`, `hold_until_deactivation`, `drop_until_toggle`, `packet_group_send`, `subsequent_packet_hold_mode`, `ack_restoration` | none; need stateful holding and ordered release by the controller | **Not supported.** Rejected at startup on this backend |
| `capture_options.sniff` | none | Not supported |
| `capture_options.forward` | rules on the egress interface, see §6.3 | Supported |
| Region enforcement, server discovery, pcap capture | need packet contents | Not supported (use NFQUEUE, or run the probes from a separate backend) |
| Desync countdown | derived from active duration only | Works unchanged (no packet data needed) |

Profiles are validated against this table when the backend is selected: a profile using an unsupported mode fails with an explicit message rather than silently degrading.

## 9. Lifecycle, privileges, failure behaviour

### 9.1 Ownership and start-up

- Own the chain `mangle/LAGSW`, the ipset `lagsw_srv`, the ifb device `ifb_lagsw`, and the qdiscs the controller creates. Never touch anything else.
- Refuse to start if the target interface already has a root qdisc other than the default (`noqueue`, `pfifo_fast`, `fq_codel`, `mq`, `fq`), because `tc qdisc add ... root` would replace it. Record the previous root qdisc and restore it on exit (`tc qdisc replace`).
- A stale `LAGSW` chain or qdisc from a previous crashed run is detected by name/handle and replaced.
- Install order: ipset, then qdiscs (netem at zero delay), then the iptables jump. Remove in reverse order so classification never points at a missing class.

### 9.2 Privileges

`CAP_NET_ADMIN` is required for iptables, ipset, tc and ifb creation. As with the NFQUEUE backend, rules are installed by spawning binaries (`iptables`, `ipset`), which do not inherit file capabilities, so the process must run as root. Hotkeys still need `/dev/input/event*`.

### 9.3 Failure behaviour (differs from NFQUEUE)

The NFQUEUE backend fails **open**: `queue ... bypass` passes traffic when the process dies. netem has no equivalent. If the controller is killed while a profile is active, the last netem parameters **stay in force** until someone removes them. Mitigations, to be implemented in the PoC:

1. Handle SIGTERM/SIGHUP/SIGINT by resetting netem to zero delay and removing every object in §9.1.
2. Before `exec`, spawn a small detached watchdog (e.g. `systemd-run --on-active=<max> tc qdisc del ...`, or a child that polls the parent pid) that removes the qdiscs when the parent disappears, which also covers SIGKILL.
3. Print the exact one-line cleanup command on start and in the troubleshooting section of the README.

### 9.4 Offloads

netem treats a GSO/GRO super-packet as one packet, so with offloads on, `loss` and `limit` are per super-packet and delay granularity is coarse. For packet-accurate behaviour the PoC documents `ethtool -K <if> gro off gso off tso off` (same recommendation as §8.5 of the NFQUEUE PoC).

## 10. Build and packaging

- New Linux backend selection in `xmake.lua`, e.g. `--linux_backend=nfqueue|netem` (default `nfqueue`), compiled from `backends/netem/`. No `libnetfilter_queue`/`libmnl` dependency; optional `libnl-route-3` for in-process `tc`.
- Share `filter_parser.cc`, `filter_lexer.cc` and `filter_ast.h` with the NFQUEUE backend by moving them to a common directory; only the renderer is new.
- The backend implements the same `PacketBackend` seam only where it makes sense. Because it has no per-packet path, it is more naturally a *shaper* plugin selected by the engine for the subset of profiles in §8. The PoC decides whether that is a second interface (`LatencyShaper { apply(ProfileParams); clear(); }`) or a mode of the existing backend.
- Runtime requirements: kernel modules `sch_netem`, `sch_prio`, `cls_flower`, `act_mirred`, `ifb`, `xt_set`/`ip_set`, `xt_CLASSIFY`; binaries `iptables` (nft or legacy variant, both work), `ipset`, and `tc` from `iproute2`.

## 11. Test plan

Reuse the privileged-container / network-namespace pattern from `scripts/tests/test_nfqueue_localhost.sh` and `scripts/tests/test_nfqueue_gateway.sh`.

### Functional
- Idle: with netem at zero delay, `ping` and `iperf3` to a listed server show no added latency and no loss.
- Fixed delay: set `delay 120ms`; RTT increases by ≈ 120 ms for egress-only, ≈ 240 ms when both directions are configured.
- Jitter: `delay 60ms 10ms distribution normal`; sample 1000 pings and compare mean/stddev to the configured values, and to the NFQUEUE backend's output.
- Drop: `loss 100%` stops traffic to listed servers only; unlisted destinations are unaffected.
- Reordering: with jitter and a UDP sequence-numbered stream, record whether packets are reordered, to settle the `preserve_order` row in §8.
- Unlisted traffic: unaffected in all states (the prio default band).

### Topology
- Host-local: client in one namespace to a server on a veth peer; delay on egress and, via ifb, on ingress.
- Gateway: client ns → router ns (engine) → server ns, shaping on the LAN and WAN egress interfaces, with and without NAT.

### Failure
- `SIGTERM`: all qdiscs, the ifb, the iptables chain and the ipset are removed, and the previous root qdisc is restored.
- `SIGKILL`: the watchdog removes the shaping within its timeout; without it, document that the delay persists.
- Second instance start: stale objects replaced cleanly.
- Queue overflow: set `limit 100` and a high rate; `tc -s qdisc show` reports drops and nothing deadlocks.

### Performance
- Compare CPU use and added-latency error (measured vs. configured) against the NFQUEUE backend with `iperf3 -u` at 10k/50k/100k pps.
- Measure activation latency: `tc` spawn vs. in-process netlink.

## 12. Phases

1. **Harness**: namespace test script that applies the commands in §6 by hand and records the latency/jitter/reorder measurements in §11. No C++ changes. This answers most of the open questions.
2. **Renderer**: share the filter parser, add the iptables/flower renderer and the §8 validator.
3. **Controller**: netlink (or spawned `tc`) apply/change/clear, lifecycle and watchdog (§9).
4. **Integration**: xmake option, engine hook for `passive_latency`/`from_timestamp`/`drop`, README section.

## 13. Open questions

1. Is a reduced-feature backend worth shipping, or is this only useful as a measurement baseline for the NFQUEUE backend?
2. Does netem preserve ordering under jitter on the target kernels? If not, is `preserve_order` acceptable to document as unsupported on this backend?
3. Is the ingress path (flower + ifb) acceptable for local-host profiles, or should this backend be limited to gateway mode where only egress shaping is needed?
4. Should server lists beyond a few addresses use a `u32` hash table, or reject the profile?
5. Is the SIGKILL watchdog (§9.3) acceptable complexity, or is documenting the sticky-delay behaviour enough?
6. Minimum versions: proposal kernel ≥ 4.15 (stable `flower` + `mirred` + ifb), iproute2 ≥ 4.15.
