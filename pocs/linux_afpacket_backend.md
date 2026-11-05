# PoC: Linux AF_PACKET Passive Capture Tier

## 0. Status

AF_PACKET/TPACKET_V3 is already used as a sniff-only reference by
[`pocs/linux_kernel_module_backend/`](linux_kernel_module_backend.md)'s `swbench` benchmark. This document proposes
the production-facing shape of a passive capture tier; there is not yet an AF_PACKET capture implementation or engine
routing integration.

AF_PACKET is intended to run **alongside**, not instead of, the other Linux backends. It receives copies for work that
only needs observation. NFQUEUE, the tc eBPF tier and swdivert/kmod continue to handle work that needs to control an
original packet or inject/reinject packets.

## 1. Summary

Linux packet sockets can deliver a copy of packets observed on a selected network interface to a userspace process.
With `AF_PACKET`, `SOCK_RAW`, and a `TPACKET_V3` memory-mapped receive ring, a sniff-only consumer can inspect packets
without making the original wait for a userspace verdict. The kernel continues normal packet processing independently
of whether or when the capture worker reads the copy.

This is the preferred starting point for Linux sniff-only work when a device-level packet tap provides the required
traffic visibility and metadata. Enabling this capture tier does not change which backend handles active packet work:
the engine can consume AF_PACKET copies for discovery, probes or pcap while the matching originals continue through
NFQUEUE, eBPF or swdivert as required by the active profile. The tc eBPF ring buffer or the kernel module's sniff ring
remain alternatives when their hook placement or integrated filtering is required.

## 2. Goals

1. Provide passive packet copies to observation-only consumers, including discovery, probes and pcap recording where
   the captured interface and packet format meet their needs.
2. Allow capture to coexist with a verdict-capable backend; it must not take ownership of packets or interfere with
   that backend's verdict, delay, modification or reinjection.
3. Ensure capture does not wait for a userspace decision and never changes the original packet's fate.
4. Filter as early as practical and batch packet delivery using the TPACKET_V3 ring.
5. Report capture drops and setup errors explicitly; never treat an incomplete capture as complete.
6. Reuse the repository's common benchmark to compare AF_PACKET with other Linux capture and diversion paths.

## 3. Non-goals

- Holding, delaying, dropping, modifying or reinjecting packets.
- Reproducing an arbitrary netfilter hook or a WinDivert divert handle's full metadata.
- Replacing NFQUEUE, eBPF or swdivert for modes that need a userspace verdict, kernel-side packet action, or injection/reinjection.
- Promising lossless capture under overload. Packet sockets can report drops, but cannot make the reader keep up.
- Automatically capturing all interfaces or silently guessing the correct interface.

## 4. Capture model

```text
                         +--> AF_PACKET socket --> TPACKET_V3 ring --> observation-only consumers
packet at device tap ----+
                         +--> active path (unchanged by AF_PACKET)
                              NFQUEUE / tc eBPF / swdivert as selected
```

The capture worker drains complete ring blocks, applies any userspace consumer logic and returns each block to the
kernel. It is not in the original packet's forwarding or local-delivery path. The active backend remains responsible
for any packet that needs a verdict or action. If the capture worker is delayed or the ring fills, copies may be dropped;
the original still follows the active path and is not held for that reason.

Routing is by **work/consumer**, not by globally selecting one backend for the whole process:

- Send observation-only consumers a copy from AF_PACKET when its interface-level view meets their needs.
- Send each original packet requiring a decision or action to the appropriate active backend. Do not have the AF_PACKET
  consumer issue a verdict or reinject the copy.
- When one flow needs both observation and active handling, both paths may see it: AF_PACKET sees a passive copy, while
  the active backend handles the original. Keep those responsibilities separate so an observation callback cannot also
  process the active backend's copy as a second original.
- A consumer must be registered with only one capture source for a given observation purpose, unless it explicitly
  needs separate tap points. This avoids duplicate discovery/probe events when AF_PACKET and an eBPF or module copy path
  are both enabled.

The socket is bound to an explicitly selected interface and protocol. A classic socket filter (cBPF) should narrow
delivery to the configured addresses, ports and protocols before packets enter the receive ring, where feasible. Any
remaining filtering is done by the capture worker. Direction can be derived from packet-socket metadata such as
`sll_pkttype`; outgoing copies may be disabled with `PACKET_IGNORE_OUTGOING` when the consumer needs inbound-only
observation.

Use `SOCK_RAW` when consumers need link-layer headers, as pcap generally does. If a consumer needs only network-layer
packets, link-layer parsing must account for the selected device type and header length rather than assuming Ethernet.

## 5. TPACKET_V3 ring

1. Open `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` (or the narrowest suitable protocol) in the target network
   namespace.
2. Set `PACKET_VERSION` to `TPACKET_V3`, configure `PACKET_RX_RING` with `tpacket_req3`, then `mmap` the ring.
3. Bind the socket to the selected interface with `sockaddr_ll`; configure promiscuous membership only when explicitly
   requested and needed.
4. Poll the socket for ready blocks. Walk each block's packet descriptors using the kernel-provided offsets and lengths;
   validate every offset and captured length against the block boundary before reading.
5. Copy or synchronously consume packet data while the block is user-owned, then return it to the kernel by setting its
   status to `TP_STATUS_KERNEL` with the required memory ordering.

Block size, block count, frame size and retire timeout are configuration inputs to the PoC, not assumed universal
defaults. The initial benchmark should use the current `swbench afpacket` settings for parity, then separately measure
reasonable ring configurations. The snap length limits bytes retained per packet and must be large enough for each
consumer; truncated records must be marked as truncated.

## 6. Interface, namespace and direction semantics

- The socket sees packets at a packet-socket device tap. This is not an arbitrary NFQUEUE or tc hook, so the exact set
  of visible packets depends on which interface is selected and where in the path that interface sits.
- For gateway forwarding, select the interface whose traffic the consumer needs. Observing both ingress and egress
  interfaces can produce more than one observation of a forwarded flow; do not treat these as duplicate packets without
  accounting for tap placement.
- A packet socket is created in the network namespace where it should capture. Interface indexes are namespace-local.
- `PACKET_OUTGOING` identifies outgoing packet-socket copies. If outgoing packets should not be delivered at all,
  request `PACKET_IGNORE_OUTGOING` where supported; otherwise filter direction explicitly.
- VLAN tags, loopback, cooked/non-Ethernet devices, checksum offload and GSO/GRO can affect the bytes or number of
  records observed. Preserve available packet metadata and document the capture point; do not infer wire-level frames
  from a host-side tap when offloads may have coalesced them.
- Promiscuous mode broadens which link-layer traffic reaches the socket, but does not bypass network-namespace or
  device visibility constraints and should not be enabled by default.

## 7. Feature mapping

| Consumer or engine behavior | AF_PACKET path |
|---|---|
| Sniff-only copy | Supported, subject to interface visibility and capture loss; may run beside an active backend |
| Discovery/probe observation | Supported when its required packets and metadata are visible at the selected tap; route the observation consumer here |
| Pcap capture | Supported with link-layer data and timestamps suitable for the chosen pcap format; can record while an active backend handles originals |
| Direction and interface metadata | Packet-socket packet type and bound interface; not identical to WinDivert metadata |
| Drop, delay, reorder or hold | Not supported |
| Payload/header rewrite | Not supported |
| Region enforcement requiring a verdict | Not supported |
| Synthetic packet injection | Not part of this PoC |

If a consumer requires hook-level data not available from AF_PACKET, route that consumer to the tc eBPF ring-buffer
path or another suitable capture mechanism. If it needs to decide the original packet's fate, use NFQUEUE, eBPF or
swdivert as appropriate. These active backends remain enabled for their work when AF_PACKET is enabled; do not
silently replace them with packet-socket capture.

## 8. Privileges and lifecycle

Creating an `AF_PACKET` socket normally requires `CAP_NET_RAW` in the governing user/network namespace (or equivalent
privilege). Capture should fail with an actionable error if permission is absent; the program must not silently fall
back to an unfiltered or different-interface capture.

The socket, ring mapping and any promiscuous membership are owned by the process. Closing the socket releases the ring
and membership, including on process termination. No firewall rules, qdiscs or persistent kernel objects are installed.
The normal packet path is unaffected by capture-worker exit.

## 9. Loss, timestamps and reporting

Read packet-socket statistics (`PACKET_STATISTICS`) and expose kernel-reported packet/drop counts alongside any
consumer-level parse or output errors. Statistics retrieval may reset counters on some kernel versions; accumulate
each returned interval and report the total. Keep separate counters for kernel ring drops, snap-length truncation and
consumer rejection/write failures.

Use the packet-socket timestamp metadata when it is available and appropriate for the consumer. Record the timestamp
source and clock in pcap output; do not label userspace ring-drain time as packet arrival time. Benchmark `cap` timing
should follow the common harness definition so comparisons remain consistent.

## 10. Benchmark and validation plan

The existing harness provides a starting point:

```sh
xmake build swbench
python3 pocs/linux_kernel_module_backend/bench.py --modes baseline,afpacket --pps 20000,100000
```

The common benchmark sends a paced UDP flow through a gateway namespace and compares baseline delivery with passive
capture. It records packets seen, missed packets, end-to-end latency and reader/host CPU. Keep the path and snap length
the same when comparing AF_PACKET with NFQUEUE or swdivert. These measurements characterize the benchmark setup only,
not every NIC, kernel, traffic pattern or production capture workload.

Before production integration, validate:

- The selected interface captures the intended local and forwarded traffic in the intended network namespace.
- Direction selection and optional outgoing suppression behave as configured.
- The original traffic continues when the reader is stopped or killed.
- AF_PACKET observation and each active backend can run concurrently on the same matching flow: observation receives
  copies, while the active backend still applies its verdict/action exactly once.
- A packet copied to observation consumers is not re-injected, re-queued or delivered to an active consumer as if it
  were a second original.
- A consumer configured for AF_PACKET is not also subscribed to an eBPF/module capture copy for the same observation
  unless it explicitly requests both tap points.
- Ring blocks are returned correctly across wraparound and under sustained load; packet data is not read after ownership
  is returned.
- Kernel drop statistics rise under deliberate reader overload and are reported accurately.
- Snap truncation, VLAN frames and non-Ethernet link types are handled without out-of-bounds reads or invalid pcap
  records.
- Permission failures, interface removal and socket setup errors are surfaced and cleaned up.
- No filtering, interface or privilege failure causes an implicit fallback to NFQUEUE or capture on another device.

## 11. Open questions

1. Which engine consumers need passive copies, and which interfaces provide their complete traffic view?
2. Which packet metadata and timestamp source are required by discovery, latency probes and pcap output?
3. What ring sizing and retire timeout give an acceptable trade-off between reader wakeups, burst capacity and capture
   loss on supported Linux systems?
4. Should production integration provide a `--capture-interface` option, or derive an interface from the existing
   routing/profile information? It must not guess silently when that information is ambiguous.
