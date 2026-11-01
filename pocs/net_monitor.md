# Net monitor PoC

A full-screen view, opened with the configured key (`features.net_monitor.key`, default `N`), that shows live network statistics for the configured servers. Nothing is
captured or drawn until the view is opened; closing it stops both. `Space` pauses/resumes the measurement while the
view is open, `r` resets the statistics, the configured key closes the view.

Enable it in the profile file with `features: net_monitor: {enabled: true, key: N}`; the code is compiled in by the
`net_monitor` build feature (`xmake f --net_monitor=y|n`, default `y`).

## How it works

- `NetMonitor` (`include/net_monitor.h`, `src/net_monitor/net_monitor.cc`) opens its own **sniff** channel when the view
  opens. The filter is `profile()` with `tcp or udp` plus bare ACKs, restricted to every configured server address in
  both directions, so it never delays or alters traffic and is closed again when the view closes.
- The layout fills the terminal: charts are as wide as the window and grow taller with spare rows (history of up to
  10 minutes is kept for wide terminals); table columns scale with the width.
- A capture thread feeds `record()`; a render thread ticks the one-second buckets and redraws about 5 times a second.
  The view uses the terminal's alternate screen. `logging::set_suspended()` holds log lines and the status line back
  while it is shown and replays them afterwards.
- While paused, packets are still read (so nothing queues up in the kernel) but ignored; on resume, in-flight RTT
  state is dropped so a pause is never counted as latency.

### What is measured today

| Stat | How |
|---|---|
| packets/s and bandwidth (bit/s), up/down, plus peak bandwidth | per-second buckets, total and per server |
| per-port table | server-side TCP/UDP port (top 6, busiest first, with a service label for well-known ports): pkt/s and bit/s up/down, per-port RTT and a trend |
| packet size distribution | share of packets in <128, 128-511, 512-1023 and >=1024 byte buckets, per direction |
| TCP handshake time | SYN to SYN-ACK per new connection (last/avg/min/max), SYN retries and half-open connections of the selected server |
| duplicate ACKs, zero-window events, stalls | repeated ACKs without data (up = we are missing server data, down = the server is missing ours), advertised window of 0, and inbound gaps of 250 ms or more |
| TCP flag mix | SYN, FIN, RST, PSH and pure-ACK packet counts |
| flows and port churn | active TCP flows, flows opened and a new-flows/s chart; a rising rate means the client keeps changing source ports (reconnects or NAT rebinding) |
| burstiness and up/down ratio | peak versus average packets/s, and the up/down byte ratio |
| path watch (selected server) | TTL of inbound packets with an estimated hop count, TTL changes as a route-change hint, DSCP value and changes, ECN-CE marks |
| stability score | 0-100 from retransmit %, jitter, arrival jitter, stalls and resets since the view opened, with a trend arrow; shown per server |
| this machine | CPU use of lagsw and NIC errors+drops per second (Linux: /proc/net/dev; shows n/a where unavailable, e.g. NIC counters on Windows) |
| lagsw effect | packets held by the engine over time, queue peak, active profiles, next release and the passive latency setting |
| latency (RTT) | passive: time between an outbound TCP data segment and the first ACK that covers it. Segments that were retransmitted never produce a sample (Karn's rule) |
| RTT min/avg/p50/p95/max | all samples / last 256 samples |
| RTT jitter | EWMA of the change between consecutive RTT samples |
| arrival jitter, longest gap, silence | inter-arrival time of inbound packets (also works for UDP) |
| retransmits up/down | outbound or inbound segments that do not advance the highest sequence number seen on the flow |
| TCP resets, TCP/UDP split, average packet size | counters |
| per-server table | pkt/s, RTT now/avg, jitter, retransmit %, silence and an RTT trend sparkline for every configured server; the selected server is marked |

### Known PoC limits

- Latency is only measured for TCP; a UDP-only server shows arrival jitter and gaps but no RTT. See below for an
  active probe option.
- The server list is the configured one; servers added by discovery at runtime are not monitored.
- Only IPv4/IPv6 packets with plain TCP/UDP headers are understood (no IPv6 extension headers).
- The layout adapts to the terminal size, but the minimum is about 25 lines (and 60 columns); below that the view scrolls.
  It is not redrawn on a resize until the next frame (200 ms).
- The key must differ from `q`, `r`, Space, the navigation keys, the passive latency pause key and every profile key
  (checked at startup).

## Proposed additions

Measured without extra traffic:

- **Loss and quality**: estimated loss from sequence gaps (SACK/dup-ACK counts for TCP, RTP-style sequence numbers
  where the game protocol has them), reordering rate, duplicate packets, out-of-window packets.
- **Per-flow view**: one row per 5-tuple with state (SYN/established/closing), bytes, RTT and a drill-down chart.
- **TCP health**: advertised receive window and zero-window events, estimated bytes in flight, MSS, ECN marks,
  time-to-first-byte of new connections and connect (SYN to SYN-ACK) time, which gives a second, cleaner RTT.
- **Burstiness**: packet size histogram, inter-packet gap histogram, microburst detection and a "stall" counter
  (inbound silence over 250 ms) with a timeline of when stalls happened.
- **Throughput**: peak and 95th percentile rate, goodput versus retransmitted bytes, protocol-overhead share.
- **Distribution charts**: RTT histogram and a time/value scatter instead of only the mean line, plus min/max bands
  on the sparkline.
- **Heatmap of RTT per server over the last few minutes** for spotting a server that degrades at certain times.
- **Alerts**: configurable thresholds (RTT, jitter, retransmit %, stall) that turn the row red and log a line when the
  view closes. Useful to confirm a lag-switch activation or its effect: mark profile activations on the time axis.
- **Engine overlay**: show the active profiles and the held-packet count next to the charts so the effect of a profile
  on RTT and packets/s is visible; also the passive-latency delay in force and the measured RTT with and without it.
- **Interface and system**: per-interface counters (drops, errors), NFQUEUE backlog and drop counters from the
  netfilter monitor, process CPU use and capture thread lag so you can tell when the monitor itself is the bottleneck.
- **Recording**: `e` to export the current window as CSV/JSON, and a `--netmonitor-log` option to keep the history
  after the view closes.

Needs extra traffic (opt-in):

- **Active probes**: ICMP echo or a TCP connect to each server on an interval for servers that are idle or UDP-only,
  also gives one-way-delay trends and path MTU. Must stay opt-in and rate limited.
- **Traceroute/hop view** and per-hop loss for locating where the latency comes from.
- **DNS and region lookup time** for the server regions already resolved by the tool.
- **Jitter buffer estimate** for the game flow based on arrival jitter and gap percentiles.

Next steps for a real implementation: configurable history length and thresholds,
terminal height handling, scrolling per-server table, per-flow drill-down and a view for each profile.
