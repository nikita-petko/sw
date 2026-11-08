# Net monitor PoC

A full-screen view, opened with the configured key (`features.net_monitor.key`, default `N`), that shows live network statistics for the known servers. Nothing is
captured or drawn until the view is opened; closing it stops both. While the view is open:

| Key | Action |
|---|---|
| `Space` (`pause_key`) | pause/resume the measurement |
| `r` (`reset_key`) | reset the statistics |
| `f` (`flows_key`) | switch between the overview and the per-flow view |
| `p` (`profiles_key`) | switch between the overview and the per-profile view |
| `Up` / `Down` | select a flow (flow view) |
| `e` (`export_key`) | export the measured window as CSV and JSON |
| the configured key | close the view |

The keys in parentheses are the defaults' setting names; all of them can be changed in `features.net_monitor`.

Enable it in the profile file with `features: net_monitor: {enabled: true, key: N}`; the code is compiled in by the
`net_monitor` build feature (`xmake f --net_monitor=y|n`, default `y`). The alert thresholds, the export directory and
the log file are further keys of the same block, see the README.

## How it works

- `NetMonitor` (`include/net_monitor.h`, `src/net_monitor/net_monitor.cc`, `src/net_monitor/export.cc`) opens its own
  **sniff** channel when the view opens. The filter is `profile()` with `tcp or udp` plus bare ACKs, restricted to every
  known server address in both directions, so it never delays or alters traffic and is closed again when the view
  closes. It asks for forwarded traffic as well (`include_forward`), so a gateway sees routed packets: WinDivert opens a
  second handle on the forward layer, nfqueue hooks the forward chain.
- Servers that server discovery adds while the view is open are picked up by the render thread, which reopens the
  capture with a filter that includes them.
- The layout fills the terminal: charts are as wide as the window and grow taller with spare rows (history of up to
  10 minutes is kept for wide terminals); table columns scale with the width. A console resize wipes the screen before
  the next frame, so the old layout never lingers.
- A capture thread feeds `record()`; a render thread ticks the one-second buckets and redraws about 5 times a second.
  The view uses the terminal's alternate screen. `logging::set_suspended()` holds log lines back while it is shown and
  replays them afterwards. The status lines (main and extra) stay visible: the view is drawn into the rows above them and
  `logging::write_frame()` repaints them over the bottom rows after every frame (on consoles too short to share, they are
  hidden until the view closes).
- While paused, packets are still read (so nothing queues up in the kernel) but ignored; on resume, in-flight RTT
  state is dropped so a pause is never counted as latency.
- The header shows the capture backend and what it covers (for example `WinDivert (network + forward layers)`), how many
  packets matched a server, matched none, could not be parsed, and capture errors. It warns when nothing, or only one
  direction, is being captured.
- Windows may hand outbound packets to the capture with large send offload, which leaves the IP length field at 0; the
  parser takes the captured length in that case, otherwise every such outbound packet would be dropped.

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
| this machine | CPU use of lagsw and NIC errors+drops per second (Linux: /proc/net/dev; Windows: `GetIfTable2`, interfaces that are up and not loopback; shows n/a where unavailable) |
| lagsw effect | packets held by the engine over time, queue peak, active profiles, next release and the passive latency setting |
| latency (RTT) | passive: time between an outbound TCP data segment and the first ACK that covers it. Segments that were retransmitted never produce a sample (Karn's rule) |
| RTT min/avg/p50/p95/max | all samples / last 256 samples |
| RTT jitter | EWMA of the change between consecutive RTT samples |
| arrival jitter, longest gap, silence | inter-arrival time of inbound packets (also works for UDP) |
| retransmits up/down | outbound or inbound segments that do not advance the highest sequence number seen on the flow |
| TCP resets, TCP/UDP split, average packet size | counters |
| per-server table | pkt/s, RTT now/avg, jitter, retransmit %, silence and an RTT trend sparkline for every configured server; the selected server is marked |

After `silent_timeout` milliseconds without inbound traffic (default 30000, 0 disables it), the server's row is gray
and retains only its label, marker, last RTT, silence and score; the other fields and RTT trend are hidden. Silence is
unknown until an inbound packet is seen, and does not advance while the monitor is paused. This changes only the
display, not stored statistics, alerts or exports.

Silence and server alert inputs use traffic on `features.server_discovery.port` when it is configured and nonzero,
whether or not discovery is enabled. Otherwise all ports are included except `features.region_enforcement.probe_port`;
that probe port is excluded even when a discovery port is configured. The same filtering applies to per-server RTT,
jitter and TCP retransmission measurements, while packet, port and flow counts still include probe traffic. A server
seen only through probes has no silence timestamp or probe-driven alerts.

### Known PoC limits

- Latency is only measured for TCP; a UDP-only server shows arrival jitter and gaps but no RTT. See below for an
  active probe option.
- Only IPv4/IPv6 packets with plain TCP/UDP headers are understood (no IPv6 extension headers).
- The overview needs about 62 lines (and 60 columns); below that it scrolls. A console resize is noticed within one
  frame (200 ms).
- Alerts are evaluated per second from what was measured since the view opened. The stall alert uses the gap between
  two inbound packets, so it is reported when traffic resumes, and an idle server can trip it.
- The flow view keeps at most 256 flows per server (closed ones are dropped first) and the history of the selected flow
  only. UDP flows are keyed by the client and server port; they have no RTT or state beyond active/idle.
- Every view key (`key`, `pause_key`, `reset_key`, `flows_key`, `profiles_key`, `export_key`) must be distinct, must differ
  from `q`, Backspace, Tab, Page Up/Down and the arrow keys, from the passive latency pause key (when that feature is enabled) and from every profile
  activation key and `send_key`; the configuration fails to load otherwise (checked at startup).

### Alerts, events, flows and export

- **Alerts**: per server, `alert_rtt` (ms, one second's mean RTT), `alert_jitter` (ms, smoothed RTT jitter),
  `alert_retransmit` (percent of data packets over the last 10 seconds, needs at least 20 of them) and `alert_stall`
  (ms of inbound silence); 0 disables one. A raised alert marks the server red unless it is silent, and is added to the events
  panel, and the cleared state is added too. When the view closes, a warning line summarises how often each server
  raised each alert.
- **Events** (last four shown, 200 kept): alerts, profiles switching on or off, servers added by discovery. The
  `profiles active` and `alerts` rows under the charts mark the seconds in which a profile was active or an alert was
  raised, aligned with the time axis of the charts above them.
- **RTT spread**: the RTT charts show a darker bar up to the lowest RTT of each second, the mean above it and a thin line
  up to the highest (needs a chart taller than one row; a short terminal shows the mean only). The selected server also
  gets an RTT histogram (`<25`, `25-49`, `50-99`, `100-199`, `200-499`, `>=500 ms`).
- **Flow view** (`f`): one row per TCP connection or UDP port pair with state, bytes, RTT and idle time; `Up`/`Down`
  select one and show its bytes/s and RTT history.
- **Profile view** (`p`): one row per profile with its state, activation count, total active time (and share of the
  measured time), the running, last and longest activation and the engine's packet-mode status. A second table shows the
  mean RTT (and its difference to the seconds in which no profile was active), retransmit percentage and download rate
  measured while each profile was active. A second is attributed to every profile active at its end, so profiles active
  together share their seconds; the statistics are cleared by `r` and are not part of the export.
- **Export** (`e`): writes `netmonitor-<date>-<time>.csv` (one row per server and second) and `.json` (totals, RTT
  statistics and histogram, alert counts, series, events, flows) to `export_directory` (default: a `netmonitor` folder in
  the per-user data directory).
- **Log** (`log_file`): a JSON Lines file that receives one record per server and second plus the events while the view
  is open, so the history outlives the view.

## Proposed additions

Measured without extra traffic:

- **Loss and quality**: estimated loss from sequence gaps (SACK/dup-ACK counts for TCP, RTP-style sequence numbers
  where the game protocol has them), reordering rate, duplicate packets, out-of-window packets.
- **TCP health**: estimated bytes in flight, MSS, time-to-first-byte of new connections.
- **Burstiness**: inter-packet gap histogram, microburst detection and a timeline of when stalls happened.
- **Throughput**: 95th percentile rate, goodput versus retransmitted bytes, protocol-overhead share.
- **Heatmap of RTT per server over the last few minutes** for spotting a server that degrades at certain times.
- **Engine overlay**: the measured RTT with and without the passive-latency delay.
- **Interface and system**: NFQUEUE backlog and drop counters from the backend monitor, capture thread lag so you can
  tell when the monitor itself is the bottleneck.

Needs extra traffic (opt-in):

- **Active probes**: ICMP echo or a TCP connect to each server on an interval for servers that are idle or UDP-only,
  also gives one-way-delay trends and path MTU. Must stay opt-in and rate limited.
- **Traceroute/hop view** and per-hop loss for locating where the latency comes from.
- **DNS and region lookup time** for the server regions already resolved by the tool.
- **Jitter buffer estimate** for the game flow based on arrival jitter and gap percentiles.

Next steps for a real implementation: configurable history length, a scrolling per-server table and a view for each
profile.
