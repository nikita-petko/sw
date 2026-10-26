# Tom Clancy's The Division (2016) — Networking Architecture: PCAP-Based Analysis

## Status

Research document. Derived from a packet capture (`full-init.pcapng`, ~384KB,
1357 TCP packets, single Windows 10 client, single session) covering session
startup: matchmaking, region-latency probing, voice-server connection, and
the initial handshake/steady-state traffic of the main game server
connection. Findings are correlated against this repository's existing
[`profiles/div1.sw.yml`](../profiles/div1.sw.yml) and
[`README.md`](../README.md), which independently encode several of the same
server roles and ports observed in the capture. This document is a factual,
observation-driven companion to
[division1_lag_switch_weapon_swap_analysis.md](division1_lag_switch_weapon_swap_analysis.md)
and [division1_rpm_exploit_variants.md](division1_rpm_exploit_variants.md),
intended to ground those documents' assumptions about the game's transport
layer in direct evidence.

This document has been revised to incorporate, and defer to where the two
disagree, the deeper multi-capture and static-binary analysis recorded in
[division1_server_list_and_latency_probes.md](division1_server_list_and_latency_probes.md),
which examined five independent session captures plus the client's embedded
server-list resource rather than the single `full-init.pcapng` capture this
document was originally built from. Where the two documents' conclusions
differ, that companion document's conclusions are the more reliable ones and
are called out explicitly below.

## 1. Methodology

No packet-analysis tooling (`tshark`, `python`/`scapy`/`dpkt`) was available
in this environment, so the pcapng file was parsed directly with a small
PowerShell script that walks the pcapng Section Header / Interface
Description / Enhanced Packet blocks, decodes the Ethernet/IPv4/TCP headers
by hand, and extracts per-flow statistics and raw payload bytes. This is
sufficient because the capture contains only Ethernet-framed IPv4 TCP traffic
(no VLAN tags, no IPv6, no UDP was observed at all — see Section 2). The
capture was recorded on a machine identified in its capture-metadata block as
an "Intel(R) Core(TM) i7-10510U CPU" running "64-bit Windows 10 (22H2), build
19045". The client's local address in the capture is `192.168.137.186`, an
RFC 1918 private address (a mobile-hotspot-style `.137.` subnet), behind NAT.

## 2. Transport layer: TCP-only, no UDP observed

Across all 1357 packets in the capture, **every single packet is TCP**; zero
UDP packets were observed for any of the connections established during this
capture window (matchmaking, region-latency probing, voice, and the main game
server). This is a directly relevant, confirmable fact for the companion
exploit documents, which had to reason about TCP vs UDP framing
hypothetically: the observed evidence is that The Division 1's session/control
traffic during connect — and, notably, the beginning of the actual game
server session itself — rides over persistent TCP connections, not UDP
datagrams. This matches this repository's own default configuration, whose
`global_filter` defaults to `tcp.DstPort == 55000 or tcp.SrcPort == 55000`
(see [`README.md`](../README.md)) and whose only observed game-server port,
`55000`, is exclusively TCP in this capture.

Practical implication for the exploit families described in the companion
documents: because the game's session traffic is TCP, an interceptor does not
need to independently implement retransmission/reassembly to hold and later
release "packets" — it can rely on the OS/NIC-level TCP segments the game
already produces and reinjects them as ordinary segments, and the receiving
TCP stack will still deliver them in-order once released. This is consistent
with head-of-line blocking being the dominant mechanism for "release a
burst on demand" behavior described in the RPM exploit document, and explains
why blocking or delaying a single segment can stall an entire logical stream
until it is released.

## 3. Observed server roles, by port and IP

Correlating the capture's destination IPs/ports against the named server
groups already present in [`profiles/div1.sw.yml`](../profiles/div1.sw.yml) shows a
consistent multi-service architecture, where a single game session requires
establishing several independent TCP connections to different
Google-Cloud-hosted IPs, distinguished by destination port. Reverse-DNS
lookups on the two IPs the client contacts first refine the original
port-based role guesses:

- `34.78.88.218` resolves via `tctd-xb1.ubisoft.com`, which is a CNAME for
  `public-key-store.xb.prod.tctd1.ubisoft.com`.
- `34.76.151.88` resolves via `xb-foxtrot.prod.tctd1.ubisoft.com`, which is a
  CNAME for `proxy-core.xb.prod.tctd1.ubisoft.com`.

Both hostnames encode the platform (`xb` = Xbox) and product/environment
(`tctd1` = *Tom Clancy's The Division 1*, `prod`), and both give a literal,
descriptive service name (`public-key-store`, `proxy-core`) that supersedes
the earlier, purely port-number-based guesses of "matchmaking" and "voice
server" for these two hosts:

| Port | Role (revised, DNS-informed) | Evidence |
| --- | --- | --- |
| `27015` | **Public-key bootstrap service** ("public-key-store") | First connection made in the capture, to `34.78.88.218:27015`, whose hostname literally identifies it as a public-key store; see Section 6 for why the 32-byte value observed in the pre-TLS handshake preamble (Section 4) is a plausible candidate for material originating from this service. Port 27015 is also the conventional Source-engine/Steam matchmaking/query port, which may be an incidental reuse rather than a matchmaking role here |
| `51000` | **Directory / bootstrap config broker** ("proxy-core") | Connection to `34.76.151.88:51000`; a separate, out-of-band raw/plaintext probe against this host (see Section 6) returned a directory listing of all 10 candidate backend servers plus a per-server port/service table, indicating this host's role is distributing server topology, not carrying voice media as originally assumed from the port number alone |
| `55002` | Region-latency probe ("region enforcement") | Five parallel connections opened in this capture to `34.76.248.132`, `34.13.202.203`, `136.110.106.37`, `136.112.189.19`, `34.116.109.80` — these are 5 of the 10 candidate addresses also present in [`profiles/div1.sw.yml`](../profiles/div1.sw.yml), and `55002` is exactly the `features.region_enforcement.probe_port` value already configured in that profile. [division1_server_list_and_latency_probes.md](division1_server_list_and_latency_probes.md) shows across five sessions that this is a **random sample of 5 of the 10 candidates, with replacement**, refreshed on a roughly 5-minute interval for the life of the client — not a fixed subset tied to this one capture |
| `55000` (lobby) | Persistent, low-traffic control-plane connection, held for the duration of any menu session | Opened to a europe-west1 candidate (`104.155.45.25` in this capture; also observed alternating with `34.76.248.132` across sessions in the companion document) as soon as the home-menu loading screen appears; single-digit packet counts over multi-second windows |
| `55000` (authoritative game server) | The actual gameplay session, opened only once a match starts | In this capture, opened to `34.90.202.108` and carrying by far the most traffic (493 server→client and 397 client→server packets). [division1_server_list_and_latency_probes.md](division1_server_list_and_latency_probes.md) reports this connection targets a **server-assigned IP that is not guaranteed to be, and in the one fully-traced session was not, a member of the set the client had probed on `55002`** — see Section 6a |

The server list already hard-coded into [`profiles/div1.sw.yml`](../profiles/div1.sw.yml)
matches the 10-address candidate pool observed across both the network
traffic in this capture and the client's own embedded resource (Section 6),
so it is not speculative as a *candidate list*. However, per
[division1_server_list_and_latency_probes.md](division1_server_list_and_latency_probes.md),
that candidate pool is probed for latency telemetry purposes and is **not
the same thing** as the set of servers eligible for actual game-host
assignment; see Section 6a for why this matters for `lagsw`'s server
discovery.

## 4. Connection-establishment handshake (matchmaking and game-server ports)

Both the `27015` matchmaking connection and the `55000` game-server
connections (to `104.155.45.25` and `34.90.202.108`) show the **same
five-step establishment sequence** before any TLS handshake begins:

1. Standard TCP three-way handshake (`SYN` / `SYN,ACK` / `ACK`).
2. The **server** immediately sends an unsolicited 36-byte payload, always
   beginning with the bytes `46 01 02 20`, followed by 32 bytes that appear
   uniformly random (high entropy, no repeated structure across independent
   connections) — consistent with a per-connection nonce or challenge value
   rather than a fixed protocol constant.
3. The **client** replies with an 8-byte message of the form
   `0e 01 00 04 NN 00 00 00`, where the single byte `NN` was observed to
   increment across successive connections opened by the same client during
   the capture (`01` for the first connection opened in the capture, `02` for
   the next `55000` connection) — consistent with a small
   per-client-process connection/sequence counter embedded in this
   handshake step, though its exact semantic meaning could not be determined
   from the capture alone since the payload is otherwise opaque.
4. The **server** replies with a short 3-byte acknowledgment (`04 00 01` or
   `04 02 00` depending on the connection), after which the connection stops
   producing plaintext-visible structure.
5. Only after this exchange does the client send a standard **TLS 1.2
   ClientHello** (record type `0x16`, version `0x0301`), beginning the actual
   TLS handshake. The observed cipher suite offered/selected is
   `0xC02C` (`TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`), with an ECDHE key
   exchange (`ServerKeyExchange` carrying a ~900-byte certificate chain,
   observed as two chained X.509 certificates in the `Certificate` message)
   and a standard `ServerHelloDone`/`ClientKeyExchange`/`ChangeCipherSpec`/
   `Finished` exchange, after which all further traffic on the connection is
   opaque AEAD-encrypted TLS application data.

This is a noteworthy architectural detail: the game layers a small,
proprietary, unencrypted framing/negotiation exchange **underneath** TLS,
before the TLS handshake itself begins, rather than starting TLS immediately
on connect. Because this pre-TLS exchange is unencrypted, it is visible in
full to any network-layer observer (including a WinDivert-based interceptor),
even though everything that follows it is opaque.

This exact sequence has since been reproduced standalone with a small raw
TCP client, [`pocs/tcp_tls_proxy/plaintext_handshake_sim.cc`](../pocs/tcp_tls_proxy/plaintext_handshake_sim.cc),
which connects directly to a target host/port and replays the four
plaintext steps observed in the capture (naming them, in the tool's own
comments, the "Client Probe", "Server Challenge Frame", "Client TLS Upgrade
Command", and "Server Confirmation Signal"), confirming the fixed header
bytes (`0x46`/salt length `0x20` on the server challenge, `0x0E 01 00 04`
on the client's upgrade command) are stable across independent connection
attempts rather than artifacts of the one captured session.

### Deviation observed on the voice-server connection

The `51000` ("proxy-core") connection does **not** show the server-initiated
36-byte preamble in this capture. Instead, immediately after the TCP
handshake, the client sends a 6-byte all-zero payload (`00 00 00 00 00 00`),
and the very next payload-bearing segment is already a TLS ClientHello. This
suggests the pre-TLS negotiation step observed on the matchmaking/game-server
ports is specific to those service types (or to a per-service
capability/versioning flag) rather than a single fixed framing layer used
identically by every service the client connects to — consistent with
Section 6's finding that this same host, when probed directly outside of a
normal TLS session, can also answer with an entirely different, larger
plaintext response.

## 5. Region-latency probe protocol (port 55002)

The five parallel `55002` connections observed in this capture (one per
probed candidate) do **not** use TLS at all; they exchange short, fixed-shape
binary messages entirely in the clear. [division1_server_list_and_latency_probes.md](division1_server_list_and_latency_probes.md)
analyzed this protocol across five independent sessions and several
additional targeted captures, and its findings are adopted here in place of
this document's original, single-capture description:

- **Framing.** Every message after the initial hello follows
  `[length-byte][payload]`, where `length_byte = 2 × (total_message_length − 1)`.
  The very first server message (`07 03 ac 04`) is a fixed sentinel hello/
  version value rather than a length-derived byte, and is constant across
  every server and session observed.
- **Exchange sequence**, per connection:
  1. Server → client, `07 03 ac 04` — fixed hello/protocol-version sentinel.
  2. Server → client, `06 00 c8 01` — fixed info/capability message.
  3/4/5. Client → server `04 01 NN`, server → client `04 02 NN` — three
     ping/pong rounds, `NN` = 0, 1, 2. Byte 1 of each ping/pong message tags
     the sender (`01` = client, `02` = server); byte 2 is the round sequence
     number. **Exactly three rounds were observed in every capture, on every
     server, across every session.**
  6. Client → server, a final variable-length report of the form
     `[length-byte][03 03][packed samples][trailing byte]`, whose total
     length scales with measured round-trip time (7 bytes for low-latency
     servers, up to 10 bytes for high-latency ones) — consistent with a
     varint-style encoding of the three RTT samples. The trailing byte was
     initially assumed to be a fixed terminator (`18`) but was also observed
     as `17` on some servers/sessions; its exact meaning (checksum,
     packet-loss flag, or a rounding artifact of the varint scheme) is
     unconfirmed.
  7. Client sends `FIN`; the server responds with two back-to-back `RST`
     segments rather than a clean `FIN`/`ACK` teardown.
- **Candidate selection.** Across five independently captured startup
  sessions plus periodic in-session refreshes, the client always probes
  **exactly 5 of the 10** candidate addresses, drawn **at random with
  replacement** — the same index can and does recur across sessions, and no
  fixed rotation or ordering was found. This selection **repeats on a
  roughly 5-minute interval for the life of the client**, not only at
  startup. Across all sessions reviewed, 8 of the 10 indices had been
  observed probed at least once; the remaining two (indices 8 and 9 in the
  companion document's numbering, corresponding to `34.90.202.108` and
  `35.232.75.10`) had never been observed in a probe.
- **Measured latency** (client located in Europe) clustered by GCP region as
  expected for real network paths: ~21–46ms for `europe-west1`/`europe-west4`,
  ~111–112ms for `us-central1`, ~253–258ms for `asia-northeast1`, and
  ~290–295ms for `australia-southeast1`.

Per this repository's own [`README.md`](../README.md) description of
`--resolve-region` and `features.region_enforcement`, the measured
round-trip characteristics are presumably used as one input to region
selection or validation. However, as detailed in Section 6a, the probe
results are best understood as **telemetry reported back to the backend**
rather than as the mechanism that directly selects the authoritative game
host. The absence of TLS on this channel is notable: since the payloads
carry no gameplay-sensitive information (only small counters used for RTT
timing), the developers evidently judged encryption unnecessary here, which
also makes it the easiest of the observed protocols for a third party to
fully understand from traffic alone.

## 6. The server-directory / bootstrap response protocol (`proxy-core`, port 51000)

A separate, out-of-band raw probe against `34.76.151.88` ("proxy-core") —
made outside of the game client, without completing a real TLS session —
returned the following 303-byte plaintext payload instead of, or prior to,
any TLS record:

```
0000   07 03 a4 0c d2 04 00 5d e4 ae 92 e1 3c de f9 a3   .......]....<...
0010   2f 29 df 5f 77 11 ac 86 33 13 14 76 fa df d3 5a   /)._w...3..v...Z
0020   ac 2c 46 55 20 56 6a 0a 0d 31 30 34 2e 31 35 35   .,FU Vj..104.155
0030   2e 34 35 2e 32 35 0e 31 33 36 2e 31 31 30 2e 31   .45.25.136.110.1
0040   30 36 2e 33 37 0e 31 33 36 2e 31 31 32 2e 31 38   06.37.136.112.18
0050   39 2e 31 39 0e 33 34 2e 31 30 34 2e 31 34 33 2e   9.19.34.104.143.
0060   31 36 37 0d 33 34 2e 31 31 36 2e 31 30 39 2e 38   167.34.116.109.8
0070   30 0d 33 34 2e 31 33 2e 32 30 32 2e 32 30 33 0d   0.34.13.202.203.
0080   33 34 2e 31 35 31 2e 31 32 37 2e 39 38 0d 33 34   34.151.127.98.34
0090   2e 37 36 2e 32 34 38 2e 31 33 32 0d 33 34 2e 39   .76.248.132.34.9
00a0   30 2e 32 30 32 2e 31 30 38 0c 33 35 2e 32 33 32   0.202.108.35.232
00b0   2e 37 35 2e 31 30 14 00 d8 ad 03 00 00 00 da ad   .75.10..........
00c0   03 00 01 01 d8 ad 03 16 00 01 da ad 03 16 01 02   ................
00d0   d8 ad 03 23 00 02 da ad 03 23 01 03 d8 ad 03 16   ...#.....#......
00e0   00 03 da ad 03 16 01 04 d8 ad 03 1a 00 04 da ad   ................
00f0   03 1a 01 05 d8 ad 03 1f 00 05 da ad 03 1f 01 06   ................
0100   d8 ad 03 1a 00 06 da ad 03 1a 01 07 d8 ad 03 00   ................
0110   00 07 da ad 03 00 01 08 d8 ad 03 1f 00 08 da ad   ................
0120   03 1f 01 09 d8 ad 03 23 00 09 da ad 03 23 01      .......#.....#.
```

Wireshark's HTTP heuristic mis-tagged this as an "HTTP continuation"
segment, and a browser that requested it reported an invalid HTTP response.
Neither is correct: the bytes are a self-contained, length-prefixed binary
message in the same style as the region-latency probe traffic in Section 5,
not HTTP and not a decrypted TLS record — it is a plaintext response served
directly on connection, before or instead of a TLS session being negotiated.

### Field-by-field breakdown

| Bytes | Value | Interpretation |
| --- | --- | --- |
| `0x00`–`0x01` | `07 03` | Message type/opcode. The same `07 03` prefix appears on the much smaller region-probe responses in Section 5, suggesting a shared opcode family ("topology/info", subtype `03`) reused across endpoints for structurally different payload shapes, rather than a fixed-length message |
| `0x02`–`0x06` | `a4 0c d2 04 00` | Unidentified 5-byte field — plausibly a sequence number, timestamp fragment, or response-length hint; no repeated structure was available across samples to confirm |
| `0x07`–`0x26` | 32 bytes, high entropy | A 32-byte opaque token positioned immediately before the server address list. 32 bytes is also the exact length of an Ed25519/X25519 public key. Given that a sibling connection from the same client run resolves to a host literally named `public-key-store` (Section 3), the most plausible reading is that this token is public-key or key-derivation material the client uses to validate or bootstrap trust in the server list that immediately follows it — this is a structural inference from hostname and length evidence, not a confirmed decode |
| `0x27` | `0a` (10) | Count of address entries that follow |
| `0x28` onward | Pascal-style length-prefixed ASCII strings, e.g. `0d 31 30 34 2e 31 35 35 2e 34 35 2e 32 35` = length `13` + `"104.155.45.25"` | 10 server IPv4 addresses in dotted-decimal text form. All 10 addresses exactly match, as a set, the 10 addresses already hard-coded across `servers.addresses` and the `EU`/`ASIA`/`US`/`OCEANIA` groups in [`profiles/div1.sw.yml`](../profiles/div1.sw.yml) (only the order differs) |
| After the address list | `14` (20) | Count of 6-byte records that follow (2 per server × 10 servers) |
| Each 6-byte record | e.g. `d8 ad 03 00 00 00` / `da ad 03 00 01 01` | A repeating `[d8|da] ad 03 [selector] [00|01] [index]` shape: a constant 2-byte tag body (`ad 03`) preceded by an alternating discriminator byte (`d8` or `da`), a `selector` byte that takes only 5 distinct values (`00`, `16`, `1a`, `1f`, `23`) across the whole table, a flag byte that mirrors the `d8`/`da` discriminator (`00`/`01`), and a final byte that increments once per server index (`00`–`09`) |

The 6-byte record table's counts line up neatly with
[`profiles/div1.sw.yml`](../profiles/div1.sw.yml)'s grouping of the same 10
addresses into 5 named groups of 2 servers each (`servers.addresses`, `EU`,
`ASIA`, `US`, `OCEANIA`): it contains exactly 20 records (2 per server) and
the `selector` byte takes exactly 5 distinct values. This document originally
treated that count match as reasonably strong support for "selector = region/
group ID, discriminator = per-server role/port". [division1_server_list_and_latency_probes.md](division1_server_list_and_latency_probes.md),
which examined this exact same blob via static analysis of the client's
embedded server-list resource (not just this one network response), is more
conservative: it describes the repeated `selector` values as "consistent with
static offsets/category tags rather than a cache of runtime data" but
explicitly lists the exact semantics of the selector byte and the two-record-
per-slot structure as an **open, unconfirmed question**. This document
defers to that more cautious conclusion — the region/group-ID mapping
remains a plausible but unverified hypothesis, not a confirmed decode.

### Implication

The fact that this same byte layout was independently found via static
analysis of the client's own shipped resources, and via a live raw-socket
response from `proxy-core`, indicates this is a shared serialization format
used both for a default list embedded in the client and for any
server-refreshed copy of it, rather than something invented solely for this
one network response. This means the server list in
[`profiles/div1.sw.yml`](../profiles/div1.sw.yml) reflects a real, currently-valid
candidate pool by two independent lines of evidence (embedded resource and
network response) — but, per Section 6a below, that candidate pool is not
necessarily identical to the pool of servers eligible for actual game-host
assignment.

## 6a. The candidate probe pool is decoupled from the authoritative game-host assignment

The single most important correction from
[division1_server_list_and_latency_probes.md](division1_server_list_and_latency_probes.md)
to this document's original analysis is this: **the server ultimately
assigned as the authoritative game host in the one fully-traced session
(`34.90.202.108`) had never once appeared in that session's `55002` probes,
and has never been observed in a probe in any session reviewed.** Combined
with the persistent, low-traffic "lobby" connection described in Section 3
(held open on a separate `55000` connection for the duration of any menu
session, to a different, europe-west1 address), this indicates:

- The `55002` probe results are most plausibly **client-to-backend
  telemetry**, likely reported to the lobby connection, rather than a
  client-side server-selection algorithm in their own right.
- The actual assignment of a game-hosting IP is a **backend decision**,
  communicated to the client over the lobby connection, using inputs not
  observable purely from the `55002` traffic.
- The pool of servers eligible to be assigned as an authoritative game host
  may be **partially or fully disjoint** from the 10-address list that is
  both embedded in the client and probed over `55002`.

This matters directly for this repository's own tooling: `lagsw`'s
`servers.discovery_port` mechanism (see [`README.md`](../README.md))
identifies the "authoritative server" as whichever configured address
receives the most packets on a given port during a discovery window. Because
the candidate pool in [`profiles/div1.sw.yml`](../profiles/div1.sw.yml) is drawn
from the same 10-address list used for `55002` probing, and that list is not
guaranteed to contain the real game host, `lagsw`'s discovery/server-list
approach should be treated as a best-effort heuristic that may need its
`servers` list extended if a session's real game host turns out not to be one
of the 10 known candidates.

## 7. Steady-state game-session traffic pattern (post-handshake)

Once the TLS handshake on the main `34.90.202.108:55000` game-server
connection completes, the observed steady-state pattern (visible only at the
TCP-segment-size level, since payloads are AEAD-encrypted) is a repeating,
regular cadence:

- The **server** periodically pushes a small encrypted PSH segment,
  consistently in the 35–95 byte range in the observed window (most commonly
  ~39 bytes), at what appears to be a roughly fixed interval.
- The **client** replies to most of these with a fixed 6-byte encrypted ACK
  payload (i.e. a minimal application-layer acknowledgment riding on top of
  the TCP ACK, distinct from a bare TCP ACK with no payload), before the next
  server push arrives.
- Larger, irregular bursts (in the hundreds-of-bytes to ~1360-byte,
  near-MTU range) appear interleaved with this steady cadence, consistent
  with bulk/state-sync payloads (e.g. initial world-state replication) rather
  than the regular small per-tick pushes.

This is consistent with a **server-push, tick-driven session model** over a
single persistent TCP connection: the server emits small, frequent state
updates on its own schedule, the client acknowledges each at the application
layer, and larger irregular transfers correspond to bulk state replication
events. This matches the general assumption underlying both companion
documents — that the server is the authoritative source of world/combat
state pushed to the client, and that the client's own outbound messages
(fire, movement input, equip changes) are comparatively small, frequent,
individually-acknowledged application messages layered on the same
connection — which is exactly the kind of stream that a `from_timestamp` or
`ratio`-style packet-delay profile (as implemented by `lagsw`, see
[`include/packet_engine.h`](../include/packet_engine.h)) is built to
selectively hold and release.

## 8. Relationship to the exploit documents and to `lagsw`'s configuration

This capture provides direct, observation-based support for several claims
made in the companion exploit documents and encoded in
[`profiles/div1.sw.yml`](../profiles/div1.sw.yml):

- The exclusive use of TCP for the game session (Section 2) confirms the
  premise, used throughout both exploit documents, that packet delay/drop is
  operating on TCP segments — including the head-of-line-blocking behavior
  that lets a single held segment stall an entire logical stream until
  released, which is central to how the "release a burst on demand" behavior
  in both exploits is achieved.
- The server list and `55002` probe port already present in
  [`profiles/div1.sw.yml`](../profiles/div1.sw.yml) are shown to be accurate,
  currently-live values, not placeholders, since they match observed traffic
  exactly (Section 3).
- The steady-state, small-frequent-push/small-frequent-ack cadence on the
  main session (Section 7) is consistent with the companion documents'
  model of a server-authoritative combat/position stream layered with
  client-originated action events on the same connection, which is the
  precondition both exploit documents rely on for delaying/reordering
  specific classes of client-originated packets (fire events, equip-swap
  events) independently of the server's ongoing push stream.
- The server-directory response served by `proxy-core` (Section 6) confirms
  that the exact 10-address candidate server set used throughout this
  repository's [`profiles/div1.sw.yml`](../profiles/div1.sw.yml) is the game's real,
  dynamically-served topology rather than a static snapshot that could go
  stale, which matters for keeping `lagsw`'s `servers` groupings and
  `discovery_port` behavior aligned with the live environment.
- The TLS encryption observed on the matchmaking/voice/game connections
  (Section 4) means a network-layer interceptor cannot read or selectively
  target packets *by application-level content* (e.g. "the packet that says
  I fired the shotgun") — it can only discriminate by externally observable
  properties: direction, timing, and segment length. This directly explains
  why the RPM exploit document's Variant 3 (targeting a specific inbound
  packet) is reported as being dependent on "a specific packet length" or "an
  exact moment in time" rather than on parsing any recognizable field —
  those are the only two discriminators available once payloads are opaque,
  matching this repository's own filter language (WinDivert filters can match
  on `tcp.PayloadLength` and direction, but not on decrypted application
  content).

## 9. Limitations

- The capture reflects a single client, a single session, and only the
  connect/handshake phase plus a short window of the main game-server
  session; it does not include actual combat/damage traffic, so it cannot by
  itself confirm the specific weapon-swap or RPM misattribution behavior
  described in the companion documents — it only establishes the transport
  and framing context those exploits operate within.
- All conclusions about the meaning of the unencrypted pre-TLS preamble bytes
  (Section 4), the region-probe message bytes (Section 5), and the
  server-directory response fields (Section 6) are inferred from observed
  structure, repetition, byte-length coincidences (e.g. the 32-byte token),
  and matching counts against this repository's own configuration, not from
  any authoritative protocol specification or vendor documentation; the exact
  semantics of individual fields beyond the observed incrementing counters
  and address list are working hypotheses, not confirmed decodes.
- Port- and hostname-based service role attribution (Section 3) is a
  reasonable inference from DNS names and matching known server addresses
  already present in this repository's configuration, not from decrypted
  application-layer confirmation of each service's actual function.
- The Section 6 directory response was obtained out-of-band (a raw probe
  against `proxy-core` outside of a normal client session), not from within
  the original `full-init.pcapng` capture itself, so its relationship to the
  exact sequencing of a real client session (e.g. whether a real client ever
  receives this exact plaintext response, or only an equivalent message
  inside its TLS session) is not established.
- As detailed in Section 6a, this document's original single-capture
  analysis could not, and did not, establish how the authoritative game host
  is actually selected; treat any assumption that "the probed/`profiles/div1.sw.yml`
  candidate list is the same as the assignable game-host pool" as unverified,
  per [division1_server_list_and_latency_probes.md](division1_server_list_and_latency_probes.md).
  That document's own open questions (exact `selector`-byte semantics, varint
  scale factor for RTT samples, the `17`/`18` trailing-byte anomaly, whether
  indices 8/9 are structurally excluded from probing, and what data on the
  lobby connection actually drives game-host assignment) remain unresolved
  and apply equally here.

## 10. Summary

The capture and follow-up probes show The Division 1 using a multi-
connection, all-TCP session model built around at least five distinct
backend roles: a public-key bootstrap service (`public-key-store`, port
27015), a directory/config broker (`proxy-core`, port 51000) that can supply
the full list of candidate backend servers and a per-server port/role table,
parallel unencrypted region-latency probes to a random 5-of-10 subset of
candidate servers (port 55002, refreshed roughly every 5 minutes), a
persistent low-traffic "lobby" connection held for the duration of any menu
session (port 55000), and a separate, high-traffic authoritative game-server
connection opened only once a match starts (also port 55000, but to a
server-assigned IP that is not guaranteed to be a member of the probed
candidate set). Every one of these connections, except the region probe and
the raw directory response, wraps a short proprietary unencrypted handshake
and then a standard TLS 1.2 session (AES-256-GCM/ECDHE) around the actual
application traffic, after which the game session settles into a regular
small server-push / small client-ack cadence consistent with a
server-authoritative, tick-driven combat and world-state stream. These
findings directly corroborate the server list and probe-port configuration
already present in [`profiles/div1.sw.yml`](../profiles/div1.sw.yml) and support
the transport-layer assumptions made in the companion analyses of the
weapon-swap lag switch and the RPM exploit family — while also showing, per
[division1_server_list_and_latency_probes.md](division1_server_list_and_latency_probes.md),
that the probed candidate pool and the actual game-hosting server are
decoupled systems, which is the most important open caveat for anyone relying
on this repository's `servers` configuration to locate a live game session.
