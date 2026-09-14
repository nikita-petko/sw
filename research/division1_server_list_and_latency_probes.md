# Server List File & Latency-Check Protocol — Analysis Notes

*Reverse-engineering notes compiled from static analysis of an embedded server-list binary blob and packet captures of the associated client traffic (Tom Clancy's The Division 1).*

---

## 1. Overview

The client embeds a small binary blob containing a **candidate server list** (10 IPs) plus a static per-slot metadata table. On startup — and again periodically during play — the client runs a lightweight **plaintext TCP latency-check protocol on port 55002** against a subset of these candidates. Separately, a **persistent low-traffic connection on port 55000** is held open to a fixed "lobby" server for the duration of any menu session, and a **second, high-traffic 55000 connection** is opened to a different server once a match actually starts.

Key conclusion: **the 55002 latency probes and the actual authoritative game-server assignment appear to be two separate systems.** The probe results look like telemetry reported back to a backend service; the real game-hosting IP is assigned server-side and is not guaranteed to be a member of the probed set.

---

## 2. The Embedded Binary Blob

### 2.1 Structure

```
[ ~20-byte header/checksum-looking blob, high entropy ]
[ 10x length-prefixed ASCII IP strings ]
[ 1-byte count = 0x14 (20) ]
[ 20x 6-byte records, in pairs, indexed 0–9 ]
```

### 2.2 IP List (10 candidates, indices 0–9)

| Idx | IP | GCP Region | Approx. location |
|---|---|---|---|
| 0 | 104.155.45.25 | europe-west1 | Belgium |
| 1 | 136.110.106.37 | asia-northeast1 | Tokyo |
| 2 | 136.112.189.19 | us-central1 | Iowa |
| 3 | 34.104.143.167 | asia-northeast1 | Tokyo |
| 4 | 34.116.109.80 | australia-southeast1 | Sydney |
| 5 | 34.13.202.203 | europe-west4 | Netherlands |
| 6 | 34.151.127.98 | australia-southeast1 | Sydney |
| 7 | 34.76.248.132 | europe-west1 | Belgium |
| 8 | 34.90.202.108 | europe-west4 | Netherlands |
| 9 | 35.232.75.10 | us-central1 | Iowa |

Regions represented: **Europe ×4, Asia (Tokyo) ×2, Australia (Sydney) ×2, US (Iowa) ×2.**

Region assignments were resolved against Google's published GCP IP-range registry (`gstatic.com/ipranges/cloud.json`), matching each IP to its most specific announced prefix.

### 2.3 Per-Slot Metadata Table

Following the count byte (`0x14` = 20 records), 20 six-byte records appear in pairs per index:

```
d8 ad 03 [XX] 00 [N]
da ad 03 [XX] 01 [N]
```

- `N` runs 0x00–0x09, one pair per IP-list index.
- `d8 ad 03` / `da ad 03` distinguish the two records in each pair (flag byte `00` vs `01`).
- `XX` cycles through only five distinct values (`00, 16, 1a, 1f, 23`), reused across multiple indices rather than being unique per server — consistent with static offsets/category tags rather than a cache of runtime data (e.g. not stored RTT results).

**Open question:** exact semantics of `XX` and the two records per slot are unconfirmed.

---

## 3. The Latency-Check Protocol (port 55002)

### 3.1 Transport

Plain TCP, **unencrypted**. No authentication observed. Each probe is a short-lived connection: connect → exchange → clean disconnect (FIN from client, RST from server).

### 3.2 Message Framing

Every message (after an initial fixed hello) is: **`[length-byte][payload]`**, where:

```
length_byte = 2 × (total_message_length − 1)
```

This holds for every observed message *except* the very first server "hello," which uses a fixed sentinel value instead of a length-derived one. There is no separate explicit length field — the first byte does double duty as both a message discriminator and an implicit length.

### 3.3 Exchange Sequence

| # | Direction | Payload (hex) | Purpose |
|---|---|---|---|
| 1 | Server → Client | `07 03 ac 04` | Hello / protocol version (constant across all servers & sessions) |
| 2 | Server → Client | `06 00 c8 01` | Info / capability flags (constant across all servers & sessions) |
| 3 | Client → Server | `04 01 00` | Ping, seq 0 |
| 4 | Server → Client | `04 02 00` | Pong, seq 0 |
| 5 | Client → Server | `04 01 01` | Ping, seq 1 |
| 6 | Server → Client | `04 02 01` | Pong, seq 1 |
| 7 | Client → Server | `04 01 02` | Ping, seq 2 |
| 8 | Server → Client | `04 02 02` | Pong, seq 2 |
| 9 | Client → Server | `0c/0e/12 03 03 ... 17/18` | Final report (see §3.4) |
| — | Client → Server | FIN | Connection close |
| — | Server → Client | RST, RST | Abrupt teardown (no clean FIN/ACK) |

Byte 1 of the ping/pong messages tags the sender: `01` = client, `02` = server. Byte 2 is the round sequence number (0, 1, 2). **Exactly 3 rounds observed in every capture, on every server, across every session.**

### 3.4 Final Report Message

Format: `[length-byte][03][03][...packed sample bytes...][terminator]`

- Total length scales with measured RTT: short (7 bytes) for low-latency servers, up to 10 bytes for high-latency ones — consistent with a **variable-length integer (varint-style) encoding** of the 3 RTT samples, where larger values consume more bytes.
- `03 03` header bytes and the packed samples are followed by a trailing byte that was initially assumed to be a fixed terminator (`18`) — **this assumption did not hold** across all sessions: several servers/sessions produced a trailing `17` instead. The exact meaning of this byte (checksum, packet-loss flag, rounding artifact of the varint scheme, etc.) is **unconfirmed**.
- The report content is **highly repeatable**: the same server produces byte-for-byte or near-identical final reports across independent sessions, and different servers in the same GCP region produce near-identical reports to each other. This strongly indicates the encoded values track real, physically-consistent network latency rather than random or synthetic data.

### 3.5 Measured Latency by Region (client located in Europe)

| Region | Observed avg RTT |
|---|---|
| europe-west1 / europe-west4 | ~21–46 ms |
| us-central1 | ~111–112 ms |
| asia-northeast1 | ~253–258 ms |
| australia-southeast1 | ~290–295 ms |

These values are consistent with real-world fiber-path round-trip times for the corresponding geographic distances from a Europe-based vantage point.

---

## 4. Candidate Selection Behavior

Across five independently captured startup sessions, the client probed the following subsets of the 10-entry list:

| Session | Indices probed |
|---|---|
| 1 | 1, 2, 4, 5, 7 |
| 2 | 0, 5, 2, 4, 3 *(part of the same batch as session 1)* |
| 3 | 0, 3, 2, 4, 5 |
| 4 | 0, 5, 2, 3, 6 |

- Every session probes **exactly 5 of the 10** candidates.
- **Repeats are allowed** — the same index has appeared across multiple sessions, and within the observed data the selection does not follow any fixed rotation or sequential order.
- Combined across sessions, **8 of the 10 indices** have now been observed in a probe (all except idx 8 and idx 9).
- **The user's own instrumentation confirms this refreshes periodically during play (every 5 minutes), again against 5 random servers with repeats permitted** — which supports the conclusion that the *initial* startup selection is drawn from the same random-with-replacement process, rather than being a distinct one-time algorithm.

**Conclusion: candidate selection for the 55002 probe is a random sample of 5 (with replacement) from the 10-entry list, repeated on a ~5-minute interval throughout the client's lifetime, not just at startup.**

---

## 5. The Lobby / Session Server (port 55000)

### 5.1 Behavior

- A single connection to one of the **europe-west1 candidates** (`104.155.45.25` or `34.76.248.132`) is opened on port 55000 as soon as the home-menu loading screen appears.
- This connection is **low-traffic** (single-digit packet counts over multi-second windows) and stays open for the entire duration spent in menus.
- The IP used for this role is **not fixed to one specific address** — it has been observed alternating between the two europe-west1 candidates across sessions — but both belong to the same region and both are also members of the general 10-IP probe pool (i.e., they get probed on 55002 like any other candidate; being probed does not exempt or confirm a server for this role).

### 5.2 Role

Strongly consistent with an account/session, presence, matchmaking-queue, or telemetry endpoint — i.e. a control-plane "lobby" service, not a game-simulation host.

---

## 6. The Authoritative Game Server (port 55000, second connection)

### 6.1 Behavior

- A **second**, separate connection to port 55000 is opened against a **different IP** at the moment gameplay actually begins (loading into the match/world).
- This connection is **high-traffic**: in one full session capture, the assigned server sent on the order of ~95 packets in a 5-second window (vs. 1 packet in 5 seconds for the lobby connection) — consistent with continuous real-time game-state traffic.
- Shortly after this connection opens, a large burst of back-to-back, near-maximum-size TCP segments (~1300+ bytes each) was observed — plausibly a full world/session state push as the client loads into the match.

### 6.2 Key Finding — Decoupled from the 55002 Probe Pool

In the one full-session capture available, the server that was ultimately assigned as the authoritative game host (`34.90.202.108`, idx 8, europe-west4) **had never appeared in that session's 55002 probes at all.** This has held true across every capture reviewed: **idx 8 has never once been observed in a latency probe, in any session, despite being the actual game host in the one full session traced end-to-end.**

This indicates:
- The 55002 probe results are most plausibly **telemetry reported to the lobby/backend service**, used (if at all) as one input among others to a server-side matchmaking decision.
- The **actual assignment of a game-hosting IP is a backend decision**, communicated to the client via the lobby connection, and is not simply "whichever probed candidate had the lowest RTT."
- The pool of servers eligible to be assigned as an authoritative game host may be **partially or fully disjoint** from the 10-IP list embedded in the client binary and exercised by the 55002 probe.

---

## 7. Summary Model

```
Startup
  │
  ├─▶ [55002] Probe 5 of 10 candidate IPs (random, w/ replacement)
  │      – plaintext, 3-round ping/pong + varint-encoded latency report
  │      – repeats every ~5 minutes for the life of the session
  │      – purpose: appears to be telemetry only
  │
  ├─▶ [55000] Open persistent low-traffic connection to a europe-west1
  │      candidate ("lobby" server) — held for entire menu dwell time
  │
  └─▶ On entering a match:
         [55000] Open a NEW connection to a server-assigned IP
            – high traffic, real-time game state
            – NOT guaranteed / observed to be a member of the
              probed candidate set
```

---

## 8. Open Questions

1. Exact semantics of the `XX` byte and the two-record-per-slot structure in the embedded metadata table.
2. Exact encoding/units of the varint-style latency samples in the final-report message (scale factor unconfirmed).
3. Meaning of the trailing byte in the final report (`17` vs `18` — not clearly tied to region, server, or observed RTT bucket).
4. Whether idx 8 and idx 9 are ever probed on 55002 under any circumstance, or structurally excluded from the probe pool while remaining eligible for game-host assignment.
5. What data, if any, is exchanged over the lobby (55000) connection that determines the eventual game-host assignment — not captured/analyzed here.

---

*Compiled from static binary analysis and multiple packet captures (`port_55002.pcapng`, `port_55002_others.pcapng`, `port_55002_again.pcapng`, `full-init.pcapng`, `port_55002_other.pcapng`).*