# PoC: TLS Record Segment Removal by Size Filter

## 1. Summary

Add a packet-mutation mode that inspects the TLS record layer inside a captured TCP payload, matches individual TLS records ("segments") against a size filter, and removes the matching records from the packet before it is reinjected. The mode never requires TLS decryption: the 5-byte TLS record header (content type, protocol version, record length) is always sent in the clear, even for encrypted application-data records, so record boundaries and sizes are fully visible to a WinDivert-level interceptor.

This is a packet-mutation feature, not a stream proxy. It fits the existing `PacketMode` model in [packet_engine.h](../include/packet_engine.h) and [packet_mode.h](../src/modules/packet_mode.h): one packet in, zero-or-one mutated packet out, with the same capture/queue/release pipeline already used by `drop`, `ratio`, and `hold_and_send`. It must only be used against traffic and endpoints the operator is authorized to intercept.

```mermaid
flowchart LR
    P[Captured packet\nWinDivert] --> PH[Parse IP/TCP headers]
    PH --> W[Walk TLS record layer]
    W --> M{Any record\nmatches size_filter?}
    M -->|no| PASS[Pass through unmodified]
    M -->|yes| SEL[Apply selection strategy\nall / first / last / random / n]
    SEL --> SPLICE[Splice out selected record bytes]
    SPLICE --> RENUM[Correct SeqNum / AckNum\nusing profile-scoped N]
    RENUM --> REFRAME[Recompute IP length, PSH flag,\nIP/TCP checksums]
    REFRAME --> SEND[Reinject via WinDivertSend]
    PASS --> SEND
```

## 2. Terminology

- **Segment**: one TLS record as framed by the TLS record layer: `struct { uint8 type; uint16 legacy_record_version; uint16 length; opaque fragment[length]; }` (5-byte header + `length` bytes of fragment, `length` ≤ 16384 + 256 for TLS 1.3 or 16384 for TLS 1.2/1.0). "Segment size" in this document always means the *total* on-wire record size (`5 + length`), not the fragment length alone, unless a filter explicitly targets the fragment length.
- **Coalesced packet**: a single TCP segment (in the TCP/IP sense) whose payload contains more than one TLS record back-to-back, as observed repeatedly in the existing pcap analysis (e.g. `ServerHello` + `Certificate` + `ServerKeyExchange` + `ServerHelloDone` inside one 954-byte payload — see [division1_networking_architecture_pcap_analysis.md](../research/division1_networking_architecture_pcap_analysis.md)).
- **Straddled record**: a TLS record whose bytes are split across two or more TCP segments. This mode operates on one WinDivert-captured packet at a time and cannot see the rest of the byte stream, so straddled records are a hard limitation (see §7).
- **Removal**: excising a matched record's on-wire bytes from the packet's TCP payload, shrinking the packet, and repairing every affected header field so the result is still a well-formed IPv4/TCP packet.

## 3. Motivation

Existing modes (`drop`, `ratio`, `hold_and_send`, etc.) act on whole packets. Several coalesced TLS packets carry more than one logical message per packet (handshake messages during setup, and potentially multiple small application-data records once a session is established). A whole-packet drop is too coarse when only one record inside a coalesced packet is the target — dropping the packet also discards unrelated records, and (per §7) it is not equivalent to removing only the intended record's bytes.

A size-based filter is useful because:

- Ciphertext defeats content matching, but AEAD framing keeps a fixed per-plaintext-byte expansion (record length = plaintext length + explicit IV/tag/padding overhead depending on cipher suite), so a record's on-wire size is often a stable, decryption-free proxy for "what kind of message this probably is" (e.g. small fixed-size heartbeats/acks vs. larger state pushes), consistent with the size-based fingerprinting already used in [division1_networking_architecture_pcap_analysis.md](../research/division1_networking_architecture_pcap_analysis.md) (`34-byte` `17 03 03` application-data records observed repeatedly).
- It requires no protocol decoding beyond the public, unencrypted record header.

## 4. Goals

1. Parse the sequence of TLS records inside a single captured packet's TCP payload, without requiring TLS termination or key material.
2. Evaluate a compact, explicit filter syntax against each record's size.
3. Select which matching record(s) to remove according to a configurable selection strategy.
4. Produce a correctly re-framed IPv4/TCP packet: correct IP total length, correct TCP header length (unchanged), correct TCP/IP checksums, and a corrected `PSH` flag when the resulting payload is empty.
5. Make the sequence-number consequences of shrinking a live TCP stream an explicit, documented, and testable part of the design (see §8) rather than an afterthought.

## 5. Non-goals

- Decrypting or re-encrypting TLS application data.
- Handling records that straddle more than one captured packet (§7 documents the limitation and the safe fallback).
- Rewriting TLS handshake messages (`ClientHello`/`ServerHello`/certificates); the mode may still remove them by size, but it does not validate that doing so keeps the handshake state machine consistent — removing handshake records is expected to break the handshake and is primarily useful against already-established application-data traffic.
- Providing a general stream-rewriting proxy. If full correctness under retransmission and reordering turns out to require this, that is an explicit escalation point, not something this mode silently attempts (see §8.4).

## 6. Filter syntax

The filter is a single expression evaluated against the total on-wire size (`5 + length`) of one TLS record. Supported forms, in order of precedence in the grammar:

| Form | Meaning | Example |
|---|---|---|
| `N` | size equals `N` | `34` |
| `X..Y` | size in the inclusive range `[X, Y]` | `40..120` |
| `>X` | size strictly greater than `X` | `>512` |
| `<X` | size strictly less than `X` | `<64` |
| `>=X` | size greater than or equal to `X` | `>=1024` |
| `<=X` | size less than or equal to `X` | `<=48` |

Grammar (informal EBNF):

```text
filter      := clause ("," clause)*
clause      := exact | range | comparison
exact       := integer
range       := integer ".." integer
comparison  := ("<" | ">" | "<=" | ">=") integer
integer     := digit+          ; unsigned, 0..65540 (5 + max TLS record length)
```

Notes:

- A comma-separated `filter` is the union (logical OR) of its clauses; a record matches if it matches any clause. This mirrors the existing profile filter style of combining independent predicates (e.g. `disables` accepting a list) rather than inventing boolean operators.
- `X..Y` requires `X <= Y`; the loader must reject `Y < X` as a configuration error rather than silently matching nothing.
- Bounds are validated against the protocol's own record-size ceiling (16389 bytes for TLS 1.2/1.0's plaintext max, 16645 accounting for TLS 1.3 `content-type` byte and up to 255 bytes of padding) at load time so typos surface immediately instead of silently never matching.
- Whitespace around clauses and operators is trimmed by the loader; the stored/compiled form has none.
- There is no filter for record *content type* (handshake/alert/application-data/change-cipher-spec) in the first iteration; adding one is a natural, low-risk follow-up (§13) that composes with the size filter using the same comma-list-as-OR convention, or an explicit `type:` prefix if AND-composition with size is needed later.

### 6.1 Configuration shape

Proposed profile-level extension, additive to the existing `ProfileOptions`/`profiles.schema.json` shape and independent of `delay_mode` (a profile can combine packet-level delay/ratio behavior with segment removal, or use segment removal with `delay_mode: from_timestamp` and no additional delay):

```yaml
profiles:
  - name: "Strip small app-data records"
    key: k
    mode: toggle
    filter: "tcp.Psh and tcp.SrcPort == 55000"
    segment_removal:
      enabled: true
      size_filter: "34, 40..48, <32"
      selection: all        # all (default) | first | last | random | n
      count: 1               # required only when selection == n
```

`size_filter` and `selection`/`count` are validated the same way other profile fields are validated in `options.cc`/`profiles.schema.json`: reject unknown keys, reject `count` without `selection: n`, reject `count <= 0`.

## 7. Segment identification and the straddled-record limitation

For each captured packet with a non-empty TCP payload:

1. Parse the IPv4 and TCP headers with `WinDivertHelperParsePacket` (as already done throughout [packet_mode.cc](../src/modules/packet_mode.cc)) to get the payload pointer and length.
2. Walk the payload as a sequence of candidate TLS records: read `type` (1 byte), `version` (2 bytes), `length` (2 bytes, big-endian), then expect `length` bytes of fragment.
3. If the bytes remaining are fewer than 5, or a declared `length` would run past the end of the payload, treat the *remaining* bytes as an **unparsed tail**, not a record. The tail is left untouched by the size filter (it cannot be evaluated because its true size is unknown from this packet alone) and is never removed.
4. A payload that parses as zero complete records (e.g. plaintext pre-TLS control bytes, or the pre-TLS probe/challenge frames documented in [tcp_tls_proxy.md](tcp_tls_proxy.md#171-captured-protocol-lifecycle-overview)) is passed through unmodified — the segment filter only ever acts on payload that fully decodes as one or more TLS records.

```mermaid
flowchart TD
    Start([Start at payload offset 0]) --> Check{Bytes remaining\n>= 5?}
    Check -->|no| Tail[Remaining bytes = unparsed tail\nleft untouched]
    Check -->|yes| Hdr[Read type, version, length]
    Hdr --> Full{length bytes\nfit in payload?}
    Full -->|no| Tail
    Full -->|yes| Rec[Complete record found:\noffset, total size = 5 + length]
    Rec --> Filter{size matches\nsize_filter?}
    Filter -->|yes| Mark[Mark as candidate for removal]
    Filter -->|no| Keep[Keep record as-is]
    Mark --> Advance[Advance offset by 5 + length]
    Keep --> Advance
    Advance --> Check
    Tail --> Done([Done: candidate list + tail])
```

This means:

- A packet whose payload is exactly one or more complete, non-straddled TLS records is fully eligible for filtering.
- A packet whose *last* record is truncated because the record continues in a later TCP segment only has its complete leading records evaluated; the truncated tail is preserved as-is and reattached after any removed leading records.
- A record that starts *before* the current packet (i.e., the current packet is a continuation of a record whose header appeared in an earlier packet) cannot be identified as a record at all from this packet in isolation, and the whole payload is treated as an unparsed tail and passed through.

Because coalescing is common at the start of a TLS session (handshake messages) but far from guaranteed in application-data traffic — a busy stream can just as easily split one record across two packets as it can coalesce several into one, depending on write sizes, Nagle/`TCP_NODELAY`, and MSS — **this mode is a best-effort, per-packet filter. It is not a substitute for a stream reassembler.** A production version that must reliably match every occurrence of a given record size regardless of TCP segmentation would need the reassembly machinery already scoped out in [tcp_tls_proxy.md](tcp_tls_proxy.md) (§6, "Stream buffer"), which is explicitly out of scope here.

## 8. Removal, re-framing, and sequence-number consequences

This is the part of the design that most needs to be correct, because it mutates a live, ordered, acknowledged byte stream. Two candidate strategies exist; only one is recommended for this PoC.

### 8.1 Strategy A (recommended): true splice with profile-scoped SEQ/ACK correction

Removing a record's bytes shortens the TCP payload by exactly the record's total on-wire size. This is a single physical TCP connection passing through WinDivert in place — not a proxy splitting it into two independent hops — so the correction only needs to keep each real endpoint's own internally consistent expectations satisfied, not maintain a synthetic second sequence space.

Take a profile whose filter removes bytes only from client→server packets (server→client removal is the mirror image with client/server swapped — see §8.1.1 for why a profile should only ever target one direction). Before any removal, client and server are synchronized: `Client: SEQ=1, ACK=1` / `Server: SEQ=1, ACK=1`.

The client sends 16 bytes: `C→S PSH,ACK SEQ=1 ACK=1 LEN=16`. The client's own internal state now expects an ACK of 17 back, and will use `SEQ=17` for its own next packet — regardless of what happens to this packet in flight.

If the engine removes 2 bytes (`N=2`), it forwards `C→S PSH,ACK SEQ=1 ACK=1 LEN=14` — `SeqNum` on the trimmed packet itself is left untouched; only the payload/`LEN` shrinks. The server, having only received 14 bytes starting at `SEQ=1`, correctly ACKs `S→C ACK SEQ=1 ACK=15`. Left alone this desynchronizes both sides: the client is waiting for `ACK=17`, and the client's next packet will arrive at the server carrying `SEQ=17`, two bytes ahead of the `15` the server expects next.

The fix is two single-field, single-direction rewrites driven by the same tracked counter `N` (bytes removed so far on the tracked direction):

1. **Reverse-direction ACKs**: every `S→C` packet's `AckNum` is increased by `N` before it reaches the client, so the client sees the ACK number it expects for the bytes *it* believes it sent (`15 + 2 = 17`).
2. **Forward-direction SEQs**: every subsequent `C→S` packet's `SeqNum` is decreased by `N` before it reaches the server, so the server sees the SEQ number it expects for the bytes it actually has (`17 - 2 = 15`).

```mermaid
sequenceDiagram
    participant Client
    participant Engine as WinDivert (in-path, single connection)
    participant Server

    Note over Engine: profile activates, N = 0

    Client->>Engine: C to S SEQ=1 ACK=1 LEN=16 (PSH,ACK)
    Engine->>Engine: remove 2 bytes, LEN 16 to 14, SeqNum unchanged, N += 2 (N=2)
    Engine->>Server: C to S SEQ=1 ACK=1 LEN=14

    Server->>Engine: S to C ACK SEQ=1 ACK=15
    Engine->>Engine: AckNum' = 15 + N(2) = 17
    Engine->>Client: S to C ACK SEQ=1 ACK=17

    Note over Client: client's own state now expects to send SEQ=17 next
    Client->>Engine: C to S SEQ=17 ACK=1 LEN=2 (PSH,ACK)
    Engine->>Engine: SeqNum' = 17 - N(2) = 15
    Engine->>Server: C to S SEQ=15 ACK=1 LEN=2
```

Neither real endpoint ever observes a value it doesn't expect: the client's ACKs always match what it believes it sent, and the server's SEQs always match what it has actually received. The discrepancy only ever exists inside the engine's own `N` counter.

Further considerations building on this:

1. `N` only ever accumulates upward — every additional removal on the tracked direction adds to it — and is never decreased except by the reset described in point 3.
2. SACK blocks (`TCP_OPT_SACK`) and TCP timestamp echoes referencing pre-shrink sequence numbers are not rewritten by this design; either strip them from affected packets or scope the profile's filter to exclude peers that negotiate SACK, since a stale SACK block is a correctness bug, not a cosmetic one.
3. **`N`'s lifetime is scoped to the profile's activation, not the connection.** `N` starts at 0 when the profile activates (toggle on, or key held for `mode: hold`) and is discarded back to 0 the instant the profile deactivates, mirroring the existing per-direction state already reset in `PacketMode::reset()` (see [packet_mode.h](../src/modules/packet_mode.h) `last_sent_ack_`/`has_last_sent_ack_`). While active, every packet in both directions on the tracked connection continues to be corrected using the current `N`; once deactivated, correction stops immediately and unconditionally — there is no drain or gradual rollback.
4. Deactivating mid-connection leaves the two real endpoints permanently off by the final value of `N` — the physical bytes already removed cannot be un-removed after the fact. Once correction stops, the client's next real `SeqNum` and the server's next expected sequence number differ by `N`, indistinguishable from either endpoint's perspective from `N` bytes having been silently lost on the wire. Recovery is left entirely to the two endpoints' own TCP stacks (duplicate ACKs, retransmission timeout, most likely ending in the connection being reset and re-established) rather than anything this engine does. This is acceptable for short, deliberately-triggered activations — "a little amount of lag" while the endpoints resync or reconnect — and is precisely why this is not proposed as a permanent, connection-lifetime mechanism in the baseline design.
5. A variant that keeps correcting forever regardless of profile activation state — so the two endpoints never have to resync — is possible in principle, but it requires `N` to live in a new, connection-scoped state store that outlives any single profile's activation window, which is a materially bigger architectural change than the profile-scoped tracker above. This is deferred as an open question (§14) rather than part of the baseline design.
6. Retransmissions of an *already-shrunk* original segment must be shrunk identically and deterministically (same filter, same selection outcome), so a retransmission is byte-for-byte equal to the first transmission's shrunk form; this is why `selection: random` (§9) is unsafe under retransmission unless the random choice is derived deterministically from stable per-packet material (e.g. original `SeqNum`), not a fresh RNG draw per capture.

### 8.1.1 One filtered direction per profile

The correction above only ever touches two fields — the trimmed direction's `SeqNum` and the opposite direction's `AckNum` — because it assumes removal happens in exactly one direction of one connection at a time under one tracked `N`. This is why **a profile's WinDivert filter should match packets in only one direction of a connection** (e.g. `outbound and tcp.DstPort == 55000`, not both directions of the same tuple). Removing bytes from both directions under a single shared `N` would conflate two independent removal decisions — and their independent retransmission and deactivation behavior — into one counter, which no longer cleanly maps to either direction's real byte offset.

If both directions need bytes removed, run two independently activated profiles — one per direction — each with its own `size_filter`/`selection` and its own independently tracked `N`. Both profiles can share the same activation key (`ProfileOptions::keys`/`key_mode`, see [packet_engine.h](../include/packet_engine.h)) so a single keypress starts or stops both together, but their tracked state remains two separate sessions with two separate lifetimes. This has no bearing on the connection-lifetime variant in point 5 above, which would need its own design regardless of how many directions it covers.

### 8.1.2 Coordinating two or more simultaneous activations

Splitting removal across two profiles (§8.1.1) reintroduces a problem the single-profile model avoids: with both profiles active on the same connection, **every** packet in **both** directions needs corrections from **both** profiles, not just one:

- A `client→server` packet needs `SeqNum -= N_A` (profile A, the direction it removes from) **and** `AckNum += N_B` (profile B's reverse-direction correction, since profile B removed bytes going the other way).
- A `server→client` packet needs `AckNum += N_A` **and** `SeqNum -= N_B`, symmetrically.

Today's engine gives each active profile its own `Session` — its own WinDivert handle and its own `read_packets`/`write_packets` threads calling `WinDivertSend` independently (see [packet_engine.cc](../src/packet_engine.cc)). If profile A's and profile B's threads each apply only their own `N` and send independently, whichever one actually owns/captures a given packet can only apply its own half of the required correction; the other profile's `N` for that same packet is never applied, because the packet has already left through the first profile's handle. There is no natural point where both corrections are guaranteed to land on the same packet before it reaches the wire.

```mermaid
sequenceDiagram
    participant OS as OS network stack
    participant A as Profile A session (tracks N_A only)
    participant B as Profile B session (tracks N_B only)
    participant Wire as Wire (to peer)

    OS->>A: C to S packet SEQ=100 ACK=50
    Note over A: only knows N_A, applies SeqNum -= N_A
    A->>Wire: SEQ=100-N_A ACK=50
    Note over Wire: AckNum was never corrected for profile B's N_B, server-side tracking for the S to C direction silently drifts
    Note over B: never sees this packet, B's own S to C packets are sent the same uncoordinated way, missing A's N_A
```

Without a shared authority, each profile is only ever internally consistent with itself, and the connection still desynchronizes as soon as a second profile starts touching the same packets.

The fix is to stop letting each profile send independently, and instead route every outbound packet on a connection with two-or-more active profiles through one shared arbiter: a single per-connection "outbound authority" that all participating profiles report their current `N` into, and that is the *only* thing allowed to call `WinDivertSend` for that connection. The authority applies every currently-active profile's applicable correction (SeqNum decrements for profiles tracking this packet's direction, AckNum increments for profiles tracking the reverse direction) in one pass, then sends the packet exactly once.

```mermaid
sequenceDiagram
    participant OS as OS network stack
    participant A as Profile A (updates N_A)
    participant B as Profile B (updates N_B)
    participant Auth as Outbound authority (per connection, single writer)
    participant Wire as Wire (to peer)

    OS->>Auth: C to S packet SEQ=100 ACK=50
    A-->>Auth: current N_A (removed on C to S)
    B-->>Auth: current N_B (removed on S to C)
    Note over Auth: SeqNum -= N_A (this direction's tracker), AckNum += N_B (reverse direction's tracker)
    Auth->>Wire: SEQ=100-N_A ACK=50+N_B
```

This makes profiles producers of `N` updates and removal decisions only; a single authority per connection (not per profile) becomes the sole place that reads every relevant profile's `N` and performs the actual `SeqNum`/`AckNum` correction and send, which is the only way to guarantee both halves of the correction always land on the same packet. This is a real architectural change from today's one-`Session`-per-profile model (§8.1.2 is therefore scoped as a follow-on to Phase 2, not part of the initial single-profile implementation in §13) and only matters once two or more profiles with overlapping SEQ/ACK corrections are active on the same connection at the same time; a single active profile (§8.1, §8.1.1) needs no arbitration since it is already the sole writer for its connection.



An alternative is to keep every packet's length and sequence numbers unchanged and instead overwrite the removed record's bytes with a same-length filler, so no renumbering is ever needed. This is rejected because there is no generally safe filler:

- For TLS 1.2 and earlier, every record type is meaningful to the peer; a same-length record with fabricated content is either rejected outright (bad MAC/AEAD tag on an application-data or handshake record → immediate `bad_record_mac` fatal alert and connection teardown) or, if crafted as a valid-looking record of a different declared length, is exactly the "true splice" problem in a different shape.
- For TLS 1.3, a `change_cipher_spec` (content type `0x14`) record is a defined middlebox-compatibility no-op that a compliant TLS 1.3 stack silently ignores regardless of its contents — but it can only stand in for a removed record whose size exactly equals the replacement CCS record's size (a fixed 6 bytes: `14 03 03 00 01 01`), so it only covers the case of removing one very specific record size and does not generalize to "remove any record matching an arbitrary filter."
- Padding therefore only trivially works for the degenerate case of removing an entire record and replacing it with nothing further needed *and* the packet becoming empty — which strategy A already gives for free by shrinking to zero-length payload (§8.3) — so strategy B adds complexity without covering the general case.

Strategy B is recorded here as a rejected alternative, not pursued further, and should not be resurrected without first identifying a filler that is simultaneously (a) protocol-legal for every TLS version in scope and (b) constant-size-independent of the removed record's size.

### 8.3 The empty-payload case and the PSH flag

If a packet's payload, after removal, is empty — because it contained exactly one record and that record was removed, or because every record inside a coalesced packet matched and was removed — the resulting packet must not be sent as a zero-length `PSH, ACK` segment. `PSH` signals "deliver buffered bytes to the application now"; a packet asserting `PSH` with no payload is a harmless but nonsensical construction that some TCP stacks tolerate and others treat as suspicious. The mode therefore always clears `TCP_FLAG_PSH` (and only that flag) when it produces a zero-length payload, regardless of whether the original packet had one record or several, yielding a plain `ACK`. Existing flags (`ACK`, `URG`, `FIN`, `RST`, if any were set) are left untouched; `FIN`/`RST` packets are excluded from record parsing entirely (§8.5) because a FIN/RST payload, if any, is not a fresh TLS record stream.

If instead only *some* records inside a coalesced packet are removed, the remaining record(s) are copied into place contiguously, the payload length shrinks by the removed bytes, and `PSH` is preserved as-is (the packet still pushes real remaining data).

### 8.4 Recomputing headers

After the payload bytes are rewritten:

1. IPv4 `Total Length` is reduced by the removed byte count.
2. TCP header length (data offset) is unchanged — only the payload shrinks, not the TCP header/options.
3. `WinDivertHelperCalcChecksums` recomputes the IPv4 and TCP checksums exactly as the existing `ack_restoration` path already does after mutating `AckNum` in [packet_mode.cc](../src/modules/packet_mode.cc); the segment-removal path reuses the same call after all field rewrites (payload, `SeqNum`, `AckNum`, flags) are applied, not after each individual rewrite, to avoid recomputing checksums against an intermediate, inconsistent packet.
4. The `WINDIVERT_ADDRESS`/packet length passed to `WinDivertSend` must reflect the new, shorter length; the engine must not reuse the original captured length after shrinking the buffer.

### 8.5 Exclusions

Records are only ever considered inside packets that are pure application data carriers for this feature's purposes:

- Packets with `SYN`, `FIN`, or `RST` set are passed through unmodified — these are connection-lifecycle signals, and mutating their (often zero-length or lifecycle-only) payload has no well-defined meaning here.
- Packets with zero-length payload are passed through unmodified (nothing to parse).
- Out-of-order or already-duplicate packets (as already detected by `retransmission_mode`) should be filtered *before* segment removal runs, so the deterministic-retransmission requirement in §8.1 point 6 is checked against the same de-duplication the engine already performs.

## 9. Selection strategies

Once the size filter identifies the set of matching records within one packet, `selection` decides which of them are actually removed:

| `selection` | Behavior |
|---|---|
| `all` (default) | Remove every matching record. |
| `first` | Remove only the first matching record encountered in wire order; later matches in the same packet are left alone. |
| `last` | Remove only the last matching record encountered in wire order. |
| `random` | Remove exactly one matching record, chosen pseudo-randomly. Per §8.1 point 6, the "random" choice must be derived deterministically from stable per-packet material (e.g. a hash of `SeqNum` and the ordered list of matching record offsets) rather than a fresh RNG draw, so that a TCP retransmission of the identical original packet reproduces the identical removal instead of removing a different record and desynchronizing the renumbering state. |
| `n` | Remove up to `count` matching records (in wire order), requiring an explicit `count >= 1` in configuration; if fewer than `count` records match, all matches are removed and no error is raised. |

`selection` operates purely within the scope of records inside a single packet; it does not track "the 3rd matching record across the whole connection" — extending selection to a connection-wide budget (e.g. "remove only the first 5 matching records for the life of the connection") is a reasonable follow-up but requires connection-scoped state beyond what §8.1 already introduces, and is deferred (see §13).

```mermaid
flowchart LR
    Matches[Matching records in wire order\ne.g. R1, R2, R3] --> Sel{selection mode}
    Sel -->|all| RmAll[Remove R1, R2, R3]
    Sel -->|first| RmFirst[Remove R1 only]
    Sel -->|last| RmLast[Remove R3 only]
    Sel -->|random| RmRand[Remove one record\nchosen via deterministic hash\nof SeqNum + match offsets]
    Sel -->|n, count=2| RmN[Remove R1, R2\nstop at count]
```

## 10. Interaction with existing modes

- Segment removal is a payload-shaping step that should run before a profile's existing `delay_mode` (from_timestamp/ratio/hold_and_send/etc.) queues the packet, so delayed or ratio-selected packets are already in their final, re-framed form when they are queued and later released.
- `retransmission_mode` and `ack_restoration` operate on `SeqNum`/`AckNum` as already observed on the wire; once §8.1's renumbering is applied, these existing features naturally see the renumbered values and keep working unmodified, provided renumbering happens first in the per-packet pipeline.
- `subsequent_packet_hold_mode` matches held/subsequent packets by sequence/acknowledgment; because §8.1 keeps the stream's numbering internally consistent (just shifted), this matching continues to work against the renumbered values.
- A profile combining segment removal with `windivert_options.forward` (WinDivert `NETWORK_FORWARD` layer, used for a router/gateway-style deployment) is the primary intended deployment shape, since forwarded traffic is not the local host's own TCP stack and this mode never needs to coordinate with a local socket's own sequence-number bookkeeping.

## 11. Security and correctness requirements

- Reject configuration where `size_filter` can never match anything (e.g. `X..Y` with `Y < X`, or a `<X`/`<=X` clause with `X <= 5`, since every record is at least 5 bytes) at load time.
- Reject `selection: n` without a positive `count`.
- Never mutate `SYN`/`FIN`/`RST` packets or zero-length payloads (§8.5).
- Never leave `PSH` set on a packet with an empty payload (§8.3).
- Never recompute checksums against a partially-mutated packet buffer — all field rewrites for a given packet happen before the single `WinDivertHelperCalcChecksums` call (§8.4).
- Never treat an unparsed tail (§7) as a record; never remove bytes whose true record boundary this packet cannot establish.
- Log, at debug level, every removal decision: connection tuple, direction, matched record offsets/sizes, selection outcome, and the resulting profile-scoped `N`, mirroring the existing `LOG_DEBUG` style already used for retransmission/duplicate decisions in [packet_mode.cc](../src/modules/packet_mode.cc).
- Do not log TLS record *contents* by default (consistent with the payload-redaction stance already established in [tcp_tls_proxy.md](tcp_tls_proxy.md#12-security-and-privacy-requirements)); logging sizes and offsets is sufficient for debugging and does not risk exposing plaintext or ciphertext.

## 12. Test plan

### Functional

- Single-record packet, filter matches: payload becomes empty, `PSH` cleared, `ACK` remains, checksums valid, `SeqNum`/later-packet `SeqNum`s shifted by the removed size, peer-direction `AckNum`s shifted to match.
- Coalesced packet with 4 records (mirroring the `ServerHello`/`Certificate`/`ServerKeyExchange`/`ServerHelloDone` capture in [tcp_tls_proxy.md](tcp_tls_proxy.md#172-detailed-byte-by-byte-packet-dissection)), filter matches records 2 and 3 only, `selection: all`: resulting payload contains only records 1 and 4, contiguous, correctly length-adjusted.
- Same packet with `selection: first`, `last`, `random`, and `n: 1` each produce the documented single-record-removed result and remain stable across a simulated retransmission of the identical original packet.
- A record whose header is present but whose declared `length` runs past the captured payload (straddled) is left untouched; only the complete leading record(s), if any, are eligible for removal.
- A packet with a payload that fails to parse as any TLS record (plaintext pre-TLS control bytes) passes through unmodified.

### Sequence-consistency

- After several removals across multiple packets in one direction, `N` correctly equals the sum of removed bytes, and a final packet's `SeqNum` plus its payload length still lands exactly where the next untouched packet's (SEQ-corrected) `SeqNum` expects.
- A reverse-direction `AckNum` observed after a forward-direction removal is increased by the same `N` and remains numerically consistent with the corrected forward stream.
- Deactivating the profile mid-connection stops correction immediately: subsequent packets are forwarded unmodified, and the two endpoints' SEQ/ACK expectations are left off by the final value of `N` (§8.1, point 4) rather than silently continuing to drift or snap back.
- `retransmission_mode` correctly recognizes a retransmitted-and-reshrunk packet as a duplicate of the first shrunk transmission, not as a new distinct packet.

### Negative / configuration

- `size_filter` with an inverted range, a filter clause below the minimum 5-byte record size, or `selection: n` without `count` are all rejected at load time with an actionable error, consistent with existing schema validation in [profiles.schema.json](../schemas/profiles.schema.json).

## 13. Suggested implementation phases

### Phase 0: record parser and filter grammar

- Implement the standalone TLS record-boundary walker (type/version/length parsing, unparsed-tail detection) and the filter grammar (parse + validate + evaluate) as pure, unit-testable functions with no WinDivert dependency, alongside the existing modules in `src/modules/`.
- Traffic generator: [tls_segment_removal/traffic_gen.cc](tls_segment_removal/traffic_gen.cc) (`segment_traffic_gen` target) runs a TLS 1.2 client/server pair that continuously exchanges bursts of one or more coalesced records with randomized `close`/`random`/`far` size and record-count patterns, giving the parser/filter and later phases a live, varied packet stream to run against instead of only static fixtures.

### Phase 1: single-packet splice (no cross-packet renumbering)

- Wire the parser/filter into a new `PacketMode` (or an option on an existing one) that removes matching records and re-frames the packet (§8.3, §8.4), but only against a synthetic test harness with a single packet at a time, to validate framing/checksum correctness in isolation before introducing stateful renumbering.

### Phase 2: profile-scoped SEQ/ACK correction

- Add the profile-scoped `N` counter (§8.1) alongside the existing `last_sent_ack_`/`has_last_sent_ack_` state in `PacketMode`, resetting it in `PacketMode::reset()` so it is discarded on deactivation rather than persisting for the connection's lifetime; rewrite `SeqNum` (tracked direction) and `AckNum` (reverse direction) for every packet on the connection while the profile is active.
- Validate against a live loopback TCP echo test with a scripted, coalesced-and-split TLS-record-shaped payload generator, including a case that deactivates the profile mid-connection and confirms correction stops immediately (§8.1, point 4).

### Phase 3: selection strategies and deterministic retransmission behavior

- Implement `first`/`last`/`random`/`n`, with `random` derived deterministically as described in §9.
- Add a retransmission-simulation test that re-delivers an already-shrunk packet unmodified from the wire and confirms identical shrinkage is reproduced.

### Phase 4: profile schema, docs, and logging

- Extend `profiles.schema.json` and `ProfileOptions`/`options.cc` loading for `segment_removal` (§6.1).
- Add the debug logging described in §11.

## 14. Open questions

- Should a connection-wide removal budget (e.g. "remove at most N matching records for the life of the connection," beyond the per-packet `n` in §9) be added, and if so, does it share state with `disable_wait_ms`-style profile lifecycle tracking already in `ProfileOptions`?
- Should SACK options be actively stripped/rewritten on affected connections (§8.1 point 2) rather than requiring the operator to avoid SACK-using peers via filter scoping?
- Is a record content-type filter (handshake/alert/application-data/change-cipher-spec) needed before this is useful in practice, given that early-session traffic is dominated by handshake records this mode is not meant to target (§5)?
- Does this mode need its own PoC executable/harness under `pocs/`, similar to [tcp_tls_proxy/](tcp_tls_proxy/), for isolated testing before integrating into `PacketEngine`/`PacketMode` proper?
- Is the connection-lifetime correction variant (§8.1, point 5) — where SEQ/ACK correction keeps running after the owning profile deactivates, so the two endpoints never need to resync — worth the new connection-scoped (rather than profile-scoped) state store it would require, given that the profile-scoped tracker is deliberately simpler and treats deactivation-time desync as an accepted cost for short activations?
- How should the outbound authority (§8.1.2) be scoped and discovered — one authority instance per connection tuple, created lazily the moment a second profile with an overlapping SEQ/ACK correction activates on that connection, and torn down when the last such profile deactivates? Does it need to exist even for a single active profile (today's sole-writer `Session` model), or only once two or more profiles overlap?
