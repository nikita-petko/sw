# PoC: Shared TCP packet handling

## Status and scope

**Implemented:** profile `retransmission_mode` can discard captured TCP packets
whose sequence, acknowledgment, or pair matches a packet still in that
profile's queue. `none` disables this filter. Matching uses the configured TCP
numbers against queued packets; it is not a general TCP retransmission detector.

With `ack_restoration`, ACK-bearing non-PSH packets bypass the mode's hold
policy. Before reinjection, PSH ACK numbers that would go backward relative to
the recorded directional flow are raised and checksums recalculated.
These options affect all packet modes and can change their apparent behavior.

## Phases

1. **Complete — duplicate filtering:** inspect queued TCP numbers and report
   discarded packets to the backend.
2. **Complete — ACK handling:** let eligible ACK packets pass and preserve
   nondecreasing acknowledged sequence values for sent PSH packets.
3. **Proposed — protocol study:** test sequence wraparound, overlapping flows,
   malformed packets, and interactions between options in isolated traffic.

## Reproducible check

Run `xmake build modes_test && xmake run modes_test retransmission` and
`xmake run modes_test ack_restoration`. The cases in
[modes_test.cc](../tests/modes/modes_test.cc) cover queued duplicates,
non-TCP traffic, ACK bypass and restoration.

Implementation: [packet_mode.cc](../src/packet_mode/packet_mode.cc).
