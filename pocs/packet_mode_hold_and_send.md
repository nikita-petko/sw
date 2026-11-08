# PoC: `hold_and_send` packet mode

## Status and scope

**Implemented:** hold the first positive packet-count `ratio` and let subsequent
packets pass; flush the held packets on deactivation. Optional
`subsequent_packet_hold_mode` values `seq_only`, `ack_only`, and `seq_ack`
also hold later TCP packets matching an initially held packet; `none` is the
default. Non-TCP packets count toward the initial quota.

## Phases

1. **Complete — initial hold:** hold the quota while later packets pass.
2. **Complete — subsequent matches:** apply the selected TCP-number matching
   policy and reset tracking for a new activation.
3. **Proposed — interaction testing:** characterize combinations with
   retransmission filtering and ACK restoration using isolated flows.

## Reproducible check

Run `xmake build modes_test && xmake run modes_test hold_and_send`.
The cases in [modes_test.cc](../tests/modes/modes_test.cc) exercise the
quota, all matching policies, non-TCP packets, and reset.

Implementation: [hold_and_send.cc](../src/packet_mode/hold_and_send.cc);
shared options: [TCP packet handling](packet_tcp_handling.md).
