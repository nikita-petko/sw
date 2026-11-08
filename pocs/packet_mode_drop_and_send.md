# PoC: `drop_and_send` packet mode

## Status and scope

**Implemented:** the first packet starts a `delay_ms` batch. At release, the
first `ratio` packets are discarded and the rest sent. A percentage rounds up;
a count is capped at the batch size. Both a positive delay and a ratio are
required. The same discard rule applies when an unfinished batch is flushed.

## Phases

1. **Complete — batching:** group captured packets on the first packet's timer.
2. **Complete — selective loss:** discard the first count or percentage and
   notify the backend, including on teardown flush.
3. **Proposed — backend validation:** measure delivered versus discarded
   packets at timer and early-deactivation boundaries.

## Reproducible check

Run `xmake build modes_test && xmake run modes_test drop_and_send`.
The cases in [modes_test.cc](../tests/modes/modes_test.cc) cover counts,
percentage rounding, capping, and flushing. Use only authorized isolated
traffic for real packet-loss trials.

Implementation: [drop_and_send.cc](../src/packet_mode/drop_and_send.cc).
