# PoC: `from_timestamp` packet mode

## Status and scope

**Implemented:** each captured packet is scheduled for its receive time plus
`delay_ms`; equal deadlines retain receive order. With `delay_ms: 0`, packets
are held until the profile is flushed. This is the default delay mode.
Scheduling is approximate, not a real-time delivery guarantee.

## Phases

1. **Complete — scheduling:** copy packets and metadata into the release queue
   and release each when its deadline is due.
2. **Complete — lifecycle:** preserve ordering at equal deadlines and flush
   outstanding packets on deactivation.
3. **Proposed — timing characterization:** measure deadline error under load
   on each supported backend; report percentiles and loss separately.

## Reproducible check

Run `xmake build modes_test && xmake run modes_test from_timestamp`. The
fake-clock cases in [modes_test.cc](../tests/modes/modes_test.cc) check
individual deadlines, ordering, and zero-delay holding. Queue teardown is
also exercised in [engine_test.cc](../tests/engine/engine_test.cc).
Use only authorized isolated traffic for any live timing experiment.

Implementation: [from_timestamp.cc](../src/packet_mode/from_timestamp.cc).
