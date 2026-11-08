# PoC: `drop` packet mode

## Status and scope

**Implemented:** matching packets are discarded while the profile is active,
and the backend is notified of each discard. They are not queued for later
replay. Common TCP options can affect packets before the mode sees them; see
[TCP packet handling](packet_tcp_handling.md).

## Phases

1. **Complete — discard:** discard each captured packet through the backend
   sink instead of reinjection.
2. **Complete — lifecycle:** release no packets on normal release or flush.
3. **Proposed — backend validation:** compare discard accounting and recovery
   after deactivation across real supported backends.

## Reproducible check

Run `xmake build modes_test && xmake run modes_test drop_discards`.
The case in [modes_test.cc](../tests/modes/modes_test.cc) checks discard
notifications and an empty queue; [engine_test.cc](../tests/engine/engine_test.cc)
checks backend discard reporting. Live loss tests require an authorized,
isolated connection.

Implementation: [drop.cc](../src/packet_mode/drop.cc).
