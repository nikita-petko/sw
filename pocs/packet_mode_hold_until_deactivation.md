# PoC: `hold_until_deactivation` packet mode

## Status and scope

**Implemented:** with `mode: toggle`, hold matching packets until requested.
An optional `send_key` releases `amount` packets without deactivating; `amount:
0` means all. On deactivation the mode releases the configured amount and
the engine flushes the remainder, so none are intentionally retained afterward.

## Phases

1. **Complete — hold and release:** defer packets and support bounded or
   all-at-once releases.
2. **Complete — control integration:** support an on-demand send key and
   flush remaining packets on deactivation.
3. **Proposed — stress study:** measure memory and release latency during
   prolonged holds and repeated send-key presses.

## Reproducible check

Run `xmake build modes_test && xmake run modes_test hold_until_deactivation`.
[modes_test.cc](../tests/modes/modes_test.cc) checks amount-limited releases
and flush; [engine_test.cc](../tests/engine/engine_test.cc) checks toggle and
on-demand integration.

Implementation: [hold_until_deactivation.cc](../src/packet_mode/hold_until_deactivation.cc).
