# PoC: `packet_group_send` packet mode

## Status and scope

**Implemented:** `mode: toggle` and a positive `group_count` capture successive
groups. Activation starts group 1; each subsequent press ends the current group.
The press ending the last group also sends the first selected group; further
presses send one group each. `group_order` is `fifo`, `lifo`, or `random`.
Packets within a group retain receive order, and newly captured packets pass
through once group capture has ended. The profile finishes after the last group.

## Phases

1. **Complete — group capture:** delimit groups by activation-key presses.
2. **Complete — ordered sending:** send one group per press, track empty groups,
   backend send failures, and status; reset on the next activation.
3. **Proposed — operational study:** test long captures, forced teardown, and
   group ordering under load on real backends.

## Reproducible check

Run `xmake build modes_test && xmake run modes_test packet_group_send`.
The cases in [modes_test.cc](../tests/modes/modes_test.cc) cover all orders,
pass-through, empty groups, failures, and reset.

Implementation: [packet_group_send.cc](../src/packet_mode/packet_group_send.cc).
