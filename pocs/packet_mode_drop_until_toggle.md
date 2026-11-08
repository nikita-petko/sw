# PoC: `drop_until_toggle` packet mode

## Status and scope

**Implemented:** with `mode: toggle`, activation starts a discard phase; the
next activation-key press switches to holding, and the following press sends
the held packets and deactivates the profile. Reset returns to discarding.

## Phases

1. **Complete — drop phase:** notify the backend of discarded packets.
2. **Complete — hold and finish:** advance on key presses, hold packets, and
   flush them when the profile finishes.
3. **Proposed — end-to-end trials:** verify phase boundaries and forced
   teardown with real capture backends and isolated traffic.

## Reproducible check

Run `xmake build modes_test && xmake run modes_test drop_until_toggle`.
The fake-clock case in [modes_test.cc](../tests/modes/modes_test.cc) checks
drop, hold, flush, and reset; profile lifecycle is covered in
[engine_test.cc](../tests/engine/engine_test.cc).

Implementation: [drop_until_toggle.cc](../src/packet_mode/drop_until_toggle.cc).
