# PoC: Desync countdown

## Status and scope

**Implemented:** selected profiles show an approximate countdown after
deactivation, based on their last active duration multiplied by
`duration_percent` (default 80%, valid 1–100). The display can be
`alongside`, `override`, or `until_reactivated`. It is an estimate, not a
measurement of remote state or a guarantee of any network outcome.

## Phases

1. **Complete — estimate:** track activation duration and calculate the
   countdown for enabled profiles.
2. **Complete — presentation:** implement display policies, expiration, and
   profile selection.
3. **Proposed — calibration:** compare predictions with independently
   measured outcomes in controlled experiments; report uncertainty rather
   than assuming a universal percentage.

## Reproducible check

With the feature compiled in, run
`xmake build engine_test && xmake run engine_test desync_countdown`.
[engine_test.cc](../tests/engine/engine_test.cc) checks timing, expiry, and
reactivation display behavior. Configuration is described in the
[README](../README.md#features).

Implementation: [desync_countdown.cc](../src/packet_engine/desync_countdown.cc).
