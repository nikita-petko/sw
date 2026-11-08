# PoC: Server discovery and disconnect detection

## Status and scope

**Implemented:** the optional `server_discovery` feature observes TCP/UDP
traffic on a configured port in recurring windows and selects the busiest
remote address. It adds or reuses the server, and automatically selects it
only while no concrete server has been manually selected. Discovery pauses
while profiles are active and starts a fresh window afterward.

The disconnect detector compares each window with the preceding six-window
average. It requires three prior windows averaging at least 10 packets; the
default drop threshold is 80%, and `0` disables detection. It reports recovery,
not actual transport connection state.

## Phases

1. **Complete — discovery:** sniff port-scoped traffic, rank remote addresses,
   select an automatic server without overriding manual selection.
2. **Complete — lifecycle and health:** pause discovery during active profiles
   and report traffic drops and recovery with a minimum-traffic guard.
3. **Proposed — validation:** assess mixed UDP/TCP traffic, tied candidates and
   noisy background traffic on live isolated interfaces.

## Reproducible check

Run `xmake build engine_test && xmake run engine_test discovery` and
`xmake test disconnect_detector_test`. Cases are in
[engine_test.cc](../tests/engine/engine_test.cc) and
[disconnect_detector_test.cc](../tests/packet/disconnect_detector_test.cc).
Configure `features.server_discovery` as documented in the
[README](../README.md#features); runtime enablement is separate from the
`--server_discovery` build flag.

Implementation: [discovery.cc](../src/packet_engine/discovery.cc) and
[disconnect_detector.h](../src/packet_engine/disconnect_detector.h).
