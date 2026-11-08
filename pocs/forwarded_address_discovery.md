# PoC: Forwarded address discovery

## Status and scope

**Implemented:** the optional `forwarded_address_discovery` feature sniffs
traffic on a configured port and two distinct interface indices. Each window
selects the most frequent destination on the client-facing interface and
source on the shared interface. Discovered addresses override configured
client addresses, and changed addresses restart active profile captures.
This is a traffic-based heuristic, not authenticated client identification.

## Phases

1. **Complete — observation:** open a dedicated sniff channel and count
   candidate addresses per interface.
2. **Complete — application:** update discovered addresses and reconfigure
   active profiles when a winner changes.
3. **Proposed — gateway validation:** test NAT/interface changes, ties, and
   competing clients in isolated Windows ICS and Linux gateway setups.

## Reproducible check

With the feature compiled in, run `xmake build engine_test && xmake run engine_test forwarded_address_discovery`.
Cases in [engine_test.cc](../tests/engine/engine_test.cc) exercise learning
and disabled behavior. Configure distinct interface indices, a port, and
interval using the [README](../README.md#features).

Implementation: [forwarded_address.cc](../src/packet_engine/forwarded_address.cc).
