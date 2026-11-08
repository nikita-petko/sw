# PoC: Profile capture and filtering

## Status and scope

**Implemented:** a profile may override the global filter and request sniff,
forwarded, or outbound capture. Client address enforcement and selected-server
direction add optional address restrictions; selecting a server group includes
its members. Sniff observes rather than holds packets. Backend filter support
and platform capture semantics differ; Linux translates a documented subset of
the WinDivert filter language.

## Phases

1. **Complete — configuration:** parse and validate global/profile filters,
   capture options and their legacy `windivert_options` alias.
2. **Complete — integration:** build backend capture specifications, restart
   active profiles when server selection changes, and support sniff channels.
3. **Proposed — cross-backend parity:** exercise equivalent filters and
   direction/forward behavior in isolated network namespaces and on Windows.

## Reproducible check

Run `xmake test options_test` and
`xmake build engine_test && xmake run engine_test capture_filters`.
On Linux, `xmake test nfqueue_filter_test` checks the filter compiler.
The [README](../README.md#capture-options) describes configuration and
platform restrictions.

Implementation: [filters.cc](../src/options/filters.cc),
[selection.cc](../src/packet_engine/selection.cc), and
[packet_backend.h](../include/packet_backend.h).
