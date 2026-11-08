# PoC: Region enforcement

## Status and scope

**Implemented:** the optional `region_enforcement` feature observes the
configured probe port and delays matching TCP PSH traffic from configured
servers outside the currently enforced group. Left/Right cycle groups; a
server without a group falls back to its name. The delay is randomized between
1000 and 1500 ms. Changing regions or stopping flushes queued packets.
This influences packet timing; it cannot guarantee which remote server is chosen.

## Phases

1. **Complete — region selection:** derive groups from configured servers and
   provide runtime cycling, including `none`.
2. **Complete — probe and delay:** observe probes, create a filter for other
   regions, schedule captured packets, and flush on change or shutdown.
3. **Proposed — validation:** measure selection behavior and false positives on
   controlled multi-server traffic; verify capture coverage on each backend.

## Reproducible check

With the feature compiled in, run `xmake test region_enforcement_test`.
The cases in [region_enforcement_test.cc](../tests/region_enforcement/region_enforcement_test.cc)
cover selection, filtering, probe observation, delayed release, and flushing.
Configure a valid `probe_port` as in the [README](../README.md#features).
Run live experiments only on authorized networks.

Implementation: [region_enforcement.cc](../src/packet_engine/region_enforcement.cc)
and [region.cc](../src/packet_engine/region.cc).
