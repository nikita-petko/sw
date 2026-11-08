# PoC: Per-activation PCAP capture

## Status and scope

**Implemented:** when compiled with `--pcap_files=y` and enabled in the
profile file, selected profile activations write their received packets to
separate raw-IP (`DLT_RAW`) PCAP files. `enabled_for` selects `*` or profile
names; the file and deactivation log share a GUID. The build and runtime
feature are both disabled by default.

PCAP files may contain sensitive packet data. Capture only authorized traffic,
restrict file access, and dispose of captures according to local policy.

## Phases

1. **Complete — capture:** create a per-activation file and record received
   packets with PCAP headers.
2. **Complete — selection:** validate the configuration and select profiles
   by name or wildcard.
3. **Proposed — resilience validation:** exercise write failures, concurrent
   activations and large captures, and inspect outputs with a PCAP reader.

## Reproducible check

Configure `xmake f --pcap_files=y`, then run `xmake test options_test` for
configuration coverage. In an authorized isolated environment, enable
`features.pcap_files`, activate a selected profile twice, and verify two
independently readable raw-IP files and matching log identifiers. This live
procedure is a proposed validation, not a recorded test result.

Implementation: [pcap.cc](../src/packet_engine/pcap.cc); settings:
[README](../README.md#features).
