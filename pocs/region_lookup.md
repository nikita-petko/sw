# PoC: Geographic region lookup

## Status and scope

**Implemented:** `--resolve-region` enables geographic lookup and naming for
discovered servers, with a local cache for successful results. Configured
server names are preserved. Private/local addresses are excluded by the
lookup's address checks. Lookup-derived geographic labels are approximate and
do not establish a server's actual network location.

This feature sends lookup requests to an external service. Obtain authorization
before looking up addresses and consider the privacy of those addresses.

## Phases

1. **Complete — lookup:** parse responses and build region labels and server
   names without replacing explicitly configured names.
2. **Complete — caching and retries:** cache successful results and handle
   rate limits; tests use fake HTTP, sleep, and data directories.
3. **Proposed — service robustness:** evaluate API errors, stale cache
   behavior and IPv6/local-address classification without sending real
   sensitive addresses to a third party.

## Reproducible check

Run `xmake test region_test` and
`xmake build engine_test && xmake run engine_test regions`.
[region_test.cc](../tests/region/region_test.cc) covers parsing, caching and
retry; [engine_test.cc](../tests/engine/engine_test.cc) covers integration.

Implementation: [region_lookup.cc](../src/packet_engine/region_lookup.cc) and
[region.cc](../src/packet_engine/region.cc).
