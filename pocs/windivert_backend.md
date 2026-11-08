# PoC: Windows WinDivert backend

## Status and scope

**Implemented:** the Windows backend uses the bundled WinDivert runtime for
packet capture and reinjection, including sniff and forward capture. It
requires suitable driver support and administrator privileges. The common
packet-engine interface isolates profiles from backend details; backend health
has a separate [monitor PoC](backend_monitor.md).

## Phases

1. **Complete — capture backend:** initialize WinDivert, open capture
   channels, receive, send and close them.
2. **Complete — integration:** support capture options, runtime resources and
   health reporting through the shared backend interface.
3. **Proposed — Windows validation:** run authorized loopback and forward
   tests for shutdown, driver failures, ordering, and queue pressure on the
   supported Windows versions; record OS/driver versions and results.

## Reproducible check

`xmake test engine_test` verifies engine behavior against the in-memory fake,
not the WinDivert driver. Real-driver verification requires a Windows test host,
administrator privileges and isolated authorized traffic. The existing
[benchmark](windivert_benchmark/bench.py) can help measure the backend but is
not a substitute for functional tests.

Implementation: [backend.cc](../backends/windivert/backend.cc),
[runtime.cc](../backends/windivert/runtime.cc); build/run instructions:
[README](../README.md#usage).
