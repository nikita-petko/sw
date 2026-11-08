# PoC: Stub packet backend

## Status and scope

**Implemented:** unsupported platforms use a stub backend that warns on
initialization and fails capture-channel opens explicitly. It does not delay,
drop, or reinject traffic; filter validation accepts inputs without checking a
real backend's language. Other application facilities can still operate.

## Phases

1. **Complete — fallback:** implement the shared backend interface without
   pretending capture is available.
2. **Complete — diagnostics:** warn at initialization and return a concrete
   error when a capture channel is requested.
3. **Proposed — portability validation:** build and exercise startup, open
   failure, and shutdown on each supported stub-platform toolchain.

## Reproducible check

Inspect the warning and failed-open paths in [backend.cc](../backends/stub/backend.cc).
`xmake test engine_test` tests engine behavior with a fake backend and does not
prove platform-specific stub startup; the latter remains a proposed check.
