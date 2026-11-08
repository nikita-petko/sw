# PoC: Backend health monitor

## Status and scope

**Implemented:** the optional `backend_monitor` adds a sampled status line for
supported backends. NFQUEUE reports queue/drop counters and table presence;
the Linux module reports handle and packet counters; WinDivert reports handles,
receive/send errors, backlog, driver-queue delay and service state. The stub
shows no backend monitor. A warning marker reflects backend-specific thresholds.
This is health telemetry, not a guarantee of complete packet delivery.

## Phases

1. **Complete — sampling:** read backend-specific counters at the configured
   interval without changing the capture policy.
2. **Complete — presentation:** display health and threshold warnings on the
   extra status line.
3. **Proposed — fault injection:** check counter resets, lost tables, driver
   stop, queue pressure and unavailable metrics on real platforms.

## Reproducible check

Run `xmake test options_test` for configuration validation. On an authorized
test host, enable `features.backend_monitor`, exercise the applicable backend
and compare its displayed counters with the underlying backend's metrics.
Platform fault injection is proposed, not an already recorded result.

Implementation: [status.cc](../src/packet_engine/status.cc),
[monitor.cc](../backends/windivert/monitor.cc); settings:
[README](../README.md#features).
