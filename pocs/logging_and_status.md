# PoC: Logging and runtime status

## Status and scope

**Implemented:** logs have levels and hierarchical group rules; per-packet
groups are off by default, while warnings and errors remain visible. `--print-log-groups`
lists groups, and `--show-log-groups` adds labels. Tab reports packet/profile
state and log-group counts. Status lines also present active profile state and
eligible feature information. Full-screen views suspend and later replay logs.

## Phases

1. **Complete — logs:** implement levels, group selection and counts.
2. **Complete — status:** render persistent status and an on-demand state
   report, including coexistence with full-screen views.
3. **Proposed — console validation:** exercise resizing, long output and log
   suspension on supported terminals and under heavy packet logging.

## Reproducible check

Run `xmake build format_test && xmake run format_test log_group` and
`xmake build engine_test && xmake run engine_test state_report`.
The cases in [format_test.cc](../tests/packet/format_test.cc) and
[engine_test.cc](../tests/engine/engine_test.cc) cover group rules/counts and
state reporting; interactive console checks remain proposed.

Implementation: [logging.cc](../src/log/logging.cc),
[report.cc](../src/packet_engine/report.cc), and [status_line.cc](../src/status_line.cc).
