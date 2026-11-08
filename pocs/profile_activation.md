# PoC: Profile activation and runtime control

## Status and scope

**Implemented:** profiles respond to toggle, hold, or timed `period` activation,
with single keys, combinations, or `oneof` keys. Shared toggle keys operate as
a group; profiles may disable named profiles or `*`, optionally respecting a
fixed and percentage-based disable wait. The special multi-step packet modes
consume additional activation presses. Profiles have independent capture and
queue state.

Runtime commands include server cycling, the Tab state report, and quit.
Specific feature keys and the TUI are documented in their own PoCs.

## Phases

1. **Complete — key and lifecycle:** activate/deactivate profiles and enforce
   period expiry and shared-key behavior.
2. **Complete — coordination:** implement disable targets, waits and
   mode-specific toggle/send actions.
3. **Proposed — interactive validation:** test rapid key transitions, shared
   combinations, delayed disabling and quit across supported consoles.

## Reproducible check

Run `xmake test engine_test` for capture lifecycle, concurrency, toggles, queue
flush and state-report cases in [engine_test.cc](../tests/engine/engine_test.cc).
Interactive key-controller behavior also needs the proposed console tests;
the engine suite alone does not establish keyboard coverage.

Implementation: [profile_controller.cc](../src/profile_controller.cc) and
[main.cc](../src/main.cc); settings: [README](../README.md#profile-fields).
