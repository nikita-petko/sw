# PoC: Profile loading and validation

## Status and scope

**Implemented:** command-line and YAML-shaped profile configuration load into
engine options, including servers, profiles, filters and optional feature
blocks. The loader validates settings and reports failures; command-line values
override corresponding profile values. Features omitted at build time are
ignored with a warning. The separate [config TUI PoC](config_tui.md) covers
interactive editing and switching.

## Phases

1. **Complete — parsing:** load profile fields and command-line overrides,
   including legacy configuration aliases.
2. **Complete — validation:** check option relationships, feature gates and
   profile/command-key conflicts; surface configuration errors.
3. **Proposed — compatibility:** exercise schema/loader parity and migration
   of older profiles across build-flag combinations.

## Reproducible check

Run `xmake test options_test`. Cases in
[options_test.cc](../tests/options/options_test.cc) cover shipped profiles,
settings, rejected inputs and disabled features. The documented YAML subset
and schema are in the [README](../README.md#configuration) and
[profiles.schema.json](../schemas/profiles.schema.json).

Implementation: [options.cc](../src/options/options.cc),
[profiles.cc](../src/options/profiles.cc), and [validate.cc](../src/options/validate.cc).
