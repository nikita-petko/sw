# PoC: App code reduction via libraries

## Status and scope

**Proposed:** evaluate established libraries for configuration parsing and JSON
generation before adding more handwritten format handling. No dependency or
runtime behavior changes are part of this PoC.

The largest direct opportunities are profile YAML loading and the net monitor's
JSON output. The app does not currently parse JSON at runtime: the profile JSON
Schema is for external validation tooling, not a second application config
format.

## Current implementation

| Area | Current code | What it does |
| --- | --- | --- |
| Profile YAML | [profiles.cc](../src/options/profiles.cc) | A line-oriented parser for the documented YAML-shaped subset. It tracks indentation, lists and sections, then maps values into options and performs type/range checks. |
| Config TUI YAML outline | [outline.cc](../src/config_tui/outline.cc) | Finds keys and values in source lines so the editor can replace a value without reformatting the file. `yaml_scalar()` quotes edited strings. |
| Recent-files YAML | [recent_files.cc](../src/config_tui/recent_files.cc) | Reads and writes a small `recent.yml` format with custom trimming, quoting and field handling. |
| Net monitor JSON | [export.cc](../src/net_monitor/export.cc), [events.cc](../src/net_monitor/events.cc), [json.h](../src/net_monitor/json.h) | Builds JSON and JSON Lines with stream concatenation and a handwritten JSON string escaper. |
| Region lookup JSON | [region_lookup.cc](../src/packet_engine/region_lookup.cc) | Extracts string and number fields from an HTTP JSON response with substring scans; this does not correctly handle escaped quotes or nested keys. |
| Region cache CSV | [region_lookup.cc](../src/packet_engine/region_lookup.cc) | Reads and writes a four-column cache using custom quoting and field splitting, alongside legacy TSV support. |
| Profile schema | [profiles.schema.json](../schemas/profiles.schema.json) | Describes profile configuration for external/tooling validation; it is not used to load profiles in the app. |

Replacing a parser does not replace the app's semantic validation. The loader
still needs to enforce option ranges, enum values, required relationships,
feature-gated behavior, legacy aliases, and the existing diagnostics.

## Package candidates

| Format | Recommendation | Why it fits | Costs and caveats |
| --- | --- | --- | --- |
| YAML | **yaml-cpp** | Mature C++ node API; handles YAML syntax, quoting and collections; parser marks can support file-and-line diagnostics. Could replace syntax handling in both profile loading and the recent-files store, while leaving typed option mapping under app control. | Compiled dependency rather than a small header-only addition. Verify xmake package availability and static builds for MSVC, MinGW, Linux, and the project's Linux sysroot/cross-build path before adopting. |
| JSON | **nlohmann/json** | Header-only C++ API; structured object/array construction and `dump()` can replace manual output escaping and punctuation. Its parser can also replace the region lookup response's substring extraction. | Template compile time and binary size. Validate response fields and types explicitly, and check generated output and numeric edge cases. |

These are candidates, not a mandate to add both dependencies. Prefer package
manager dependencies over copied or vendored parser source. If yaml-cpp does
not fit the supported cross-build matrix, compare an alternative such as
RapidYAML in a small build-and-diagnostics spike before selecting it.

## Other format-handling candidates

| Priority | Area | Candidate | Assessment |
| --- | --- | --- | --- |
| High if JSON is adopted | Region lookup response | Reuse **nlohmann/json** from above. | Avoids a second JSON implementation and correctly handles escaped strings, nested objects and numeric syntax. Keep missing, null, and wrong-typed fields as explicit validation cases; do not silently treat malformed responses as valid data. |
| High if YAML is adopted | Recent-files store | Reuse **yaml-cpp** from above. | Reads and writes `recent.yml` using the same dependency as profiles. Preserve the current entry cap, missing-file behavior, and handling of unrecognized or malformed files. |

Keep the packet-filter grammar and packet-header parsing purpose-built. They
encode backend-specific filter semantics and low-level packet layouts; a
generic expression or protocol library would not directly replace those rules.

## Non-serialization opportunities

| Priority | Area | Candidate | Assessment |
| --- | --- | --- | --- |
| Conditional | Command-line options | **CLI11** | Could replace the manual `argv` dispatch in [options.cc](../src/options/options.cc) with declarative options, typed values and generated help. The current CLI is short and has a custom config/TUI flow, so this is worthwhile mainly if options, subcommands or validation grow. Preserve option precedence and the existing behavior where help exits through the `parse_options` result. |
| Conditional, larger change | Terminal UI | **FTXUI** or a comparable cross-platform C++ TUI toolkit | Could replace parts of the custom menu, layout, key handling and ANSI frame drawing in [config_tui/app.cc](../src/config_tui/app.cc), [session.cc](../src/config_tui/session.cc) and the net monitor renderer. This is a UI redesign/migration rather than a small refactor: verify alternate-screen/log integration, resize behavior, Windows/Linux support and accessibility. It would not replace the packet-engine hotkey input, including Linux evdev support that works when the terminal is unfocused. |
| Low / targeted | IP address parsing | **Boost.Asio IP address** or a small focused IPv4/IPv6 address library | Could replace ad hoc string checks and `stoi` in `is_public_address()` with parsed address bytes and explicit CIDR range checks. Parsing alone does not define “public”; the app must choose and test the exact excluded special-use ranges. A new dependency may be excessive for this isolated helper, so first compare with the platform socket conversion APIs already used in the backends. |

Do not add a package just to replace small helpers. The app already uses
standard-library facilities for filesystem paths, clocks, random distributions
and containers; those are not meaningful replacement targets. Similarly,
terminal chart drawing and formatting are application-specific presentation,
and packet-filter grammar and packet-header parsing encode backend semantics.
The project already uses libcurl for HTTPS, so replacing its HTTP transport is
not an obvious code-reduction opportunity.

## Proposed phases

1. **Baseline — proposed:** run the relevant test targets and preserve
   representative profile files, recent-file stores, region API responses,
   cache files and net monitor exports as compatibility fixtures. Record
   package/build impact for the supported toolchains.
2. **YAML loader — proposed:** parse into YAML nodes, then reuse the existing
   option setters, enum conversions and validation where practical. Preserve
   feature guards and the behavior of shared profiles containing sections not
   compiled into a particular build. Use parser marks for useful diagnostics;
   reject malformed YAML rather than silently accepting it. Verify shipped
   profiles, comments and quoted values, inline and block lists, aliases,
   unknown keys, invalid types/ranges and feature-disabled builds. Apply the
   same parser to `recent.yml` only if it preserves the store's current
   recovery and compatibility behavior.
3. **JSON — proposed:** use the selected library for both structured net
   monitor output and region API response parsing. Keep the export schema,
   JSON Lines record shapes and CSV behavior unchanged. Compare parsed output
   rather than whitespace, and cover quotes, escaped strings, nested keys,
   missing/wrong-typed fields, empty strings, large counters and floating-point
   edge cases.
4. **TUI decision — proposed:** do not replace the outline editor with a
   parse-then-dump flow as part of the loader migration. Its source-offset
   edits intentionally retain comments and formatting. Keep its narrow
   source-preserving logic unless a concrete YAML library API can support
   edits without losing that behavior.

## Acceptance criteria

- The test suite continues to accept the shipped and documented profiles and
  reject invalid configurations with actionable file/line context.
- Feature-disabled builds retain current profile-sharing behavior.
- TUI edits preserve unrelated comments, whitespace and source formatting.
- JSON and JSON Lines outputs remain valid and retain their existing field
  names, types and values.
- `xmake build`, tests and packaging work for supported native and cross
  targets, with dependency size/build-time impact recorded before adoption.

## Reproducible checks

Run the relevant existing tests individually:

```sh
xmake test options_test
xmake test config_tui_test
xmake test net_monitor_test
```

Profile behavior is documented in
[profile configuration](profile_configuration.md) and [config TUI](config_tui.md);
JSON export behavior is covered in [net monitor](net_monitor.md).
