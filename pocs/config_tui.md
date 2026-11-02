# Config TUI PoC

A terminal UI for creating and updating profile files (`*.sw.yml`), so they no longer have to be edited by hand.

## Goal

- Create a new profile file and edit an existing one from inside the terminal, validated against the same rules the
  loader uses (`schemas/profiles.schema.json`, `src/options/validate.cc`).
- Remove the requirement to pass `--config`. Today `src/options/options.cc` fails with `--config is required`; without
  the argument the program now starts the **config loader/editor** instead.
- If `--config <file>` **is** given, the loader/editor is skipped entirely and the program goes straight to the
  `initial_view` (the normal runtime view, as today). The argument keeps its current meaning, so scripts and the README
  examples keep working.
- From the running program the TUI can be reopened at any time (see [Swapping back to the TUI](#swapping-back-to-the-tui))
  to switch profile or change a setting without restarting the app. This works the same whether the app was started
  with `--config` or through the loader.

## Start-up flow

```
lagsw [--config <file>]
  |
  +-- --config present --------------------------> initial_view   (no TUI, no recent-files lookup)
  |
  +-- --config absent
        |
        v
      config loader/editor  --(open/create + confirm)--> initial_view with the chosen file
        |
        +-- quit ------------------------------------> exit 0
```

`initial_view` is the first runtime view after the profile is loaded (the profile's `default_view`, or the plain
status view when it is unset). The loader/editor only decides *which file* gets loaded and hands the path over exactly
as if it had been passed with `--config`; nothing downstream knows the difference.

## Swapping back to the TUI

While running, a hotkey (`features.config_tui.key`, default `C`) returns to the TUI. It is handled like the net
monitor's view key and is only active when the TUI is compiled in.

1. **Suspend**: the running engine is paused (packet channels are closed so nothing queues in the kernel, and the
   traffic being shaped is released, never held). `logging::set_suspended()` holds log lines back while the TUI is shown
   and replays them afterwards. Open views (for example the net monitor) are closed first.
2. **Edit/switch**: the TUI opens on the editor for the **currently loaded file** (`Esc` from there reaches the loader
   view to switch profile). Everything in the loader and editor works as at start-up.
3. **Resume**, depending on what the user did:
   - `Esc`/cancel, or nothing changed: the engine resumes with the already loaded options, unchanged.
   - Saved the current file (`Ctrl+S`) or picked another one and confirmed (`Ctrl+R`): the file is parsed and validated
     with the production loader **before** anything is torn down. If it is invalid the user stays in the editor with the
     error shown, and the old configuration keeps being the active one. If it is valid, the engine is stopped, the new
     options are applied and the engine is started again, ending in the profile's `initial_view`.
   - Quit from the TUI (`q`): the app exits.
4. The file that is now active is moved to the top of the recent list, exactly as when chosen at start-up.

Restart rules for a swap:

- Settings are applied by a full engine stop/start, not by patching live state, so every setting (including ones read
  once at start-up such as the backend and filters) takes effect. Runtime statistics (net monitor window, counters) reset
  with the engine.
- Privileges, the platform backend and the console are kept; only profile-dependent state is rebuilt, so no elevation
  prompt or driver reload is needed.
- A failed restart (for example the new profile's backend cannot open) rolls back: the previous options are restored and
  started again, and the error is shown in the TUI.
- The CLI options other than `--config` (flags given on the command line) stay in force across swaps and win over the
  profile values as they do at start-up.

## Loader view

Lists the recently opened files, newest first, plus two fixed entries: **New profile...** and **Open path...**.

| Key | Action |
|---|---|
| `Up` / `Down` | move the selection |
| `Enter` | open the selected file in the editor (and then run it on confirm) |
| `n` | new profile (starts from a minimal template) |
| `o` | type or paste a path to open |
| `d` | forget the selected entry (never deletes the file) |
| `q` | quit |

### Recent-files list

The list lives in one **shared file** in the per-user config directory, so every invocation (and every working
directory) sees the same history:

| Platform | Location |
|---|---|
| Linux / POSIX | `$XDG_CONFIG_HOME/lagsw/recent.yml`, falling back to `~/.config/lagsw/recent.yml` |
| Windows | `%APPDATA%\lagsw\recent.yml` |

Format (paths stored absolute, newest first, capped at 20 entries, duplicates collapsed):

```yaml
recent:
  - path: /home/user/sw/profiles/div1.sw.yml
    last_opened: 2026-11-02T18:40:57Z
```

The file is rewritten atomically (write to a temp file, rename) whenever a file is opened or created, and is created on
first use. A missing or unparsable `recent.yml` is treated as an empty list and never blocks start-up.

### Status markers

Each entry is checked when the loader view opens (and again on `r` refresh). A red `!` is shown in front of the entry
when:

1. **Missing** - the file does not exist anymore (moved or deleted). Label: `! not found`.
2. **Unreadable** - the file exists but cannot be read or parsed (permission error, bad YAML, or it fails validation).
   Label: `! cannot read` followed by the first parser message (line and reason).

Healthy entries show no marker. A marked entry can still be selected: *missing* offers to remove it from the list or
re-create it from the template; *unreadable* opens the editor on the raw text with the parse error pinned to its line
so it can be fixed in place. Entries are never removed automatically.

## Editor view

- A form for the structured keys (`default_view`, `servers`, `profiles`, `features`, ...), driven by the JSON schema so
  new keys show up without UI changes. Enumerations are pick lists, booleans are toggles, numbers are validated on
  input.
- A raw YAML tab for anything the form does not cover; switching tabs re-parses and shows any error.
- `Ctrl+S` validates with the production loader and writes the file (atomic rename, original kept as `<file>.bak` once
  per session). Invalid content can be saved only after an explicit confirmation, and is then marked `!` in the list.
- `Ctrl+R` saves and starts the program with this file, going to `initial_view`.
- `Esc` goes back to the loader view, asking first when there are unsaved changes.

## Implementation sketch

- `src/config_tui/` (new, behind a `config_tui` build feature like `net_monitor`: `xmake f --config_tui=y|n`, default
  `y`). With the feature off, a missing `--config` keeps the current error.
  - `recent_files.{h,cc}`: locate the config dir, load/save `recent.yml`, probe each entry (exists / readable /
    parses).
  - `loader_view.cc`, `editor_view.cc`: the two views, drawn on the terminal's alternate screen like the net monitor.
  - `template.cc`: the minimal new-profile template.
- `src/config_tui/session.cc`: the suspend / edit / apply-or-roll-back loop used by the hotkey; `main.cc` owns the
  engine lifecycle so it can be stopped and rebuilt from new options.
- `src/options/options.cc`: `--config` stops being mandatory. When absent, `main.cc` calls the loader/editor, which
  returns a path (or "quit"); the result is fed to the existing profile loading. The `--config is required` error and the
  README line (`Required.`) are updated accordingly.
- Validation reuses `src/options/profiles.cc` and `validate.cc` through a "parse only, no side effects" entry point, so
  the TUI never diverges from the real loader.
- The TUI needs an interactive terminal. When stdin/stdout is not a TTY and `--config` is absent, keep failing with the
  current error instead of waiting for input.

## Open questions

- Which TUI primitives to use: reuse the net monitor's raw-terminal/alt-screen helpers, or add a small widget layer.
- Comment preservation when saving a form-edited file (a YAML round-trip library versus raw-text edits for the touched
  keys only).
- Whether the editor may create files outside `profiles/` or only in a configured directory.
- Whether unsaved edits should survive a swap that was cancelled (proposed: yes, kept in memory for the session).
- Whether the hotkey should be disabled for profiles that set `features.config_tui.enabled: false`, for unattended runs.
- Whether `--config` should also record the file in the recent list (proposed: no, since that path skips the TUI
  entirely).

## Out of scope

- Patching a running engine in place (hot reload). Changes are applied by suspending and restarting the engine, see
  [Swapping back to the TUI](#swapping-back-to-the-tui).
- Remote or shared profile storage.
