# lagsw

`lagsw` is a Windows console utility that temporarily delays matching network
packets. It uses the embedded [WinDivert](win_divert/README) driver to capture
packets, hold them in memory, and reinject them after the configured delay.

Profiles define which key or key combination activates packet capture, which
packets are captured, and how those packets are released. This makes it useful
for testing network-sensitive software and for manually simulating latency.

> **Warning:** Delaying or reinjecting packets can disrupt network connections.
> Use this only on systems and networks where you are authorized to intercept
> traffic. Start with a narrow filter and keep a way to terminate the program.

## Requirements

- Windows 10 or newer, or Windows Server with WinDivert support
- Visual Studio C++ tools with C++20 support
- [XMake](https://xmake.io/)
- Administrator privileges at runtime

WinDivert binaries and headers are included in [`win_divert/`](win_divert/).
The executable is built with a Windows administrator manifest because WinDivert
needs permission to open its capture handle. The project currently targets
64-bit Windows through the checked-in WinDivert runtime resources.

## Build

From a Visual Studio developer PowerShell or command prompt:

```powershell
xmake f -p windows -a x64 -m release
xmake
```

For a debug build:

```powershell
xmake f -p windows -a x64 -m debug
xmake
```

The executable is generated under XMake's build directory, typically
`build/windows/x64/release/lagsw.exe` or
`build/windows/x64/debug/lagsw.exe`.

To remove generated build output:

```powershell
xmake clean
```

## Usage

The configuration file must be supplied explicitly:

```powershell
lagsw.exe --config profiles/test.yml
```

To discover the busiest server on a port while the program runs, configure
`servers` as an object with `discovery_port` (see [Configuration](#configuration)):

```yaml
servers:
  discovery_port: 55000
  interval: 5000
```

```powershell
lagsw.exe --config profiles/test.yml
```

Options:

| Option | Description |
| --- | --- |
| `--config <file>` | Load profiles from a YAML file. Required. |
| `--log-level <level>`, `-l <level>` | Set the minimum log level: `error`, `warn`, `info`, or `debug`. |
| `--server <server>`, `-s <server>` | Select the initial configured server by name or address. Unknown values warn and use `none`. |
| `--resolve-region` | Resolve the geographic region of discovered servers. |
| `--help`, `-h` | Print command help and exit. |

While the program is running:

- Activate a `toggle` profile by pressing its configured key or key combination.
  Press it again to deactivate the profile.
- Activate a `hold` profile by holding its configured key or combination.
  Releasing the key deactivates it.
- Press `Tab` to print packet and activation statistics.
  When discovery is enabled, it also prints the current authoritative server
  and a packet-ranked list for the active discovery window.
- Press Page Up or Page Down to cycle the configured server filter, including
  `none` (which applies no server filter).
- Press `q`, `Q`, or Backspace to quit.

Multiple profiles can be active at the same time. Profiles may share keys; a
key press enables every matching toggle profile when the group is only partly
active, and deactivates the group only when every matching profile is active.
Hold profiles follow the key state independently. Each active profile has its
own capture handle and packet queue. `Tab` is reserved for displaying state
and cannot be used as a profile key.

When discovery is enabled (via `servers.discovery_port` in the configuration),
lagsw opens a sniff-only handle and counts packets to and from the selected
port without delaying them. At the end of each window, the remote address with
the highest packet count is logged as authoritative and added to the server
list. If that address is already in the list, lagsw warns and reuses the
existing entry. Discovery switches to the authoritative server when no
concrete server was selected. Both an omitted `--server` argument and explicit
`--server none` request automatic selection. A concrete `--server` selection is
never replaced by discovery. Discovery is temporarily paused while any profile
is active and resumes with a fresh window after all profiles are deactivated.
Profiles with `server_direction` use the selected server when they are next
activated.

## Configuration

The parser accepts the YAML-shaped subset used by the examples in
[`profiles/`](profiles/). A configuration contains a global filter and one or
more profiles:

```yaml
global_filter: "tcp.DstPort == 55000 or tcp.SrcPort == 55000"

servers:
  - "34.90.202.108:game server"
  - "203.0.113.10:backup server"

profiles:
  - name: "Example"
    key: space
    mode: toggle
    disables: "Other profile"
    delay_mode: from_timestamp
    retransmission_mode: both
    delay_ms: 500
    windivert_options:
      forward: false
      server_direction: destination
```

### Top-level fields

| Field | Required | Description |
| --- | --- | --- |
| `global_filter` | No | WinDivert filter used by profiles that do not define `filter`. Defaults to `tcp.DstPort == 55000 or tcp.SrcPort == 55000`. |
| `servers` | No | Either a string array of server addresses, or an object enabling server discovery (see below). |
| `profiles` | Yes | A non-empty list of profile definitions. |

`servers` as a list is a set of known server addresses. An entry may use
`address:name` to provide the status-bar name:

```yaml
servers:
  - "34.90.202.108:game server"
  - "203.0.113.10:backup server"
```

`servers` as an object enables server discovery instead of a fixed list:

```yaml
servers:
  discovery_port: 55000
  interval: 5000
```

| Field | Required | Description |
| --- | --- | --- |
| `discovery_port` | Yes | Port (1-65535) to observe TCP and UDP traffic on; the remote address receiving the most packets in each discovery window is selected. |
| `interval` | No | Discovery window length in milliseconds. Defaults to `5000`. |

### Profile fields

| Field | Required | Description |
| --- | --- | --- |
| `name` | Yes | Display name shown in logs and state output. |
| `key` | One of `key` or `keys` | One activation key. |
| `keys` | One of `key` or `keys` | A list of keys that must all be held, for example `keys: [ctrl, shift]`. A block list is also supported. |
| `key_mode` | No | `oneof` activates when any configured key is held; `combination` activates when all configured keys are held. Defaults to `combination`. |
| `mode` | No | `toggle` or `hold`; defaults to `toggle`. |
| `disables` | No | A profile name, `*`, or a list of either, to keep disabled while this profile is active. `*` disables every other profile. Named targets must be configured profiles and cannot include this profile. |
| `delay_mode` | No | `from_timestamp`, `send_all_after_delay`, `ratio`, `drop`, `drop_and_send`, or `drop_until_toggle`; defaults to `from_timestamp`. |
| `retransmission_mode` | No | `none` allows retransmissions; `only_seq` drops duplicate sequence numbers; `only_ack` drops duplicate acknowledgment numbers; `both` requires a unique `(SeqNum, AckNum)` pair. Defaults to `none`. |
| `delay_ms` | No | Delay in milliseconds. Defaults to `0`. |
| `ratio` | For `ratio` mode | Positive packet count, or a positive percentage such as `50%`. Percentage ratios also require `delay_ms > 0` and may not exceed `100%`. |
| `filter` | No | Profile-specific WinDivert filter. Overrides `global_filter`. |
| `windivert_options` | No | WinDivert capture options described below. |

Keys may be a single printable character or one of `tab`, `space`, `alt`,
`ctrl`, and `shift`. Printable characters are case-insensitive and are stored
as their uppercase virtual-key value. Numeric virtual-key codes are also
accepted, including hexadecimal values such as `0x41`.

When two profiles list each other in `disables`, pressing either profile's key
while the other is active switches directly to the requested profile.

### Delay modes

- `from_timestamp`: Each packet is released at approximately its receive time
  plus `delay_ms`. Packets retain their receive order when release times match.
- `send_all_after_delay`: The first packet starts a batch timer. All packets
  captured in that batch are released together after `delay_ms`.
- `ratio`: Releases packets in groups. With `ratio: 3`, three packets are sent
  per delay interval. With `ratio: 50%`, half of the queued packets are sent at
  each interval, with at least one packet sent when packets are available.
- `drop`: Drops every filtered packet while the profile is active.
- `drop_and_send`: Drops the configured `ratio` of each batch, then sends the
  remaining packets after `delay_ms`. Both `ratio` and a positive `delay_ms` are
  required.
- `drop_until_toggle`: Drops packets after activation. The next toggle starts
  holding packets, and the following toggle sends the held packets and
  deactivates the profile. This mode requires `mode: toggle`.

When `delay_ms` is zero, queued packets wait until the profile is deactivated.
Deactivation flushes all remaining packets immediately, so this is a packet
hold rather than a permanent drop.

### WinDivert options

```yaml
windivert_options:
  sniff: false
  forward: false
  outbound: false
  server_direction: destination
```

Each option is a boolean:

- `sniff`: Capture packets without diverting them from the normal network path.
  Sniffed packets are observed but are not delayed or reinjected by `lagsw`.
- `forward`: Open the WinDivert `NETWORK_FORWARD` layer instead of the normal
  `NETWORK` layer.
- `outbound`: Restrict the filter to outbound packets. Internally, the capture
  filter becomes `outbound and (<filter>)`. This applies only to the normal
  `NETWORK` layer; do not combine it with `forward: true`.
- `server_direction`: When a server is selected, add an `ip.SrcAddr`,
  `ip.DstAddr`, or `ip.Addr` filter for `source`, `destination`, or `both`.
  If no server is selected, no IP server filter is added.

Filters are compiled with WinDivert before the program starts. Invalid filters,
missing profile names or keys, invalid booleans, and invalid delay modes cause
startup to fail with an error.

## Included profiles

[`profiles/test.yml`](profiles/test.yml) provides two simple toggle profiles:

- `RPM`: Space toggles a one-second `send_all_after_delay` batch.
- `Long`: Alt toggles a nine-second `send_all_after_delay` batch.

[`profiles/div1.yml`](profiles/div1.yml) demonstrates timestamp, count-based
ratio, percentage ratio, hold, and indefinite packet-hold behavior. It uses
`forward: true` for every profile and is a useful reference for more advanced
configurations.

## Troubleshooting

- **The program exits with an initialization or handle error:** Run the console
  as Administrator and confirm the WinDivert files match the target
  architecture.
- **No packets are delayed:** Check the active profile's filter, layer, and
  `outbound` setting. Use `--log-level debug` to inspect received packets.
- **The configuration is rejected:** Check that every profile has a name and
  unique key, that all booleans are exactly `true` or `false`, and that a
  `ratio` profile has a positive ratio and `delay_ms`.
- **The console appears stuck:** This is expected while packets are being held.
  Press the active toggle key again, release a hold key, or press `q` to stop;
  queued packets are flushed during teardown.

## Project layout

| Path | Purpose |
| --- | --- |
| `src/` | Application, configuration parser, packet engine, logging, and resource files |
| `include/` | Public project headers |
| `profiles/` | Example YAML configurations |
| `win_divert/` | Embedded WinDivert headers, libraries, drivers, and documentation |
| `xmake.lua` | Project-wide compiler and linker settings |

## License

The `lagsw` project does not currently include a root license file. WinDivert
is distributed under the terms described in [`win_divert/LICENSE`](win_divert/LICENSE).
Review the bundled WinDivert license before redistributing builds that include
its binaries or driver.