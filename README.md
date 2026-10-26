# lagsw

![](https://share.cdn.vmminfra.dev/petko-new/2026/10/powershell_04MIiHw9Ux.png)

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
| `--client-address <address>` | Set both the client source and destination addresses. |
| `--client-source-address <address>` | Set the client source address. |
| `--client-destination-address <address>` | Set the client destination address. |
  client_address_enforcement: both
| `--resolve-region` | Resolve the geographic region of discovered servers. Successful lookups are cached locally for 30 days. |
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
    disable_wait_percent: 50
    respect_disable_wait: true
    delay_mode: from_timestamp
    retransmission_mode: both
    delay_ms: 500
    windivert_options:
      forward: false
      server_direction: destination
```

Servers may also be grouped. Selecting any server in a group applies the
profile filter to every server in that group:

```yaml
servers:
  EU:
    - "34.13.202.203:GR-EUC-203"
    - "34.90.202.108:GR-EUC-108"
```

### Top-level fields

| Field | Required | Description |
| --- | --- | --- |
| `global_filter` | No | WinDivert filter used by profiles that do not define `filter`. Defaults to `tcp.DstPort == 55000 or tcp.SrcPort == 55000`. |
| `servers` | No | Either a string array of server addresses, or an object enabling server discovery (see below). |
| `features` | No | Optional feature configuration, including debug PCAP capture. |
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

### Features

PCAP output is a debugging feature and is disabled by default. When enabled,
each activation of a selected profile writes every packet received by that
profile's capture thread to a separate PCAP file. The file name and the
deactivation log share a GUID. PCAP files contain raw IP packets (`DLT_RAW`)
and can be opened by Wireshark.

```yaml
features:
  pcap_files:
    enabled: true
    output_dir: pcap_files
    enabled_for: "*"
```

| Field | Required | Description |
| --- | --- | --- |
| `enabled` | No | Enables PCAP output. Defaults to `false`. A warning is logged at startup when enabled. |
| `output_dir` | No | Destination directory. Defaults to `pcap_files` beneath the current working directory. |
| `enabled_for` | Yes when enabled | `"*"` for every profile, or a non-empty list of configured profile names. |

The optional `desync_countdown` feature displays an approximate status-line
countdown after selected profiles are deactivated. The estimate is 80% of the
profile's most recent active duration, based on preliminary observations; it
is not a measurement of server state or a guarantee that desync ends at that
time. It is disabled by default.

```yaml
features:
  desync_countdown:
    enabled: true
    duration_percent: 80
    enabled_for:
      - "RPM"
```

| Field | Required | Description |
| --- | --- | --- |
| `enabled` | No | Enables the approximate countdown. Defaults to `false`. |
| `display` | No | `alongside` (default) shows the countdown next to profile activations; `override` shows it instead of the profile's activation status; `until_reactivated` hides it once the profile is reactivated. |
| `duration_percent` | No | Estimated desync duration as a percentage of the selected profile's active duration. Defaults to `80`; valid values are `1`-`100`. |
| `enabled_for` | Yes when enabled | `"*"` for every profile, or a non-empty list of configured profile names. |

Forwarded address discovery dynamically finds the client addresses used to
filter packets when lagsw runs on a PC that shares its internet connection
with a client device (for example, DeviceA is hard-wired to the PC, and the
PC's Wi-Fi, Ethernet, or VPN interface has Windows Internet Connection
Sharing enabled). Packets originating from the client are translated by
Windows ICS as they leave the shared interface, so they arrive twice: once on
the client's own interface with the client's real address, and once on the
shared interface with the PC's address. This feature observes both
interfaces to keep `client_source_address` and `client_destination_address`
up to date automatically, overriding `--client-source-address` and
`--client-destination-address` while addresses are being discovered.

Like server discovery, each interface's traffic is scoped to a configured port
and tallied over a recurring window, with the most frequently observed address
per interface selected at the end of each window. Scoping to the actual
game/server port (the same way server discovery does) keeps unrelated traffic
such as broadcasts from being mistaken for the client's address.

```yaml
features:
  forwarded_address_discovery:
    enabled: true
    inbound: 12
    outbound: 21
    port: 55000
    interval: 5000
```

| Field | Required | Description |
| --- | --- | --- |
| `enabled` | No | Enables forwarded address discovery. Defaults to `false`. |
| `inbound` | Yes when enabled | Interface index of the interface DeviceA (the client) is directly connected to. Used to discover `client_destination_address`. |
| `outbound` | Yes when enabled | Interface index of the shared interface with Internet Connection Sharing enabled (Wi-Fi, Ethernet, or VPN). Used to discover `client_source_address`. |
| `port` | Yes when enabled | Port (1-65535) to observe TCP and UDP traffic on, scoping discovery to the actual game/server traffic. |
| `interval` | No | Discovery window length in milliseconds. Defaults to `5000`. |

Interface indexes can be found with `Get-NetAdapter` in PowerShell (the
`ifIndex` column) or `netsh interface ipv4 show interfaces`. `inbound` and
`outbound` must reference different interfaces. Active profiles are
automatically reconfigured whenever a discovered address changes.

### Profile fields

| Field | Required | Description |
| --- | --- | --- |
| `name` | Yes | Display name shown in logs and state output. |
| `key` | One of `key` or `keys` | One activation key. |
| `keys` | One of `key` or `keys` | A list of keys that must all be held, for example `keys: [ctrl, shift]`. A block list is also supported. |
| `send_key` | No | Optional key that releases the configured `amount` without deactivating the profile. It cannot overlap any profile activation key. |
| `key_mode` | No | `oneof` activates when any configured key is held; `combination` activates when all configured keys are held. Defaults to `combination`. |
| `mode` | No | `toggle`, `hold`, or `period`; defaults to `toggle`. `period` behaves like `toggle` but automatically deactivates after `activation_period`. |
| `activation_period` | Required for `period` | Positive activation duration in milliseconds. At expiry the profile deactivates and flushes queued packets as it does on a manual toggle-off. |
| `disables` | No | A profile name, `*`, or a list of either, to keep disabled while this profile is active. `*` disables every other profile. Named targets must be configured profiles and cannot include this profile. |
| `disable_wait_ms` | No | Time in milliseconds this profile remains active after it is disabled. Defaults to `0`. |
| `disable_wait_percent` | No | Additional wait equal to this percentage of the profile's current enabled time, from `0` to `100`. This is added to `disable_wait_ms`. Defaults to `0`. |
| `respect_disable_wait` | No | When this profile disables another profile with a configured disable wait, wait for that profile to stop before activating. Defaults to `true`; set to `false` to activate immediately. |
| `delay_mode` | No | `from_timestamp`, `send_all_after_delay`, `ratio`, `drop`, `drop_and_send`, `hold_and_send`, `drop_until_toggle`, `hold_until_deactivation`, or `packet_group_send`; defaults to `from_timestamp`.|
| `retransmission_mode` | No | `none` allows retransmissions; `only_seq` drops duplicate sequence numbers; `only_ack` drops duplicate acknowledgment numbers; `both` requires a unique `(SeqNum, AckNum)` pair. Defaults to `none`. |
| `subsequent_packet_hold_mode` | No | For `hold_and_send`, `none` holds only the configured initial packet count; `seq_only`, `ack_only`, or `seq_ack` also holds subsequent TCP packets matching an initially held packet. Defaults to `none`. |
| `delay_ms` | No | Delay in milliseconds. Defaults to `0`. |
| `ratio` | For `ratio`, `drop_and_send`, or `hold_and_send` mode | Positive packet count, or a positive percentage such as `50%`. Percentage ratios also require `delay_ms > 0` and may not exceed `100%`; `hold_and_send` requires a packet count. |
| `amount` | For `hold_until_deactivation` mode | Number of deferred packets released on deactivation; `0` releases all deferred packets. Defaults to `0`. |
| `group_count` | For `packet_group_send` mode | Positive number of packet groups to capture. Activation-key presses delimit groups and then send one group per press.|
| `group_order` | No | `fifo`, `lifo`, or `random`; order in which `packet_group_send` releases captured groups. Defaults to `fifo`.|
| `ratio_selection` | No | `first`, `last`, or `random`; controls which packets a percentage-based `ratio` releases immediately: the first x, the last x, or a random x of the batch. Defaults to `first`. |
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
  each interval, with at least one packet sent when packets are available. For
  percentage-based ratios, `ratio_selection` controls which packets in the
  batch are released immediately: `first` releases the earliest-received
  packets, `last` releases the most recently received packets, and `random`
  releases a random selection. The remaining packets are held until the next
  interval.
- `drop`: Drops every filtered packet while the profile is active.
- `drop_and_send`: Drops the configured `ratio` of each batch, then sends the
  remaining packets after `delay_ms`. Both `ratio` and a positive `delay_ms` are
  required.
- `hold_and_send`: Holds the first `ratio` packets while allowing every later
  packet through immediately. Held packets are sent when the profile is
  deactivated. With `subsequent_packet_hold_mode`, later packets matching an
  initially held TCP packet by sequence, acknowledgment, or both are held as
  well. This mode requires a positive packet-count `ratio`.
- `drop_until_toggle`: Drops packets after activation. The next toggle starts
  holding packets, and the following toggle sends the held packets and
  deactivates the profile. This mode requires `mode: toggle`.
- `hold_until_deactivation`: Holds every packet while active. On the deactivation
  key press, releases `amount` packets for normal sending and then flushes all
  remaining packets during deactivation. An `amount` of `0` releases all held
  packets at once. When `send_key` is configured, pressing it releases the
  configured amount while leaving the profile active. This mode requires
  `mode: toggle`.
- `packet_group_send`: Captures packets into `group_count` groups. The first
  activation starts capturing group 1; each subsequent activation starts the
  next group. After the final group has been captured, each activation sends
  one group in `group_order` (`fifo`, `lifo`, or `random`) order. Packets within
  each group retain their original receive order. The profile deactivates after
  its final group is sent. Group capture, send, and completion are logged, and
  the active group and stage are shown in the status bar. This mode requires
  `mode: toggle`.

When `delay_ms` is zero, queued packets wait until the profile is deactivated.
Deactivation flushes all remaining packets immediately, so this is a packet
hold rather than a permanent drop.

### WinDivert options

```yaml
windivert_options:
  sniff: false
  forward: false
  outbound: false
  client_address_enforcement: both
  server_direction: destination
```

The `client_address_enforcement` option defaults to `both` and accepts
`none`, `source`, `destination`, or `both`. It controls which configured
client address clauses are included in the profile filter.

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

[`profiles/div1.sw.yml`](profiles/div1.sw.yml) demonstrates timestamp, count-based
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