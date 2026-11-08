# Proof-of-concept index

These documents describe the current implementation and phased work for app
features and proposed experiments. **Complete** refers to the documented core,
not every proposed follow-up; **proposed** phases are ideas, not claims that
tests have been run. See each document for limitations and reproducible checks.
Packet manipulation and capture must be limited to authorized traffic.

## Packet modes

Each configured `delay_mode` has its own PoC:

| Mode | PoC |
| --- | --- |
| `from_timestamp` | [Per-packet delay](packet_mode_from_timestamp.md) |
| `send_all_after_delay` | [Batch delay](packet_mode_send_all_after_delay.md) |
| `ratio` | [Ratio release](packet_mode_ratio.md) |
| `drop` | [Drop](packet_mode_drop.md) |
| `drop_and_send` | [Drop and send](packet_mode_drop_and_send.md) |
| `hold_and_send` | [Hold and send](packet_mode_hold_and_send.md) |
| `drop_until_toggle` | [Drop until toggle](packet_mode_drop_until_toggle.md) |
| `hold_until_deactivation` | [Hold until deactivation](packet_mode_hold_until_deactivation.md) |
| `packet_group_send` | [Packet group send](packet_mode_packet_group_send.md) |

[Shared TCP handling](packet_tcp_handling.md) covers retransmission filtering
and ACK restoration that apply across modes.

## App features

| Feature | PoC |
| --- | --- |
| Profile loading and validation | [Profile configuration](profile_configuration.md) |
| Profile keys, lifecycle and coordination | [Profile activation](profile_activation.md) |
| Filters, sniff and forwarding | [Capture filters](capture_filters.md) |
| Server discovery and disconnect detection | [Server discovery](server_discovery.md) |
| Region enforcement | [Region enforcement](region_enforcement.md) |
| Geographic region lookup | [Region lookup](region_lookup.md) |
| Forwarded client-address discovery | [Forwarded address discovery](forwarded_address_discovery.md) |
| Passive baseline latency | [Passive latency](passive_latency.md) |
| Per-activation PCAP | [PCAP files](pcap_files.md) |
| Desync countdown | [Desync countdown](desync_countdown.md) |
| Backend health | [Backend monitor](backend_monitor.md) |
| Network statistics view | [Net monitor](net_monitor.md) |
| Profile editor and loader | [Config TUI](config_tui.md) |
| Logs and runtime status | [Logging and status](logging_and_status.md) |

## Packet backends and proposed experiments

| Area | PoC |
| --- | --- |
| Windows WinDivert | [WinDivert backend](windivert_backend.md) |
| Unsupported-platform fallback | [Stub backend](stub_backend.md) |
| Linux NFQUEUE | [NFQUEUE backend](linux_nfqueue_backend.md) |
| Linux eBPF / netlink | [eBPF / netlink backend](linux_ebpf_netlink_backend.md) |
| Linux kernel module | [Kernel-module backend](linux_kernel_module_backend.md) |
| Linux AF_PACKET passive capture | [AF_PACKET backend](linux_afpacket_backend.md) |
| Linux tc/netem | [tc/netem backend](linux_tc_netem_backend.md) |
| TCP/TLS proxy experiment | [TCP/TLS proxy](tcp_tls_proxy.md) |
| TLS record segment removal experiment | [TLS segment removal](tls_segment_removal.md) |

The [main README](../README.md#proofs-of-concept) contains the original
implementation-status summary. See the individual documents for details.
