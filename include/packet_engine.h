#ifndef PACKET_ENGINE_H_
#define PACKET_ENGINE_H_

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "packet_backend.h"



/// Optional per-profile overrides for packet capture and filtering.
struct CaptureOptions
{
	/// Optional override for sniff mode (observe without intercepting).
	std::optional<bool> sniff;
	/// Optional override for capturing forwarded traffic.
	std::optional<bool> forward;
	/// Optional override for capturing outbound traffic.
	std::optional<bool> outbound;
	/// Which client address fields to enforce when filtering packets.
	using ClientAddressEnforcement = backend::ClientAddressEnforcement;
	std::optional<ClientAddressEnforcement> client_address_enforcement;
	/// Which packet endpoint is matched against the selected server.
	using ServerDirection = backend::ServerDirection;
	std::optional<ServerDirection> server_direction;
};

/// A configured server address and its optional display metadata.
struct ServerOptions
{
	/// Server IP address.
	std::string address;
	/// Optional display name for the server.
	std::string name;
	/// Optional group used to organize server choices.
	std::string group;
};

/// How a profile is activated and deactivated.
enum class ProfileActivationMode
{
	toggle, ///< Activation toggles on each key press.
	hold,   ///< The profile remains active while its key is held.
	period, ///< The profile activates for a configured period.
};
/// How keys in a profile's key list are combined.
enum class ProfileKeyMode
{
	combination, ///< All configured keys are required together.
	oneof,       ///< Any configured key can activate the profile.
};
/// The packet handling behavior selected for a profile.
enum class PacketDelayMode
{
	from_timestamp,         ///< Preserve capture timing and add the configured delay.
	send_all_after_delay,   ///< Release queued packets after the configured delay.
	ratio,                  ///< Delay a selected ratio of packets.
	drop,                   ///< Drop packets while the profile is active.
	drop_and_send,          ///< Drop packets, then send them when the profile deactivates.
	hold_and_send,          ///< Hold packets, then send them when the profile deactivates.
	drop_until_toggle,      ///< Drop packets until the profile is toggled off.
	hold_until_deactivation,///< Hold packets until the profile deactivates.
	packet_group_send,      ///< Capture packet groups, then send one ordered group per activation key press.
};

/// Order in which packet groups are sent by packet_group_send mode.
enum class PacketGroupOrder
{
	fifo,   ///< Send groups in capture order.
	lifo,   ///< Send groups in reverse capture order.
	random, ///< Send groups in a random order.
};

/// Which queued TCP retransmissions are recognized and discarded.
enum class RetransmissionMode
{
	none,     ///< Do not filter retransmissions.
	only_seq, ///< Treat matching TCP sequence numbers as duplicates.
	only_ack, ///< Treat matching TCP acknowledgment numbers as duplicates.
	both,     ///< Require both sequence and acknowledgment numbers to match.
};

/// Which TCP number fields determine whether a subsequent packet is held.
enum class SubsequentPacketHoldMode
{
	none,     ///< Do not hold subsequent packets based on TCP numbers.
	seq_only, ///< Match by TCP sequence number.
	ack_only, ///< Match by TCP acknowledgment number.
	seq_ack,  ///< Match by both TCP sequence and acknowledgment numbers.
};

/// Which packet is chosen when applying ratio-based selection.
enum class RatioSelection
{
	first,  ///< Select the first matching packet.
	last,   ///< Select the last matching packet.
	random, ///< Select a matching packet at random.
};

/// Configuration for one packet-processing profile.
struct ProfileOptions
{
	/// Profile display name.
	std::string name;
	/// Virtual keys used to activate the profile.
	std::vector<int> keys;
	/// Optional key used to send queued packets on demand.
	std::optional<int> send_key;
	/// Names of profiles disabled while this profile is active.
	std::vector<std::string> disables;
	/// Delay before dependent profiles are allowed to activate, in milliseconds.
	uint32_t disable_wait_ms = 0;
	/// Percentage-based disable wait.
	uint8_t disable_wait_percent = 0;
	/// Whether the disable wait is observed when deactivating.
	bool respect_disable_wait = true;
	/// Rule for combining configured activation keys.
	ProfileKeyMode key_mode = ProfileKeyMode::combination;
	/// Profile activation behavior.
	ProfileActivationMode mode = ProfileActivationMode::toggle;
	/// Activation duration for period mode, in milliseconds.
	uint32_t activation_period_ms = 0;
	/// Packet scheduling or dropping behavior.
	PacketDelayMode delay_mode = PacketDelayMode::from_timestamp;
	/// TCP retransmission filtering behavior.
	RetransmissionMode retransmission_mode = RetransmissionMode::none;
	/// TCP sequence/acknowledgment matching for holding subsequent packets.
	SubsequentPacketHoldMode subsequent_packet_hold_mode = SubsequentPacketHoldMode::none;
	/// Whether to restore monotonically increasing TCP acknowledgments when sending.
	bool ack_restoration = false;
	/// Packet delay in milliseconds.
	int32_t delay_ms = 0;
	/// Packet selection ratio or count, depending on ratio_percent.
	int32_t ratio = 1;
	/// Number of packets used by modes that take an amount.
	int32_t amount = 0;
	/// Number of groups to capture in packet_group_send mode.
	int32_t group_count = 0;
	/// Order used to send captured packet groups.
	PacketGroupOrder group_order = PacketGroupOrder::fifo;
	/// Whether ratio is interpreted as a percentage.
	bool ratio_percent = false;
	/// Whether ratio was explicitly configured.
	bool ratio_configured = false;
	/// Selection rule for ratio-based packet handling.
	RatioSelection ratio_selection = RatioSelection::first;
	/// Optional filter expression for this profile, in the active backend's filter syntax.
	std::optional<std::string> filter;
	/// Optional capture behavior overrides for this profile (YAML key: capture_options; legacy alias: windivert_options).
	CaptureOptions capture_options;
};

// Each optional feature is compiled in only when its LAGSW_FEATURE_* definition is set (see the root xmake.lua).

#ifdef LAGSW_FEATURE_SERVER_DISCOVERY
/// Settings for discovering the authoritative server from the traffic observed on a port.
struct ServerDiscoveryOptions
{
	/// Enables server discovery.
	bool enabled = false;
	/// Port whose traffic is observed; the remote address receiving the most packets in a window is the authoritative server.
	uint16_t port = 0;
	/// Discovery observation window, in milliseconds.
	uint64_t window_ms = 5000;
	/// Percentage a discovery window's packet count must fall below the recent average to report a disconnect. 0 disables detection.
	uint32_t disconnect_drop_percent = 80;
};
#endif

#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
/// Settings for automatic region enforcement based on network probes.
struct RegionEnforcementOptions
{
	/// Enables region enforcement.
	bool enabled = false;
	/// UDP probe port used to identify the active region.
	uint16_t probe_port = 0;
};
#endif

#ifdef LAGSW_FEATURE_PASSIVE_LATENCY
/// Distribution of the baseline delay, see pocs/passive_latency.md.
enum class PassiveLatencyMode
{
	fixed,
	uniform,
	normal,
};

/// Which packets passive latency delays.
enum class PassiveLatencyDirection
{
	both,
	inbound,
	outbound,
};

/// Settings for an always-on baseline delay applied to filtered packets, independent of profile activation.
/// See pocs/passive_latency.md. The pause key and capture options are added in a later phase.
struct PassiveLatencyOptions
{
	/// Enables passive latency.
	bool enabled = false;
	/// Delay distribution. Fixed uses delay_ms as is; uniform and normal use it as the mean.
	PassiveLatencyMode mode = PassiveLatencyMode::fixed;
	/// Baseline delay applied to every filtered packet, in milliseconds.
	int32_t delay_ms = 0;
	/// Uniform half-range or normal standard deviation, in milliseconds. Must be 0 for the fixed mode.
	int32_t jitter_ms = 0;
	/// Upper clamp applied after sampling. 0 means delay + 3 * jitter for each direction.
	int32_t max_delay_ms = 0;
	/// Which packets are delayed. Packets of the other direction pass through undelayed.
	PassiveLatencyDirection direction = PassiveLatencyDirection::both;
	/// Overrides delay_ms for inbound packets.
	std::optional<int32_t> inbound_delay_ms;
	/// Overrides delay_ms for outbound packets.
	std::optional<int32_t> outbound_delay_ms;
	/// Never release a packet before an earlier packet of the same direction.
	bool preserve_order = true;
	/// Capture filter in the active backend's syntax. Defaults to global_filter when unset.
	std::optional<std::string> filter;
	/// Virtual key that pauses and resumes passive latency at runtime.
	std::optional<int> pause_key;
	/// Safety bound on queued packets; packets are released immediately (not dropped) past this bound.
	uint32_t max_queued_packets = 4096;

	/// Mean delay for one direction; 0 when that direction is not delayed.
	int32_t effective_delay_ms(bool outbound) const
	{
		if (direction == PassiveLatencyDirection::inbound && outbound)
			return 0;
		if (direction == PassiveLatencyDirection::outbound && !outbound)
			return 0;
		const std::optional<int32_t>& override_ms = outbound ? outbound_delay_ms : inbound_delay_ms;
		return override_ms.value_or(delay_ms);
	}
	/// Jitter for one direction; undelayed directions have none.
	int32_t effective_jitter_ms(bool outbound) const
	{
		return mode == PassiveLatencyMode::fixed || effective_delay_ms(outbound) == 0 ? 0 : jitter_ms;
	}
	/// Upper clamp for one direction.
	int32_t effective_max_delay_ms(bool outbound) const
	{
		const int32_t mean = effective_delay_ms(outbound);
		if (mean == 0)
			return 0;
		return max_delay_ms > 0 ? max_delay_ms : mean + 3 * effective_jitter_ms(outbound);
	}
};
#endif

#ifdef LAGSW_FEATURE_PCAP_FILES
/// Settings for optional per-profile PCAP capture files.
struct PcapFilesOptions
{
	/// Enables packet capture to PCAP files.
	bool enabled = false;
	/// Directory where capture files are written.
	std::string output_dir = "pcap_files";
	/// Profile names to capture, or "*" to capture all profiles.
	std::vector<std::string> enabled_for;
};
#endif

#ifdef LAGSW_FEATURE_DESYNC_COUNTDOWN
/// Controls when the estimated desynchronization countdown is displayed.
enum class DesyncCountdownDisplay
{
	alongside,           ///< Show the countdown alongside normal activation status.
	override_activation, ///< Show the countdown in place of activation status.
	until_reactivated,   ///< Hide the countdown while active and show it until reactivation.
};

/// Settings for the estimated post-deactivation desynchronization countdown.
struct DesyncCountdownOptions
{
	/// Enables the estimated desynchronization countdown.
	bool enabled = false;
	/// Controls how the countdown is presented in the status display.
	DesyncCountdownDisplay display = DesyncCountdownDisplay::alongside;
	/// Estimated countdown as a percentage of the previous active duration.
	uint8_t duration_percent = 80;
	/// Profile names for which to display the countdown.
	std::vector<std::string> enabled_for;
};
#endif

#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
/// Settings for learning the client's forwarded addresses from captured packets.
struct ForwardedAddressDiscoveryOptions
{
	/// Enables learning client addresses from forwarded packets.
	bool enabled = false;
	/// Optional inbound interface index used for packet capture.
	std::optional<uint32_t> inbound_if_idx;
	/// Optional outbound interface index used for packet capture.
	std::optional<uint32_t> outbound_if_idx;
	/// Port used to identify discovery traffic.
	uint16_t port = 0;
	/// Discovery observation window, in milliseconds.
	uint64_t window_ms = 5000;
};
#endif

#ifdef LAGSW_FEATURE_BACKEND_MONITOR
/// Settings for the packet backend health line (NFQUEUE/nftables, swdivert module or WinDivert, depending on the backend).
struct BackendMonitorOptions
{
	/// Enables the extra status line.
	bool enabled = false;
	/// Minimum time between samples of the backend's kernel-side state, in milliseconds.
	uint64_t interval_ms = 1000;
	/// Number of packets waiting (in the kernel, or in user space for WinDivert) at which the line is flagged as backlogged.
	uint32_t backlog_threshold = 1000;
};
#endif

/// Upper-cases a letter key so configured and pressed keys compare equal.
constexpr int normalize_key(int key)
{
	return key >= 'a' && key <= 'z' ? key - 'a' + 'A' : key;
}

#ifdef LAGSW_FEATURE_NET_MONITOR
/// Settings for the full-screen network statistics view, see pocs/net_monitor.md.
struct NetMonitorOptions
{
	/// Enables the view and its key.
	bool enabled = false;
	/// Virtual key that opens and closes the view (upper-case letter, digit or other platform::key code).
	int key = 'N';
	/// Key that pauses and resumes the measurement while the view is open.
	int pause_key = 0x20;
	/// Key that resets the statistics while the view is open.
	int reset_key = 'R';
	/// Key that switches between the overview and the per-flow view.
	int flows_key = 'F';
	/// Key that switches between the overview and the per-profile view.
	int profiles_key = 'P';
	/// Key that exports the measured window.
	int export_key = 'E';
	/// Latency (ms) above which a server raises an alert; 0 disables the alert.
	uint32_t alert_rtt_ms = 150;
	/// Smoothed RTT jitter (ms) above which a server raises an alert; 0 disables the alert.
	uint32_t alert_jitter_ms = 30;
	/// Share of retransmitted TCP data packets (percent, over the last 10 seconds) above which a server raises an alert; 0 disables it.
	uint32_t alert_retransmit_percent = 2;
	/// Inbound silence (ms) from a server at or above which an alert is raised; 0 disables the alert.
	uint32_t alert_stall_ms = 1000;
	/// Inbound silence (ms) at which a server's table row is grayed out; 0 disables this display behavior.
	uint32_t silent_timeout_ms = 30000;
	/// Directory for the files written by the export key; empty uses a `netmonitor` folder in the per-user data directory.
	std::string export_directory;
	/// JSON Lines file that receives one record per server and second while the view is open; empty disables logging.
	std::string log_file;
};
#endif

#ifdef LAGSW_FEATURE_CONFIG_TUI
/// Key that returns to the profile loader/editor while running, see pocs/config_tui.md. It is fixed, not configurable,
/// and profiles that use it for something else fail to load.
constexpr int kConfigTuiKey = 'I';
#endif

/// Which Linux data plane a profile or the passive latency uses.
enum class LinuxTier
{
	automatic, ///< Kernel shaping (eBPF + fq) where it supports the profile, NFQUEUE otherwise.
	nfqueue,   ///< Always NFQUEUE.
	bpf,	   ///< Kernel shaping only; a profile it cannot serve fails to activate.
};

/// Linux kernel-shaping settings (the `linux_bpf` feature). Ignored by other backends.
struct LinuxBpfOptions
{
	LinuxTier				 tier = LinuxTier::automatic;
	/// Interfaces whose egress is shaped. Without any, every profile uses NFQUEUE.
	std::vector<std::string> interfaces;
};

/// Optional packet-engine features and their configuration. Only the features compiled into the build are present.
struct FeaturesOptions
{
	/// Linux kernel-shaping settings (always present; only the Linux backend uses them).
	LinuxBpfOptions linux_bpf;
#ifdef LAGSW_FEATURE_SERVER_DISCOVERY
	/// Server-discovery feature settings.
	ServerDiscoveryOptions server_discovery;
#endif
#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
	/// Region-enforcement feature settings.
	RegionEnforcementOptions region_enforcement;
#endif
#ifdef LAGSW_FEATURE_PASSIVE_LATENCY
	/// Passive-latency feature settings.
	PassiveLatencyOptions passive_latency;
#endif
#ifdef LAGSW_FEATURE_PCAP_FILES
	/// PCAP-capture feature settings.
	PcapFilesOptions pcap_files;
#endif
#ifdef LAGSW_FEATURE_DESYNC_COUNTDOWN
	/// Desynchronization-countdown feature settings.
	DesyncCountdownOptions desync_countdown;
#endif
#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
	/// Forwarded-address-discovery feature settings.
	ForwardedAddressDiscoveryOptions forwarded_address_discovery;
#endif
#ifdef LAGSW_FEATURE_BACKEND_MONITOR
	/// Backend-monitor feature settings.
	BackendMonitorOptions backend_monitor;
#endif
#ifdef LAGSW_FEATURE_NET_MONITOR
	/// Net-monitor feature settings.
	NetMonitorOptions net_monitor;
#endif
#ifdef LAGSW_FEATURE_CONFIG_TUI
	/// Config-TUI feature settings.
#endif
};

/// The view that is shown when the program starts.
enum class DefaultView
{
	/// The scrolling log with the status line.
	log,
	/// The full-screen network statistics view; needs the net_monitor feature to be enabled.
	net_monitor,
};

/// Complete configuration used to construct a packet engine.
struct PacketEngineOptions
{
	/// Filter applied globally to captured packets.
	std::string global_filter;
	/// Configured server addresses and display metadata.
	std::vector<ServerOptions> servers;
	/// Packet-processing profiles.
	std::vector<ProfileOptions> profiles;
	/// Optional server address selected when the engine starts.
	std::optional<std::string> initial_server;
	/// Optional configured client source address.
	std::optional<std::string> client_source_address;
	/// Optional configured client destination address.
	std::optional<std::string> client_destination_address;
	/// Whether to resolve server and client regions.
	bool resolve_region = false;
	/// View shown at startup.
	DefaultView default_view = DefaultView::log;
	/// Optional feature settings.
	FeaturesOptions features;
};

class PacketMode;

/// Manages profile packet processing, server selection, and optional features.
class PacketEngine
{
public:
	/// Creates an engine using the supplied configuration.
	explicit PacketEngine(PacketEngineOptions options);
	/// Stops active profiles and worker threads before destroying the engine.
	~PacketEngine();

	/// Packet engines cannot be copied because they own worker threads and handles.
	/// Copying is disabled because the engine owns worker threads and handles.
	PacketEngine(const PacketEngine&) = delete;
	/// Copy assignment is disabled because the engine owns worker threads and handles.
	PacketEngine& operator=(const PacketEngine&) = delete;

	/// Starts the background workers of the region lookups and the enabled features.
	void start_workers();
	/// Stops background workers started by start_workers().
	void stop_workers();
	/// Activates the numbered profile (profile numbers start at 1).
	void setup(int profile);
	/// Deactivates the numbered profile (profile numbers start at 1).
	void teardown(int profile);
	/// Toggles the numbered profile and returns its resulting active state.
	bool toggle(int profile);
	/// Requests an immediate flush of queued packets for the profile.
	void flush_on_demand(int profile);
	/// Deactivates all profiles and releases engine resources.
	void teardown();
	/// Returns whether any profile is currently active.
	bool is_running() const;
	/// Returns whether the numbered profile is currently active.
	bool is_running(int profile) const;
#ifdef LAGSW_FEATURE_DESYNC_COUNTDOWN
	/// Returns the remaining estimated desynchronization countdown, if available.
	std::optional<uint64_t> profile_desync_countdown_ms(int profile) const;
#endif
#ifdef LAGSW_FEATURE_SERVER_DISCOVERY
	/// Returns whether the selected server has been identified as authoritative.
	bool is_authoritative_server() const;
#endif
#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
	/// Returns whether region enforcement is configured as enabled.
	bool is_region_enforcement_enabled() const;
	/// Returns the current region-enforcement status text.
	std::string region_enforcement_status() const;
#endif
#ifdef LAGSW_FEATURE_PASSIVE_LATENCY
	/// Returns whether passive latency is configured as enabled.
	bool is_passive_latency_enabled() const;
	/// Compact description for the status line, for example "60ms +/-10 (both)".
	std::string passive_latency_status() const;
	/// Pauses or resumes passive latency. Pausing releases every queued packet at once and lets new packets through undelayed.
	void toggle_passive_latency_pause();
	bool is_passive_latency_paused() const;
	/// The configured pause key as an upper-case virtual-key code.
	std::optional<int> passive_latency_pause_key() const;
#endif
#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
	/// Returns whether forwarded-address discovery is configured as enabled.
	bool is_forwarded_address_discovery_enabled() const;
	/// Returns the current forwarded-address discovery status text.
	std::string forwarded_address_discovery_status() const;
#endif
	/// Returns elapsed time in milliseconds since the earliest active profile started.
	uint64_t running_time_ms() const;
	/// Returns the active time in milliseconds for a profile.
	uint64_t profile_running_time_ms(int profile) const;
	/// Returns packet-mode progress text for an active profile, if available.
	std::string profile_packet_status(int profile) const;
	/// Returns the total number of packets currently queued for release.
	size_t pending_packets() const;
	/// Returns the milliseconds until the next queued packet batch is due.
	uint64_t next_batch_in_ms() const;
	/// Selects the next or previous configured server according to direction.
	void cycle_server(int direction);
#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
	/// Selects the next or previous region for enforcement according to direction.
	void cycle_enforced_region(int direction);
#endif
	/// Returns the currently selected server address.
	std::string current_server() const;
	/// Returns a snapshot of the known servers: the configured ones plus those added by server discovery.
	std::vector<ServerOptions> servers() const;
#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
	/// Returns the currently selected enforced region.
	std::string current_enforced_region() const;
	/// Returns the set of configured regions available for enforcement.
	std::vector<std::string> configured_regions() const;
#endif
	/// Returns the resolved region of the selected server, if known.
	std::string current_server_region() const;
	/// Returns the resolved client region, if known.
	std::string client_region() const;
	/// Logs a report of the engine, profile, and feature state.
	void print_state() const;

private:
	struct Session;
	/// Receives and schedules packets for an active profile.
	void read_packets(const std::shared_ptr<Session>& session);
	/// Processes one packet received by a profile, including packets handed off by another stage.
	bool record_profile_packet(const std::shared_ptr<Session>& session, const uint8_t* packet, uint32_t length, const backend::PacketMeta& meta);
	/// Releases scheduled packets for an active profile.
	void write_packets(const std::shared_ptr<Session>& session);
#ifdef LAGSW_FEATURE_SERVER_DISCOVERY
	/// Runs server discovery.
	void discover_packets();
#endif
#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
	/// Monitors packets used by region enforcement.
	void probe_packets();
	/// Receives packets used by region-enforcement forwarding.
	void region_enforcement_recv();
	/// Sends packets buffered by region enforcement.
	void region_enforcement_send();
	/// Opens the region-enforcement capture channel and starts its workers.
	void start_region_enforcement();
	/// Stops region-enforcement workers and closes their handle.
	void stop_region_enforcement();
	/// Builds the backend filter used for region enforcement.
	std::string region_enforcement_filter() const;
	/// Waits until region-enforcement packets are due and sends them. Returns false when the worker should stop.
	bool send_due_enforcement_packets();
	/// Sends every packet still held by region enforcement.
	void flush_enforcement_queue();
	/// Opens the probe-detection capture and starts its thread, then starts region enforcement.
	void start_probe_worker();
	/// Handles a packet captured by probe detection: starts a new probe window and logs the probed server.
	void handle_probe_packet(const uint8_t* packet_data, uint32_t length, const backend::PacketMeta& meta);
	/// Logs a server that was probed for the first time in the current window.
	void log_probed_server(const std::string& server_address);
#endif
#ifdef LAGSW_FEATURE_PASSIVE_LATENCY
	/// Opens the passive-latency capture channel and starts its workers.
	/// Mode and per-direction delays for the startup log.
	std::string describe_passive_latency() const;
	void start_passive_latency();
	/// Stops passive-latency workers, flushing queued packets, and closes their handle.
	void stop_passive_latency();
	/// Receives packets and schedules their delayed release.
	void passive_latency_recv();
	/// Waits until passive-latency packets are due and sends them.
	void passive_latency_send();
	/// Passes a released packet to a profile when backend reinjection cannot reach its capture stage.
	bool handoff_passive_packet(const uint8_t* packet, uint32_t length, const backend::PacketMeta& meta);
	void release_passive_packet(const uint8_t* packet, uint32_t length, const backend::PacketMeta& meta, const char* reason);
	/// Sends every packet still queued by passive latency, unconditionally.
	void flush_passive_latency_queue();
	/// Whether the packet belongs to the region-enforcement probe port, which passive latency must not delay.
	bool is_probe_traffic(const uint8_t* packet, uint32_t length) const;
#endif
#ifdef LAGSW_FEATURE_SERVER_DISCOVERY
	/// Resolves and stores a server region.
	void resolve_region(const std::string& address, bool preserve_name = false);
	/// Applies a cached region of the server; returns false when there is no usable cache entry.
	bool use_cached_region(const std::string& address, bool preserve_name);
	/// Looks up a server's region online (runs on its own thread) and stores the result.
	void lookup_region(const std::string& address, bool preserve_name);
	/// Gives the server its resolved name, unless it is no longer tracked.
	void rename_server(const std::string& address, const std::string& name);
#endif
	/// Looks up the client's own region online (runs on its own thread) and stores the result.
	void lookup_client_region();
#ifdef LAGSW_FEATURE_SERVER_DISCOVERY
	/// Opens the server-discovery capture and starts its thread.
	void start_discovery_worker();
#endif
	/// Resolves the configured or discovered client region.
	void resolve_client_region();
#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
	/// Opens the forwarded-address-discovery capture and starts its thread.
	void start_forwarded_address_worker();
	/// Receives forwarded packets used to discover client addresses.
	void forwarded_address_discovery_recv();
	/// Adopts the busiest address in `counts` as the client's destination (or source) address and restarts active profiles.
	void apply_forwarded_address_winner(std::unordered_map<std::string, uint64_t>& counts, bool is_destination);
#endif
	/// Returns the discovered client source address or its configured fallback.
	std::optional<std::string> effective_client_source_address() const;
	/// Returns the discovered client destination address or its configured fallback.
	std::optional<std::string> effective_client_destination_address() const;
	/// Builds a backend filter for the given profile.
	backend::ProfileFilter server_filter(const ProfileOptions& profile) const;

#ifdef LAGSW_FEATURE_SERVER_DISCOVERY
	struct DiscoveryScan;
	/// Counts one packet captured by server discovery. Returns false when discovery is paused because a profile is active.
	bool scan_discovery_packet(DiscoveryScan& scan, const uint8_t* packet_data, uint32_t length, const backend::PacketMeta& meta);
	/// Records a packet seen from `address` and announces servers that were not seen before.
	void count_discovered_server(DiscoveryScan& scan, const std::string& address);
	/// Ends a discovery window: adopts the busiest address as the authoritative server and starts a new window.
	void finish_discovery_window(DiscoveryScan& scan);
	/// Display name of a server address, with the address in brackets when the server has a different configured name.
	std::string server_label(const std::string& address) const;
#endif

	PacketEngineOptions options_;
	std::atomic<bool> running_ = false;
	std::atomic<bool> shutdown_ = false;
	std::atomic<size_t> server_index_ = 0;
#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
	std::atomic<size_t> enforced_region_index_ = 0;
#endif
	std::vector<std::unique_ptr<PacketMode>> packet_modes_;

	struct State;
	std::unique_ptr<State> state_;
};

#endif