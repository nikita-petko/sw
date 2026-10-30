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

#ifdef LAGSW_FEATURE_NETFILTER_MONITOR
/// Settings for the NFQUEUE/nftables health line (only reported by the Linux nfqueue backend).
struct NetfilterMonitorOptions
{
	/// Enables the extra status line.
	bool enabled = false;
	/// Minimum time between samples of the kernel queue state and the nftables table, in milliseconds.
	uint64_t interval_ms = 1000;
	/// Queue depth (packets waiting in the kernel for a verdict) at which the line is flagged as backlogged.
	uint32_t backlog_threshold = 1000;
};
#endif

/// Optional packet-engine features and their configuration. Only the features compiled into the build are present.
struct FeaturesOptions
{
#ifdef LAGSW_FEATURE_SERVER_DISCOVERY
	/// Server-discovery feature settings.
	ServerDiscoveryOptions server_discovery;
#endif
#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
	/// Region-enforcement feature settings.
	RegionEnforcementOptions region_enforcement;
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
#ifdef LAGSW_FEATURE_NETFILTER_MONITOR
	/// Netfilter-monitor feature settings.
	NetfilterMonitorOptions netfilter_monitor;
#endif
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