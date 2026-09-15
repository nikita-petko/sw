#ifndef PACKET_ENGINE_H_
#define PACKET_ENGINE_H_

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <thread>
#include <string>
#include <vector>



struct WinDivertOptions
{
	std::optional<bool> sniff;
	std::optional<bool> forward;
	std::optional<bool> outbound;
	enum class ClientAddressEnforcement
	{
		none,
		source,
		destination,
		both,
	};
	std::optional<ClientAddressEnforcement> client_address_enforcement;
	enum class ServerDirection
	{
		source,
		destination,
		both,
	};
	std::optional<ServerDirection> server_direction;
};

struct ServerOptions
{
	std::string address;
	std::string name;
	std::string group;
};

enum class ProfileActivationMode
{
	toggle,
	hold,
};
enum class ProfileKeyMode
{
	combination,
	oneof,
};
enum class PacketDelayMode
{
	from_timestamp,
	send_all_after_delay,
	ratio,
	drop,
	drop_and_send,
	hold_and_send,
	drop_until_toggle,
};

enum class RetransmissionMode
{
	none,
	only_seq,
	only_ack,
	both,
};

enum class SubsequentPacketHoldMode
{
	none,
	seq_only,
	ack_only,
	seq_ack,
};

enum class RatioSelection
{
	first,
	last,
	random,
};

struct ProfileOptions
{
	std::string name;
	std::vector<int> keys;
	std::vector<std::string> disables;
	uint32_t disable_wait_ms = 0;
	uint8_t disable_wait_percent = 0;
	bool respect_disable_wait = true;
	ProfileKeyMode key_mode = ProfileKeyMode::combination;
	ProfileActivationMode mode = ProfileActivationMode::toggle;
	PacketDelayMode delay_mode = PacketDelayMode::from_timestamp;
	RetransmissionMode retransmission_mode = RetransmissionMode::none;
	SubsequentPacketHoldMode subsequent_packet_hold_mode = SubsequentPacketHoldMode::none;
	bool ack_restoration = false;
	int32_t delay_ms = 0;
	int32_t ratio = 1;
	bool ratio_percent = false;
	bool ratio_configured = false;
	RatioSelection ratio_selection = RatioSelection::first;
	std::optional<std::string> filter;
	WinDivertOptions windivert_options;
};

struct RegionEnforcementOptions
{
	bool enabled = false;
	uint16_t probe_port = 0;
};

struct PcapFilesOptions
{
	bool enabled = false;
	std::string output_dir = "pcap_files";
	std::vector<std::string> enabled_for;
};

struct FeaturesOptions
{
	RegionEnforcementOptions region_enforcement;
	PcapFilesOptions pcap_files;
};

struct PacketEngineOptions
{
	std::string global_filter;
	std::vector<ServerOptions> servers;
	std::vector<ProfileOptions> profiles;
	std::optional<std::string> initial_server;
	std::optional<std::string> client_source_address;
	std::optional<std::string> client_destination_address;
	std::optional<uint16_t> discovery_port;
	uint64_t discovery_window_ms = 5000;
	bool resolve_region = false;
	FeaturesOptions features;
};

class PacketMode;

class PacketEngine
{
public:
	explicit PacketEngine(PacketEngineOptions options);
	~PacketEngine();

	PacketEngine(const PacketEngine&) = delete;
	PacketEngine& operator=(const PacketEngine&) = delete;

	void start_workers();
	void stop_workers();
	void setup(int profile);
	void teardown(int profile);
	bool toggle(int profile);
	void teardown();
	bool is_running() const;
	bool is_running(int profile) const;
	bool is_authoritative_server() const;
	bool is_region_enforcement_enabled() const;
	uint64_t running_time_ms() const;
	uint64_t profile_running_time_ms(int profile) const;
	size_t pending_packets() const;
	uint64_t next_batch_in_ms() const;
	void cycle_server(int direction);
	void cycle_enforced_region(int direction);
	std::string current_server() const;
	std::string current_enforced_region() const;
	std::vector<std::string> configured_regions() const;
	std::string current_server_region() const;
	std::string client_region() const;
	std::string region_enforcement_status() const;
	void print_state() const;

private:
	struct Session;
	void read_packets(const std::shared_ptr<Session>& session);
	void write_packets(const std::shared_ptr<Session>& session);
	void discover_packets();
	void probe_packets();
	void region_enforcement_recv();
	void region_enforcement_send();
	void start_region_enforcement();
	void stop_region_enforcement();
	std::string region_enforcement_filter() const;
	void resolve_region(const std::string& address, bool preserve_name = false);
	void resolve_client_region();
	std::string server_filter(const ProfileOptions& profile) const;

	PacketEngineOptions options_;
	std::atomic<bool> running_ = false;
	std::atomic<bool> shutdown_ = false;
	std::atomic<size_t> server_index_ = 0;
	std::atomic<size_t> enforced_region_index_ = 0;
	std::vector<std::unique_ptr<PacketMode>> packet_modes_;

	struct State;
	std::unique_ptr<State> state_;
};

#endif