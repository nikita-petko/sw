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
};

struct ProfileOptions
{
	std::string name;
	std::vector<int> keys;
	ProfileKeyMode key_mode = ProfileKeyMode::combination;
	ProfileActivationMode mode = ProfileActivationMode::toggle;
	PacketDelayMode delay_mode = PacketDelayMode::from_timestamp;
	int32_t delay_ms = 0;
	int32_t ratio = 1;
	bool ratio_percent = false;
	bool ratio_configured = false;
	std::optional<std::string> filter;
	WinDivertOptions windivert_options;
};

struct PacketEngineOptions
{
	std::string global_filter;
	std::vector<ServerOptions> servers;
	std::vector<ProfileOptions> profiles;
	std::optional<std::string> initial_server;
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
	void teardown();
	bool is_running() const;
	bool is_running(int profile) const;
	uint64_t running_time_ms() const;
	size_t pending_packets() const;
	uint64_t next_batch_in_ms() const;
	void cycle_server(int direction);
	std::string current_server() const;
	void print_state() const;

private:
	struct Session;
	void read_packets(const std::shared_ptr<Session>& session);
	void write_packets(const std::shared_ptr<Session>& session);
	std::string server_filter(const ProfileOptions& profile) const;

	PacketEngineOptions options_;
	std::atomic<bool> running_ = false;
	std::atomic<bool> shutdown_ = false;
	std::atomic<size_t> server_index_ = 0;
	std::vector<std::unique_ptr<PacketMode>> packet_modes_;

	struct State;
	std::unique_ptr<State> state_;
};

#endif