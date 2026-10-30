#include "internal.h"

#ifdef LAGSW_FEATURE_SERVER_DISCOVERY

#include <atomic>
#include <cstdlib>
#include <ctime>
#include <thread>

#include "disconnect_detector.h"
#include "log.h"

LOG_DEFAULT_GROUP(logging::group::discovery)

namespace {
using AddressCounts = std::unordered_map<std::string, uint64_t>;

/// Packet counters reported by the debug heartbeat of server discovery.
struct DiscoveryCounters
{
	std::atomic<uint64_t> received{0}, suppressed{0}, unparsed{0};
};

/// Whether the server of a discovery packet is its destination. The server is the endpoint on the discovery port.
/// Forwarded packets are all tagged outbound, so the direction alone cannot tell the server from the client there.
bool server_is_destination(const ParsedPacket& parsed, const backend::PacketMeta& meta, uint16_t discovery_port)
{
	uint16_t source_port = 0, destination_port = 0;
	if (parsed.tcp)
	{
		source_port		 = swap_u16(parsed.tcp->SrcPort);
		destination_port = swap_u16(parsed.tcp->DstPort);
	}
	else if (parsed.udp)
	{
		source_port		 = swap_u16(parsed.udp->SrcPort);
		destination_port = swap_u16(parsed.udp->DstPort);
	}
	if (source_port == discovery_port && destination_port != discovery_port)
		return false;
	if (destination_port == discovery_port && source_port != discovery_port)
		return true;
	return meta.outbound;
}
}  // namespace

/// Per-run state of server discovery: the address counts of the current window and the heartbeat counters.
struct PacketEngine::DiscoveryScan
{
	explicit DiscoveryScan(uint64_t now) : window_started(now) {}

	AddressCounts					packet_counts;
	std::unordered_set<std::string> seen_servers;
	uint64_t						window_started;
	bool							was_running	   = false;
	uint64_t						total_received = 0;
	DiscoveryCounters				counters;
};

namespace {
/// Logs a summary of the discovery counters once per window. recv() blocks while the port is silent, so the summary has
/// to come from a separate thread to report windows in which no packet was hit at all.
class DiscoveryHeartbeat
{
public:
	DiscoveryHeartbeat(DiscoveryCounters& counters, const uint64_t& window_ms, uint32_t disconnect_drop_percent)
		: detector_(disconnect_drop_percent), thread_([this, &counters, &window_ms] { run(counters, window_ms); })
	{
	}

	~DiscoveryHeartbeat()
	{
		stop_.store(true);
		if (thread_.joinable())
			thread_.join();
	}

	DiscoveryHeartbeat(const DiscoveryHeartbeat&)			 = delete;
	DiscoveryHeartbeat& operator=(const DiscoveryHeartbeat&) = delete;

private:
	void run(DiscoveryCounters& counters, const uint64_t& window_ms)
	{
		uint64_t waited = 0;
		while (!stop_.load())
		{
			platform::sleep_ms(100);
			waited += 100;
			if (waited < window_ms)
				continue;
			waited = 0;
			[[maybe_unused]] const uint64_t received   = counters.received.exchange(0);
			[[maybe_unused]] const uint64_t suppressed = counters.suppressed.exchange(0);
			[[maybe_unused]] const uint64_t unparsed   = counters.unparsed.exchange(0);
			LOG_DEBUG_GROUP(logging::group::discovery_stats,
							"Server discovery: last %s: %llu packets captured (%llu skipped while a profile was active, %llu unparsable)%s",
							logging::format_duration(window_ms).c_str(),
							static_cast<unsigned long long>(received),
							static_cast<unsigned long long>(suppressed),
							static_cast<unsigned long long>(unparsed),
							received == 0 ? " - no packets hit the discovery filter" : "");
			detect_disconnect(received - suppressed, suppressed, window_ms);
		}
	}

	/// Compares the packets counted in a window with the recent average. Windows in which a profile paused discovery
	/// are not comparable, so they reset the history.
	void detect_disconnect(uint64_t counted, uint64_t suppressed, uint64_t window_ms)
	{
		if (suppressed > 0)
		{
			detector_.reset();
			return;
		}
		const double avg = detector_.average();
		switch (detector_.observe(counted))
		{
		case DisconnectDetector::Event::disconnected:
			LOG_WARN("Disconnect detected: %llu packets in the last %s, down from an average of %.1f per window",
					 static_cast<unsigned long long>(counted),
					 logging::format_duration(window_ms).c_str(),
					 avg);
			break;
		case DisconnectDetector::Event::reconnected:
			LOG_INFO("Connection recovered: %llu packets in the last %s", static_cast<unsigned long long>(counted), logging::format_duration(window_ms).c_str());
			break;
		case DisconnectDetector::Event::none:
			break;
		}
	}

	std::atomic<bool> stop_{false};
	DisconnectDetector detector_;
	std::thread		  thread_;
};
}  // namespace

std::string PacketEngine::server_label(const std::string& address) const
{
	const auto server = std::find_if(options_.servers.begin(), options_.servers.end(), [&](const ServerOptions& item) {
		return item.address == address;
	});
	return server == options_.servers.end() ? address : server->name + " [" + address + "]";
}

void PacketEngine::start_discovery_worker()
{
	const ServerDiscoveryOptions& discovery = options_.features.server_discovery;
	const std::string			  filter	= backend::filters::port(discovery.port);
	backend::OpenOptions		  open_options;
	open_options.filter			 = filter;
	open_options.sniff			 = true;
	open_options.include_forward = true;
	std::string open_error;
	LOG_DEBUG_GROUP(logging::group::discovery, "Server discovery setup: opening sniff channel with filter '%s'", filter.c_str());
	state_->discovery_handle = backend::open(open_options, open_error);
	if (!state_->discovery_handle)
	{
		LOG_ERROR("Server discovery setup: failed to open capture channel: %s", open_error.c_str());
		return;
	}
	LOG_INFO("Server discovery enabled on port %u with a %s window", discovery.port, logging::format_duration(discovery.window_ms).c_str());
	state_->discovery_thread = std::thread(&PacketEngine::discover_packets, this);
}

void PacketEngine::discover_packets()
{
	const ServerDiscoveryOptions& discovery = options_.features.server_discovery;
	DiscoveryScan				  scan(platform::tick_ms());
	DiscoveryHeartbeat			  heartbeat(scan.counters, discovery.window_ms, discovery.disconnect_drop_percent);
	uint8_t			   packet_data[0xFFFF];
	LOG_DEBUG_GROUP(logging::group::discovery, "Server discovery: capture loop started, waiting for packets");
	while (!shutdown_)
	{
		backend::PacketMeta address;
		uint32_t			received_length = 0;
		std::string			io_error;
		const backend::IoStatus recv_status =
			state_->discovery_handle->recv(packet_data, sizeof(packet_data), received_length, address, io_error);
		if (recv_status == backend::IoStatus::ok)
		{
			if (!scan_discovery_packet(scan, packet_data, received_length, address))
				continue;
		}
		else if (!shutdown_ && recv_status == backend::IoStatus::error)
		{
			LOG_ERROR_GROUP(logging::group::discovery, "Server discovery recv: %s", io_error.c_str());
		}
		else if (!shutdown_)
		{
			LOG_DEBUG_GROUP(logging::group::discovery_packet, "Server discovery: recv returned status %d without a packet", static_cast<int>(recv_status));
		}

		const uint64_t now = platform::tick_ms();
		if (now - scan.window_started < discovery.window_ms)
			continue;
		finish_discovery_window(scan);
		scan.window_started = now;
	}
}

bool PacketEngine::scan_discovery_packet(DiscoveryScan& scan, const uint8_t* packet_data, uint32_t length, const backend::PacketMeta& meta)
{
	++scan.counters.received;
	if (++scan.total_received == 1)
		LOG_DEBUG_GROUP(logging::group::discovery, "Server discovery: first packet captured (%u bytes)", length);
	if (running_.load())
	{
		if (!scan.was_running)
			LOG_DEBUG_GROUP(logging::group::discovery, "Server discovery disabled while a profile is active");
		++scan.counters.suppressed;
		scan.was_running = true;
		scan.packet_counts.clear();
		{
			std::lock_guard<std::mutex> lock(state_->discovery_mutex);
			state_->discovery_counts.clear();
		}
		scan.window_started = platform::tick_ms();
		return false;
	}
	if (scan.was_running)
	{
		LOG_DEBUG_GROUP(logging::group::discovery, "Server discovery enabled after all profiles were deactivated");
		scan.was_running	= false;
		scan.window_started = platform::tick_ms();
	}
	ParsedPacket parsed;
	if (!parse_packet(packet_data, length, parsed))
	{
		++scan.counters.unparsed;
		LOG_DEBUG_GROUP(logging::group::discovery_packet, "Server discovery: ignoring unparsable packet (%u bytes)", length);
		return true;
	}
	const std::string address_text = endpoint_address(parsed, server_is_destination(parsed, meta, options_.features.server_discovery.port));
	if (address_text.empty())
	{
		LOG_DEBUG_GROUP(logging::group::discovery_packet, "Server discovery: packet has no usable IP address");
		return true;
	}
	LOG_DEBUG_GROUP(logging::group::discovery_packet,
					"Server discovery: %s packet, %u bytes, %s, counted for server %s (if_index = %u)",
					meta.outbound ? "outbound" : "inbound",
					length,
					parsed.tcp ? format_tcp_flags(*parsed.tcp).c_str() : (parsed.udp ? "UDP" : "-"),
					address_text.c_str(),
					meta.if_index);
	count_discovered_server(scan, address_text);
	return true;
}

void PacketEngine::count_discovered_server(DiscoveryScan& scan, const std::string& address_text)
{
	std::lock_guard<std::mutex> lifecycle_lock(state_->lifecycle_mutex);
	const bool					first_seen = scan.seen_servers.insert(address_text).second;
	const bool					configured_server =
		std::any_of(options_.servers.begin(), options_.servers.end(), [&](const ServerOptions& server) {
			return server.address == address_text;
		});
	if (!configured_server)
		options_.servers.push_back({address_text, address_text, ""});
	if (first_seen)
	{
		const std::string label = server_label(address_text);
		LOG_SERVER("Server '%s' is potentially the authoritative server (first packet received)", label.c_str());
		if (options_.resolve_region)
		{
			if (is_public_address(address_text))
			{
				LOG_DEBUG_GROUP(logging::group::discovery, "Server discovery: '%s' is public, triggering region lookup", address_text.c_str());
				resolve_region(address_text, configured_server);
			}
			else
				LOG_DEBUG_GROUP(logging::group::discovery, "Server discovery: '%s' is private/local, skipping region lookup", address_text.c_str());
		}
	}
	++scan.packet_counts[address_text];
	state_->discovery_counts = scan.packet_counts;
}

void PacketEngine::finish_discovery_window(DiscoveryScan& scan)
{
	if (!scan.packet_counts.empty())
	{
		const auto winner = std::max_element(scan.packet_counts.begin(), scan.packet_counts.end(), [](const auto& left, const auto& right) {
			return left.second < right.second;
		});
		std::lock_guard<std::mutex> lifecycle_lock(state_->lifecycle_mutex);
		std::lock_guard<std::mutex> lock(state_->discovery_mutex);
		if (state_->discovered_server != winner->first)
		{
			auto existing_server = std::find_if(options_.servers.begin(), options_.servers.end(), [&](const ServerOptions& server) {
				return server.address == winner->first;
			});
			if (existing_server == options_.servers.end())
			{
				options_.servers.push_back({winner->first, winner->first, ""});
				existing_server = options_.servers.end() - 1;
			}
			else
				LOG_WARN("Discovered server '%s' already exists in the server list; switching to '%s'",
						 winner->first.c_str(),
						 existing_server->name.c_str());
			state_->discovered_server	   = winner->first;
			const std::string label = server_label(winner->first);
			LOG_SERVER("Server '%s' is the authoritative server (%llu packets in %s)",
					   label.c_str(),
					   static_cast<unsigned long long>(winner->second),
					   logging::format_duration(options_.features.server_discovery.window_ms).c_str());
			if (state_->select_authoritative_server || state_->authoritative_server)
			{
				state_->authoritative_server		= true;
				state_->select_authoritative_server = false;
				server_index_						= static_cast<size_t>(std::distance(options_.servers.begin(), existing_server)) + 1;
			}
		}
	}
	scan.packet_counts.clear();
	std::lock_guard<std::mutex> lock(state_->discovery_mutex);
	state_->discovery_counts.clear();
}

#endif  // LAGSW_FEATURE_SERVER_DISCOVERY
