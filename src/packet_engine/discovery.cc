#include "internal.h"

#include <atomic>
#include <cstdlib>
#include <ctime>
#include <thread>

#include "log.h"

namespace {
using AddressCounts = std::unordered_map<std::string, uint64_t>;

/// Packet counters reported by the debug heartbeat of server discovery.
struct DiscoveryCounters
{
	std::atomic<uint64_t> received{0}, suppressed{0}, unparsed{0};
};

/// The source or destination address of an IPv4 or IPv6 packet as text; empty when it has neither header.
std::string endpoint_address(const ParsedPacket& parsed, bool destination)
{
	if (parsed.ipv4)
		return format_ipv4_address(destination ? parsed.ipv4->DstAddr : parsed.ipv4->SrcAddr);
	if (parsed.ipv6)
		return format_ipv6_address(destination ? parsed.ipv6->DstAddr : parsed.ipv6->SrcAddr);
	return {};
}

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

/// Counts a packet seen on the forwarded-address-discovery capture. Returns false when the packet is ignored.
bool count_forwarded_address(const uint8_t*			packet_data,
							 uint32_t				received_length,
							 const backend::PacketMeta& address,
							 uint32_t				inbound_if_idx,
							 uint32_t				outbound_if_idx,
							 AddressCounts&			destination_counts,
							 AddressCounts&			source_counts)
{
	const bool is_inbound_interface	 = address.if_index == inbound_if_idx;
	const bool is_outbound_interface = address.if_index == outbound_if_idx;
	if (!is_inbound_interface && !is_outbound_interface)
	{
		LOG_DEBUG("Forwarded address discovery: ignoring packet on unrelated ifIdx %u (outbound=%d)", address.if_index, address.outbound);
		return false;
	}
	ParsedPacket parsed;
	if (!parse_packet(packet_data, received_length, parsed))
	{
		LOG_DEBUG("Forwarded address discovery: failed to parse packet on ifIdx %u (%s)",
				  address.if_index,
				  is_inbound_interface ? "inbound" : "outbound");
		return false;
	}
	const std::string address_text = endpoint_address(parsed, is_inbound_interface);
	if (address_text.empty())
	{
		LOG_DEBUG("Forwarded address discovery: packet on ifIdx %u (%s) had no IPv4/IPv6 header",
				  address.if_index,
				  is_inbound_interface ? "inbound" : "outbound");
		return false;
	}
	auto& counts = is_inbound_interface ? destination_counts : source_counts;
	++counts[address_text];
	LOG_DEBUG("Forwarded address discovery: observed %s = %s on ifIdx %u (outbound=%d) [count=%llu]",
			  is_inbound_interface ? "dst" : "src",
			  address_text.c_str(),
			  address.if_index,
			  address.outbound,
			  static_cast<unsigned long long>(counts[address_text]));
	return true;
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
	DiscoveryHeartbeat(DiscoveryCounters& counters, const uint64_t& window_ms) : thread_([this, &counters, &window_ms] { run(counters, window_ms); }) {}

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
			[[maybe_unused]] const uint64_t received = counters.received.exchange(0);
			LOG_DEBUG("Server discovery: last %s: %llu packets captured (%llu skipped while a profile was active, %llu unparsable)%s",
					  logging::format_duration(window_ms).c_str(),
					  static_cast<unsigned long long>(received),
					  static_cast<unsigned long long>(counters.suppressed.exchange(0)),
					  static_cast<unsigned long long>(counters.unparsed.exchange(0)),
					  received == 0 ? " - no packets hit the discovery filter" : "");
		}
	}

	std::atomic<bool> stop_{false};
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

void PacketEngine::discover_packets()
{
	DiscoveryScan	   scan(platform::tick_ms());
	DiscoveryHeartbeat heartbeat(scan.counters, options_.discovery_window_ms);
	uint8_t			   packet_data[0xFFFF];
	LOG_DEBUG("Server discovery: capture loop started, waiting for packets");
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
			LOG_ERROR("Server discovery recv: %s", io_error.c_str());
		}
		else if (!shutdown_)
		{
			LOG_DEBUG("Server discovery: recv returned status %d without a packet", static_cast<int>(recv_status));
		}

		const uint64_t now = platform::tick_ms();
		if (now - scan.window_started < options_.discovery_window_ms)
			continue;
		finish_discovery_window(scan);
		scan.window_started = now;
	}
}

bool PacketEngine::scan_discovery_packet(DiscoveryScan& scan, const uint8_t* packet_data, uint32_t length, const backend::PacketMeta& meta)
{
	++scan.counters.received;
	if (++scan.total_received == 1)
		LOG_DEBUG("Server discovery: first packet captured (%u bytes)", length);
	if (running_.load())
	{
		if (!scan.was_running)
			LOG_DEBUG("Server discovery disabled while a profile is active");
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
		LOG_DEBUG("Server discovery enabled after all profiles were deactivated");
		scan.was_running	= false;
		scan.window_started = platform::tick_ms();
	}
	ParsedPacket parsed;
	if (!parse_packet(packet_data, length, parsed))
	{
		++scan.counters.unparsed;
		LOG_DEBUG("Server discovery: ignoring unparsable packet (%u bytes)", length);
		return true;
	}
	const std::string address_text = endpoint_address(parsed, server_is_destination(parsed, meta, *options_.discovery_port));
	if (address_text.empty())
	{
		LOG_DEBUG("Server discovery: packet has no usable IP address");
		return true;
	}
	LOG_DEBUG("Server discovery: %s packet, %u bytes, %s, counted for server %s (if_index = %u)",
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
				LOG_DEBUG("Server discovery: '%s' is public, triggering region lookup", address_text.c_str());
				resolve_region(address_text, configured_server);
			}
			else
				LOG_DEBUG("Server discovery: '%s' is private/local, skipping region lookup", address_text.c_str());
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
					   logging::format_duration(options_.discovery_window_ms).c_str());
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

void PacketEngine::probe_packets()
{
	uint8_t packet_data[0xFFFF];
	while (!shutdown_)
	{
		backend::PacketMeta address;
		uint32_t			received_length = 0;
		std::string			io_error;
		const backend::IoStatus recv_status =
			state_->probe_handle->recv(packet_data, sizeof(packet_data), received_length, address, io_error);
		if (recv_status == backend::IoStatus::ok)
			handle_probe_packet(packet_data, received_length, address);
		else if (!shutdown_ && recv_status == backend::IoStatus::error)
		{
			LOG_ERROR("Probe detection recv: %s", io_error.c_str());
		}
	}
}

void PacketEngine::handle_probe_packet(const uint8_t* packet_data, uint32_t length, const backend::PacketMeta& meta)
{
	ParsedPacket parsed;
	if (!parse_packet(packet_data, length, parsed) || !parsed.tcp || !parsed.tcp->Syn)
		return;
	const uint64_t	  now			 = platform::tick_ms();
	const std::string server_address = endpoint_address(parsed, meta.outbound);

	bool is_new_window = false;
	{
		std::lock_guard<std::mutex> probe_lock(state_->probe_mutex);
		if (!state_->probe_received || now >= state_->probe_window_end)
		{
			state_->probe_received	 = true;
			state_->probe_window_end = now + 30000;
			state_->next_check_time	 = now + 300000;
			state_->probed_addresses_in_window.clear();
			is_new_window = true;
		}
	}
	if (is_new_window)
		LOG_INFO("Region probe detected on port %u; next check in ~5m", options_.features.region_enforcement.probe_port);

	if (server_address.empty())
		return;
	bool first_in_window = false;
	{
		std::lock_guard<std::mutex> probe_lock(state_->probe_mutex);
		first_in_window = state_->probed_addresses_in_window.insert(server_address).second;
	}
	if (first_in_window)
		log_probed_server(server_address);
}

void PacketEngine::log_probed_server(const std::string& server_address)
{
	const std::string enforced_region = current_enforced_region();
	const auto		  server = std::find_if(options_.servers.begin(), options_.servers.end(), [&](const ServerOptions& s) {
		  return s.address == server_address;
	  });
	if (server == options_.servers.end())
	{
		LOG_DEBUG("Unknown server '%s' was probed", server_address.c_str());
		return;
	}
	const std::string server_region = !server->group.empty() ? server->group : server->name;
	const std::string label = server->name == server->address ? server->address : server->name + " [" + server->address + "]";
	if (enforced_region != "none" && !enforced_region.empty() && server_region == enforced_region)
		LOG_SERVER("Server '%s' within enforced region '%s' was probed", label.c_str(), enforced_region.c_str());
	else
		LOG_DEBUG("Server '%s' (region '%s') was probed", label.c_str(), server_region.c_str());
}

void PacketEngine::apply_forwarded_address_winner(AddressCounts& counts, bool is_destination)
{
	const uint64_t window_ms = options_.features.forwarded_address_discovery.window_ms;
	const char*	   label	 = is_destination ? "client destination address (inbound)" : "client source address (outbound)";
	if (counts.empty())
	{
		LOG_DEBUG("Forwarded address discovery: no packets observed for %s in the last %s window", label, logging::format_duration(window_ms).c_str());
		return;
	}
	const auto winner = std::max_element(counts.begin(), counts.end(), [](const auto& left, const auto& right) {
		return left.second < right.second;
	});
	LOG_DEBUG("Forwarded address discovery: %s window closed with %zu candidate address(es); winner '%s' with %llu packet(s)",
			  label,
			  counts.size(),
			  winner->first.c_str(),
			  static_cast<unsigned long long>(winner->second));
	std::string previous;
	bool		changed = false;
	{
		std::lock_guard<std::mutex> lock(state_->fad_mutex);
		std::string&				target = is_destination ? state_->fad_client_destination_address : state_->fad_client_source_address;
		if (target != winner->first)
		{
			previous = target;
			target	 = winner->first;
			changed	 = true;
		}
	}
	if (!changed)
		return;
	LOG_SERVER("Forwarded address discovery: %s changed from '%s' to '%s' (%llu packets in %s)",
			   label,
			   previous.empty() ? "none" : previous.c_str(),
			   winner->first.c_str(),
			   static_cast<unsigned long long>(winner->second),
			   logging::format_duration(window_ms).c_str());

	std::vector<int> active_profiles;
	{
		std::lock_guard<std::mutex> lifecycle_lock(state_->lifecycle_mutex);
		for (size_t index = 0; index < state_->active_profiles.size(); ++index)
			if (state_->active_profiles[index])
				active_profiles.push_back(static_cast<int>(index + 1));
	}
	for (const int profile : active_profiles)
		teardown(profile);
	for (const int profile : active_profiles)
		setup(profile);
}

void PacketEngine::forwarded_address_discovery_recv()
{
	const uint32_t inbound_if_idx  = *options_.features.forwarded_address_discovery.inbound_if_idx;
	const uint32_t outbound_if_idx = *options_.features.forwarded_address_discovery.outbound_if_idx;
	const uint64_t window_ms	   = options_.features.forwarded_address_discovery.window_ms;

	AddressCounts destination_counts;
	AddressCounts source_counts;
	uint64_t	  window_started = platform::tick_ms();
	uint8_t		  packet_data[0xFFFF];
	while (!shutdown_)
	{
		backend::PacketMeta address;
		uint32_t			received_length = 0;
		std::string			io_error;
		const backend::IoStatus recv_status =
			state_->fad_handle->recv(packet_data, sizeof(packet_data), received_length, address, io_error);
		if (recv_status == backend::IoStatus::ok)
		{
			if (!count_forwarded_address(packet_data, received_length, address, inbound_if_idx, outbound_if_idx, destination_counts, source_counts))
				continue;
		}
		else if (!shutdown_ && recv_status == backend::IoStatus::error)
		{
			LOG_ERROR("Forwarded address discovery recv: %s", io_error.c_str());
		}

		const uint64_t now = platform::tick_ms();
		if (now - window_started < window_ms)
			continue;
		LOG_DEBUG("Forwarded address discovery: window closed after %s (dst candidates=%zu, src candidates=%zu)",
				  logging::format_duration(now - window_started).c_str(),
				  destination_counts.size(),
				  source_counts.size());
		apply_forwarded_address_winner(destination_counts, true);
		apply_forwarded_address_winner(source_counts, false);
		destination_counts.clear();
		source_counts.clear();
		window_started = now;
	}
}
