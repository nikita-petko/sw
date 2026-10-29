#include "internal.h"

#include <atomic>
#include <cstdlib>
#include <thread>
#include <ctime>

#include "log.h"

void PacketEngine::discover_packets()
{
	std::unordered_map<std::string, uint64_t> packet_counts;
	std::unordered_set<std::string>			  seen_servers;
	auto									  format_server_label = [&](const std::string& address) {
		const auto server = std::find_if(options_.servers.begin(), options_.servers.end(), [&](const ServerOptions& item) {
			return item.address == address;
		});
		return server == options_.servers.end() ? address : server->name + " [" + address + "]";
	};
	uint64_t window_started = platform::tick_ms();
	bool	 was_running	= false;
	uint8_t	 packet_data[0xFFFF];
	// Counters for the debug heartbeat. recv() blocks while the port is silent, so the summary has to come from a
	// separate thread to report windows in which no packet was hit at all.
	std::atomic<uint64_t> window_received{0}, window_suppressed{0}, window_unparsed{0};
	uint64_t			  total_received = 0;
	std::atomic<bool>	  heartbeat_stop{false};
	std::thread			  heartbeat([&] {
		   uint64_t waited = 0;
		   while (!heartbeat_stop.load())
		   {
			   platform::sleep_ms(100);
			   waited += 100;
			   if (waited < options_.discovery_window_ms)
				   continue;
			   waited = 0;
			   [[maybe_unused]] const uint64_t received = window_received.exchange(0);
			   LOG_DEBUG("Server discovery: last %s: %llu packets captured (%llu skipped while a profile was active, %llu unparsable)%s",
						 logging::format_duration(options_.discovery_window_ms).c_str(),
						 static_cast<unsigned long long>(received),
						 static_cast<unsigned long long>(window_suppressed.exchange(0)),
						 static_cast<unsigned long long>(window_unparsed.exchange(0)),
						 received == 0 ? " - no packets hit the discovery filter" : "");
		   }
	});
	struct HeartbeatJoin
	{
		std::atomic<bool>& stop;
		std::thread&	   thread;
		~HeartbeatJoin()
		{
			stop.store(true);
			if (thread.joinable())
				thread.join();
		}
	} heartbeat_join{heartbeat_stop, heartbeat};
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
			++window_received;
			if (++total_received == 1)
				LOG_DEBUG("Server discovery: first packet captured (%u bytes)", received_length);
			if (running_.load())
			{
				if (!was_running)
					LOG_DEBUG("Server discovery disabled while a profile is active");
				++window_suppressed;
				was_running = true;
				packet_counts.clear();
				std::lock_guard<std::mutex> lock(state_->discovery_mutex);
				state_->discovery_counts.clear();
				window_started = platform::tick_ms();
				continue;
			}
			if (was_running)
			{
				LOG_DEBUG("Server discovery enabled after all profiles were deactivated");
				was_running	   = false;
				window_started = platform::tick_ms();
			}
			ParsedPacket parsed;
			if (!parse_packet(packet_data, received_length, parsed))
			{
				++window_unparsed;
				LOG_DEBUG("Server discovery: ignoring unparsable packet (%u bytes)", received_length);
			}
			else
			{
				const Ipv4Header* ip_header	  = parsed.ipv4;
				const Ipv6Header* ipv6_header = parsed.ipv6;
				std::string		  address_text;
				// The server is the endpoint on the discovery port. Forwarded packets are all tagged outbound, so the
				// direction alone cannot tell the server from the client there.
				const uint16_t discovery_port = *options_.discovery_port;
				uint16_t	   source_port = 0, destination_port = 0;
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
				bool use_destination = address.outbound;
				if (source_port == discovery_port && destination_port != discovery_port)
					use_destination = false;
				else if (destination_port == discovery_port && source_port != discovery_port)
					use_destination = true;
				if (ip_header)
					address_text = format_ipv4_address(use_destination ? ip_header->DstAddr : ip_header->SrcAddr);
				else if (ipv6_header)
					address_text = format_ipv6_address(use_destination ? ipv6_header->DstAddr : ipv6_header->SrcAddr);
				if (address_text.empty())
					LOG_DEBUG("Server discovery: packet has no usable IP address");
				else
				{
					LOG_DEBUG("Server discovery: %s packet, %u bytes, %s, counted for server %s (if_index = %u)",
							  address.outbound ? "outbound" : "inbound",
							  received_length,
							  parsed.tcp ? format_tcp_flags(*parsed.tcp).c_str() : (parsed.udp ? "UDP" : "-"),
							  address_text.c_str(),
							  address.if_index);
					std::lock_guard<std::mutex> lifecycle_lock(state_->lifecycle_mutex);
					const bool					first_seen = seen_servers.insert(address_text).second;
					auto existing_server = std::find_if(options_.servers.begin(), options_.servers.end(), [&](const ServerOptions& server) {
						return server.address == address_text;
					});
					const bool configured_server = existing_server != options_.servers.end();
					if (existing_server == options_.servers.end())
					{
						options_.servers.push_back({address_text, address_text, ""});
						existing_server = options_.servers.end() - 1;
					}
					if (first_seen)
					{
						const std::string server_label = format_server_label(address_text);
						LOG_SERVER("Server '%s' is potentially the authoritative server (first packet received)", server_label.c_str());
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
					++packet_counts[address_text];
					state_->discovery_counts = packet_counts;
				}
			}
		}
		else if (!shutdown_ && recv_status == backend::IoStatus::error)
		{
			LOG_ERROR("Server discovery recv: %s", io_error.c_str());
		}
		else if (!shutdown_)
		{
			LOG_DEBUG("Server discovery: recv returned status %d without a packet", static_cast<int>(recv_status));
		}

		const uint64_t 		now = platform::tick_ms();
		if (now - window_started < options_.discovery_window_ms)
			continue;
		if (!packet_counts.empty())
		{
			const auto winner = std::max_element(packet_counts.begin(), packet_counts.end(), [](const auto& left, const auto& right) {
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
				const std::string server_label = format_server_label(winner->first);
				LOG_SERVER("Server '%s' is the authoritative server (%llu packets in %s)",
						 server_label.c_str(),
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
		packet_counts.clear();
		{
			std::lock_guard<std::mutex> lock(state_->discovery_mutex);
			state_->discovery_counts.clear();
		}
		window_started = now;
	}
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
		{
			ParsedPacket parsed;
			if (parse_packet(packet_data, received_length, parsed) && parsed.tcp && parsed.tcp->Syn)
			{
				const Ipv4Header* ip_header	  = parsed.ipv4;
				const Ipv6Header* ipv6_header = parsed.ipv6;
				const uint64_t	  now		  = platform::tick_ms();
				std::string		  server_address;
				if (ip_header)
					server_address = format_ipv4_address(address.outbound ? ip_header->DstAddr : ip_header->SrcAddr);
				else if (ipv6_header)
					server_address = format_ipv6_address(address.outbound ? ipv6_header->DstAddr : ipv6_header->SrcAddr);

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

				if (!server_address.empty())
				{
					bool first_in_window = false;
					{
						std::lock_guard<std::mutex> probe_lock(state_->probe_mutex);
						first_in_window = state_->probed_addresses_in_window.insert(server_address).second;
					}
					if (first_in_window)
					{
						const std::string enforced_region = current_enforced_region();
						auto server = std::find_if(options_.servers.begin(), options_.servers.end(), [&](const ServerOptions& s) {
							return s.address == server_address;
						});
						if (server != options_.servers.end())
						{
							const std::string server_region = !server->group.empty() ? server->group : server->name;
							const std::string server_label =
								server->name == server->address ? server->address : server->name + " [" + server->address + "]";
							if (enforced_region != "none" && !enforced_region.empty() && server_region == enforced_region)
							{
								LOG_SERVER("Server '%s' within enforced region '%s' was probed",
										 server_label.c_str(),
										 enforced_region.c_str());
							}
							else
							{
								LOG_DEBUG("Server '%s' (region '%s') was probed", server_label.c_str(), server_region.c_str());
							}
						}
						else
						{
							LOG_DEBUG("Unknown server '%s' was probed", server_address.c_str());
						}
					}
				}
			}
		}
		else if (!shutdown_ && recv_status == backend::IoStatus::error)
		{
			LOG_ERROR("Probe detection recv: %s", io_error.c_str());
		}
	}
}

void PacketEngine::forwarded_address_discovery_recv()
{
	const uint32_t inbound_if_idx	= *options_.features.forwarded_address_discovery.inbound_if_idx;
	const uint32_t outbound_if_idx = *options_.features.forwarded_address_discovery.outbound_if_idx;
	const uint64_t window_ms		= options_.features.forwarded_address_discovery.window_ms;

	std::unordered_map<std::string, uint64_t> destination_counts;
	std::unordered_map<std::string, uint64_t> source_counts;

	// picks the most frequently observed address within the window, weeding out one-off broadcast/noise addresses
	auto apply_winner = [&](std::unordered_map<std::string, uint64_t>& counts, bool is_destination) {
		const char* label = is_destination ? "client destination address (inbound)" : "client source address (outbound)";
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
			std::string&				 target = is_destination ? state_->fad_client_destination_address : state_->fad_client_source_address;
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
	};


	uint64_t window_started = platform::tick_ms();
	uint8_t	 packet_data[0xFFFF];
	while (!shutdown_)
	{
		backend::PacketMeta address;
		uint32_t			received_length = 0;
		std::string			io_error;
		const backend::IoStatus recv_status =
			state_->fad_handle->recv(packet_data, sizeof(packet_data), received_length, address, io_error);
		if (recv_status == backend::IoStatus::ok)
		{
			const bool is_inbound_interface  = address.if_index == inbound_if_idx;
			const bool is_outbound_interface = address.if_index == outbound_if_idx;
			if (!is_inbound_interface && !is_outbound_interface)
			{
				LOG_DEBUG("Forwarded address discovery: ignoring packet on unrelated ifIdx %u (outbound=%d)",
						  address.if_index,
						  address.outbound);
				continue;
			}
			ParsedPacket parsed;
			if (!parse_packet(packet_data, received_length, parsed))
			{
				LOG_DEBUG("Forwarded address discovery: failed to parse packet on ifIdx %u (%s)",
						  address.if_index,
						  is_inbound_interface ? "inbound" : "outbound");
				continue;
			}
			const Ipv4Header* ip_header	  = parsed.ipv4;
			const Ipv6Header* ipv6_header = parsed.ipv6;
			std::string address_text;
			if (ip_header)
				address_text = format_ipv4_address(is_inbound_interface ? ip_header->DstAddr : ip_header->SrcAddr);
			else if (ipv6_header)
				address_text = format_ipv6_address(is_inbound_interface ? ipv6_header->DstAddr : ipv6_header->SrcAddr);
			if (address_text.empty())
			{
				LOG_DEBUG("Forwarded address discovery: packet on ifIdx %u (%s) had no IPv4/IPv6 header",
						  address.if_index,
						  is_inbound_interface ? "inbound" : "outbound");
				continue;
			}
			auto& counts = is_inbound_interface ? destination_counts : source_counts;
			++counts[address_text];
			LOG_DEBUG("Forwarded address discovery: observed %s = %s on ifIdx %u (outbound=%d) [count=%llu]",
					  is_inbound_interface ? "dst" : "src",
					  address_text.c_str(),
					  address.if_index,
					  address.outbound,
					  static_cast<unsigned long long>(counts[address_text]));
		}
		else if (!shutdown_ && recv_status == backend::IoStatus::error)
		{
			LOG_ERROR("Forwarded address discovery recv: %s", io_error.c_str());
		}

		const uint64_t 		now = platform::tick_ms();
		if (now - window_started < window_ms)
			continue;
		LOG_DEBUG("Forwarded address discovery: window closed after %s (dst candidates=%zu, src candidates=%zu)",
				  logging::format_duration(now - window_started).c_str(),
				  destination_counts.size(),
				  source_counts.size());
		apply_winner(destination_counts, true);
		apply_winner(source_counts, false);
		destination_counts.clear();
		source_counts.clear();
		window_started = now;
	}
}
