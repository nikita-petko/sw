#include "internal.h"

#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT

#include <cstdlib>

#include "log.h"

LOG_DEFAULT_GROUP(logging::group::enforcement)

void PacketEngine::start_region_enforcement()
{
	const std::string filter = region_enforcement_filter();
	if (filter.empty())
		return;

	state_->region_enforcement_stopping = false;
	backend::OpenOptions open_options;
	open_options.filter	  = filter;
	open_options.priority = -100;
	std::string open_error;
	state_->region_enforcement_handle = backend::open(open_options, open_error);
	if (!state_->region_enforcement_handle)
	{
		LOG_ERROR("Region enforcement setup: failed to open capture channel: %s", open_error.c_str());
		return;
	}
	LOG_REGION("Region enforcement filter active: %s", filter.c_str());
	state_->region_enforcement_recv_thread = std::thread(&PacketEngine::region_enforcement_recv, this);
	state_->region_enforcement_send_thread = std::thread(&PacketEngine::region_enforcement_send, this);
}

void PacketEngine::stop_region_enforcement()
{
	if (state_->region_enforcement_handle)
	{
		state_->region_enforcement_stopping = true;
		state_->region_enforcement_handle->shutdown_recv();
		state_->region_enforcement_changed.notify_all();
		if (state_->region_enforcement_recv_thread.joinable())
			state_->region_enforcement_recv_thread.join();
		if (state_->region_enforcement_send_thread.joinable())
			state_->region_enforcement_send_thread.join();
		state_->region_enforcement_handle->close();
		state_->region_enforcement_handle.reset();
	}
}

std::string PacketEngine::region_enforcement_filter() const
{
	if (!options_.features.region_enforcement.enabled || options_.features.region_enforcement.probe_port == 0)
		return {};

	const std::string enforced_region = current_enforced_region();
	if (enforced_region == "none" || enforced_region.empty())
		return {};

	const uint16_t port = options_.features.region_enforcement.probe_port;

	std::vector<std::string> delayed_addresses;
	for (const ServerOptions& s : options_.servers)
	{
		const std::string s_region = !s.group.empty() ? s.group : s.name;
		if (s_region != enforced_region)
		{
			if (std::find(delayed_addresses.begin(), delayed_addresses.end(), s.address) == delayed_addresses.end())
				delayed_addresses.push_back(s.address);
		}
	}

	if (delayed_addresses.empty())
		return {};

	return backend::filters::region_enforcement(delayed_addresses, port);
}

void PacketEngine::region_enforcement_recv()
{
	uint8_t packet_data[0xFFFF];
	while (!state_->region_enforcement_stopping && !shutdown_)
	{
		backend::PacketMeta address;
		uint32_t			received_length = 0;
		std::string			io_error;
		const backend::IoStatus status =
			state_->region_enforcement_handle->recv(packet_data, sizeof(packet_data), received_length, address, io_error);
		if (status != backend::IoStatus::ok)
		{
			if (!state_->region_enforcement_stopping && !shutdown_ && status == backend::IoStatus::error)
				LOG_ERROR("Region enforcement recv: %s", io_error.c_str());
			continue;
		}

		const uint64_t now		  = platform::tick_ms();
		const uint64_t delay_ms	  = 1000 + (static_cast<uint64_t>(std::rand()) % 501);
		const uint64_t release_at = now + delay_ms;

		const PacketAddresses addresses = packet_addresses(packet_data, received_length);
		LOG_DEBUG_GROUP(logging::group::enforcement_packet, "Region enforcement recv: TCP PSH packet (delaying for %llums): Length = %u, Src = %s, Dst = %s",
				  static_cast<unsigned long long>(delay_ms),
				  received_length,
				  addresses.source.c_str(),
				  addresses.destination.c_str());

		{
			std::lock_guard<std::mutex> lock(state_->region_enforcement_mutex);
			if (state_->region_enforcement_stopping)
			{
				uint32_t sent = 0;
				state_->region_enforcement_handle->send(packet_data, received_length, address, sent, io_error);
				continue;
			}
			State::DelayedEnforcementPacket delayed_pkt;
			delayed_pkt.data.assign(packet_data, packet_data + received_length);
			delayed_pkt.address	   = address;
			delayed_pkt.release_at = release_at;
			state_->enforcement_queue.push_back(std::move(delayed_pkt));
			state_->region_enforcement_changed.notify_one();
		}
	}
}

void PacketEngine::region_enforcement_send()
{
	while (!state_->region_enforcement_stopping && !shutdown_)
		if (!send_due_enforcement_packets())
			break;
	flush_enforcement_queue();
}

bool PacketEngine::send_due_enforcement_packets()
{
	std::vector<State::DelayedEnforcementPacket> ready_packets;
	{
		std::unique_lock<std::mutex> lock(state_->region_enforcement_mutex);
		while (state_->enforcement_queue.empty() && !state_->region_enforcement_stopping && !shutdown_)
			state_->region_enforcement_changed.wait(lock);
		if (state_->region_enforcement_stopping || shutdown_)
			return false;

		const uint64_t now				= platform::tick_ms();
		uint64_t	   earliest_release = (std::numeric_limits<uint64_t>::max)();
		for (const auto& pkt : state_->enforcement_queue)
		{
			if (pkt.release_at < earliest_release)
				earliest_release = pkt.release_at;
		}

		if (earliest_release > now)
		{
			const uint64_t wait_ms = earliest_release - now;
			state_->region_enforcement_changed.wait_for(lock, std::chrono::milliseconds(wait_ms));
			return true;
		}

		auto it = state_->enforcement_queue.begin();
		while (it != state_->enforcement_queue.end())
		{
			if (it->release_at <= now)
			{
				ready_packets.push_back(std::move(*it));
				it = state_->enforcement_queue.erase(it);
			}
			else
			{
				++it;
			}
		}
	}

	for (auto& pkt : ready_packets)
	{
		uint32_t	sent = 0;
		std::string io_error;
		const backend::IoStatus status =
			state_->region_enforcement_handle->send(pkt.data.data(), static_cast<uint32_t>(pkt.data.size()), pkt.address, sent, io_error);
		if (status != backend::IoStatus::ok)
		{
			if (!state_->region_enforcement_stopping && !shutdown_ && status == backend::IoStatus::error)
				LOG_ERROR("Region enforcement delayed send: failed: %s", io_error.c_str());
		}
		else if (sent != 0)
		{
			const PacketAddresses addresses = packet_addresses(pkt.data.data(), static_cast<uint32_t>(pkt.data.size()));
			LOG_DEBUG_GROUP(logging::group::enforcement_packet, "Region enforcement send: delayed packet: Length = %zu, Src = %s, Dst = %s, SendLen = %u",
					  pkt.data.size(),
					  addresses.source.c_str(),
					  addresses.destination.c_str(),
					  sent);
		}
	}
	return true;
}

void PacketEngine::flush_enforcement_queue()
{
	std::vector<State::DelayedEnforcementPacket> pending_packets;
	{
		std::lock_guard<std::mutex> lock(state_->region_enforcement_mutex);
		pending_packets = std::move(state_->enforcement_queue);
		state_->enforcement_queue.clear();
	}
	for (auto& pkt : pending_packets)
	{
		uint32_t	sent = 0;
		std::string io_error;
		if (state_->region_enforcement_handle->send(pkt.data.data(), static_cast<uint32_t>(pkt.data.size()), pkt.address, sent, io_error) ==
				backend::IoStatus::ok &&
			sent != 0)
		{
			const PacketAddresses addresses = packet_addresses(pkt.data.data(), static_cast<uint32_t>(pkt.data.size()));
			LOG_DEBUG_GROUP(logging::group::enforcement_packet, "Region enforcement flush: sent packet: Length = %zu, Src = %s, Dst = %s, SendLen = %u",
					  pkt.data.size(),
					  addresses.source.c_str(),
					  addresses.destination.c_str(),
					  sent);
		}
	}
}

void PacketEngine::start_probe_worker()
{
	const uint16_t	  port	 = options_.features.region_enforcement.probe_port;
	const std::string filter = backend::filters::syn_probe(port);
	backend::OpenOptions open_options;
	open_options.filter			 = filter;
	open_options.sniff			 = true;
	open_options.include_forward = true;
	std::string open_error;
	state_->probe_handle = backend::open(open_options, open_error);
	if (!state_->probe_handle)
		LOG_ERROR("Probe detection setup: failed to open capture channel: %s", open_error.c_str());
	else
	{
		LOG_INFO("Probe detection enabled on port %u", port);
		state_->probe_thread = std::thread(&PacketEngine::probe_packets, this);
	}

	start_region_enforcement();
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
		LOG_DEBUG_GROUP(logging::group::enforcement, "Unknown server '%s' was probed", server_address.c_str());
		return;
	}
	const std::string server_region = !server->group.empty() ? server->group : server->name;
	const std::string label = server->name == server->address ? server->address : server->name + " [" + server->address + "]";
	if (enforced_region != "none" && !enforced_region.empty() && server_region == enforced_region)
		LOG_SERVER("Server '%s' within enforced region '%s' was probed", label.c_str(), enforced_region.c_str());
	else
		LOG_DEBUG_GROUP(logging::group::enforcement, "Server '%s' (region '%s') was probed", label.c_str(), server_region.c_str());
}

bool PacketEngine::is_region_enforcement_enabled() const
{
	return options_.features.region_enforcement.enabled;
}

std::string PacketEngine::region_enforcement_status() const
{
	if (!options_.features.region_enforcement.enabled)
		return {};

	std::lock_guard<std::mutex> lock(state_->probe_mutex);
	if (!state_->probe_received)
		return "Waiting for probes...";

	const uint64_t now = platform::tick_ms();
	if (now >= state_->next_check_time)
		return "~0s";

	const uint64_t remaining_ms = state_->next_check_time - now;
	return "~" + logging::format_duration(remaining_ms);
}

std::vector<std::string> PacketEngine::configured_regions() const
{
	std::vector<std::string> regions;
	for (const ServerOptions& server : options_.servers)
	{
		if (!server.group.empty())
		{
			if (std::find(regions.begin(), regions.end(), server.group) == regions.end())
				regions.push_back(server.group);
		}
	}
	if (regions.empty())
	{
		for (const ServerOptions& server : options_.servers)
		{
			const std::string& name = server.name.empty() ? server.address : server.name;
			if (!name.empty() && std::find(regions.begin(), regions.end(), name) == regions.end())
				regions.push_back(name);
		}
	}
	return regions;
}

std::string PacketEngine::current_enforced_region() const
{
	std::lock_guard<std::mutex> lifecycle_lock(state_->lifecycle_mutex);
	const auto					regions		 = configured_regions();
	const size_t				region_index = enforced_region_index_.load();
	if (region_index != 0 && region_index <= regions.size())
	{
		return regions[region_index - 1];
	}
	return "none";
}

void PacketEngine::cycle_enforced_region(int direction)
{
	const auto regions = configured_regions();
	if (regions.empty() || direction == 0)
		return;
	const size_t option_count = regions.size() + 1;
	size_t		 current	  = enforced_region_index_.load();
	if (direction > 0)
		current = (current + 1) % option_count;
	else
		current = current == 0 ? option_count - 1 : current - 1;
	enforced_region_index_ = current;
	LOG_REGION("Enforced region changed to: %s", current_enforced_region().c_str());

	stop_region_enforcement();
	start_region_enforcement();
}

#endif
