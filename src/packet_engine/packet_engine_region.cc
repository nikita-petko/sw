#include "packet_engine_internal.h"

#include <cstdlib>
#include <ctime>

#include "log.h"

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

void PacketEngine::resolve_region(const std::string& address, bool preserve_name)
{
	RegionCacheEntry cached;
	{
		std::lock_guard<std::mutex> lock(state_->region_mutex);
		const auto					cache_entry = state_->region_cache.find(address);
		if (cache_entry != state_->region_cache.end() && cache_entry->second.expires_at > static_cast<uint64_t>(std::time(nullptr)))
		{
			cached							= cache_entry->second;
			state_->server_regions[address] = cached.label;
		}
	}
	if (!cached.label.empty())
	{
		LOG_DEBUG("Region lookup for '%s': using local cache", address.c_str());
		// resolve_region is only ever called by discover_packets, which already holds lifecycle_mutex here
		if (!preserve_name && !cached.server_name.empty())
		{
			const auto server = std::find_if(options_.servers.begin(), options_.servers.end(), [&](ServerOptions& item) {
				return item.address == address;
			});
			if (server != options_.servers.end())
				server->name = cached.server_name;
		}
		return;
	}
	{
		std::lock_guard<std::mutex> lock(state_->region_mutex);
		if (!state_->region_lookups_started.insert(address).second)
		{
			LOG_DEBUG("Region lookup for '%s': already started, skipping", address.c_str());
			return;
		}
	}
	LOG_DEBUG("Region lookup for '%s': queued", address.c_str());
	state_->region_threads.emplace_back([this, address, preserve_name] {
		LOG_DEBUG("Region lookup for '%s': requesting https://ipapi.co/%s/json/", address.c_str(), address.c_str());
		const std::string  path		= "/" + address + "/json/";
		const HttpResponse response = https_get_until_not_rate_limited("ipapi.co", path);
		if (response.status < 200 || response.status >= 300 || response.body.empty())
		{
			LOG_DEBUG("Region lookup for '%s': unsuccessful response (status %u), giving up", address.c_str(), response.status);
			return;
		}
		LOG_DEBUG("Region lookup for '%s': received %zu byte response", address.c_str(), response.body.size());
		const auto label = extract_region_label(response.body);
		if (!label)
		{
			LOG_DEBUG("Region lookup for '%s': response missing region/country fields, body: %s",
					  address.c_str(),
					  response.body.substr(0, 300).c_str());
			return;
		}
		const std::string new_name = build_server_name(address, response.body);
		{
			std::lock_guard<std::mutex> lock(state_->region_mutex);
			state_->server_regions[address] = *label;
			state_->region_cache[address]	= {*label, new_name, static_cast<uint64_t>(std::time(nullptr)) + region_cache_lifetime_seconds};
			save_region_cache(state_->region_cache);
		}
		LOG_DEBUG("Region lookup for '%s': cached result", address.c_str());
		LOG_REGION("Resolved region for server '%s': %s", address.c_str(), label->c_str());

		if (!preserve_name)
		{
			LOG_DEBUG("Region lookup for '%s': rewriting server name to '%s'", address.c_str(), new_name.c_str());
			{
				std::lock_guard<std::mutex> lifecycle_lock(state_->lifecycle_mutex);
				const auto server = std::find_if(options_.servers.begin(), options_.servers.end(), [&](ServerOptions& item) {
					return item.address == address;
				});
				if (server != options_.servers.end())
					server->name = new_name;
				else
					LOG_DEBUG("Region lookup for '%s': server no longer tracked, skipping rename", address.c_str());
			}
			LOG_REGION("Server '%s' renamed to '%s'", address.c_str(), new_name.c_str());
		}
	});
}

void PacketEngine::resolve_client_region()
{
	{
		std::lock_guard<std::mutex> lock(state_->region_mutex);
		const auto					cache_entry = state_->region_cache.find(client_region_cache_key);
		if (cache_entry != state_->region_cache.end() && cache_entry->second.expires_at > static_cast<uint64_t>(std::time(nullptr)))
		{
			state_->client_region = cache_entry->second.label;
			LOG_DEBUG("Client region lookup: using local cache");
			return;
		}
	}
	LOG_DEBUG("Client region lookup: queued");
	state_->region_threads.emplace_back([this] {
		LOG_DEBUG("Client region lookup: requesting https://ipapi.co/json/");
		const HttpResponse response = https_get_until_not_rate_limited("ipapi.co", "/json/");
		if (response.status < 200 || response.status >= 300 || response.body.empty())
		{
			LOG_DEBUG("Client region lookup: unsuccessful response (status %u), giving up", response.status);
			return;
		}
		LOG_DEBUG("Client region lookup: received %zu byte response", response.body.size());
		const auto label = extract_region_label(response.body);
		if (!label)
		{
			LOG_DEBUG("Client region lookup: response missing region/country fields, body: %s", response.body.substr(0, 300).c_str());
			return;
		}
		{
			std::lock_guard<std::mutex> lock(state_->region_mutex);
			state_->client_region						  = *label;
			state_->region_cache[client_region_cache_key] = {*label,
															 "",
															 static_cast<uint64_t>(std::time(nullptr)) + region_cache_lifetime_seconds};
			save_region_cache(state_->region_cache);
		}
		LOG_DEBUG("Client region lookup: cached result");
		LOG_REGION("Resolved client region: %s", label->c_str());
	});
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
		LOG_DEBUG("Region enforcement recv: TCP PSH packet (delaying for %llums): Length = %u, Src = %s, Dst = %s",
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
	{
		std::vector<State::DelayedEnforcementPacket> ready_packets;
		{
			std::unique_lock<std::mutex> lock(state_->region_enforcement_mutex);
			while (state_->enforcement_queue.empty() && !state_->region_enforcement_stopping && !shutdown_)
				state_->region_enforcement_changed.wait(lock);
			if (state_->region_enforcement_stopping || shutdown_)
				break;

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
				continue;
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
				LOG_DEBUG("Region enforcement send: delayed packet: Length = %zu, Src = %s, Dst = %s, SendLen = %u",
						  pkt.data.size(),
						  addresses.source.c_str(),
						  addresses.destination.c_str(),
						  sent);
			}
		}
	}

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
			LOG_DEBUG("Region enforcement flush: sent packet: Length = %zu, Src = %s, Dst = %s, SendLen = %u",
					  pkt.data.size(),
					  addresses.source.c_str(),
					  addresses.destination.c_str(),
					  sent);
		}
	}
}
