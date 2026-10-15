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
	state_->region_enforcement_handle	= WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, -100, 0);
	if (state_->region_enforcement_handle == INVALID_HANDLE_VALUE)
	{
		const DWORD error = GetLastError();
		LOG_ERROR("Region enforcement setup: failed to open WinDivert handle %lu: %s", error, format_win32_error(error).c_str());
		return;
	}
	WinDivertSetParam(state_->region_enforcement_handle, WINDIVERT_PARAM_QUEUE_LENGTH, 4096);
	WinDivertSetParam(state_->region_enforcement_handle, WINDIVERT_PARAM_QUEUE_TIME, 1024);
	LOG_REGION("Region enforcement filter active: %s", filter.c_str());
	state_->region_enforcement_recv_thread = std::thread(&PacketEngine::region_enforcement_recv, this);
	state_->region_enforcement_send_thread = std::thread(&PacketEngine::region_enforcement_send, this);
}

void PacketEngine::stop_region_enforcement()
{
	if (state_->region_enforcement_handle != INVALID_HANDLE_VALUE)
	{
		state_->region_enforcement_stopping = true;
		WinDivertShutdown(state_->region_enforcement_handle, WINDIVERT_SHUTDOWN_RECV);
		state_->region_enforcement_changed.notify_all();
		if (state_->region_enforcement_recv_thread.joinable())
			state_->region_enforcement_recv_thread.join();
		if (state_->region_enforcement_send_thread.joinable())
			state_->region_enforcement_send_thread.join();
		WinDivertClose(state_->region_enforcement_handle);
		state_->region_enforcement_handle = INVALID_HANDLE_VALUE;
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

	if (delayed_addresses.size() == 1)
		return "tcp.Psh and ip.SrcAddr == " + delayed_addresses[0] + " and tcp.SrcPort == " + std::to_string(port);

	std::string address_chain;
	for (const std::string& addr : delayed_addresses)
	{
		if (!address_chain.empty())
			address_chain += " or ";
		address_chain += "ip.SrcAddr == " + addr;
	}
	return "tcp.Psh and (" + address_chain + ") and tcp.SrcPort == " + std::to_string(port);
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
		const std::wstring path		= L"/" + std::wstring(address.begin(), address.end()) + L"/json/";
		const HttpResponse response = https_get_until_not_rate_limited(L"ipapi.co", path);
		if (response.status < 200 || response.status >= 300 || response.body.empty())
		{
			LOG_DEBUG("Region lookup for '%s': unsuccessful response (status %lu), giving up", address.c_str(), response.status);
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
		const HttpResponse response = https_get_until_not_rate_limited(L"ipapi.co", L"/json/");
		if (response.status < 200 || response.status >= 300 || response.body.empty())
		{
			LOG_DEBUG("Client region lookup: unsuccessful response (status %lu), giving up", response.status);
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
	BYTE packet_data[0xFFFF];
	while (!state_->region_enforcement_stopping && !shutdown_)
	{
		WINDIVERT_ADDRESS address;
		UINT			  received_length = 0;
		if (!WinDivertRecv(state_->region_enforcement_handle, packet_data, sizeof(packet_data), &received_length, &address))
		{
			const DWORD error = GetLastError();
			if (!state_->region_enforcement_stopping && !shutdown_ && error != ERROR_INVALID_HANDLE && error != ERROR_OPERATION_ABORTED)
				LOG_ERROR("Region enforcement recv: WinDivertRecv error %lu: %s", error, format_win32_error(error).c_str());
			continue;
		}

		const uint64_t now		  = GetTickCount64();
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
				UINT sent = 0;
				WinDivertSend(state_->region_enforcement_handle, packet_data, received_length, &sent, &address);
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

			const uint64_t now				= GetTickCount64();
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
			UINT sent = 0;
			if (!WinDivertSend(state_->region_enforcement_handle, pkt.data.data(), static_cast<UINT>(pkt.data.size()), &sent, &pkt.address))
			{
				const DWORD error = GetLastError();
				if (!state_->region_enforcement_stopping && !shutdown_ && error != ERROR_INVALID_HANDLE && error != ERROR_OPERATION_ABORTED)
					LOG_ERROR("Region enforcement delayed send: WinDivertSend failed %lu: %s", error, format_win32_error(error).c_str());
			}
			else if (sent != 0)
			{
				const PacketAddresses addresses = packet_addresses(pkt.data.data(), static_cast<UINT>(pkt.data.size()));
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
		UINT sent = 0;
		if (WinDivertSend(state_->region_enforcement_handle, pkt.data.data(), static_cast<UINT>(pkt.data.size()), &sent, &pkt.address) &&
			sent != 0)
		{
			const PacketAddresses addresses = packet_addresses(pkt.data.data(), static_cast<UINT>(pkt.data.size()));
			LOG_DEBUG("Region enforcement flush: sent packet: Length = %zu, Src = %s, Dst = %s, SendLen = %u",
					  pkt.data.size(),
					  addresses.source.c_str(),
					  addresses.destination.c_str(),
					  sent);
		}
	}
}
