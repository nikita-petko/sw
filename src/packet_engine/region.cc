#include "internal.h"

#include <ctime>

#include "log.h"

LOG_DEFAULT_GROUP(logging::group::region)

bool PacketEngine::use_cached_region(const std::string& address, bool preserve_name)
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
	if (cached.label.empty())
		return false;
	LOG_DEBUG_GROUP(logging::group::region, "Region lookup for '%s': using local cache", address.c_str());
	// resolve_region is only ever called by discover_packets, which already holds lifecycle_mutex here
	if (!preserve_name && !cached.server_name.empty())
	{
		const auto server = std::find_if(options_.servers.begin(), options_.servers.end(), [&](ServerOptions& item) {
			return item.address == address;
		});
		if (server != options_.servers.end())
			server->name = cached.server_name;
	}
	return true;
}

void PacketEngine::resolve_region(const std::string& address, bool preserve_name)
{
	if (use_cached_region(address, preserve_name))
		return;
	{
		std::lock_guard<std::mutex> lock(state_->region_mutex);
		if (!state_->region_lookups_started.insert(address).second)
		{
			LOG_DEBUG_GROUP(logging::group::region, "Region lookup for '%s': already started, skipping", address.c_str());
			return;
		}
	}
	LOG_DEBUG_GROUP(logging::group::region, "Region lookup for '%s': queued", address.c_str());
	state_->region_threads.emplace_back([this, address, preserve_name] { lookup_region(address, preserve_name); });
}

void PacketEngine::lookup_region(const std::string& address, bool preserve_name)
{
	LOG_DEBUG_GROUP(logging::group::region, "Region lookup for '%s': requesting https://ipapi.co/%s/json/", address.c_str(), address.c_str());
	const std::string  path		= "/" + address + "/json/";
	const HttpResponse response = https_get_until_not_rate_limited("ipapi.co", path);
	if (response.status < 200 || response.status >= 300 || response.body.empty())
	{
		LOG_DEBUG_GROUP(logging::group::region, "Region lookup for '%s': unsuccessful response (status %u), giving up", address.c_str(), response.status);
		return;
	}
	LOG_DEBUG_GROUP(logging::group::region, "Region lookup for '%s': received %zu byte response", address.c_str(), response.body.size());
	const auto label = extract_region_label(response.body);
	if (!label)
	{
		LOG_DEBUG_GROUP(logging::group::region, "Region lookup for '%s': response missing region/country fields, body: %s",
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
	LOG_DEBUG_GROUP(logging::group::region, "Region lookup for '%s': cached result", address.c_str());
	LOG_REGION("Resolved region for server '%s': %s", address.c_str(), label->c_str());

	if (!preserve_name)
	{
		LOG_DEBUG_GROUP(logging::group::region, "Region lookup for '%s': rewriting server name to '%s'", address.c_str(), new_name.c_str());
		rename_server(address, new_name);
		LOG_REGION("Server '%s' renamed to '%s'", address.c_str(), new_name.c_str());
	}
}

void PacketEngine::rename_server(const std::string& address, const std::string& name)
{
	std::lock_guard<std::mutex> lifecycle_lock(state_->lifecycle_mutex);
	const auto					server = std::find_if(options_.servers.begin(), options_.servers.end(), [&](ServerOptions& item) {
		  return item.address == address;
	  });
	if (server != options_.servers.end())
		server->name = name;
	else
		LOG_DEBUG_GROUP(logging::group::region, "Region lookup for '%s': server no longer tracked, skipping rename", address.c_str());
}

void PacketEngine::resolve_client_region()
{
	{
		std::lock_guard<std::mutex> lock(state_->region_mutex);
		const auto					cache_entry = state_->region_cache.find(client_region_cache_key);
		if (cache_entry != state_->region_cache.end() && cache_entry->second.expires_at > static_cast<uint64_t>(std::time(nullptr)))
		{
			state_->client_region = cache_entry->second.label;
			LOG_DEBUG_GROUP(logging::group::region_client, "Client region lookup: using local cache");
			return;
		}
	}
	LOG_DEBUG_GROUP(logging::group::region_client, "Client region lookup: queued");
	state_->region_threads.emplace_back([this] { lookup_client_region(); });
}

void PacketEngine::lookup_client_region()
{
	LOG_DEBUG_GROUP(logging::group::region_client, "Client region lookup: requesting https://ipapi.co/json/");
	const HttpResponse response = https_get_until_not_rate_limited("ipapi.co", "/json/");
	if (response.status < 200 || response.status >= 300 || response.body.empty())
	{
		LOG_DEBUG_GROUP(logging::group::region_client, "Client region lookup: unsuccessful response (status %u), giving up", response.status);
		return;
	}
	LOG_DEBUG_GROUP(logging::group::region_client, "Client region lookup: received %zu byte response", response.body.size());
	const auto label = extract_region_label(response.body);
	if (!label)
	{
		LOG_DEBUG_GROUP(logging::group::region_client, "Client region lookup: response missing region/country fields, body: %s", response.body.substr(0, 300).c_str());
		return;
	}
	{
		std::lock_guard<std::mutex> lock(state_->region_mutex);
		state_->client_region						  = *label;
		state_->region_cache[client_region_cache_key] = {*label, "", static_cast<uint64_t>(std::time(nullptr)) + region_cache_lifetime_seconds};
		save_region_cache(state_->region_cache);
	}
	LOG_DEBUG_GROUP(logging::group::region_client, "Client region lookup: cached result");
	LOG_REGION("Resolved client region: %s", label->c_str());
}
