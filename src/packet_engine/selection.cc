#include "internal.h"

#include <algorithm>

#include "log.h"

LOG_DEFAULT_GROUP(logging::group::server)

backend::ProfileFilter PacketEngine::server_filter(const ProfileOptions& profile) const
{
	const size_t		  server_index = server_index_.load();
	backend::ProfileFilter spec;
	spec.user_filter		= profile.filter.value_or(options_.global_filter);
	spec.include_bare_acks	= profile.ack_restoration;
	spec.client_enforcement = profile.capture_options.client_address_enforcement.value_or(CaptureOptions::ClientAddressEnforcement::both);
	spec.client_source		= effective_client_source_address();
	spec.client_destination = effective_client_destination_address();
	spec.outbound			= profile.capture_options.outbound.value_or(false);

	if (server_index == 0 || !profile.capture_options.server_direction)
		return spec;
	spec.server_direction = profile.capture_options.server_direction;

	const std::string& server_address = options_.servers[server_index - 1].address;
	const std::string& server_group	  = options_.servers[server_index - 1].group;
	for (const ServerOptions& server : options_.servers)
		if (server_group.empty() ? server.address == server_address : server.group == server_group)
			spec.server_addresses.push_back(server.address);
	return spec;
}

std::string PacketEngine::current_server() const
{
	std::lock_guard<std::mutex> lifecycle_lock(state_->lifecycle_mutex);
	const size_t				server_index = server_index_.load();
	if (server_index != 0)
	{
		const ServerOptions& server = options_.servers[server_index - 1];
		const std::string	 label	= server.name == server.address ? server.address : server.name + " [" + server.address + "]";
		return server.group.empty() ? label : server.group + ": " + label;
	}
	return "none";
}

std::string PacketEngine::current_server_region() const
{
	std::string address;
	{
		std::lock_guard<std::mutex> lifecycle_lock(state_->lifecycle_mutex);
		const size_t				server_index = server_index_.load();
		if (server_index == 0)
			return "";
		address = options_.servers[server_index - 1].address;
	}
	std::lock_guard<std::mutex> region_lock(state_->region_mutex);
	const auto					region = state_->server_regions.find(address);
	return region == state_->server_regions.end() ? "" : region->second;
}

std::string PacketEngine::client_region() const
{
	std::lock_guard<std::mutex> region_lock(state_->region_mutex);
	return state_->client_region;
}

void PacketEngine::cycle_server(int direction)
{
	if (options_.servers.empty() || direction == 0)
		return;
	const size_t option_count = options_.servers.size() + 1;
	size_t		 current	  = server_index_.load();
	if (direction > 0)
		current = (current + 1) % option_count;
	else
		current = current == 0 ? option_count - 1 : current - 1;
	server_index_						= current;
	state_->authoritative_server		= false;
	state_->select_authoritative_server = false;
	LOG_SERVER("Server changed to: %s", current_server().c_str());

	std::vector<int> active_profiles;
	{
		std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
		for (size_t index = 0; index < state_->active_profiles.size(); ++index)
			if (state_->active_profiles[index])
				active_profiles.push_back(static_cast<int>(index + 1));
	}
	for (const int profile : active_profiles)
		teardown(profile);
	for (const int profile : active_profiles)
		setup(profile);
}
