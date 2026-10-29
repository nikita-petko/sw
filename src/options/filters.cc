#include <string>

#include "internal.h"
#include "log.h"
#include "packet_backend.h"

namespace config {
namespace {
const char* describe(const std::string& error)
{
	return error.empty() ? "unknown error" : error.c_str();
}

bool validate_region_filters(const PacketEngineOptions& options)
{
	const uint16_t	  probe_port	 = options.features.region_enforcement.probe_port;
	const std::string probe_filter	 = backend::filters::syn_probe(probe_port);
	std::string		  error;
	uint32_t		  error_position = 0;
	if (!backend::validate_filter(probe_filter, false, error, error_position))
	{
		LOG_ERROR("Invalid filter for region probe detection on port %u: %s", probe_port, describe(error));
		return false;
	}

	for (const ServerOptions& server : options.servers)
	{
		const std::string filter = backend::filters::region_enforcement({server.address}, probe_port);
		if (!backend::validate_filter(filter, false, error, error_position))
		{
			LOG_ERROR("Invalid filter for region enforcement on server '%s' port %u: %s", server.address.c_str(), probe_port, describe(error));
			return false;
		}
	}
	return true;
}

bool validate_forwarded_address_filter(const PacketEngineOptions& options)
{
	const ForwardedAddressDiscoveryOptions& discovery = options.features.forwarded_address_discovery;
	const std::string filter = backend::filters::forwarded_address(*discovery.inbound_if_idx, *discovery.outbound_if_idx, discovery.port);
	std::string		  error;
	uint32_t		  error_position = 0;
	if (!backend::validate_filter(filter, false, error, error_position))
	{
		LOG_ERROR("Invalid filter for forwarded address discovery: %s", describe(error));
		return false;
	}
	return true;
}

/// Validates the capture filter of a profile for every server the user can select (and for no server).
bool validate_profile_filters(const char* path, const PacketEngineOptions& options, const ProfileOptions& profile)
{
	LOG_DEBUG("Validating filter '%s' for profile '%s'", profile.filter.value_or(options.global_filter).c_str(), profile.name.c_str());

	const bool outbound = profile.capture_options.outbound.value_or(false);
	const bool forward	= profile.capture_options.forward.value_or(false);
	if (outbound && forward)
	{
		LOG_ERROR("Invalid options for profile '%s': outbound requires forward to be false", profile.name.c_str());
		return false;
	}
	for (size_t server_index = 0; server_index <= options.servers.size(); ++server_index)
	{
		backend::ProfileFilter spec;
		spec.user_filter		= profile.filter.value_or(options.global_filter);
		spec.include_bare_acks	= profile.ack_restoration;
		spec.client_enforcement = profile.capture_options.client_address_enforcement.value_or(CaptureOptions::ClientAddressEnforcement::both);
		spec.client_source		= options.client_source_address;
		spec.client_destination = options.client_destination_address;
		spec.outbound			= outbound;
		if (server_index != 0 && profile.capture_options.server_direction)
		{
			spec.server_direction = profile.capture_options.server_direction;
			spec.server_addresses = {options.servers[server_index - 1].address};
		}
		const std::string capture_filter = backend::filters::profile(spec);
		std::string		  error;
		uint32_t		  error_position = 0;
		if (!backend::validate_filter(capture_filter, forward, error, error_position))
		{
			LOG_ERROR("Invalid filter for profile '%s' in %s at position %u: %s", profile.name.c_str(), path, error_position, describe(error));
			return false;
		}
	}
	return true;
}
}  // namespace

bool validate_filters(const char* path, const PacketEngineOptions& options)
{
	if (options.profiles.empty())
	{
		LOG_ERROR("A profiles YAML file must contain at least one profile: %s", path);
		return false;
	}
	if (options.features.region_enforcement.enabled && options.features.region_enforcement.probe_port != 0 &&
		!validate_region_filters(options))
		return false;
	if (options.features.forwarded_address_discovery.enabled && options.features.forwarded_address_discovery.port != 0 &&
		!validate_forwarded_address_filter(options))
		return false;
	for (const ProfileOptions& profile : options.profiles)
		if (!validate_profile_filters(path, options, profile))
			return false;
	return true;
}

}  // namespace config
