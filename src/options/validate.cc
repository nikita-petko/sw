#include <algorithm>
#include <string>
#include <vector>

#include "internal.h"
#include "log.h"

namespace config {
namespace {
bool has_profile(const PacketEngineOptions& options, const std::string& name)
{
	return std::any_of(options.profiles.begin(), options.profiles.end(), [&](const ProfileOptions& candidate) {
		return candidate.name == name;
	});
}

bool validate_activation(const ProfileOptions& item)
{
	if (item.mode == ProfileActivationMode::period && item.activation_period_ms == 0)
	{
		LOG_ERROR("Profile '%s' requires a positive activation_period in period mode", item.name.c_str());
		return false;
	}
	if (item.mode != ProfileActivationMode::period && item.activation_period_ms != 0)
	{
		LOG_ERROR("Profile '%s' can only set activation_period when mode is period", item.name.c_str());
		return false;
	}
	return true;
}

bool validate_delay_mode(const ProfileOptions& item)
{
	if ((item.delay_mode == PacketDelayMode::ratio || item.delay_mode == PacketDelayMode::drop_and_send) &&
		(item.ratio <= 0 || (item.ratio_percent && item.ratio > 100) || item.delay_ms <= 0))
	{
		LOG_ERROR("Profile '%s' requires a positive ratio and delay_ms", item.name.c_str());
		return false;
	}
	if (item.delay_mode == PacketDelayMode::drop_and_send && !item.ratio_configured)
	{
		LOG_ERROR("Profile '%s' requires ratio to be configured", item.name.c_str());
		return false;
	}
	if (item.delay_mode == PacketDelayMode::hold_and_send && (!item.ratio_configured || item.ratio <= 0 || item.ratio_percent))
	{
		LOG_ERROR("Profile '%s' requires a positive packet count ratio for hold_and_send", item.name.c_str());
		return false;
	}
	if (item.delay_mode == PacketDelayMode::drop_until_toggle && item.mode != ProfileActivationMode::toggle)
	{
		LOG_ERROR("Profile '%s' requires toggle mode for drop_until_toggle", item.name.c_str());
		return false;
	}
	if (item.delay_mode == PacketDelayMode::hold_until_deactivation && item.mode != ProfileActivationMode::toggle)
	{
		LOG_ERROR("Profile '%s' requires toggle mode for hold_until_deactivation", item.name.c_str());
		return false;
	}
	if (item.delay_mode == PacketDelayMode::packet_group_send && (item.group_count <= 0 || item.mode != ProfileActivationMode::toggle))
	{
		LOG_ERROR("Profile '%s' requires a positive group_count and toggle mode for packet_group_send", item.name.c_str());
		return false;
	}
	if (item.delay_mode != PacketDelayMode::packet_group_send && item.group_count != 0)
	{
		LOG_ERROR("Profile '%s' can only set group_count when delay_mode is packet_group_send", item.name.c_str());
		return false;
	}
	return true;
}

bool validate_disables(const ProfileOptions& item, const PacketEngineOptions& options)
{
	for (const std::string& disabled_name : item.disables)
	{
		if (disabled_name == "*")
			continue;
		if (disabled_name == item.name)
		{
			LOG_ERROR("Profile '%s' cannot disable itself", item.name.c_str());
			return false;
		}
		if (!has_profile(options, disabled_name))
		{
			LOG_ERROR("Profile '%s' disables unknown profile '%s'", item.name.c_str(), disabled_name.c_str());
			return false;
		}
	}
	return true;
}

bool validate_profile(const ProfileOptions& item, const PacketEngineOptions& options, const char* path)
{
	if (item.name.empty() || item.keys.empty())
	{
		LOG_ERROR("Each profile in %s requires a name and key(s)", path);
		return false;
	}
	return validate_activation(item) && validate_delay_mode(item) && validate_disables(item, options);
}

bool validate_send_keys(const PacketEngineOptions& options)
{
	for (const ProfileOptions& profile : options.profiles)
	{
		if (!profile.send_key)
			continue;
		for (const ProfileOptions& target : options.profiles)
		{
			if (std::find(target.keys.begin(), target.keys.end(), *profile.send_key) != target.keys.end())
			{
				LOG_ERROR("Profile '%s' send_key cannot be an activation key", profile.name.c_str());
				return false;
			}
		}
	}
	return true;
}

/// Every name in an enabled_for list must be "*" or a configured profile.
bool validate_enabled_for(const PacketEngineOptions& options, const char* feature, const std::vector<std::string>& enabled_for)
{
	for (const std::string& name : enabled_for)
	{
		if (name != "*" && !has_profile(options, name))
		{
			LOG_ERROR("Feature %s enables unknown profile '%s'", feature, name.c_str());
			return false;
		}
	}
	return true;
}

bool validate_features(const char* path, const PacketEngineOptions& options)
{
	const FeaturesOptions& features = options.features;
	if (features.region_enforcement.enabled && features.region_enforcement.probe_port == 0)
	{
		LOG_ERROR("Feature region_enforcement is enabled but probe_port is missing or invalid in %s", path);
		return false;
	}
	const ForwardedAddressDiscoveryOptions& discovery = features.forwarded_address_discovery;
	if (discovery.enabled && (!discovery.inbound_if_idx || !discovery.outbound_if_idx))
	{
		LOG_ERROR("Feature forwarded_address_discovery is enabled but inbound and/or outbound is missing in %s", path);
		return false;
	}
	if (discovery.enabled && discovery.inbound_if_idx == discovery.outbound_if_idx)
	{
		LOG_ERROR("Feature forwarded_address_discovery requires inbound and outbound to be different interfaces in %s", path);
		return false;
	}
	if (discovery.enabled && discovery.port == 0)
	{
		LOG_ERROR("Feature forwarded_address_discovery is enabled but port is missing or invalid in %s", path);
		return false;
	}
	if (features.pcap_files.enabled && features.pcap_files.enabled_for.empty())
	{
		LOG_ERROR("Feature pcap_files is enabled but enabled_for is missing or empty in %s", path);
		return false;
	}
	if (features.pcap_files.enabled && !validate_enabled_for(options, "pcap_files", features.pcap_files.enabled_for))
		return false;
	if (features.desync_countdown.enabled && features.desync_countdown.enabled_for.empty())
	{
		LOG_ERROR("Feature desync_countdown is enabled but enabled_for is missing or empty in %s", path);
		return false;
	}
	if (features.desync_countdown.duration_percent == 0 || features.desync_countdown.duration_percent > 100)
	{
		LOG_ERROR("Feature desync_countdown duration_percent must be between 1 and 100 in %s", path);
		return false;
	}
	return !features.desync_countdown.enabled || validate_enabled_for(options, "desync_countdown", features.desync_countdown.enabled_for);
}
}  // namespace

bool validate_profiles(const char* path, const PacketEngineOptions& options)
{
	for (const ProfileOptions& item : options.profiles)
		if (!validate_profile(item, options, path))
			return false;
	if (!validate_send_keys(options))
		return false;
	if (options.profiles.empty())
	{
		LOG_ERROR("No profiles found in %s", path);
		return false;
	}
	return validate_features(path, options);
}

}  // namespace config
