#include <algorithm>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

#include "internal.h"
#include "log.h"
#include "platform.h"

LOG_DEFAULT_GROUP(logging::group::config)

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

#if defined(LAGSW_FEATURE_PCAP_FILES) || defined(LAGSW_FEATURE_DESYNC_COUNTDOWN)
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
#endif

#ifdef LAGSW_FEATURE_SERVER_DISCOVERY
	bool validate_server_discovery(const char* path, const ServerDiscoveryOptions& discovery)
	{
		if (discovery.enabled && discovery.port == 0)
		{
			LOG_ERROR("Feature server_discovery is enabled but port is missing or invalid in %s", path);
			return false;
		}
		return true;
	}
#endif

#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
	bool validate_region_enforcement(const char* path, const RegionEnforcementOptions& region)
	{
		if (region.enabled && region.probe_port == 0)
		{
			LOG_ERROR("Feature region_enforcement is enabled but probe_port is missing or invalid in %s", path);
			return false;
		}
		return true;
	}
#endif

#ifdef LAGSW_FEATURE_PASSIVE_LATENCY
	bool validate_passive_latency(const char* path, const PassiveLatencyOptions& passive)
	{
		if (!passive.enabled)
			return true;
		const int32_t out_delay = passive.effective_delay_ms(true);
		const int32_t in_delay	= passive.effective_delay_ms(false);
		if (out_delay <= 0 && in_delay <= 0)
		{
			LOG_ERROR("Feature passive_latency is enabled but delay_ms must be positive for at least one direction in %s", path);
			return false;
		}
		if (passive.mode == PassiveLatencyMode::fixed && passive.jitter_ms != 0)
		{
			LOG_ERROR("Feature passive_latency jitter_ms requires mode uniform or normal in %s", path);
			return false;
		}
		if (passive.mode != PassiveLatencyMode::fixed && passive.jitter_ms <= 0)
		{
			LOG_ERROR("Feature passive_latency mode uniform or normal requires a positive jitter_ms in %s", path);
			return false;
		}
		if (passive.max_delay_ms != 0 && (passive.max_delay_ms < out_delay || passive.max_delay_ms < in_delay))
		{
			LOG_ERROR("Feature passive_latency max_delay_ms must be 0 or greater than or equal to the delay of each direction in %s", path);
			return false;
		}
		const int32_t effective_max = (std::max)(passive.effective_max_delay_ms(true), passive.effective_max_delay_ms(false));
		if (effective_max > 200)
			LOG_WARN("Feature passive_latency delay of up to %d ms in %s is high enough to noticeably affect responsiveness",
					 effective_max,
					 path);
		if (passive.pause_key)
		{
			const int pause = *passive.pause_key;
			if (pause == 'Q' || pause == platform::key::backspace || pause == platform::key::tab || pause == platform::key::page_up ||
				pause == platform::key::page_down || pause == platform::key::left || pause == platform::key::right)
			{
				LOG_ERROR("Feature passive_latency pause_key conflicts with a command key in %s", path);
				return false;
			}
		}
		if (!passive.preserve_order && passive.mode != PassiveLatencyMode::fixed)
			LOG_WARN("Feature passive_latency preserve_order is false; jitter can reorder TCP packets in %s", path);
		return true;
	}
#endif

#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
	bool validate_forwarded_address_discovery(const char* path, const ForwardedAddressDiscoveryOptions& discovery)
	{
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
		return true;
	}
#endif

#ifdef LAGSW_FEATURE_PCAP_FILES
	bool validate_pcap_files(const char* path, const PacketEngineOptions& options)
	{
		const PcapFilesOptions& pcap = options.features.pcap_files;
		if (pcap.enabled && pcap.enabled_for.empty())
		{
			LOG_ERROR("Feature pcap_files is enabled but enabled_for is missing or empty in %s", path);
			return false;
		}
		return !pcap.enabled || validate_enabled_for(options, "pcap_files", pcap.enabled_for);
	}
#endif

#ifdef LAGSW_FEATURE_DESYNC_COUNTDOWN
	bool validate_desync_countdown(const char* path, const PacketEngineOptions& options)
	{
		const DesyncCountdownOptions& countdown = options.features.desync_countdown;
		if (countdown.enabled && countdown.enabled_for.empty())
		{
			LOG_ERROR("Feature desync_countdown is enabled but enabled_for is missing or empty in %s", path);
			return false;
		}
		if (countdown.duration_percent == 0 || countdown.duration_percent > 100)
		{
			LOG_ERROR("Feature desync_countdown duration_percent must be between 1 and 100 in %s", path);
			return false;
		}
		return !countdown.enabled || validate_enabled_for(options, "desync_countdown", countdown.enabled_for);
	}
#endif

#ifdef LAGSW_FEATURE_NET_MONITOR
	bool validate_net_monitor(const char* path, const PacketEngineOptions& options)
	{
		const NetMonitorOptions& monitor = options.features.net_monitor;
		if (!monitor.enabled)
			return true;
		const std::pair<const char*, int> keys[] = {{"key", monitor.key},
													{"pause_key", monitor.pause_key},
													{"reset_key", monitor.reset_key},
													{"flows_key", monitor.flows_key},
													{"profiles_key", monitor.profiles_key},
													{"export_key", monitor.export_key}};
		for (size_t i = 0; i < std::size(keys); ++i)
		{
			const char* name = keys[i].first;
			const int	key	 = normalize_key(keys[i].second);
			if (key == 'Q' || key == platform::key::backspace || key == platform::key::tab || key == platform::key::page_up ||
				key == platform::key::page_down || key == platform::key::left || key == platform::key::right || key == platform::key::up ||
				key == platform::key::down)
			{
				LOG_ERROR("Feature net_monitor %s conflicts with a command key in %s", name, path);
				return false;
			}
			for (size_t j = i + 1; j < std::size(keys); ++j)
				if (normalize_key(keys[j].second) == key)
				{
					LOG_ERROR("Feature net_monitor %s conflicts with net_monitor %s in %s", keys[j].first, name, path);
					return false;
				}
#	ifdef LAGSW_FEATURE_PASSIVE_LATENCY
			if (options.features.passive_latency.enabled && options.features.passive_latency.pause_key &&
				normalize_key(*options.features.passive_latency.pause_key) == key)
			{
				LOG_ERROR("Feature net_monitor %s conflicts with the passive_latency pause_key in %s", name, path);
				return false;
			}
#	endif
			for (const ProfileOptions& profile : options.profiles)
			{
				const auto same = [key](int candidate) { return normalize_key(candidate) == key; };
				if (std::any_of(profile.keys.begin(), profile.keys.end(), same))
				{
					LOG_ERROR("Feature net_monitor %s conflicts with an activation key of profile '%s' in %s",
							  name,
							  profile.name.c_str(),
							  path);
					return false;
				}
				if (profile.send_key && same(*profile.send_key))
				{
					LOG_ERROR("Feature net_monitor %s conflicts with the send_key of profile '%s' in %s", name, profile.name.c_str(), path);
					return false;
				}
			}
		}
		return true;
	}
#endif

	bool validate_default_view([[maybe_unused]] const char* path, [[maybe_unused]] const PacketEngineOptions& options)
	{
		if (options.default_view != DefaultView::net_monitor)
			return true;
#ifdef LAGSW_FEATURE_NET_MONITOR
		if (!options.features.net_monitor.enabled)
		{
			LOG_ERROR("default_view net_monitor requires the net_monitor feature to be enabled in %s", path);
			return false;
		}
#else
		LOG_WARN("default_view net_monitor is ignored in %s because the net_monitor feature is not compiled into this build", path);
#endif
		return true;
	}

	bool validate_linux_bpf(const char* path, const LinuxBpfOptions& linux_bpf)
	{
		for (const std::string& name : linux_bpf.interfaces)
		{
			// Interface names are at most 15 bytes and never contain '/', whitespace or control characters.
			const bool valid = !name.empty() && name.size() <= 15 && name != "." && name != ".." &&
							   std::all_of(name.begin(), name.end(), [](unsigned char c) { return c > ' ' && c < 0x7F && c != '/'; });
			if (!valid)
			{
				LOG_ERROR("Feature linux_bpf interface '%s' is not a valid network interface name in %s", name.c_str(), path);
				return false;
			}
		}
		if (linux_bpf.tier == LinuxTier::bpf && linux_bpf.interfaces.empty())
		{
			LOG_ERROR("Feature linux_bpf tier bpf requires at least one interface in %s", path);
			return false;
		}
		return true;
	}

#ifdef LAGSW_FEATURE_CONFIG_TUI
	bool validate_config_tui(const char* path, const PacketEngineOptions& options)
	{
		const auto reserved = [](int candidate) { return normalize_key(candidate) == normalize_key(kConfigTuiKey); };
		const auto fail		= [&](const char* what) {
			LOG_ERROR("%s uses the key reserved for the config TUI (%c) in %s", what, kConfigTuiKey, path);
			return false;
		};
		for (const ProfileOptions& profile : options.profiles)
		{
			if (std::any_of(profile.keys.begin(), profile.keys.end(), reserved))
				return fail("A profile activation key");
			if (profile.send_key && reserved(*profile.send_key))
				return fail("A profile send_key");
		}
#	ifdef LAGSW_FEATURE_NET_MONITOR
		const NetMonitorOptions& monitor = options.features.net_monitor;
		if (monitor.enabled)
			for (const int other : {monitor.key, monitor.pause_key, monitor.reset_key, monitor.flows_key, monitor.profiles_key, monitor.export_key})
				if (reserved(other))
					return fail("A net_monitor key");
#	endif
#	ifdef LAGSW_FEATURE_PASSIVE_LATENCY
		if (options.features.passive_latency.enabled && options.features.passive_latency.pause_key && reserved(*options.features.passive_latency.pause_key))
			return fail("The passive_latency pause_key");
#	endif
		return true;
	}
#endif

	bool validate_features([[maybe_unused]] const char* path, [[maybe_unused]] const PacketEngineOptions& options)
	{
		if (!validate_linux_bpf(path, options.features.linux_bpf))
			return false;
#ifdef LAGSW_FEATURE_SERVER_DISCOVERY
		if (!validate_server_discovery(path, options.features.server_discovery))
			return false;
#endif
#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
		if (!validate_region_enforcement(path, options.features.region_enforcement))
			return false;
#endif
#ifdef LAGSW_FEATURE_PASSIVE_LATENCY
		if (!validate_passive_latency(path, options.features.passive_latency))
			return false;
#endif
#ifdef LAGSW_FEATURE_NET_MONITOR
		if (!validate_net_monitor(path, options))
			return false;
#endif
#ifdef LAGSW_FEATURE_CONFIG_TUI
		if (!validate_config_tui(path, options))
			return false;
#endif
#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
		if (!validate_forwarded_address_discovery(path, options.features.forwarded_address_discovery))
			return false;
#endif
#ifdef LAGSW_FEATURE_PCAP_FILES
		if (!validate_pcap_files(path, options))
			return false;
#endif
#ifdef LAGSW_FEATURE_DESYNC_COUNTDOWN
		if (!validate_desync_countdown(path, options))
			return false;
#endif
		return true;
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
	return validate_default_view(path, options) && validate_features(path, options);
}

}  // namespace config
