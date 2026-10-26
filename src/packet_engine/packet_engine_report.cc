#include "packet_engine_internal.h"

#include <cstdlib>
#include <ctime>

#include "log.h"

void PacketEngine::print_state() const
{
	std::vector<bool> active_profiles;
	{
		std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
		active_profiles = state_->active_profiles;
	}

	const size_t								  queued_packets  = pending_packets();
	const uint64_t								  next_release_in = next_batch_in_ms();
	std::vector<std::pair<std::string, uint64_t>> discovery_counts;
	std::string									  discovered_server;
	bool										  authoritative_server = false;
	{
		std::lock_guard<std::mutex> lifecycle_lock(state_->lifecycle_mutex);
		std::lock_guard<std::mutex> lock(state_->discovery_mutex);
		discovery_counts.assign(state_->discovery_counts.begin(), state_->discovery_counts.end());
		discovered_server	 = state_->discovered_server;
		authoritative_server = state_->authoritative_server;
	}
	std::sort(discovery_counts.begin(), discovery_counts.end(), [](const auto& left, const auto& right) {
		if (left.second != right.second)
			return left.second > right.second;
		return left.first < right.first;
	});

	size_t state_width = 53;
	for (size_t index = 0; index < options_.profiles.size(); ++index)
	{
		const std::string label = "profile #" + std::to_string(index + 1) + " - " + options_.profiles[index].name;
		if (label.size() + 4 > state_width)
			state_width = label.size() + 4;
	}
	const std::string max_value			 = std::to_string((std::numeric_limits<uint64_t>::max)());
	const size_t	  enabled_time_width = std::string("enabled time:    ").size() + max_value.size() + std::string("ms current, ").size() +
										   max_value.size() + std::string("ms min, ").size() + max_value.size() +
										   std::string("ms max, ").size() + max_value.size() + std::string("ms avg").size();
	if (enabled_time_width + 4 > state_width)
		state_width = enabled_time_width + 4;
	LOG_INFO("+%s+", std::string(state_width - 2, '-').c_str());
	log_state_line(state_width, "status:          " + highlight(running_ ? "RUNNING" : "STOPPED"));
	for (size_t index = 0; index < options_.profiles.size(); ++index)
	{
		const size_t			   profile_number		= index + 1;
		const ProfileOptions&	   profile_options		= options_.profiles[index];
		const State::ProfileStats& stats				= state_->profile_stats[index];
		uint64_t				   enabled_time_current = 0;
		uint64_t				   last_enabled_time	= 0;
		uint64_t				   enabled_time_min		= 0;
		uint64_t				   enabled_time_total	= 0;
		uint64_t				   enabled_time_max		= 0;
		uint64_t				   enabled_count		= 0;
		{
			std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
			if (active_profiles[index])
				enabled_time_current = platform::tick_ms() - stats.enabled_since;
			enabled_time_total = stats.enabled_time_total;
			enabled_time_min   = stats.enabled_count == 0 ? 0 : stats.enabled_time_min;
			enabled_time_max   = stats.enabled_time_max;
			last_enabled_time  = stats.last_enabled_time;
			enabled_count	   = stats.enabled_count;
		}
		const uint64_t enabled_time_average = enabled_count == 0 ? 0 : enabled_time_total / enabled_count;
		std::string	   profile_label		= profile_options.name;
		if (active_profiles[index])
			profile_label += " (ACTIVE)";
		else if (enabled_count != 0)
			profile_label += " (held " + logging::format_duration(last_enabled_time) + ")";
		LOG_INFO("%s", format_state_divider(state_width, profile_label).c_str());
		log_state_line(state_width, "profile:         " + highlight("#" + std::to_string(profile_number) + " - " + profile_options.name));
		log_state_line(state_width,
					   "enabled time:    " + highlight(logging::format_duration(enabled_time_current)) + " current, " +
						   highlight(logging::format_duration(enabled_time_min)) + " min, " +
						   highlight(logging::format_duration(enabled_time_max)) + " max, " +
						   highlight(logging::format_duration(enabled_time_average)) + " avg");
		log_state_line(state_width,
					   "enabled total:   " + highlight(logging::format_duration(enabled_time_total)) + " across " +
						   highlight(std::to_string(enabled_count)) + " activations");
		log_state_line(state_width, "packets caught:  " + highlight(std::to_string(stats.packets_caught.load())));
		log_state_line(state_width, "sent after delay: " + highlight(std::to_string(stats.delayed_packets_sent.load())));
		log_state_line(state_width, "sent at teardown: " + highlight(std::to_string(stats.teardown_packets_sent.load())));
		LOG_INFO("%s", format_state_divider(state_width).c_str());
	}
	log_state_line(state_width, "queued packets:  " + highlight(std::to_string(queued_packets)));
	if (queued_packets != 0)
	{
		if (next_release_in == (std::numeric_limits<uint64_t>::max)())
			log_state_line(state_width, "next release:    " + highlight("on profile deactivation"));
		else
			log_state_line(state_width, "next release:    in " + highlight(logging::format_duration(next_release_in)));
	}
	if (options_.discovery_port)
	{
		std::unordered_map<std::string, std::string> server_regions;
		{
			std::lock_guard<std::mutex> lock(state_->region_mutex);
			server_regions = state_->server_regions;
		}
		LOG_DEBUG("print_state: snapshotted %zu resolved region(s)", server_regions.size());
		auto region_suffix = [&](const std::string& address) -> std::string {
			const auto region = server_regions.find(address);
			return region == server_regions.end() ? "" : " (" + region->second + ")";
		};
		LOG_INFO("%s", format_state_divider(state_width, "server discovery").c_str());
		log_state_line(
			state_width,
			"authoritative:   " + highlight(discovered_server.empty() ? "none" : discovered_server + region_suffix(discovered_server)) +
				(authoritative_server ? " (selected)" : " (observed)"));
		log_state_line(state_width, "ranked servers:  " + highlight(std::to_string(discovery_counts.size())));
		for (size_t index = 0; index < discovery_counts.size(); ++index)
		{
			const auto& [address, count] = discovery_counts[index];
			const auto		  server	 = std::find_if(options_.servers.begin(), options_.servers.end(), [&](const ServerOptions& item) {
				return item.address == address;
			});
			const std::string label =
				(server == options_.servers.end() || server->name == server->address ? address : server->name + " [" + address + "]") +
				region_suffix(address);
			log_state_line(state_width, std::to_string(index + 1) + ". " + label + " - " + highlight(std::to_string(count)) + " packets");
		}
		LOG_INFO("%s", format_state_divider(state_width).c_str());
	}
	if (options_.features.region_enforcement.enabled)
	{
		LOG_INFO("%s", format_state_divider(state_width, "region enforcement").c_str());
		log_state_line(state_width, "probe port:      " + highlight(std::to_string(options_.features.region_enforcement.probe_port)));
		log_state_line(state_width, "probe status:    " + highlight(region_enforcement_status()));
		log_state_line(state_width, "enforced region: " + highlight(current_enforced_region()));
		LOG_INFO("%s", format_state_divider(state_width).c_str());
	}
	if (options_.features.forwarded_address_discovery.enabled)
	{
		LOG_INFO("%s", format_state_divider(state_width, "forwarded address discovery").c_str());
		log_state_line(state_width, "addresses:       " + highlight(forwarded_address_discovery_status()));
		LOG_INFO("%s", format_state_divider(state_width).c_str());
	}
	LOG_INFO("+%s+", std::string(state_width - 2, '-').c_str());
}
