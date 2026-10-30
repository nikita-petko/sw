#include "internal.h"

#include <cstdlib>
#include <cstring>
#include <ctime>

#include "log.h"

LOG_DEFAULT_GROUP(logging::group::report)

namespace {
/// A snapshot of one profile's counters for the state report.
struct ProfileReport
{
	bool	 active				 = false;
	uint64_t enabled_time_current = 0;
	uint64_t last_enabled_time	 = 0;
	uint64_t enabled_time_min	 = 0;
	uint64_t enabled_time_total	 = 0;
	uint64_t enabled_time_max	 = 0;
	uint64_t enabled_count		 = 0;
	uint64_t packets_caught		 = 0;
	uint64_t delayed_packets_sent = 0;
	uint64_t teardown_packets_sent = 0;
};

/// A snapshot of the server discovery results for the state report.
struct DiscoveryReport
{
	std::vector<std::pair<std::string, uint64_t>> counts;
	std::string									  discovered_server;
	bool										  authoritative = false;
	std::unordered_map<std::string, std::string>  regions;
};

/// One state line per log group that has logged or muted anything, e.g. "discovery.packet  err 0, warn 0, info 0, debug 12 (muted 3)".
std::vector<std::string> log_group_lines()
{
	const auto&				   registry = logging::groups();
	const auto				   stats	= logging::group_stats();
	size_t					   name_width = 0;
	for (size_t index = 0; index < registry.size(); ++index)
		if (stats[index].written() != 0 || stats[index].muted != 0)
			name_width = (std::max)(name_width, std::strlen(registry[index].name));

	std::vector<std::string> lines;
	for (size_t index = 0; index < registry.size(); ++index)
	{
		const logging::group_counts& counts = stats[index];
		if (counts.written() == 0 && counts.muted == 0)
			continue;
		std::string name = registry[index].name;
		name.resize(name_width, ' ');
		std::string line = name + "  err " + highlight(std::to_string(counts.by_level[static_cast<size_t>(logging::level::error)])) + ", warn " +
						   highlight(std::to_string(counts.by_level[static_cast<size_t>(logging::level::warn)])) + ", info " +
						   highlight(std::to_string(counts.by_level[static_cast<size_t>(logging::level::info)])) + ", debug " +
						   highlight(std::to_string(counts.by_level[static_cast<size_t>(logging::level::debug)]));
		if (counts.muted != 0)
			line += " (" + highlight(std::to_string(counts.muted)) + " muted)";
		lines.push_back(std::move(line));
	}
	return lines;
}

/// The width of the report box: wide enough for the longest profile label, the longest possible enabled-time line, and the log group lines.
size_t report_width(const PacketEngineOptions& options, const std::vector<std::string>& group_lines)
{
	size_t width = 53;
	for (const std::string& line : group_lines)
		width = (std::max)(width, visible_length(line) + 4);
	for (size_t index = 0; index < options.profiles.size(); ++index)
	{
		const std::string label = "profile #" + std::to_string(index + 1) + " - " + options.profiles[index].name;
		if (label.size() + 4 > width)
			width = label.size() + 4;
	}
	const std::string max_value			 = std::to_string((std::numeric_limits<uint64_t>::max)());
	const size_t	  enabled_time_width = std::string("enabled time:    ").size() + max_value.size() + std::string("ms current, ").size() +
										   max_value.size() + std::string("ms min, ").size() + max_value.size() +
										   std::string("ms max, ").size() + max_value.size() + std::string("ms avg").size();
	if (enabled_time_width + 4 > width)
		width = enabled_time_width + 4;
	return width;
}

void log_profile_report(size_t width, size_t profile_number, const ProfileOptions& profile_options, const ProfileReport& report)
{
	const uint64_t enabled_time_average = report.enabled_count == 0 ? 0 : report.enabled_time_total / report.enabled_count;
	std::string	   profile_label		= profile_options.name;
	if (report.active)
		profile_label += " (ACTIVE)";
	else if (report.enabled_count != 0)
		profile_label += " (held " + logging::format_duration(report.last_enabled_time) + ")";
	LOG_INFO("%s", format_state_divider(width, profile_label).c_str());
	log_state_line(width, "profile:         " + highlight("#" + std::to_string(profile_number) + " - " + profile_options.name));
	log_state_line(width,
				   "enabled time:    " + highlight(logging::format_duration(report.enabled_time_current)) + " current, " +
					   highlight(logging::format_duration(report.enabled_time_min)) + " min, " +
					   highlight(logging::format_duration(report.enabled_time_max)) + " max, " +
					   highlight(logging::format_duration(enabled_time_average)) + " avg");
	log_state_line(width,
				   "enabled total:   " + highlight(logging::format_duration(report.enabled_time_total)) + " across " +
					   highlight(std::to_string(report.enabled_count)) + " activations");
	log_state_line(width, "packets caught:  " + highlight(std::to_string(report.packets_caught)));
	log_state_line(width, "sent after delay: " + highlight(std::to_string(report.delayed_packets_sent)));
	log_state_line(width, "sent at teardown: " + highlight(std::to_string(report.teardown_packets_sent)));
	LOG_INFO("%s", format_state_divider(width).c_str());
}

void log_queue_report(size_t width, size_t queued_packets, uint64_t next_release_in)
{
	log_state_line(width, "queued packets:  " + highlight(std::to_string(queued_packets)));
	if (queued_packets == 0)
		return;
	if (next_release_in == (std::numeric_limits<uint64_t>::max)())
		log_state_line(width, "next release:    " + highlight("on profile deactivation"));
	else
		log_state_line(width, "next release:    in " + highlight(logging::format_duration(next_release_in)));
}

void log_discovery_report(size_t width, const PacketEngineOptions& options, const DiscoveryReport& report)
{
	LOG_DEBUG("print_state: snapshotted %zu resolved region(s)", report.regions.size());
	auto region_suffix = [&](const std::string& address) -> std::string {
		const auto region = report.regions.find(address);
		return region == report.regions.end() ? "" : " (" + region->second + ")";
	};
	LOG_INFO("%s", format_state_divider(width, "server discovery").c_str());
	log_state_line(width,
				   "authoritative:   " +
					   highlight(report.discovered_server.empty() ? "none" : report.discovered_server + region_suffix(report.discovered_server)) +
					   (report.authoritative ? " (selected)" : " (observed)"));
	log_state_line(width, "ranked servers:  " + highlight(std::to_string(report.counts.size())));
	for (size_t index = 0; index < report.counts.size(); ++index)
	{
		const auto& [address, count] = report.counts[index];
		const auto		  server	 = std::find_if(options.servers.begin(), options.servers.end(), [&](const ServerOptions& item) {
			return item.address == address;
		});
		const std::string label =
			(server == options.servers.end() || server->name == server->address ? address : server->name + " [" + address + "]") +
			region_suffix(address);
		log_state_line(width, std::to_string(index + 1) + ". " + label + " - " + highlight(std::to_string(count)) + " packets");
	}
	LOG_INFO("%s", format_state_divider(width).c_str());
}
}  // namespace

void PacketEngine::print_state() const
{
	std::vector<bool> active_profiles;
	{
		std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
		active_profiles = state_->active_profiles;
	}

	const size_t	queued_packets	= pending_packets();
	const uint64_t	next_release_in = next_batch_in_ms();
	DiscoveryReport discovery;
	{
		std::lock_guard<std::mutex> lifecycle_lock(state_->lifecycle_mutex);
		std::lock_guard<std::mutex> lock(state_->discovery_mutex);
		discovery.counts.assign(state_->discovery_counts.begin(), state_->discovery_counts.end());
		discovery.discovered_server = state_->discovered_server;
		discovery.authoritative		= state_->authoritative_server;
	}
	std::sort(discovery.counts.begin(), discovery.counts.end(), [](const auto& left, const auto& right) {
		if (left.second != right.second)
			return left.second > right.second;
		return left.first < right.first;
	});

	const std::vector<std::string> group_lines = log_group_lines();
	const size_t				   state_width = report_width(options_, group_lines);
	LOG_INFO("+%s+", std::string(state_width - 2, '-').c_str());
	log_state_line(state_width, "status:          " + highlight(running_ ? "RUNNING" : "STOPPED"));
	for (size_t index = 0; index < options_.profiles.size(); ++index)
	{
		const State::ProfileStats& stats = state_->profile_stats[index];
		ProfileReport			   report;
		report.active = active_profiles[index];
		{
			std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
			if (report.active)
				report.enabled_time_current = platform::tick_ms() - stats.enabled_since;
			report.enabled_time_total = stats.enabled_time_total;
			report.enabled_time_min	  = stats.enabled_count == 0 ? 0 : stats.enabled_time_min;
			report.enabled_time_max	  = stats.enabled_time_max;
			report.last_enabled_time  = stats.last_enabled_time;
			report.enabled_count	  = stats.enabled_count;
		}
		report.packets_caught		= stats.packets_caught.load();
		report.delayed_packets_sent = stats.delayed_packets_sent.load();
		report.teardown_packets_sent = stats.teardown_packets_sent.load();
		log_profile_report(state_width, index + 1, options_.profiles[index], report);
	}
	log_queue_report(state_width, queued_packets, next_release_in);
	if (options_.discovery_port)
	{
		{
			std::lock_guard<std::mutex> lock(state_->region_mutex);
			discovery.regions = state_->server_regions;
		}
		log_discovery_report(state_width, options_, discovery);
	}
#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
	if (options_.features.region_enforcement.enabled)
	{
		LOG_INFO("%s", format_state_divider(state_width, "region enforcement").c_str());
		log_state_line(state_width, "probe port:      " + highlight(std::to_string(options_.features.region_enforcement.probe_port)));
		log_state_line(state_width, "probe status:    " + highlight(region_enforcement_status()));
		log_state_line(state_width, "enforced region: " + highlight(current_enforced_region()));
		LOG_INFO("%s", format_state_divider(state_width).c_str());
	}
#endif
#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
	if (options_.features.forwarded_address_discovery.enabled)
	{
		LOG_INFO("%s", format_state_divider(state_width, "forwarded address discovery").c_str());
		log_state_line(state_width, "addresses:       " + highlight(forwarded_address_discovery_status()));
		LOG_INFO("%s", format_state_divider(state_width).c_str());
	}
#endif
	if (!group_lines.empty())
	{
		LOG_INFO("%s", format_state_divider(state_width, "log groups").c_str());
		for (const std::string& line : group_lines)
			log_state_line(state_width, line);
		LOG_INFO("%s", format_state_divider(state_width).c_str());
	}
	LOG_INFO("+%s+", std::string(state_width - 2, '-').c_str());
}
