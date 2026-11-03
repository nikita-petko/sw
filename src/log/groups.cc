#include <log.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "internal.h"

namespace logging_detail {
std::mutex group_mutex;
std::vector<std::pair<std::string, bool>> group_rules;
std::atomic<bool> groups_configured{false};
GroupCounters group_counters[max_groups];
}

namespace {
using namespace logging_detail;

// The registry is small, so a linear scan keeps lookups simple; max_groups is returned for an unregistered name
size_t group_index(const char* group_name)
{
	const std::vector<logging::group_info>& registry = logging::groups();
	for (size_t index = 0; index < registry.size() && index < max_groups; ++index)
		if (std::strcmp(registry[index].name, group_name) == 0)
			return index;
	return max_groups;
}
}

namespace logging {
using namespace logging_detail;
const std::vector<group_info>& groups()
{
	static const std::vector<group_info> registry = {
		{group::startup, "Startup banner, loaded profile listing, and shutdown"},
		{group::config, "Command line and profile configuration parsing and validation"},
		{group::server, "Server list and server selection"},
		{group::pcap, "PCAP file capture"},
		{group::report, "The state report printed with Tab"},
		{group::profile, "Profile activation, setup, and teardown"},
		{group::input, "Keyboard input"},
		{group::nft, "nftables table and chain lifecycle (Linux)"},
		{group::nft_script, "Every nf_tables batch and rule sent to the kernel, and its result (Linux)"},
		{group::nfq, "NFQUEUE queue lifecycle, verdicts, and errors (Linux)"},
		{group::nfq_packet, "Every packet queued, accepted, or dropped by NFQUEUE (Linux)", false},
		{group::nfq_filter, "Capture filter compilation to nftables rules (Linux)"},
		{group::nfq_monitor, "NFQUEUE and nftables health sampling (Linux)"},
		{group::kmod, "swdivert kernel-module handles: lifecycle, verdicts, and errors (Linux)"},
		{group::kmod_packet, "Every packet held, resumed, or dropped by the swdivert module (Linux)", false},
		{group::kmod_filter, "Capture filter compilation to filter programs (Linux)"},
		{group::kmod_monitor, "swdivert module health sampling (Linux)"},
		{group::backend, "Packet backend internals"},
		{group::http, "HTTPS requests"},
		{group::packet, "All per-packet profile traffic"},
		{group::packet_recv, "Packets received by a profile", false},
		{group::packet_send, "Packets sent or flushed by a profile", false},
		{group::packet_drop, "Packets dropped by a profile", false},
		{group::discovery, "Server discovery lifecycle and decisions"},
		{group::discovery_stats, "Periodic server discovery capture totals"},
		{group::discovery_packet, "Every packet seen by server discovery", false},
		{group::forwarded, "Forwarded address discovery windows and results"},
		{group::forwarded_packet, "Every packet seen by forwarded address discovery", false},
		{group::region, "Server region lookups"},
		{group::region_client, "Client region lookup"},
		{group::enforcement, "Region enforcement decisions"},
		{group::enforcement_packet, "Every packet delayed or sent by region enforcement", false},
		{group::passive_latency, "Passive latency lifecycle and configuration"},
		{group::passive_latency_packet, "Every packet delayed or sent by passive latency", false},
	};
	return registry;
}

std::vector<group_counts> group_stats()
{
	std::vector<group_counts> snapshot(groups().size());
	for (size_t index = 0; index < snapshot.size(); ++index)
	{
		for (size_t message_level = 0; message_level < 4; ++message_level)
			snapshot[index].by_level[message_level] = group_counters[index].by_level[message_level].load(std::memory_order_relaxed);
		snapshot[index].muted = group_counters[index].muted.load(std::memory_order_relaxed);
	}
	return snapshot;
}

bool set_groups(const std::string& spec, std::string& error)
{
	std::vector<std::pair<std::string, bool>> parsed;
	size_t									  start = 0;
	while (start <= spec.size())
	{
		size_t end = spec.find(',', start);
		if (end == std::string::npos)
			end = spec.size();

		std::string name = spec.substr(start, end - start);
		start			 = end + 1;
		bool enabled	 = true;
		if (!name.empty() && (name[0] == '-' || name[0] == '+'))
		{
			enabled = name[0] == '+';
			name.erase(0, 1);
		}
		if (name.empty())
		{
			error = "empty log group name";
			return false;
		}
		if (name != "all")
		{
			bool known = false;
			for (const group_info& candidate : groups())
				known = known || name == candidate.name;
			if (!known)
			{
				error = "unknown log group '" + name + "'";
				return false;
			}
		}
		parsed.emplace_back(name == "all" ? std::string() : name, enabled);
	}

	std::lock_guard lock(group_mutex);
	for (auto& [name, enabled] : parsed)
	{
		// "all" restarts from a clean slate so it overrides every earlier, more specific rule
		if (name.empty())
			group_rules.clear();
		const auto existing = std::find_if(group_rules.begin(), group_rules.end(), [&](const auto& rule) { return rule.first == name; });
		if (existing != group_rules.end())
			existing->second = enabled;
		else
			group_rules.emplace_back(std::move(name), enabled);
	}
	groups_configured = !group_rules.empty();
	return true;
}

bool group_enabled(const char* group_name)
{
	const std::string name = group_name;
	bool			  enabled = true;
	for (const group_info& candidate : groups())
		if (name == candidate.name)
			enabled = candidate.enabled_by_default;
	if (!groups_configured.load(std::memory_order_acquire))
		return enabled;

	std::lock_guard	  lock(group_mutex);
	size_t			  best_length = 0;
	bool			  matched	  = false;
	for (const auto& [rule, rule_enabled] : group_rules)
	{
		const bool matches = rule.empty() || name == rule || (name.size() > rule.size() && name.compare(0, rule.size(), rule) == 0 && name[rule.size()] == '.');
		if (matches && (!matched || rule.size() >= best_length))
		{
			enabled		= rule_enabled;
			best_length = rule.size();
			matched		= true;
		}
	}
	return enabled;
}

bool group_accepts(const char* group_name, level message_level)
{
	{
		std::lock_guard lock(log_mutex);
		if (static_cast<int>(message_level) > static_cast<int>(minimum_level))
			return false;
	}

	const size_t index = group_index(group_name);
	// Warnings and errors are never muted
	const bool enabled = message_level == level::error || message_level == level::warn || group_enabled(group_name);
	if (index < max_groups)
	{
		if (enabled)
			group_counters[index].by_level[static_cast<size_t>(message_level)].fetch_add(1, std::memory_order_relaxed);
		else
			group_counters[index].muted.fetch_add(1, std::memory_order_relaxed);
	}
	return enabled;
}

}  // namespace logging
