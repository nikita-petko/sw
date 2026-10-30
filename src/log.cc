#include <log.h>

#include <algorithm>
#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "platform.h"

namespace {
constexpr size_t max_log_message = 1024;
logging::level	 minimum_level	 = logging::level::info;
std::mutex		 log_mutex;
std::mutex		 group_mutex;
std::atomic<bool> show_groups{false};
std::vector<std::pair<std::string, bool>> group_rules;	// An empty name is the "all" rule
std::atomic<bool>						  groups_configured{false};

constexpr size_t max_groups = 64;
struct GroupCounters
{
	std::atomic<std::uint64_t> by_level[4];
	std::atomic<std::uint64_t> muted;
};
GroupCounters group_counters[max_groups];

// The registry is small, so a linear scan keeps lookups simple; max_groups is returned for an unregistered name
size_t group_index(const char* group_name)
{
	const std::vector<logging::group_info>& registry = logging::groups();
	for (size_t index = 0; index < registry.size() && index < max_groups; ++index)
		if (std::strcmp(registry[index].name, group_name) == 0)
			return index;
	return max_groups;
}
std::string		 status_line;
std::string		 status_right_line;
std::vector<std::string> extra_status_lines;

void clear_status_line()
{
	if (status_line.empty())
		return;
	std::printf("\r\033[2K");
	// The extra lines sit below the cursor; wipe them and return to the main line.
	for (size_t i = 0; i < extra_status_lines.size(); ++i)
		std::printf("\033[B\033[2K");
	if (!extra_status_lines.empty())
		std::printf("\033[%zuA\r", extra_status_lines.size());
}

int console_width()
{
	return platform::console_width();
}

void print_status_line(const std::string& status, const std::string& right_status = {})
{
	const int width = console_width();
	if (width > 0 && !right_status.empty() && status.size() + right_status.size() <= static_cast<size_t>(width))
	{
		const size_t padding = static_cast<size_t>(width) - status.size() - right_status.size();
		std::printf("\r\033[30;47m%s%*s%s\033[0m", status.c_str(), static_cast<int>(padding), "", right_status.c_str());
		return;
	}
	const size_t padding = width > 0 && status.size() < static_cast<size_t>(width) ? static_cast<size_t>(width) - status.size() : 0;
	std::printf("\r\033[30;47m%s%*s\033[0m", status.c_str(), static_cast<int>(padding), "");
}

void print_status_block(const std::string& status, const std::string& right_status)
{
	print_status_line(status, right_status);
	if (extra_status_lines.empty())
		return;
	const int width = console_width();
	for (const std::string& line : extra_status_lines)
	{
		const std::string shown = width > 0 && line.size() > static_cast<size_t>(width) ? line.substr(0, static_cast<size_t>(width)) : line;
		const size_t	  pad	= width > 0 && shown.size() < static_cast<size_t>(width) ? static_cast<size_t>(width) - shown.size() : 0;
		std::printf("\n\r\033[30;47m%s%*s\033[0m", shown.c_str(), static_cast<int>(pad), "");
	}
	std::printf("\033[%zuA\r", extra_status_lines.size());
}

const char* level_name(logging::level message_level)
{
	switch (message_level)
	{
		case logging::level::error:
			return "ERROR";
		case logging::level::warn:
			return "WARN";
		case logging::level::info:
			return "INFO";
		case logging::level::debug:
			return "DEBUG";
	}
	return "UNKNOWN";
}

const char* level_color(logging::level message_level)
{
	switch (message_level)
	{
		case logging::level::error:
			return "\033[31m";
		case logging::level::warn:
			return "\033[33m";
		case logging::level::info:
			return "\033[32m";
		case logging::level::debug:
			return "\033[36m";
	}
	return "";
}

const char* style_color(logging::style message_style)
{
	switch (message_style)
	{
		case logging::style::activate:
			return "\033[1;92m";
		case logging::style::deactivate:
			return "\033[1;35m";
		case logging::style::server:
			return "\033[94m";
		case logging::style::region:
			return "\033[96m";
		case logging::style::detail:
			return "\033[90m";
		case logging::style::normal:
			break;
	}
	return "\033[32m";
}
}  // namespace

namespace logging {

std::string format_duration(uint64_t duration_ms)
{
	if (duration_ms < 1000)
		return std::to_string(duration_ms) + "ms";

	const uint64_t total_seconds = duration_ms / 1000;
	const uint64_t minutes		 = total_seconds / 60;
	const uint64_t seconds		 = total_seconds % 60;
	if (minutes > 0)
	{
		if (seconds == 0)
			return std::to_string(minutes) + "m";
		return std::to_string(minutes) + "m " + std::to_string(seconds) + "s";
	}

	const uint64_t whole_seconds = total_seconds;
	const uint64_t fraction_ms	 = duration_ms % 1000;
	if (fraction_ms == 0)
		return std::to_string(whole_seconds) + "s";

	const uint64_t tenths = (fraction_ms + 50) / 100;
	if (tenths == 10)
		return std::to_string(whole_seconds + 1) + "s";
	return std::to_string(whole_seconds) + "." + std::to_string(tenths) + "s";
}

void set_level(level minimum)
{
	std::lock_guard lock(log_mutex);
	minimum_level = minimum;
}

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
		{group::nft_script, "Every nft script run and its result (Linux)"},
		{group::nfq, "NFQUEUE queue lifecycle, verdicts, and errors (Linux)"},
		{group::nfq_packet, "Every packet queued, accepted, or dropped by NFQUEUE (Linux)"},
		{group::nfq_filter, "Capture filter compilation to nftables rules (Linux)"},
		{group::nfq_monitor, "NFQUEUE and nftables health sampling (Linux)"},
		{group::backend, "Packet backend internals"},
		{group::http, "HTTPS requests"},
		{group::packet, "All per-packet profile traffic"},
		{group::packet_recv, "Packets received by a profile"},
		{group::packet_send, "Packets sent or flushed by a profile"},
		{group::packet_drop, "Packets dropped by a profile"},
		{group::discovery, "Server discovery lifecycle and decisions"},
		{group::discovery_stats, "Periodic server discovery capture totals"},
		{group::discovery_packet, "Every packet seen by server discovery"},
		{group::forwarded, "Forwarded address discovery windows and results"},
		{group::forwarded_packet, "Every packet seen by forwarded address discovery"},
		{group::region, "Server region lookups"},
		{group::region_client, "Client region lookup"},
		{group::enforcement, "Region enforcement decisions"},
		{group::enforcement_packet, "Every packet delayed or sent by region enforcement"},
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
	if (!groups_configured.load(std::memory_order_acquire))
		return true;

	const std::string name = group_name;
	std::lock_guard	  lock(group_mutex);
	bool			  enabled	  = true;
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

static void write_impl(const char* group_name, level message_level, const char* color, const char* format, va_list arguments)
{
	std::lock_guard lock(log_mutex);
	if (static_cast<int>(message_level) > static_cast<int>(minimum_level))
		return;

	char message[max_log_message];
	std::vsnprintf(message, sizeof(message), format, arguments);

	clear_status_line();
	if (group_name != nullptr && show_groups.load())
		std::printf("%s[%s] [%s] %s\033[0m\n", color, level_name(message_level), group_name, message);
	else
		std::printf("%s[%s] %s\033[0m\n", color, level_name(message_level), message);
	if (!status_line.empty())
		print_status_block(status_line, status_right_line);
	std::fflush(stdout);
}

void write(level message_level, const char* format, ...)
{
	va_list arguments;
	va_start(arguments, format);
	write_impl(nullptr, message_level, level_color(message_level), format, arguments);
	va_end(arguments);
}

void write_group(const char* group_name, level message_level, const char* format, ...)
{
	va_list arguments;
	va_start(arguments, format);
	write_impl(group_name, message_level, level_color(message_level), format, arguments);
	va_end(arguments);
}

void write_styled_group(const char* group_name, style message_style, const char* format, ...)
{
	va_list arguments;
	va_start(arguments, format);
	write_impl(group_name, level::info, style_color(message_style), format, arguments);
	va_end(arguments);
}

void set_show_groups(bool show)
{
	show_groups.store(show);
}

void write_styled(style message_style, const char* format, ...)
{
	va_list arguments;
	va_start(arguments, format);
	write_impl(nullptr, level::info, style_color(message_style), format, arguments);
	va_end(arguments);
}

void set_status(const std::string& status)
{
	set_status(status, {});
}

void set_status(const std::string& status, const std::string& right_status)
{
	std::lock_guard lock(log_mutex);
	print_status_block(status, right_status);
	status_line		  = status;
	status_right_line = right_status;
	std::fflush(stdout);
}

void set_extra_status(const std::vector<std::string>& lines)
{
	std::lock_guard lock(log_mutex);
	if (lines == extra_status_lines)
		return;
	// The block is redrawn by the next set_status(); wipe it first so a changed line count leaves nothing behind.
	if (lines.size() != extra_status_lines.size())
		clear_status_line();
	extra_status_lines = lines;
	std::fflush(stdout);
}

void clear_status()
{
	std::lock_guard lock(log_mutex);
	clear_status_line();
	extra_status_lines.clear();
	status_line.clear();
	status_right_line.clear();
	std::printf("\r\033[2K");
	std::fflush(stdout);
}

}  // namespace logging
