#include <log.h>

#include <cstdarg>
#include <cstdio>
#include <mutex>
#include <string>
#include <utility>

#include "internal.h"

namespace logging_detail {
logging::level minimum_level = logging::level::info;
std::mutex log_mutex;
std::atomic<bool> show_groups{false};
bool capturing = false;
std::vector<std::string> captured;
}

using namespace logging_detail;

namespace {
constexpr size_t max_log_message = 1024;
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
}

namespace logging {

static void write_impl(const char* group_name, level message_level, const char* color, const char* format, va_list arguments)
{
	std::lock_guard lock(log_mutex);
	if (static_cast<int>(message_level) > static_cast<int>(minimum_level))
		return;

	char message[max_log_message];
	std::vsnprintf(message, sizeof(message), format, arguments);
	if (capturing)
	{
		if (message_level == level::error)
			captured.emplace_back(message);
		return;
	}

	std::string line = std::string(color) + "[" + level_name(message_level) + "] ";
	if (group_name != nullptr && show_groups.load())
		line += std::string("[") + group_name + "] ";
	line += message;
	line += "\033[0m\n";
	if (suspended)
	{
		if (suspended_backlog.size() < max_suspended_backlog)
			suspended_backlog.push_back(std::move(line));
		return;
	}

	clear_status_line();
	std::fputs(line.c_str(), stdout);
	std::fputs(banner_sequence(false).c_str(), stdout);
	if (!status_line.empty())
		print_status_block(status_line, status_right_line);
	std::fflush(stdout);
}

}

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

}  // namespace logging
