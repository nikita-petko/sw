#include <log.h>

#include <windows.h>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>

namespace {
constexpr size_t max_log_message = 1024;
logging::level	 minimum_level	 = logging::level::info;
std::mutex		 log_mutex;
std::string		 status_line;
std::string		 status_right_line;

void clear_status_line()
{
	if (!status_line.empty())
		std::printf("\r\033[2K");
}

int console_width()
{
	CONSOLE_SCREEN_BUFFER_INFO console_info;
	const HANDLE			   output = GetStdHandle(STD_OUTPUT_HANDLE);
	if (output == INVALID_HANDLE_VALUE || !GetConsoleScreenBufferInfo(output, &console_info))
		return 0;
	return console_info.srWindow.Right - console_info.srWindow.Left + 1;
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

void write(level message_level, const char* format, ...)
{
	std::lock_guard lock(log_mutex);
	if (static_cast<int>(message_level) > static_cast<int>(minimum_level))
		return;

	char	message[max_log_message];
	va_list arguments;
	va_start(arguments, format);
	std::vsnprintf(message, sizeof(message), format, arguments);
	va_end(arguments);

	clear_status_line();
	std::printf("%s[%s] %s\033[0m\n", level_color(message_level), level_name(message_level), message);
	if (!status_line.empty())
		print_status_line(status_line, status_right_line);
	std::fflush(stdout);
}

void set_status(const std::string& status)
{
	set_status(status, {});
}

void set_status(const std::string& status, const std::string& right_status)
{
	std::lock_guard lock(log_mutex);
	print_status_line(status, right_status);
	status_line		  = status;
	status_right_line = right_status;
	std::fflush(stdout);
}

void clear_status()
{
	std::lock_guard lock(log_mutex);
	clear_status_line();
	status_line.clear();
	status_right_line.clear();
	std::printf("\r\033[2K");
	std::fflush(stdout);
}

}  // namespace logging
