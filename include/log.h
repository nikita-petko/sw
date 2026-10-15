#ifndef LOG_H_
#define LOG_H_

#include <string>

namespace logging {

enum class level
{
	error,
	warn,
	info,
	debug,
};

// Purely cosmetic: selects the text color of an info-level message.
enum class style
{
	normal,
	activate,
	deactivate,
	server,
	region,
	detail,
};

std::string format_duration(uint64_t duration_ms);
void set_level(level minimum_level);
void write(level message_level, const char* format, ...);
void write_styled(style message_style, const char* format, ...);
void set_status(const std::string& status);
void set_status(const std::string& status, const std::string& right_status);
void clear_status();

} // namespace logging

#define LOG_ERROR(message, ...) logging::write(logging::level::error, message, ##__VA_ARGS__)
#define LOG_WARN(message, ...) logging::write(logging::level::warn, message, ##__VA_ARGS__)
#define LOG_INFO(message, ...) logging::write(logging::level::info, message, ##__VA_ARGS__)
#define LOG_ACTIVATE(message, ...) logging::write_styled(logging::style::activate, message, ##__VA_ARGS__)
#define LOG_DEACTIVATE(message, ...) logging::write_styled(logging::style::deactivate, message, ##__VA_ARGS__)
#define LOG_SERVER(message, ...) logging::write_styled(logging::style::server, message, ##__VA_ARGS__)
#define LOG_REGION(message, ...) logging::write_styled(logging::style::region, message, ##__VA_ARGS__)
#define LOG_DETAIL(message, ...) logging::write_styled(logging::style::detail, message, ##__VA_ARGS__)
#ifdef NDEBUG
#define LOG_DEBUG(...) ((void)0)
#else
#define LOG_DEBUG(message, ...) logging::write(logging::level::debug, message, ##__VA_ARGS__)
#endif

#endif // LOG_H_
