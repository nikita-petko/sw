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

std::string format_duration(uint64_t duration_ms);
void set_level(level minimum_level);
void write(level message_level, const char* format, ...);
void set_status(const std::string& status);
void clear_status();

} // namespace logging

#define LOG_ERROR(message, ...) logging::write(logging::level::error, message, ##__VA_ARGS__)
#define LOG_WARN(message, ...) logging::write(logging::level::warn, message, ##__VA_ARGS__)
#define LOG_INFO(message, ...) logging::write(logging::level::info, message, ##__VA_ARGS__)
#ifdef NDEBUG
#define LOG_DEBUG(...) ((void)0)
#else
#define LOG_DEBUG(message, ...) logging::write(logging::level::debug, message, ##__VA_ARGS__)
#endif

#endif // LOG_H_
