#ifndef LOG_H_
#define LOG_H_

#include <string>

namespace logging {

/// Logging severity, ordered from most to least severe.
enum class level
{
	error, ///< Error conditions.
	warn,  ///< Potentially problematic conditions.
	info,  ///< Normal operational messages.
	debug, ///< Diagnostic messages.
};

/// Purely cosmetic style used to color an info-level message.
enum class style
{
	normal,     ///< Default info-message color.
	activate,   ///< Profile activation.
	deactivate, ///< Profile deactivation.
	server,     ///< Server selection or discovery.
	region,     ///< Region selection or discovery.
	detail,     ///< Supplementary status information.
};

/// Formats a millisecond duration as a compact human-readable string.
std::string format_duration(uint64_t duration_ms);
/// Sets the minimum severity written by the logging functions.
void set_level(level minimum_level);
/// Writes a printf-style message at the given severity.
void write(level message_level, const char* format, ...);
/// Writes a printf-style info message using the given visual style.
void write_styled(style message_style, const char* format, ...);
/// Displays a persistent status line, clearing any right-aligned status text.
void set_status(const std::string& status);
/// Displays a persistent status line with optional right-aligned text.
void set_status(const std::string& status, const std::string& right_status);
/// Clears the persistent status line.
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
