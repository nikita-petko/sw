#ifndef LOG_H_
#define LOG_H_

#include <string>
#include <vector>
#include <cstdint>

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
std::string format_duration(std::uint64_t duration_ms);
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
/// Sets the lines shown below the persistent status line; an empty list removes them. Takes effect on the next set_status().
void set_extra_status(const std::vector<std::string>& lines);
/// Clears the persistent status line.
void clear_status();

/// Log groups subdivide chatty output so a single source can be muted without lowering the log level.
/// Names are dotted; a child (such as "discovery.packet") can be toggled on its own, while toggling its
/// parent (such as "discovery") affects every child that has no rule of its own.
/// Muting a group hides its debug and info messages only; warnings and errors are always written.
/// Every group is listed in the registry returned by groups(), which also tracks per-level message counts.
namespace group {
inline constexpr const char* startup			 = "startup";			  ///< Startup banner, loaded profile listing, and shutdown.
inline constexpr const char* config			 = "config";			  ///< Command line and profile configuration parsing and validation.
inline constexpr const char* server			 = "server";			  ///< Server list and server selection.
inline constexpr const char* pcap				 = "pcap";				  ///< PCAP file capture.
inline constexpr const char* report			 = "report";			  ///< The state report printed with Tab.
inline constexpr const char* profile			 = "profile";			  ///< Profile activation, setup, and teardown.
inline constexpr const char* input				 = "input";				  ///< Keyboard input.
inline constexpr const char* backend			 = "backend";			  ///< Packet backend internals.
inline constexpr const char* http				 = "http";				  ///< HTTPS requests.
inline constexpr const char* packet				 = "packet";			  ///< All per-packet profile traffic.
inline constexpr const char* packet_recv		 = "packet.recv";		  ///< Packets received by a profile.
inline constexpr const char* packet_send		 = "packet.send";		  ///< Packets sent or flushed by a profile.
inline constexpr const char* packet_drop		 = "packet.drop";		  ///< Packets dropped by a profile.
inline constexpr const char* discovery			 = "discovery";			  ///< Server discovery lifecycle and decisions.
inline constexpr const char* discovery_stats	 = "discovery.stats";	  ///< Periodic server discovery capture totals.
inline constexpr const char* discovery_packet	 = "discovery.packet";	  ///< Every packet seen by server discovery.
inline constexpr const char* forwarded			 = "forwarded";			  ///< Forwarded address discovery windows and results.
inline constexpr const char* forwarded_packet	 = "forwarded.packet";	  ///< Every packet seen by forwarded address discovery.
inline constexpr const char* region				 = "region";			  ///< Server region lookups.
inline constexpr const char* region_client		 = "region.client";		  ///< Client region lookup.
inline constexpr const char* enforcement		 = "enforcement";		  ///< Region enforcement decisions.
inline constexpr const char* enforcement_packet	 = "enforcement.packet";  ///< Every packet delayed or sent by region enforcement.
}  // namespace group

/// A registered log group.
struct group_info
{
	const char* name;		 ///< Dotted group name, as accepted by set_groups().
	const char* description; ///< One-line summary of what the group logs.
};

/// Message counts for one group since startup, indexed like groups().
struct group_counts
{
	std::uint64_t by_level[4] = {}; ///< Messages written, indexed by level (error, warn, info, debug).
	std::uint64_t muted		  = 0;	///< Debug and info messages dropped because the group is muted.

	std::uint64_t written() const { return by_level[0] + by_level[1] + by_level[2] + by_level[3]; }
};

/// Returns the registry of every known log group.
const std::vector<group_info>& groups();
/// Returns a snapshot of the message counts of every group, in the same order as groups().
std::vector<group_counts> group_stats();
/// Applies a comma-separated list of group rules, e.g. "-discovery.packet,-packet". A bare or "+"-prefixed name
/// enables a group, a "-"-prefixed name disables it, and "all" matches every group and discards all earlier rules.
/// The most specific rule wins. Rules from repeated calls accumulate.
/// Returns false and describes the problem in error when a name is unknown; no rules are applied in that case.
bool set_groups(const std::string& spec, std::string& error);
/// Returns whether debug and info messages in the given group are currently written. Every group is enabled by default.
bool group_enabled(const char* group_name);
/// Counts a message in the given group and returns whether it should be written, i.e. it passes the minimum
/// level and its group is not muted. Used by the LOG_*_GROUP macros so muted messages never evaluate their arguments.
bool group_accepts(const char* group_name, level message_level);

} // namespace logging

// Every translation unit that logs declares its default group once with LOG_DEFAULT_GROUP(...); the plain
// LOG_* macros use it, while the *_GROUP variants name a group explicitly. Arguments are not evaluated when the
// message is muted or below the minimum level.
#define LOG_DEFAULT_GROUP(group_name)                                                              \
	namespace                                                                                      \
	{                                                                                              \
	[[maybe_unused]] constexpr const char* log_default_group = group_name;                         \
	}
#define LOG_GROUP_IMPL(group_name, message_level, message, ...)                                    \
	do                                                                                             \
	{                                                                                              \
		if (logging::group_accepts(group_name, message_level))                                     \
			logging::write(message_level, message, ##__VA_ARGS__);                                 \
	} while (0)
#define LOG_STYLED_GROUP_IMPL(group_name, message_style, message, ...)                             \
	do                                                                                             \
	{                                                                                              \
		if (logging::group_accepts(group_name, logging::level::info))                              \
			logging::write_styled(message_style, message, ##__VA_ARGS__);                          \
	} while (0)

#define LOG_ERROR_GROUP(group_name, message, ...) LOG_GROUP_IMPL(group_name, logging::level::error, message, ##__VA_ARGS__)
#define LOG_WARN_GROUP(group_name, message, ...) LOG_GROUP_IMPL(group_name, logging::level::warn, message, ##__VA_ARGS__)
#define LOG_INFO_GROUP(group_name, message, ...) LOG_GROUP_IMPL(group_name, logging::level::info, message, ##__VA_ARGS__)
#define LOG_ACTIVATE_GROUP(group_name, message, ...) LOG_STYLED_GROUP_IMPL(group_name, logging::style::activate, message, ##__VA_ARGS__)
#define LOG_DEACTIVATE_GROUP(group_name, message, ...) LOG_STYLED_GROUP_IMPL(group_name, logging::style::deactivate, message, ##__VA_ARGS__)
#define LOG_SERVER_GROUP(group_name, message, ...) LOG_STYLED_GROUP_IMPL(group_name, logging::style::server, message, ##__VA_ARGS__)
#define LOG_REGION_GROUP(group_name, message, ...) LOG_STYLED_GROUP_IMPL(group_name, logging::style::region, message, ##__VA_ARGS__)
#define LOG_DETAIL_GROUP(group_name, message, ...) LOG_STYLED_GROUP_IMPL(group_name, logging::style::detail, message, ##__VA_ARGS__)

#define LOG_ERROR(message, ...) LOG_ERROR_GROUP(log_default_group, message, ##__VA_ARGS__)
#define LOG_WARN(message, ...) LOG_WARN_GROUP(log_default_group, message, ##__VA_ARGS__)
#define LOG_INFO(message, ...) LOG_INFO_GROUP(log_default_group, message, ##__VA_ARGS__)
#define LOG_ACTIVATE(message, ...) LOG_ACTIVATE_GROUP(log_default_group, message, ##__VA_ARGS__)
#define LOG_DEACTIVATE(message, ...) LOG_DEACTIVATE_GROUP(log_default_group, message, ##__VA_ARGS__)
#define LOG_SERVER(message, ...) LOG_SERVER_GROUP(log_default_group, message, ##__VA_ARGS__)
#define LOG_REGION(message, ...) LOG_REGION_GROUP(log_default_group, message, ##__VA_ARGS__)
#define LOG_DETAIL(message, ...) LOG_DETAIL_GROUP(log_default_group, message, ##__VA_ARGS__)
#ifdef NDEBUG
#define LOG_DEBUG(...) ((void)0)
#define LOG_DEBUG_GROUP(...) ((void)0)
#else
#define LOG_DEBUG(message, ...) LOG_DEBUG_GROUP(log_default_group, message, ##__VA_ARGS__)
#define LOG_DEBUG_GROUP(group_name, message, ...) LOG_GROUP_IMPL(group_name, logging::level::debug, message, ##__VA_ARGS__)
#endif

#endif // LOG_H_
