#ifndef OPTIONS_INTERNAL_H_
#define OPTIONS_INTERNAL_H_

#include <cstdint>
#include <optional>
#include <string>

#include "packet_engine.h"

/// Internal pieces of the configuration loader shared by the files in src/options/.
namespace config {

/// Virtual-key code reserved for printing the packet engine state; profiles cannot use it.
inline constexpr int kTabKey = 0x09;

/// Position in the configuration file, used to report errors.
struct Context
{
	const char* path;
	int			line;
};

/// Logs "Invalid <what> in <path> at line <n><detail>" and returns false.
bool invalid(const Context& context, const std::string& what, const char* detail = "");

std::string trim(std::string value);
/// Removes one pair of matching single or double quotes around the value.
std::string unquote(std::string value);

std::optional<bool>							parse_bool(const std::string& value);
std::optional<ProfileActivationMode>		parse_activation_mode(const std::string& value);
std::optional<ProfileKeyMode>				parse_key_mode(const std::string& value);
std::optional<CaptureOptions::ClientAddressEnforcement> parse_client_address_enforcement(const std::string& value);
std::optional<CaptureOptions::ServerDirection> parse_server_direction(const std::string& value);
std::optional<PacketDelayMode>				parse_delay_mode(const std::string& value);
std::optional<RetransmissionMode>			parse_retransmission_mode(const std::string& value);
std::optional<SubsequentPacketHoldMode>		parse_subsequent_packet_hold_mode(const std::string& value);
std::optional<RatioSelection>				parse_ratio_selection(const std::string& value);
std::optional<PacketGroupOrder>				parse_packet_group_order(const std::string& value);
std::optional<DesyncCountdownDisplay>		parse_countdown_display(const std::string& value);
/// Parses a key name (single character, alt, ctrl, shift, space, VK_* names) or a number into a virtual-key code.
std::optional<int>							parse_key(std::string value);

/// Parses the whole text as a number within [min, max]; nullopt when it is not a number or out of range.
std::optional<unsigned long>	  parse_ulong(const std::string& text, unsigned long min, unsigned long max);
std::optional<unsigned long long> parse_ullong(const std::string& text, unsigned long long min);
std::optional<long>				  parse_long(const std::string& text, long min, long max);

/// Loads a profiles YAML file (replacing the profiles, servers and features in `options`) and validates it.
bool load_profiles(const char* path, PacketEngineOptions& options);
/// Checks the loaded profiles and features for consistency.
bool validate_profiles(const char* path, const PacketEngineOptions& options);
/// Checks that every capture filter the engine will build is accepted by the active backend.
bool validate_filters(const char* path, const PacketEngineOptions& options);

}  // namespace config

#endif
