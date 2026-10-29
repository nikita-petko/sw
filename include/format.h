#ifndef FORMAT_H_
#define FORMAT_H_

#include <string>

#include "options.h"

/// Human-readable text for options and enums, used when listing loaded profiles.
const char* format_mode(ProfileActivationMode mode);
const char* format_key_mode(ProfileKeyMode mode);
std::string format_key(int key);
/// The activation keys joined by " or " (oneof) or "+" (combination).
std::string format_keys(const ProfileOptions& profile);
/// The names of the profiles this profile disables, or "none".
std::string format_disable_targets(const ProfileOptions& profile);
const char* format_retransmission_mode(RetransmissionMode mode);
const char* format_subsequent_packet_hold_mode(SubsequentPacketHoldMode mode);
const char* format_ratio_selection(RatioSelection selection);
const char* format_packet_group_order(PacketGroupOrder order);
/// The explicitly configured capture options as "key=value" pairs, or "default".
std::string format_capture_options(const ProfileOptions& profile);

#endif
