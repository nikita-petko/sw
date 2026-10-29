#include "internal.h"

#include <cctype>
#include <string>
#include <utility>

#include "log.h"

namespace config {
namespace {
template <typename T, size_t N>
std::optional<T> lookup(const std::string& value, const std::pair<const char*, T> (&table)[N])
{
	for (const auto& [name, result] : table)
		if (value == name)
			return result;
	return std::nullopt;
}
}  // namespace

bool invalid(const Context& context, const std::string& what, const char* detail)
{
	LOG_ERROR("Invalid %s in %s at line %d%s", what.c_str(), context.path, context.line, detail);
	return false;
}

std::string trim(std::string value)
{
	const auto first = value.find_first_not_of(" \t\r\n");
	if (first == std::string::npos)
		return {};
	const auto last = value.find_last_not_of(" \t\r\n");
	return value.substr(first, last - first + 1);
}

std::string unquote(std::string value)
{
	if (value.size() >= 2 && ((value.front() == '\'' && value.back() == '\'') || (value.front() == '"' && value.back() == '"')))
		return value.substr(1, value.size() - 2);
	return value;
}

std::optional<bool> parse_bool(const std::string& value)
{
	static const std::pair<const char*, bool> table[] = {{"true", true}, {"false", false}};
	return lookup(value, table);
}

std::optional<ProfileActivationMode> parse_activation_mode(const std::string& value)
{
	static const std::pair<const char*, ProfileActivationMode> table[] = {
		{"toggle", ProfileActivationMode::toggle}, {"hold", ProfileActivationMode::hold}, {"period", ProfileActivationMode::period}};
	return lookup(value, table);
}

std::optional<ProfileKeyMode> parse_key_mode(const std::string& value)
{
	static const std::pair<const char*, ProfileKeyMode> table[] = {
		{"oneof", ProfileKeyMode::oneof}, {"combination", ProfileKeyMode::combination}};
	return lookup(value, table);
}

std::optional<CaptureOptions::ClientAddressEnforcement> parse_client_address_enforcement(const std::string& value)
{
	using Enforcement									   = CaptureOptions::ClientAddressEnforcement;
	static const std::pair<const char*, Enforcement> table[] = {{"none", Enforcement::none},
																{"source", Enforcement::source},
																{"destination", Enforcement::destination},
																{"both", Enforcement::both}};
	return lookup(value, table);
}

std::optional<CaptureOptions::ServerDirection> parse_server_direction(const std::string& value)
{
	using Direction									   = CaptureOptions::ServerDirection;
	static const std::pair<const char*, Direction> table[] = {
		{"source", Direction::source}, {"destination", Direction::destination}, {"both", Direction::both}};
	return lookup(value, table);
}

std::optional<PacketDelayMode> parse_delay_mode(const std::string& value)
{
	static const std::pair<const char*, PacketDelayMode> table[] = {
		{"from_timestamp", PacketDelayMode::from_timestamp},
		{"send_all_after_delay", PacketDelayMode::send_all_after_delay},
		{"ratio", PacketDelayMode::ratio},
		{"drop", PacketDelayMode::drop},
		{"drop_and_send", PacketDelayMode::drop_and_send},
		{"hold_and_send", PacketDelayMode::hold_and_send},
		{"drop_until_toggle", PacketDelayMode::drop_until_toggle},
		{"hold_until_deactivation", PacketDelayMode::hold_until_deactivation},
		{"packet_group_send", PacketDelayMode::packet_group_send}};
	return lookup(value, table);
}

std::optional<RetransmissionMode> parse_retransmission_mode(const std::string& value)
{
	static const std::pair<const char*, RetransmissionMode> table[] = {{"none", RetransmissionMode::none},
																	   {"only_seq", RetransmissionMode::only_seq},
																	   {"only_ack", RetransmissionMode::only_ack},
																	   {"both", RetransmissionMode::both}};
	return lookup(value, table);
}

std::optional<SubsequentPacketHoldMode> parse_subsequent_packet_hold_mode(const std::string& value)
{
	static const std::pair<const char*, SubsequentPacketHoldMode> table[] = {{"none", SubsequentPacketHoldMode::none},
																			 {"seq_only", SubsequentPacketHoldMode::seq_only},
																			 {"ack_only", SubsequentPacketHoldMode::ack_only},
																			 {"seq_ack", SubsequentPacketHoldMode::seq_ack}};
	return lookup(value, table);
}

std::optional<RatioSelection> parse_ratio_selection(const std::string& value)
{
	static const std::pair<const char*, RatioSelection> table[] = {
		{"first", RatioSelection::first}, {"last", RatioSelection::last}, {"random", RatioSelection::random}};
	return lookup(value, table);
}

std::optional<PacketGroupOrder> parse_packet_group_order(const std::string& value)
{
	static const std::pair<const char*, PacketGroupOrder> table[] = {
		{"fifo", PacketGroupOrder::fifo}, {"lifo", PacketGroupOrder::lifo}, {"random", PacketGroupOrder::random}};
	return lookup(value, table);
}

std::optional<DesyncCountdownDisplay> parse_countdown_display(const std::string& value)
{
	static const std::pair<const char*, DesyncCountdownDisplay> table[] = {{"alongside", DesyncCountdownDisplay::alongside},
																		   {"override", DesyncCountdownDisplay::override_activation},
																		   {"until_reactivated", DesyncCountdownDisplay::until_reactivated}};
	return lookup(value, table);
}

std::optional<int> parse_key(std::string value)
{
	value = unquote(trim(value));
	if (value.size() == 1)
		return static_cast<unsigned char>(std::toupper(static_cast<unsigned char>(value[0])));
	if (value == "tab" || value == "VK_TAB")
		return kTabKey;
	if (value == "space" || value == "VK_SPACE")
		return 0x20;
	if (value == "alt" || value == "menu" || value == "VK_MENU")
		return 0x12;
	if (value == "ctrl" || value == "control" || value == "VK_CONTROL")
		return 0x11;
	if (value == "shift" || value == "VK_SHIFT")
		return 0x10;
	try
	{
		size_t	  consumed = 0;
		const int key	   = std::stoi(value, &consumed, 0);
		return consumed == value.size() ? std::optional<int>(key) : std::nullopt;
	}
	catch (...)
	{
		return std::nullopt;
	}
}

std::optional<unsigned long> parse_ulong(const std::string& text, unsigned long min, unsigned long max)
{
	try
	{
		size_t			   consumed = 0;
		const unsigned long value	= std::stoul(text, &consumed);
		if (consumed != text.size() || value < min || value > max)
			return std::nullopt;
		return value;
	}
	catch (...)
	{
		return std::nullopt;
	}
}

std::optional<unsigned long long> parse_ullong(const std::string& text, unsigned long long min)
{
	try
	{
		size_t					 consumed = 0;
		const unsigned long long value	  = std::stoull(text, &consumed);
		if (consumed != text.size() || value < min)
			return std::nullopt;
		return value;
	}
	catch (...)
	{
		return std::nullopt;
	}
}

std::optional<long> parse_long(const std::string& text, long min, long max)
{
	try
	{
		size_t	   consumed = 0;
		const long value	= std::stol(text, &consumed);
		if (consumed != text.size() || value < min || value > max)
			return std::nullopt;
		return value;
	}
	catch (...)
	{
		return std::nullopt;
	}
}

}  // namespace config
