#include "format.h"

#include "platform.h"

const char* format_mode(ProfileActivationMode mode)
{
	return mode == ProfileActivationMode::hold ? "hold" : mode == ProfileActivationMode::period ? "period" : "toggle";
}

const char* format_key_mode(ProfileKeyMode mode)
{
	return mode == ProfileKeyMode::oneof ? "oneof" : "combination";
}

std::string format_key(int key)
{
	if (key == platform::key::space)
		return "space";
	if (key == platform::key::alt)
		return "alt";
	if (key == platform::key::ctrl)
		return "ctrl";
	if (key == platform::key::shift)
		return "shift";
	if (key >= 0x20 && key <= 0x7E)
		return std::string(1, static_cast<char>(key));
	return std::to_string(key);
}

std::string format_keys(const ProfileOptions& profile)
{
	std::string result;
	const char* separator = profile.key_mode == ProfileKeyMode::oneof ? " or " : "+";
	for (const int key : profile.keys)
	{
		if (!result.empty())
			result += separator;
		result += format_key(key);
	}
	return result;
}

std::string format_disable_targets(const ProfileOptions& profile)
{
	if (profile.disables.empty())
		return "none";
	std::string result;
	for (size_t index = 0; index < profile.disables.size(); ++index)
	{
		if (index != 0)
			result += ", ";
		result += profile.disables[index];
	}
	return result;
}

const char* format_retransmission_mode(RetransmissionMode mode)
{
	switch (mode)
	{
		case RetransmissionMode::none:
			return "none";
		case RetransmissionMode::only_seq:
			return "only_seq";
		case RetransmissionMode::only_ack:
			return "only_ack";
		case RetransmissionMode::both:
			return "both";
	}
	return "unknown";
}

const char* format_subsequent_packet_hold_mode(SubsequentPacketHoldMode mode)
{
	switch (mode)
	{
		case SubsequentPacketHoldMode::none:
			return "none";
		case SubsequentPacketHoldMode::seq_only:
			return "seq_only";
		case SubsequentPacketHoldMode::ack_only:
			return "ack_only";
		case SubsequentPacketHoldMode::seq_ack:
			return "seq_ack";
	}
	return "unknown";
}

const char* format_ratio_selection(RatioSelection selection)
{
	switch (selection)
	{
		case RatioSelection::first:
			return "first";
		case RatioSelection::last:
			return "last";
		case RatioSelection::random:
			return "random";
	}
	return "unknown";
}

const char* format_packet_group_order(PacketGroupOrder order)
{
	switch (order)
	{
		case PacketGroupOrder::fifo:
			return "fifo";
		case PacketGroupOrder::lifo:
			return "lifo";
		case PacketGroupOrder::random:
			return "random";
	}
	return "unknown";
}

std::string format_capture_options(const ProfileOptions& profile)
{
	std::string result;
	const auto	append = [&](const char* label, const std::string& value) {
		if (!result.empty())
			result += ", ";
		result += label;
		result += "=";
		result += value;
	};
	if (profile.capture_options.sniff)
		append("sniff", profile.capture_options.sniff.value() ? "true" : "false");
	if (profile.capture_options.forward)
		append("forward", profile.capture_options.forward.value() ? "true" : "false");
	if (profile.capture_options.outbound)
		append("outbound", profile.capture_options.outbound.value() ? "true" : "false");
	if (profile.capture_options.client_address_enforcement)
	{
		static const char* client_enforcement[] = {"none", "source", "destination", "both"};
		append("client_addr", client_enforcement[static_cast<int>(profile.capture_options.client_address_enforcement.value())]);
	}
	if (profile.capture_options.server_direction)
	{
		static const char* server_direction[] = {"source", "destination", "both"};
		append("server_dir", server_direction[static_cast<int>(profile.capture_options.server_direction.value())]);
	}
	return result.empty() ? "default" : result;
}
