// Unit tests for the human-readable option formatting used in the loaded-profile listing (src/format.cc).
#include <string>

#include "format.h"
#include "log.h"
#include "platform.h"
#include "support/test.h"

namespace {
void test_format_key()
{
	CHECK(format_key(platform::key::space) == "space");
	CHECK(format_key(platform::key::alt) == "alt");
	CHECK(format_key(platform::key::ctrl) == "ctrl");
	CHECK(format_key(platform::key::shift) == "shift");
	CHECK(format_key('X') == "X");
	CHECK(format_key('~') == "~");
	CHECK(format_key(platform::key::backspace) == "8");
	CHECK(format_key(0x7F) == "127");
	CHECK(format_key(platform::key::none) == "-1");
}

void test_format_keys()
{
	ProfileOptions profile;
	profile.keys = {platform::key::ctrl, 'Q'};
	CHECK(format_keys(profile) == "ctrl+Q");
	profile.key_mode = ProfileKeyMode::oneof;
	CHECK(format_keys(profile) == "ctrl or Q");
	profile.keys = {'Z'};
	CHECK(format_keys(profile) == "Z");
	profile.keys.clear();
	CHECK(format_keys(profile).empty());
}

void test_format_disable_targets()
{
	ProfileOptions profile;
	CHECK(format_disable_targets(profile) == "none");
	profile.disables = {"*"};
	CHECK(format_disable_targets(profile) == "*");
	profile.disables = {"A", "B", "C"};
	CHECK(format_disable_targets(profile) == "A, B, C");
}

void test_enum_names()
{
	CHECK(std::string(format_mode(ProfileActivationMode::toggle)) == "toggle");
	CHECK(std::string(format_mode(ProfileActivationMode::hold)) == "hold");
	CHECK(std::string(format_mode(ProfileActivationMode::period)) == "period");
	CHECK(std::string(format_key_mode(ProfileKeyMode::oneof)) == "oneof");
	CHECK(std::string(format_key_mode(ProfileKeyMode::combination)) == "combination");
	CHECK(std::string(format_retransmission_mode(RetransmissionMode::only_seq)) == "only_seq");
	CHECK(std::string(format_retransmission_mode(RetransmissionMode::both)) == "both");
	CHECK(std::string(format_subsequent_packet_hold_mode(SubsequentPacketHoldMode::ack_only)) == "ack_only");
	CHECK(std::string(format_subsequent_packet_hold_mode(SubsequentPacketHoldMode::seq_ack)) == "seq_ack");
	CHECK(std::string(format_ratio_selection(RatioSelection::random)) == "random");
	CHECK(std::string(format_packet_group_order(PacketGroupOrder::lifo)) == "lifo");
}

void test_format_capture_options()
{
	ProfileOptions profile;
	CHECK(format_capture_options(profile) == "default");
	profile.capture_options.sniff	= true;
	profile.capture_options.forward = false;
	CHECK(format_capture_options(profile) == "sniff=true, forward=false");
	profile.capture_options.outbound					  = true;
	profile.capture_options.client_address_enforcement	  = CaptureOptions::ClientAddressEnforcement::both;
	profile.capture_options.server_direction			  = CaptureOptions::ServerDirection::source;
	CHECK(format_capture_options(profile) == "sniff=true, forward=false, outbound=true, client_addr=both, server_dir=source");
}

void test_delay_description()
{
	ProfileOptions profile;
	profile.delay_ms = 500;
	CHECK(format_delay_action(profile) == "Delay each by" && format_delay_value(profile) == "500ms");

	profile.delay_mode = PacketDelayMode::send_all_after_delay;
	CHECK(format_delay_action(profile) == "after" && format_delay_value(profile) == "500ms");
	profile.delay_ms = 0;
	CHECK(format_delay_action(profile) == "Send all after" && format_delay_value(profile) == "profile is deactivated");

	profile.delay_mode = PacketDelayMode::drop_and_send;
	CHECK(format_delay_action(profile) == "Drop, then send after" && format_delay_value(profile) == "profile is deactivated");

	profile.delay_mode = PacketDelayMode::drop;
	CHECK(format_delay_action(profile) == "Drop packets" && format_delay_value(profile) == "immediately");

	profile.delay_mode = PacketDelayMode::hold_and_send;
	profile.delay_ms   = 1500;
	CHECK(format_delay_action(profile) == "Hold, then send" && format_delay_value(profile) == "1.5s");

	profile.delay_mode = PacketDelayMode::hold_until_deactivation;
	CHECK(format_delay_action(profile) == "Hold, then send on deactivation");

	profile.delay_mode = PacketDelayMode::drop_until_toggle;
	CHECK(format_delay_action(profile) == "Drop, hold, then send after");

	profile.delay_mode = PacketDelayMode::from_timestamp;
	profile.delay_ms   = 0;
	CHECK(format_delay_action(profile) == "Delay each by" && format_delay_value(profile) == "profile is deactivated");
}

void test_ratio_and_group_description()
{
	ProfileOptions profile;
	profile.delay_mode	  = PacketDelayMode::ratio;
	profile.ratio		  = 10;
	profile.ratio_percent = true;
	profile.delay_ms	  = 200;
	CHECK(format_delay_action(profile) == "Send 10% per" && format_delay_value(profile) == "200ms");
	profile.ratio_percent = false;
	profile.ratio		  = 3;
	CHECK(format_delay_action(profile) == "Send 3 packets per");

	profile.delay_mode	= PacketDelayMode::packet_group_send;
	profile.group_count = 4;
	profile.group_order = PacketGroupOrder::random;
	CHECK(format_delay_action(profile) == "Capture 4 packet groups");
	CHECK(format_delay_value(profile) == "in random order, one group per activation press");
}

void test_format_duration()
{
	CHECK(logging::format_duration(0) == "0ms");
	CHECK(logging::format_duration(999) == "999ms");
	CHECK(logging::format_duration(1000) == "1s");
	CHECK(logging::format_duration(1500) == "1.5s");
	CHECK(logging::format_duration(1960) == "2s");
	CHECK(logging::format_duration(59999) == "60s");
	CHECK(logging::format_duration(60000) == "1m");
	CHECK(logging::format_duration(61000) == "1m 1s");
	CHECK(logging::format_duration(3600000) == "60m");
}
}  // namespace

int main(int argc, char** argv)
{
	static const test::TestCase cases[] = {
		{"format_key", test_format_key},
		{"format_keys", test_format_keys},
		{"format_disable_targets", test_format_disable_targets},
		{"enum_names", test_enum_names},
		{"format_capture_options", test_format_capture_options},
		{"delay_description", test_delay_description},
		{"ratio_and_group_description", test_ratio_and_group_description},
		{"format_duration", test_format_duration},
	};
	return test::run_tests("format", cases, argc, argv);
}
