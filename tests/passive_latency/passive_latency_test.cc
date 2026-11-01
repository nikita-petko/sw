// Unit tests for passive latency (src/packet_engine/passive_latency.cc): channel setup, the delayed release path,
// overflow fail-open, teardown flushing, and ordering. The engine runs against the in-memory backend from tests/engine.
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "support/test.h"

#ifdef LAGSW_FEATURE_PASSIVE_LATENCY

#include "fakes.h"
#include "log.h"
#include "packet_engine.h"
#include "support/packets.h"

namespace {
using namespace packets;
using fakes::wait_until;

ProfileOptions profile(const char* name)
{
	ProfileOptions options;
	options.name = name;
	return options;
}

/// An engine configuration with passive latency on and a single profile (the engine requires at least one).
PacketEngineOptions passive_options(int32_t delay_ms, int32_t max_delay_ms = 0, bool enabled = true)
{
	PacketEngineOptions options;
	options.profiles							   = {profile("A")};
	options.global_filter						   = "tcp";
	options.features.passive_latency.enabled	   = enabled;
	options.features.passive_latency.delay_ms	   = delay_ms;
	options.features.passive_latency.max_delay_ms = max_delay_ms;
	return options;
}

void test_disabled_passive_latency_opens_nothing()
{
	fakes::reset();
	PacketEngine engine(passive_options(50, 0, false));
	engine.start_workers();
	CHECK(fakes::channels().empty());
	CHECK(!engine.is_passive_latency_enabled());
	engine.stop_workers();
}

void test_starting_the_workers_opens_the_passive_channel()
{
	fakes::reset();
	PacketEngine engine(passive_options(50));
	engine.start_workers();
	CHECK(engine.is_passive_latency_enabled());
	const auto channel = fakes::channel_with_filter("tcp");
	CHECK(channel != nullptr);
	CHECK(channel->options.priority == 100);
	engine.stop_workers();
}

void test_custom_filter_overrides_global_filter()
{
	fakes::reset();
	PacketEngineOptions options				 = passive_options(50);
	options.features.passive_latency.filter = "udp";
	PacketEngine engine(options);
	engine.start_workers();
	CHECK(fakes::channel_with_filter("udp") != nullptr);
	CHECK(fakes::channel_with_filter("tcp") == nullptr);
	engine.stop_workers();
}

void test_delayed_packets_are_released_after_about_the_configured_delay()
{
	fakes::reset();
	PacketEngine engine(passive_options(200));
	engine.start_workers();
	const auto channel = fakes::channel_with_filter("tcp");

	channel->inject(tcp_packet(1, 1, kAck), 1);
	CHECK(wait_until([&] { return channel->consumed() == 1; }));
	CHECK(channel->sent_count() == 0);

	const auto injected = std::chrono::steady_clock::now();
	CHECK(wait_until([&] { return channel->sent_count() == 1; }, std::chrono::milliseconds(2000)));
	const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - injected).count();
	CHECK(elapsed >= 150 && elapsed <= 1000);

	engine.stop_workers();
}

void test_order_is_preserved_for_equal_delays()
{
	fakes::reset();
	PacketEngine engine(passive_options(80));
	engine.start_workers();
	const auto channel = fakes::channel_with_filter("tcp");

	channel->inject(tcp_packet(1, 1, kAck), 1);
	channel->inject(tcp_packet(2, 1, kAck), 2);
	channel->inject(tcp_packet(3, 1, kAck), 3);
	CHECK(wait_until([&] { return channel->sent_count() == 3; }, std::chrono::milliseconds(2000)));

	const auto sent = channel->sent_packets();
	CHECK(sent.size() == 3);
	CHECK(sent[0].meta.timestamp == 1 && sent[1].meta.timestamp == 2 && sent[2].meta.timestamp == 3);

	engine.stop_workers();
}

void test_overflow_releases_packets_immediately()
{
	fakes::reset();
	PacketEngineOptions options						   = passive_options(5000);
	options.features.passive_latency.max_queued_packets = 1;
	PacketEngine engine(options);
	engine.start_workers();
	const auto channel = fakes::channel_with_filter("tcp");

	channel->inject(tcp_packet(1, 1, kAck), 1);
	CHECK(wait_until([&] { return channel->consumed() == 1; }));
	// Give the recv thread time to queue the first packet before the second arrives and overflows it.
	channel->inject(tcp_packet(2, 1, kAck), 2);
	CHECK(wait_until([&] { return channel->sent_count() >= 1; }, std::chrono::milliseconds(2000)));

	engine.stop_workers();
}

void test_stopping_the_workers_flushes_and_closes_the_channel()
{
	fakes::reset();
	PacketEngine engine(passive_options(5000));
	engine.start_workers();
	const auto channel = fakes::channel_with_filter("tcp");

	channel->inject(tcp_packet(1, 1, kAck), 1);
	channel->inject(tcp_packet(2, 1, kAck), 2);
	CHECK(wait_until([&] { return channel->consumed() == 2; }));

	engine.stop_workers();
	CHECK(channel->sent_count() == 2);
	CHECK(channel->closed());
}

void test_passive_channel_is_distinct_from_profile_channels()
{
	fakes::reset();
	// Profiles default to toggle activation, so no profile channel opens here; the passive channel must still be its own,
	// separately-filtered channel rather than reusing or aliasing a profile's "profile#<index>" filter.
	PacketEngine engine(passive_options(50));
	engine.start_workers();
	const auto passive = fakes::channel_with_filter("tcp");
	CHECK(passive != nullptr);
	CHECK(fakes::channel_with_filter("profile#0") == nullptr);
	engine.stop_workers();
}
}  // namespace

int main(int argc, char** argv)
{
	logging::set_level(logging::level::error);
	static const test::TestCase cases[] = {
		{"disabled_passive_latency_opens_nothing", test_disabled_passive_latency_opens_nothing},
		{"starting_the_workers_opens_the_passive_channel", test_starting_the_workers_opens_the_passive_channel},
		{"custom_filter_overrides_global_filter", test_custom_filter_overrides_global_filter},
		{"delayed_packets_are_released_after_about_the_configured_delay", test_delayed_packets_are_released_after_about_the_configured_delay},
		{"order_is_preserved_for_equal_delays", test_order_is_preserved_for_equal_delays},
		{"overflow_releases_packets_immediately", test_overflow_releases_packets_immediately},
		{"stopping_the_workers_flushes_and_closes_the_channel", test_stopping_the_workers_flushes_and_closes_the_channel},
		{"passive_channel_is_distinct_from_profile_channels", test_passive_channel_is_distinct_from_profile_channels},
	};
	return test::run_tests("passive_latency", cases, argc, argv);
}

#else

int main()
{
	std::puts("passive_latency: skipped, feature not compiled in");
	return 0;
}

#endif
