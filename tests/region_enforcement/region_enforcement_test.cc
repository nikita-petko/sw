// Unit tests for region enforcement (src/packet_engine/region_enforcement.cc): which servers get delayed, the enforced-region
// cycle, delayed release and flushing, and probe detection. The engine runs against the in-memory backend from tests/engine.
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include "support/test.h"

#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT

#include "fakes.h"
#include "log.h"
#include "packet_engine.h"
#include "support/capture.h"
#include "support/packets.h"

namespace {
using namespace packets;
using fakes::wait_until;

constexpr uint16_t kProbePort = 55002;

ProfileOptions profile(const char* name)
{
	ProfileOptions options;
	options.name = name;
	return options;
}

ServerOptions server(const char* address, const char* name = "", const char* group = "")
{
	return {address, *name == '\0' ? address : name, group};
}

/// An engine configuration with region enforcement on. `servers` default to two EU servers and one NA server.
PacketEngineOptions enforcement_options(std::vector<ServerOptions> servers = {server("34.0.0.1", "eu1", "EU"), server("34.0.0.2", "eu2", "EU"), server("35.0.0.1", "na1", "NA")},
										uint16_t probe_port = kProbePort, bool enabled = true)
{
	PacketEngineOptions options;
	options.profiles								  = {profile("A")};
	options.servers									  = std::move(servers);
	options.features.region_enforcement.enabled		  = enabled;
	options.features.region_enforcement.probe_port	  = probe_port;
	return options;
}

std::string logged(const std::function<void()>& body)
{
	logging::set_level(logging::level::info);
	const std::string text = test::capture_stdout(body);
	logging::set_level(logging::level::error);
	return text;
}

size_t occurrences(const std::string& text, const std::string& needle)
{
	size_t count = 0;
	for (size_t at = text.find(needle); at != std::string::npos; at = text.find(needle, at + needle.size()))
		++count;
	return count;
}

const std::string kOutsideEu	 = "region_enforcement:35.0.0.1,:55002";
const std::string kOutsideNa	 = "region_enforcement:34.0.0.1,34.0.0.2,:55002";

Bytes syn_to(std::array<uint8_t, 4> server_address)
{
	return ipv4_packet(kTcp, tcp_segment(40000, kProbePort, 1, 0, kSyn), {10, 0, 0, 5}, server_address);
}

Bytes syn_ack_from(std::array<uint8_t, 4> server_address)
{
	return ipv4_packet(kTcp, tcp_segment(kProbePort, 40000, 1, 2, kSyn | kAck), server_address, {10, 0, 0, 5});
}

void test_regions_come_from_server_groups()
{
	fakes::reset();
	PacketEngine engine(enforcement_options());
	CHECK((engine.configured_regions() == std::vector<std::string>{"EU", "NA"}));
	CHECK(engine.current_enforced_region() == "none");
}

void test_regions_fall_back_to_server_names()
{
	fakes::reset();
	PacketEngine ungrouped(enforcement_options({server("1.1.1.1", "alpha"), server("2.2.2.2", "beta"), server("3.3.3.3"), server("4.4.4.4", "alpha")}));
	CHECK((ungrouped.configured_regions() == std::vector<std::string>{"alpha", "beta", "3.3.3.3"}));

	// As soon as one server has a group, only groups count as regions.
	PacketEngine mixed(enforcement_options({server("1.1.1.1", "alpha", "EU"), server("2.2.2.2", "beta")}));
	CHECK((mixed.configured_regions() == std::vector<std::string>{"EU"}));

	PacketEngine none(enforcement_options({}));
	CHECK(none.configured_regions().empty());
}

void test_cycling_the_enforced_region()
{
	fakes::reset();
	PacketEngine engine(enforcement_options());
	engine.cycle_enforced_region(1);
	CHECK(engine.current_enforced_region() == "EU");
	engine.cycle_enforced_region(1);
	CHECK(engine.current_enforced_region() == "NA");
	engine.cycle_enforced_region(1);
	CHECK(engine.current_enforced_region() == "none");
	engine.cycle_enforced_region(-1);
	CHECK(engine.current_enforced_region() == "NA");
	engine.cycle_enforced_region(-1);
	engine.cycle_enforced_region(-1);
	CHECK(engine.current_enforced_region() == "none");
	engine.cycle_enforced_region(0);
	CHECK(engine.current_enforced_region() == "none");

	PacketEngine empty(enforcement_options({}));
	empty.cycle_enforced_region(1);
	CHECK(empty.current_enforced_region() == "none");
	CHECK(fakes::channels().size() == 4);  // the channels opened by the EU, NA, NA and EU steps of the first engine; "none" and the empty engine open none
}

void test_servers_outside_the_enforced_region_are_captured()
{
	fakes::reset();
	PacketEngine engine(enforcement_options());
	CHECK(fakes::channels().empty());

	engine.cycle_enforced_region(1);
	CHECK(fakes::channels().size() == 1);
	const auto eu = fakes::channel(0);
	CHECK(eu && eu->filter == kOutsideEu);
	if (!eu)
		return;
	CHECK(eu->options.priority == -100 && !eu->options.sniff);

	engine.cycle_enforced_region(1);
	CHECK(fakes::channels().size() == 2);
	const auto na = fakes::channel(1);
	CHECK(na && na->filter == kOutsideNa);
	CHECK(wait_until([&] { return eu->closed(); }));

	engine.cycle_enforced_region(1);  // back to "none": nothing is delayed
	CHECK(fakes::channels().size() == 2);
	CHECK(wait_until([&] { return na->closed(); }));
}

void test_servers_without_a_group_are_delayed_by_name()
{
	fakes::reset();
	PacketEngine engine(enforcement_options({server("34.0.0.1", "eu1", "EU"), server("34.0.0.2", "eu2", "EU"), server("9.9.9.9", "solo")}));
	engine.cycle_enforced_region(1);
	const auto channel = fakes::channel(0);
	CHECK(channel && channel->filter == "region_enforcement:9.9.9.9,:55002");
}

void test_no_channel_when_nothing_would_be_delayed()
{
	fakes::reset();
	PacketEngine engine(enforcement_options({server("34.0.0.1", "eu1", "EU"), server("34.0.0.2", "eu2", "EU")}));
	engine.cycle_enforced_region(1);
	CHECK(engine.current_enforced_region() == "EU");
	CHECK(fakes::channels().empty());
}

void test_disabled_enforcement_opens_nothing()
{
	fakes::reset();
	PacketEngine engine(enforcement_options({server("34.0.0.1", "eu1", "EU"), server("35.0.0.1", "na1", "NA")}, kProbePort, false));
	CHECK(!engine.is_region_enforcement_enabled() && engine.region_enforcement_status().empty());
	engine.cycle_enforced_region(1);
	engine.start_workers();
	CHECK(fakes::channels().empty());

	PacketEngine without_port(enforcement_options({server("34.0.0.1", "eu1", "EU"), server("35.0.0.1", "na1", "NA")}, 0, true));
	CHECK(without_port.is_region_enforcement_enabled());
	without_port.cycle_enforced_region(1);
	without_port.start_workers();
	CHECK(fakes::channels().empty());
}

void test_starting_the_workers_opens_the_probe_channel()
{
	fakes::reset();
	PacketEngine engine(enforcement_options());
	CHECK(engine.is_region_enforcement_enabled());
	CHECK(engine.region_enforcement_status() == "Waiting for probes...");
	engine.start_workers();
	CHECK(fakes::channels().size() == 1);
	const auto probe = fakes::channel_with_filter("syn:55002");
	CHECK(probe && probe->options.sniff && probe->options.include_forward);
}

void test_probe_detection_logs_each_server_once_per_window()
{
	fakes::reset();
	PacketEngine engine(enforcement_options());
	engine.start_workers();
	engine.cycle_enforced_region(1);  // enforce EU
	const auto probe = fakes::channel_with_filter("syn:55002");
	CHECK(probe != nullptr);
	if (!probe)
		return;

	// Packets that are not SYNs or not even IP do not start a window.
	probe->inject(tcp_packet(1, 1, kAck));
	probe->inject({0x90, 1, 2, 3});
	CHECK(wait_until([&] { return probe->consumed() == 2; }));
	std::this_thread::sleep_for(std::chrono::milliseconds(50));
	CHECK(engine.region_enforcement_status() == "Waiting for probes...");

	const std::string log = logged([&] {
		probe->inject(syn_to({34, 0, 0, 1}), 0, true);		// a probe sent to an EU server
		probe->inject(syn_ack_from({34, 0, 0, 1}), 0, false);	// the same server answering: not announced again
		probe->inject(syn_to({34, 0, 0, 2}), 0, true);		// another EU server in the same window
		probe->inject(syn_to({35, 0, 0, 1}), 0, true);		// outside the enforced region: only a debug message
		probe->inject(syn_to({8, 8, 8, 8}), 0, true);		// not a configured server
		wait_until([&] { return probe->consumed() == 7; });
		std::this_thread::sleep_for(std::chrono::milliseconds(200));
	});
	CHECK(occurrences(log, "Region probe detected on port 55002") == 1);
	CHECK(occurrences(log, "Server 'eu1 [34.0.0.1]' within enforced region 'EU' was probed") == 1);
	CHECK(occurrences(log, "Server 'eu2 [34.0.0.2]' within enforced region 'EU' was probed") == 1);
	CHECK(log.find("na1") == std::string::npos && log.find("8.8.8.8") == std::string::npos);

	// The next check is about five minutes away.
	const std::string status = engine.region_enforcement_status();
	CHECK(status.rfind("~5m", 0) == 0 || status.rfind("~4m", 0) == 0);
}

void test_delayed_packets_are_released_after_about_a_second()
{
	fakes::reset();
	PacketEngine engine(enforcement_options());
	engine.cycle_enforced_region(1);
	const auto channel = fakes::channel_with_filter(kOutsideEu);
	CHECK(channel != nullptr);
	if (!channel)
		return;

	std::vector<std::vector<uint8_t>> packets;
	for (int64_t id = 1; id <= 3; ++id)
	{
		packets.push_back(tcp_packet(static_cast<uint32_t>(id), 1, kAck | kPsh, 55002, 40000));
		channel->inject(packets.back(), id, false, 4);
	}
	CHECK(wait_until([&] { return channel->consumed() == 3; }));
	const auto injected = std::chrono::steady_clock::now();
	CHECK(channel->sent_count() == 0);

	CHECK(wait_until([&] { return channel->sent_count() == 3; }, std::chrono::milliseconds(6000)));
	const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - injected).count();
	CHECK(elapsed >= 900);

	auto sent = channel->sent_packets();
	std::sort(sent.begin(), sent.end(), [](const fakes::SentPacket& left, const fakes::SentPacket& right) { return left.meta.timestamp < right.meta.timestamp; });
	CHECK(sent.size() == 3);
	for (size_t index = 0; index < sent.size() && index < packets.size(); ++index)
	{
		CHECK(sent[index].data == packets[index]);
		CHECK(sent[index].meta.timestamp == static_cast<int64_t>(index + 1) && sent[index].meta.if_index == 4);
	}
}

void test_changing_the_region_releases_delayed_packets_at_once()
{
	fakes::reset();
	PacketEngine engine(enforcement_options());
	engine.cycle_enforced_region(1);
	const auto eu = fakes::channel_with_filter(kOutsideEu);
	if (!eu)
		return;
	eu->inject(tcp_packet(1, 1, kAck | kPsh), 1);
	eu->inject(tcp_packet(2, 1, kAck | kPsh), 2);
	CHECK(wait_until([&] { return eu->consumed() == 2; }));
	CHECK(eu->sent_count() == 0);

	engine.cycle_enforced_region(1);
	// Far sooner than the minimum one-second delay: the old queue is flushed, not waited out.
	CHECK(wait_until([&] { return eu->sent_count() == 2; }, std::chrono::milliseconds(800)));
	CHECK(eu->closed());
	CHECK(fakes::channel_with_filter(kOutsideNa) != nullptr);
}

void test_stopping_the_workers_flushes_and_closes_every_channel()
{
	fakes::reset();
	PacketEngine engine(enforcement_options());
	engine.start_workers();
	engine.cycle_enforced_region(1);
	const auto enforcement = fakes::channel_with_filter(kOutsideEu);
	const auto probe	   = fakes::channel_with_filter("syn:55002");
	if (!enforcement || !probe)
		return;
	enforcement->inject(tcp_packet(1, 1, kAck | kPsh), 1);
	CHECK(wait_until([&] { return enforcement->consumed() == 1; }));

	engine.stop_workers();
	CHECK(enforcement->sent_count() == 1 && enforcement->closed());
	CHECK(probe->closed());
}
}  // namespace

int main(int argc, char** argv)
{
	logging::set_level(logging::level::error);
	static const test::TestCase cases[] = {
		{"regions_come_from_server_groups", test_regions_come_from_server_groups},
		{"regions_fall_back_to_server_names", test_regions_fall_back_to_server_names},
		{"cycling_the_enforced_region", test_cycling_the_enforced_region},
		{"servers_outside_the_enforced_region_are_captured", test_servers_outside_the_enforced_region_are_captured},
		{"servers_without_a_group_are_delayed_by_name", test_servers_without_a_group_are_delayed_by_name},
		{"no_channel_when_nothing_would_be_delayed", test_no_channel_when_nothing_would_be_delayed},
		{"disabled_enforcement_opens_nothing", test_disabled_enforcement_opens_nothing},
		{"starting_the_workers_opens_the_probe_channel", test_starting_the_workers_opens_the_probe_channel},
		{"probe_detection_logs_each_server_once_per_window", test_probe_detection_logs_each_server_once_per_window},
		{"delayed_packets_are_released_after_about_a_second", test_delayed_packets_are_released_after_about_a_second},
		{"changing_the_region_releases_delayed_packets_at_once", test_changing_the_region_releases_delayed_packets_at_once},
		{"stopping_the_workers_flushes_and_closes_every_channel", test_stopping_the_workers_flushes_and_closes_every_channel},
	};
	return test::run_tests("region_enforcement", cases, argc, argv);
}

#else

int main()
{
	std::puts("region_enforcement: skipped, feature not compiled in");
	return 0;
}

#endif
