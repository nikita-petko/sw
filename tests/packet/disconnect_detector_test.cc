// Unit tests for the server-discovery disconnect detector (src/packet_engine/disconnect_detector.h).
#include "packet_engine/disconnect_detector.h"
#include "support/test.h"

namespace {
using Event = DisconnectDetector::Event;

void warm_up(DisconnectDetector& detector, uint64_t packets)
{
	for (int index = 0; index < 4; ++index)
		CHECK(detector.observe(packets) == Event::none);
}

void test_detects_drop_and_recovery()
{
	DisconnectDetector detector(80);
	warm_up(detector, 100);
	CHECK(detector.observe(50) == Event::none);
	CHECK(detector.observe(5) == Event::disconnected);
	CHECK(detector.disconnected());
	CHECK(detector.observe(0) == Event::none);
	CHECK(detector.observe(90) == Event::reconnected);
	CHECK(!detector.disconnected());
}

void test_needs_history_and_traffic()
{
	DisconnectDetector fresh(80);
	CHECK(fresh.observe(100) == Event::none);
	CHECK(fresh.observe(0) == Event::none);

	DisconnectDetector quiet(80);
	warm_up(quiet, 5);
	CHECK(quiet.observe(0) == Event::none);
}

void test_disabled_and_reset()
{
	DisconnectDetector disabled(0);
	warm_up(disabled, 100);
	CHECK(disabled.observe(0) == Event::none);

	DisconnectDetector detector(80);
	warm_up(detector, 100);
	detector.reset();
	CHECK(detector.observe(0) == Event::none);
}
}  // namespace

int main(int argc, char** argv)
{
	static const test::TestCase cases[] = {
		{"detects_drop_and_recovery", test_detects_drop_and_recovery},
		{"needs_history_and_traffic", test_needs_history_and_traffic},
		{"disabled_and_reset", test_disabled_and_reset},
	};
	return test::run_tests("disconnect_detector", cases, argc, argv);
}
