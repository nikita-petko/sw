// Unit tests for the verdict tracker (backends/nfqueue/verdict_tracker.*): which waiting packets one batch verdict may release.
#include <cstdint>
#include <vector>

#include "support/test.h"
#include "verdict_tracker.h"

namespace {
using Ids = std::vector<uint32_t>;

void fill(nfq::VerdictTracker& tracker, uint32_t first, uint32_t count, uint32_t mark = 0)
{
	for (uint32_t index = 0; index < count; ++index)
		tracker.add(first + index, mark);
}

void test_releasing_everything_is_one_run()
{
	nfq::VerdictTracker tracker;
	fill(tracker, 10, 5);
	const auto run = tracker.plan({10, 11, 12, 13, 14});
	CHECK(run.ids == (Ids{10, 11, 12, 13, 14}));
	CHECK(run.last_id == 14);
	CHECK(tracker.size() == 5);	 // planning does not consume anything
}

void test_the_order_of_the_request_does_not_matter()
{
	nfq::VerdictTracker tracker;
	fill(tracker, 1, 4);
	const auto run = tracker.plan({4, 2, 1, 3});
	CHECK(run.ids == (Ids{1, 2, 3, 4}));
	CHECK(run.last_id == 4);
}

void test_a_packet_held_for_another_reason_ends_the_run()
{
	nfq::VerdictTracker tracker;
	fill(tracker, 1, 6);
	// Packet 3 is not part of the release, so a batch up to a later id would wrongly release it.
	const auto run = tracker.plan({1, 2, 4, 5, 6});
	CHECK(run.ids == (Ids{1, 2}));
	CHECK(run.last_id == 2);
}

void test_the_run_must_start_at_the_oldest_waiting_packet()
{
	nfq::VerdictTracker tracker;
	fill(tracker, 1, 5);
	CHECK(tracker.plan({2, 3, 4, 5}).ids.empty());
	// Packets that already got their verdict no longer block the run.
	CHECK(tracker.remove(1));
	CHECK(tracker.plan({2, 3, 4, 5}).ids == (Ids{2, 3, 4, 5}));
	CHECK(!tracker.remove(1));
}

void test_unknown_ids_and_small_requests_never_qualify()
{
	nfq::VerdictTracker tracker;
	CHECK(tracker.plan({1, 2}).ids.empty());
	fill(tracker, 5, 3);
	CHECK(tracker.plan({}).ids.empty());
	CHECK(tracker.plan({5}).ids.empty());
	CHECK(tracker.plan({100, 101}).ids.empty());
	CHECK(tracker.plan({5, 100}).ids.empty());
}

void test_packets_with_different_marks_are_not_batched_together()
{
	nfq::VerdictTracker tracker;
	tracker.add(1, 0x10);
	tracker.add(2, 0x10);
	tracker.add(3, 0x20);
	tracker.add(4, 0x10);
	const auto run = tracker.plan({1, 2, 3, 4});
	CHECK(run.ids == (Ids{1, 2}));
	CHECK(run.mark == 0x10);
	CHECK(run.last_id == 2);
}

void test_ids_wrap_around_without_losing_order()
{
	nfq::VerdictTracker tracker;
	tracker.add(0xFFFFFFFEu, 0);
	tracker.add(0xFFFFFFFFu, 0);
	tracker.add(0, 0);
	tracker.add(1, 0);
	const auto run = tracker.plan({1, 0, 0xFFFFFFFFu, 0xFFFFFFFEu});
	CHECK(run.ids == (Ids{0xFFFFFFFEu, 0xFFFFFFFFu, 0, 1}));
	CHECK(run.last_id == 1);

	// A packet from before the wrap that is still waiting keeps its place at the front.
	nfq::VerdictTracker straggler;
	straggler.add(0xFFFFFFF0u, 0);
	straggler.add(0xFFFFFFFFu, 0);
	straggler.add(2, 0);
	CHECK(straggler.plan({2, 0xFFFFFFFFu}).ids.empty());
	CHECK(straggler.plan({0xFFFFFFF0u, 0xFFFFFFFFu, 2}).ids == (Ids{0xFFFFFFF0u, 0xFFFFFFFFu, 2}));
	CHECK(straggler.remove(0xFFFFFFF0u));
	CHECK(straggler.plan({2, 0xFFFFFFFFu}).ids == (Ids{0xFFFFFFFFu, 2}));
}

void test_late_arrivals_from_before_a_wrap_sort_first()
{
	nfq::VerdictTracker tracker;
	tracker.add(0xFFFFFFFDu, 0);
	tracker.add(1, 0);
	tracker.add(0xFFFFFFFFu, 0);  // delivered out of order, but older than id 1
	const auto run = tracker.plan({1, 0xFFFFFFFFu, 0xFFFFFFFDu});
	CHECK(run.ids == (Ids{0xFFFFFFFDu, 0xFFFFFFFFu, 1}));
}

void test_a_repeated_id_replaces_the_earlier_entry()
{
	nfq::VerdictTracker tracker;
	tracker.add(7, 1);
	tracker.add(7, 2);
	CHECK(tracker.size() == 1);
	CHECK(tracker.remove(7));
	CHECK(tracker.size() == 0);
}
}  // namespace

int main(int argc, char** argv)
{
	static const test::TestCase cases[] = {
		{"releasing_everything_is_one_run", test_releasing_everything_is_one_run},
		{"the_order_of_the_request_does_not_matter", test_the_order_of_the_request_does_not_matter},
		{"a_packet_held_for_another_reason_ends_the_run", test_a_packet_held_for_another_reason_ends_the_run},
		{"the_run_must_start_at_the_oldest_waiting_packet", test_the_run_must_start_at_the_oldest_waiting_packet},
		{"unknown_ids_and_small_requests_never_qualify", test_unknown_ids_and_small_requests_never_qualify},
		{"packets_with_different_marks_are_not_batched_together", test_packets_with_different_marks_are_not_batched_together},
		{"ids_wrap_around_without_losing_order", test_ids_wrap_around_without_losing_order},
		{"late_arrivals_from_before_a_wrap_sort_first", test_late_arrivals_from_before_a_wrap_sort_first},
		{"a_repeated_id_replaces_the_earlier_entry", test_a_repeated_id_replaces_the_earlier_entry},
	};
	return test::run_tests("verdict_tracker", cases, argc, argv);
}
