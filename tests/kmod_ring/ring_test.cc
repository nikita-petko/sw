// Unit tests of the user-space consumer of the swdivert ring (kmod/include/swdivert_ring.h) against a fake producer that
// follows the same protocol as kmod/swdivert/ring.c. They need neither root nor the module.
#include <atomic>
#include <cstdint>
#include <cstring>
#include <thread>
#include <vector>

#include "support/test.h"
#include "swdivert_ring.h"

namespace {
constexpr uint32_t kSlots		= 64;
constexpr uint32_t kSlotBytes	= 128;
constexpr uint32_t kHeaderBytes = 4096;

// The memory the kernel would map: header + slots, and the consumer page
struct FakeRing
{
	alignas(4096) unsigned char memory[kHeaderBytes + kSlots * kSlotBytes] = {};
	swdiv_cons cons_page												   = {};
	uint32_t   prod														   = 0;

	swdiv_ring_hdr* header() { return reinterpret_cast<swdiv_ring_hdr*>(memory); }

	FakeRing(uint32_t start = 0)
	{
		header()->abi		 = SWDIVERT_ABI_VERSION;
		header()->slots		 = kSlots;
		header()->slot_bytes = kSlotBytes;
		prod				 = start;
		header()->prod		 = start;
		cons_page.cons		 = start;
	}

	swdiv_ring_view view()
	{
		swdiv_ring_view view;
		swdiv_ring_view_init(&view, memory, kHeaderBytes, &cons_page);
		return view;
	}

	// ring.c's swdiv_ring_push(): full when prod - cons reaches the slot count
	bool push(uint32_t value, uint32_t len = 4)
	{
		const uint32_t used = prod - __atomic_load_n(&cons_page.cons, __ATOMIC_RELAXED);
		if (used >= kSlots)
			return false;
		auto* slot = reinterpret_cast<swdiv_slot_hdr*>(memory + kHeaderBytes + static_cast<size_t>(prod & (kSlots - 1)) * kSlotBytes);
		std::memcpy(reinterpret_cast<unsigned char*>(slot) + SWDIVERT_SLOT_HDR_BYTES, &value, sizeof(value));
		slot->len	 = len;
		slot->caplen = sizeof(value);
		++prod;
		__atomic_store_n(&header()->prod, prod, __ATOMIC_RELEASE);
		return true;
	}
};

uint32_t value_of(const swdiv_slot_hdr* slot)
{
	uint32_t value;
	std::memcpy(&value, swdiv_slot_data(slot), sizeof(value));
	return value;
}

void test_an_empty_ring_has_nothing_available()
{
	FakeRing		ring;
	swdiv_ring_view view = ring.view();
	CHECK(swdiv_ring_avail(&view) == 0);
}

void test_packets_are_consumed_in_order_and_released()
{
	FakeRing		ring;
	swdiv_ring_view view = ring.view();
	for (uint32_t i = 0; i < 10; ++i)
		CHECK(ring.push(100 + i));
	CHECK(swdiv_ring_avail(&view) == 10);
	for (uint32_t i = 0; i < 10; ++i)
		CHECK(value_of(swdiv_ring_slot(&view, i)) == 100 + i);
	swdiv_ring_release(&view, 10);
	CHECK(swdiv_ring_avail(&view) == 0);
	CHECK(ring.cons_page.cons == 10);
}

void test_a_full_ring_refuses_until_the_reader_releases()
{
	FakeRing		ring;
	swdiv_ring_view view = ring.view();
	for (uint32_t i = 0; i < kSlots; ++i)
		CHECK(ring.push(i));
	CHECK(!ring.push(999));
	swdiv_ring_release(&view, 1);
	CHECK(ring.push(1000));
	CHECK(value_of(swdiv_ring_slot(&view, kSlots - 1)) == 1000);
}

void test_counters_and_slots_wrap_around()
{
	FakeRing		ring(0xFFFFFFF0u);
	swdiv_ring_view view = ring.view();
	for (uint32_t round = 0; round < 8; ++round)
	{
		for (uint32_t i = 0; i < 16; ++i)
			CHECK(ring.push(round * 16 + i));
		CHECK(swdiv_ring_avail(&view) == 16);
		for (uint32_t i = 0; i < 16; ++i)
			CHECK(value_of(swdiv_ring_slot(&view, i)) == round * 16 + i);
		swdiv_ring_release(&view, 16);
	}
	CHECK(ring.prod == 0xFFFFFFF0u + 128u);	 // the 32-bit counter crossed zero
}

void test_a_corrupt_capture_length_cannot_leave_the_slot()
{
	FakeRing ring;
	ring.push(1);
	auto* slot			 = reinterpret_cast<swdiv_slot_hdr*>(ring.memory + kHeaderBytes);
	slot->caplen		 = 0xFFFFFFFFu;
	swdiv_ring_view view = ring.view();
	CHECK(swdiv_slot_caplen(&view, swdiv_ring_slot(&view, 0)) == kSlotBytes - SWDIVERT_SLOT_HDR_BYTES);
}

void test_a_reader_attached_late_starts_from_the_consumer_index()
{
	FakeRing ring(500);
	ring.push(7);
	swdiv_ring_view view = ring.view();
	CHECK(swdiv_ring_avail(&view) == 1);
	CHECK(value_of(swdiv_ring_slot(&view, 0)) == 7);
}

void test_a_concurrent_producer_never_shows_a_torn_or_reordered_packet()
{
	FakeRing		   ring;
	swdiv_ring_view	   view	  = ring.view();
	constexpr uint32_t kTotal = 200000;
	std::atomic<bool>  producing{true};
	std::thread		   producer([&] {
		for (uint32_t i = 0; i < kTotal;)
			if (ring.push(i))
				++i;
		producing = false;
	});
	uint32_t		   next = 0;
	while (next < kTotal)
	{
		const uint32_t avail = swdiv_ring_avail(&view);
		for (uint32_t i = 0; i < avail; ++i, ++next)
			CHECK(value_of(swdiv_ring_slot(&view, i)) == next);
		if (avail)
			swdiv_ring_release(&view, avail);
		else if (!producing.load() && swdiv_ring_avail(&view) == 0)
			break;
	}
	producer.join();
	CHECK(next == kTotal);
}
}  // namespace

int main(int argc, char** argv)
{
	static const test::TestCase cases[] = {
		{"an_empty_ring_has_nothing_available", test_an_empty_ring_has_nothing_available},
		{"packets_are_consumed_in_order_and_released", test_packets_are_consumed_in_order_and_released},
		{"a_full_ring_refuses_until_the_reader_releases", test_a_full_ring_refuses_until_the_reader_releases},
		{"counters_and_slots_wrap_around", test_counters_and_slots_wrap_around},
		{"a_corrupt_capture_length_cannot_leave_the_slot", test_a_corrupt_capture_length_cannot_leave_the_slot},
		{"a_reader_attached_late_starts_from_the_consumer_index", test_a_reader_attached_late_starts_from_the_consumer_index},
		{"a_concurrent_producer_never_shows_a_torn_or_reordered_packet", test_a_concurrent_producer_never_shows_a_torn_or_reordered_packet},
	};
	return test::run_tests("kmod_ring", cases, argc, argv);
}
