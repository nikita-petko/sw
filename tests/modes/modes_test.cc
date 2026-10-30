// Unit tests for the packet scheduling modes (src/modules/). Modes are driven directly with a fake clock: every call passes the
// current time in, nothing sleeps, and no capture backend is involved.
#include <algorithm>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "log.h"
#include "modules/packet_mode.h"
#include "support/packets.h"
#include "support/test.h"

namespace {
int checksum_calls = 0;
}

// The modes call back into the backend to repair checksums after editing a packet; count the calls instead.
namespace backend {
void calc_checksums(uint8_t*, uint32_t)
{
	++checksum_calls;
}
}  // namespace backend

namespace {
using namespace packets;
using Ids = std::vector<int64_t>;

constexpr uint64_t kForever = (std::numeric_limits<uint64_t>::max)() - 1;

ProfileOptions options_for(PacketDelayMode mode, int32_t delay_ms = 0)
{
	ProfileOptions options;
	options.name	   = "test";
	options.delay_mode = mode;
	options.delay_ms   = delay_ms;
	return options;
}

Ids ids_of(const std::vector<PacketNode*>& nodes)
{
	Ids ids;
	for (const PacketNode* node : nodes)
		ids.push_back(node->address->timestamp);
	return ids;
}

Ids sorted(Ids ids)
{
	std::sort(ids.begin(), ids.end());
	return ids;
}

/// One mode plus the queue it works on. Packets are identified by the capture timestamp stored in their metadata.
class Rig
{
public:
	explicit Rig(const ProfileOptions& options) : mode(create_packet_mode(options))
	{
		mode->set_discard_sink([this](const backend::PacketMeta& meta) { discarded.push_back(meta.timestamp); });
		mode->reset();
	}
	Rig(const Rig&)			   = delete;
	Rig& operator=(const Rig&) = delete;
	~Rig()
	{
		while (!queue.empty())
		{
			destroy_packet_node(queue.top());
			queue.pop();
		}
	}

	void feed(uint64_t now, int64_t id, const Bytes& packet)
	{
		backend::PacketMeta meta;
		meta.timestamp = id;
		mode->capture(packet.data(), static_cast<uint32_t>(packet.size()), meta, 0, now, next_order++, queue);
	}

	/// Feeds a TCP packet with a sequence number of its own.
	void feed(uint64_t now, int64_t id)
	{
		feed(now, id, tcp_packet(static_cast<uint32_t>(1000 + id), 1));
	}

	Ids release(uint64_t now) { return release_nodes(now, std::nullopt); }
	/// Releases like the engine does and then reports each packet as sent (or failed).
	Ids release_and_complete(uint64_t now, bool succeeded) { return release_nodes(now, succeeded); }

	Ids flush()
	{
		std::vector<PacketNode*> pending;
		mode->flush(queue, pending);
		const Ids ids = ids_of(pending);
		for (PacketNode* node : pending)
			destroy_packet_node(node);
		return ids;
	}

	std::unique_ptr<PacketMode> mode;
	PacketQueue					queue;
	Ids							discarded;

private:
	Ids release_nodes(uint64_t now, std::optional<bool> succeeded)
	{
		std::vector<PacketNode*> ready;
		mode->release(queue, now, ready);
		const Ids ids = ids_of(ready);
		for (PacketNode* node : ready)
		{
			if (succeeded)
				mode->packet_send_completed(*node, *succeeded);
			destroy_packet_node(node);
		}
		return ids;
	}

	uint64_t next_order = 0;
};

void test_factory_creates_every_mode()
{
	const PacketDelayMode all[] = {PacketDelayMode::from_timestamp, PacketDelayMode::send_all_after_delay, PacketDelayMode::ratio,
								   PacketDelayMode::drop,			PacketDelayMode::drop_and_send,		   PacketDelayMode::hold_and_send,
								   PacketDelayMode::drop_until_toggle, PacketDelayMode::hold_until_deactivation, PacketDelayMode::packet_group_send};
	for (const PacketDelayMode mode : all)
	{
		ProfileOptions options = options_for(mode);
		options.group_count	   = 1;
		CHECK(create_packet_mode(options) != nullptr);
	}

	bool threw = false;
	try
	{
		create_packet_mode(options_for(static_cast<PacketDelayMode>(99)));
	}
	catch (const std::logic_error&)
	{
		threw = true;
	}
	CHECK(threw);
}

void test_make_packet_node_copies_its_inputs()
{
	Bytes				packet = tcp_packet(5, 6);
	backend::PacketMeta meta;
	meta.outbound	= true;
	meta.if_index	= 7;
	meta.timestamp	= 42;
	meta.native[3]	= 9;
	PacketNode* node = make_packet_node(packet.data(), static_cast<uint32_t>(packet.size()), meta, 3, 11, 12);
	packet[0]		 = 0;
	meta.if_index	 = 0;

	CHECK(node->packet != packet.data() && node->packet[0] == 0x45);
	CHECK(node->length == packet.size());
	CHECK(node->address != &meta && node->address->outbound && node->address->if_index == 7 && node->address->timestamp == 42 && node->address->native[3] == 9);
	CHECK(node->profile == 3 && node->release_at == 11 && node->receive_order == 12);
	CHECK(!node->grouped && node->group_index == 0);
	destroy_packet_node(node);
	destroy_packet_node(nullptr);
}

void test_collect_due_packets_orders_by_release_then_receive()
{
	const Bytes			packet = tcp_packet(1, 1);
	backend::PacketMeta meta;
	PacketQueue			queue;
	const auto			add = [&](uint64_t release_at, uint64_t order, int64_t id) {
		   meta.timestamp = id;
		   queue.push(make_packet_node(packet.data(), static_cast<uint32_t>(packet.size()), meta, 0, release_at, order));
	};
	add(300, 1, 10);
	add(100, 2, 20);
	add(100, 1, 30);
	add(200, 5, 40);

	std::vector<PacketNode*> ready;
	collect_due_packets(queue, 99, ready);
	CHECK(ready.empty());
	collect_due_packets(queue, 250, ready);
	CHECK(ids_of(ready) == (Ids{30, 20, 40}));
	CHECK(queue.size() == 1);
	collect_due_packets(queue, 299, ready);
	CHECK(ready.size() == 3);
	collect_due_packets(queue, 300, ready);
	CHECK(ids_of(ready) == (Ids{30, 20, 40, 10}));
	CHECK(queue.empty());
	for (PacketNode* node : ready)
		destroy_packet_node(node);
}

void test_collect_due_packets_discards_malformed_entries()
{
	const Bytes			packet = tcp_packet(1, 1);
	backend::PacketMeta meta;
	PacketQueue			queue;
	PacketNode*			broken = make_packet_node(packet.data(), static_cast<uint32_t>(packet.size()), meta, 0, 1, 1);
	delete broken->address;
	broken->address = nullptr;
	queue.push(broken);
	meta.timestamp = 7;
	queue.push(make_packet_node(packet.data(), static_cast<uint32_t>(packet.size()), meta, 0, 500, 2));

	std::vector<PacketNode*> ready;
	collect_due_packets(queue, 100, ready);
	CHECK(ready.empty());
	CHECK(queue.size() == 1);
	collect_due_packets(queue, 500, ready);
	CHECK(ids_of(ready) == (Ids{7}));
	for (PacketNode* node : ready)
		destroy_packet_node(node);
}

void test_get_tcp_numbers()
{
	const Bytes tcp = tcp_packet(0xDEADBEEF, 0x01020304);
	uint32_t	sequence = 0, acknowledgment = 0;
	CHECK(get_tcp_numbers(tcp.data(), static_cast<uint32_t>(tcp.size()), sequence, acknowledgment));
	CHECK(sequence == 0xDEADBEEFu && acknowledgment == 0x01020304u);

	const Bytes udp = ipv4_packet(kUdp, udp_datagram(1, 2, 4));
	sequence = acknowledgment = 77;
	CHECK(!get_tcp_numbers(udp.data(), static_cast<uint32_t>(udp.size()), sequence, acknowledgment));
	CHECK(sequence == 77 && acknowledgment == 77);

	const Bytes garbage = {1, 2, 3};
	CHECK(!get_tcp_numbers(garbage.data(), static_cast<uint32_t>(garbage.size()), sequence, acknowledgment));
}

void test_from_timestamp_delays_each_packet()
{
	Rig rig(options_for(PacketDelayMode::from_timestamp, 100));
	rig.feed(1000, 1);
	rig.feed(1050, 2);
	rig.feed(1050, 3);
	CHECK(rig.release(1099).empty());
	CHECK(rig.release(1100) == (Ids{1}));
	CHECK(rig.release(1149).empty());
	CHECK(rig.release(1150) == (Ids{2, 3}));
	CHECK(rig.queue.empty() && rig.discarded.empty());
}

void test_from_timestamp_without_delay_holds_until_flush()
{
	for (const int32_t delay : {0, -5})
	{
		Rig rig(options_for(PacketDelayMode::from_timestamp, delay));
		rig.feed(10, 1);
		rig.feed(20, 2);
		CHECK(rig.release(kForever).empty());
		CHECK(rig.flush() == (Ids{1, 2}));
		CHECK(rig.queue.empty());
	}
}

void test_flush_returns_everything_in_release_order()
{
	Rig rig(options_for(PacketDelayMode::from_timestamp, 100));
	rig.feed(1000, 1);
	rig.feed(1010, 2);
	rig.feed(1010, 3);
	CHECK(rig.flush() == (Ids{1, 2, 3}));
	CHECK(rig.flush().empty());
}

void test_send_all_after_delay_releases_the_batch_together()
{
	Rig rig(options_for(PacketDelayMode::send_all_after_delay, 100));
	rig.feed(1000, 1);
	rig.feed(1040, 2);
	CHECK(rig.release(1099).empty());
	CHECK(rig.release(1100) == (Ids{1, 2}));

	// The next batch starts a new delay window.
	rig.feed(1200, 3);
	rig.feed(1250, 4);
	CHECK(rig.release(1299).empty());
	CHECK(rig.release(1300) == (Ids{3, 4}));
}

void test_send_all_after_delay_without_delay_holds_until_flush()
{
	Rig rig(options_for(PacketDelayMode::send_all_after_delay, 0));
	rig.feed(5, 1);
	rig.feed(6, 2);
	CHECK(rig.release(kForever).empty());
	CHECK(rig.flush() == (Ids{1, 2}));
}

void test_drop_discards_everything()
{
	Rig rig(options_for(PacketDelayMode::drop));
	rig.feed(1, 1);
	rig.feed(2, 2);
	CHECK(rig.discarded == (Ids{1, 2}));
	CHECK(rig.queue.empty());
	CHECK(rig.release(kForever).empty());
	CHECK(rig.flush().empty());
}

void test_discarding_without_a_sink_is_harmless()
{
	std::unique_ptr<PacketMode> mode = create_packet_mode(options_for(PacketDelayMode::drop));
	PacketQueue					queue;
	const Bytes					packet = tcp_packet(1, 1);
	mode->capture(packet.data(), static_cast<uint32_t>(packet.size()), backend::PacketMeta{}, 0, 0, 0, queue);
	CHECK(queue.empty());
}

void test_drop_and_send_drops_the_first_ratio_packets_of_a_batch()
{
	ProfileOptions options = options_for(PacketDelayMode::drop_and_send, 100);
	options.ratio		   = 1;
	Rig rig(options);
	rig.feed(1000, 1);
	rig.feed(1050, 2);
	rig.feed(1060, 3);
	CHECK(rig.release(1099).empty() && rig.discarded.empty());
	CHECK(rig.release(1100) == (Ids{2, 3}));
	CHECK(rig.discarded == (Ids{1}));
}

void test_drop_and_send_percentage_rounds_up()
{
	ProfileOptions options = options_for(PacketDelayMode::drop_and_send, 100);
	options.ratio_percent  = true;
	options.ratio		   = 50;
	Rig rig(options);
	for (int64_t id = 1; id <= 3; ++id)
		rig.feed(1000, id);
	CHECK(rig.release(1100) == (Ids{3}));
	CHECK(rig.discarded == (Ids{1, 2}));
}

void test_drop_and_send_cannot_drop_more_than_it_has()
{
	ProfileOptions options = options_for(PacketDelayMode::drop_and_send, 100);
	options.ratio		   = 5;
	Rig rig(options);
	rig.feed(1000, 1);
	rig.feed(1000, 2);
	CHECK(rig.release(1100).empty());
	CHECK(rig.discarded == (Ids{1, 2}));
}

void test_drop_and_send_applies_the_ratio_when_flushing()
{
	ProfileOptions options = options_for(PacketDelayMode::drop_and_send, 100);
	options.ratio		   = 2;
	Rig rig(options);
	for (int64_t id = 1; id <= 3; ++id)
		rig.feed(1000, id);
	CHECK(rig.flush() == (Ids{3}));
	CHECK(rig.discarded == (Ids{1, 2}));
}

void test_hold_and_send_holds_the_first_packets()
{
	ProfileOptions options = options_for(PacketDelayMode::hold_and_send);
	options.ratio		   = 2;
	Rig rig(options);
	for (int64_t id = 1; id <= 4; ++id)
		rig.feed(1000, id);
	CHECK(rig.release(1000) == (Ids{3, 4}));
	CHECK(rig.release(kForever).empty());
	CHECK(rig.flush() == (Ids{1, 2}));
}

void test_hold_and_send_holds_retransmissions_of_held_packets()
{
	struct Case
	{
		SubsequentPacketHoldMode mode;
		Ids						 released;
		Ids						 held;
	};
	// packets: 1 = (seq 100, ack 50) is held by the ratio; 2 = (200, 60); 3 = (100, 60); 4 = (300, 50)
	const Case cases[] = {
		{SubsequentPacketHoldMode::none, {2, 3, 4}, {1}},
		{SubsequentPacketHoldMode::seq_only, {2, 4}, {1, 3}},
		{SubsequentPacketHoldMode::ack_only, {2, 3}, {1, 4}},
		{SubsequentPacketHoldMode::seq_ack, {2, 3, 4}, {1}},
	};
	for (const Case& test_case : cases)
	{
		ProfileOptions options				 = options_for(PacketDelayMode::hold_and_send);
		options.ratio						 = 1;
		options.subsequent_packet_hold_mode = test_case.mode;
		Rig rig(options);
		rig.feed(10, 1, tcp_packet(100, 50));
		rig.feed(10, 2, tcp_packet(200, 60));
		rig.feed(10, 3, tcp_packet(100, 60));
		rig.feed(10, 4, tcp_packet(300, 50));
		CHECK(rig.release(10) == test_case.released);
		CHECK(rig.flush() == test_case.held);
	}

	ProfileOptions options				= options_for(PacketDelayMode::hold_and_send);
	options.ratio						= 1;
	options.subsequent_packet_hold_mode = SubsequentPacketHoldMode::seq_ack;
	Rig rig(options);
	rig.feed(10, 1, tcp_packet(100, 50));
	rig.feed(10, 2, tcp_packet(100, 50));
	rig.feed(10, 3, tcp_packet(100, 51));
	CHECK(rig.release(10) == (Ids{3}));
	CHECK(rig.flush() == (Ids{1, 2}));
}

void test_hold_and_send_counts_non_tcp_packets_and_resets()
{
	ProfileOptions options = options_for(PacketDelayMode::hold_and_send);
	options.ratio		   = 1;
	Rig rig(options);
	rig.feed(10, 1, ipv4_packet(kUdp, udp_datagram(1, 2, 4)));
	rig.feed(10, 2);
	CHECK(rig.release(10) == (Ids{2}));

	rig.mode->reset();
	rig.feed(20, 3);
	rig.feed(20, 4);
	CHECK(rig.release(20) == (Ids{4}));
	CHECK(rig.flush() == (Ids{1, 3}));
}

void test_hold_until_deactivation_releases_everything_on_toggle()
{
	Rig rig(options_for(PacketDelayMode::hold_until_deactivation));
	rig.feed(1, 1);
	rig.feed(2, 2);
	rig.feed(3, 3);
	CHECK(rig.release(kForever).empty());
	CHECK(rig.mode->toggle(rig.queue));
	CHECK(rig.release(4) == (Ids{1, 2, 3}));
	CHECK(rig.mode->toggle(rig.queue));
	CHECK(rig.release(5).empty());
}

void test_hold_until_deactivation_releases_an_amount_at_a_time()
{
	ProfileOptions options = options_for(PacketDelayMode::hold_until_deactivation);
	options.amount		   = 2;
	Rig rig(options);
	for (int64_t id = 1; id <= 5; ++id)
		rig.feed(1, id);
	rig.mode->flush_on_demand(rig.queue);
	CHECK(rig.release(2) == (Ids{1, 2}));
	CHECK(rig.mode->toggle(rig.queue));
	CHECK(rig.release(3) == (Ids{3, 4}));
	rig.mode->flush_on_demand(rig.queue);
	CHECK(rig.release(4) == (Ids{5}));
	CHECK(rig.queue.empty());
}

void test_hold_until_deactivation_flush_returns_the_rest()
{
	Rig rig(options_for(PacketDelayMode::hold_until_deactivation));
	rig.feed(1, 1);
	rig.feed(2, 2);
	CHECK(rig.flush() == (Ids{1, 2}));
}

void test_drop_until_toggle_phases()
{
	Rig rig(options_for(PacketDelayMode::drop_until_toggle));
	rig.feed(1, 1);
	CHECK(rig.discarded == (Ids{1}));

	CHECK(!rig.mode->toggle(rig.queue));  // start holding
	rig.feed(2, 2);
	rig.feed(3, 3);
	CHECK(rig.discarded == (Ids{1}));
	CHECK(rig.release(kForever).empty());

	CHECK(rig.mode->toggle(rig.queue));  // finished: later packets are dropped again
	rig.feed(4, 4);
	CHECK(rig.discarded == (Ids{1, 4}));
	CHECK(rig.flush() == (Ids{2, 3}));

	rig.mode->reset();
	rig.feed(5, 5);
	CHECK(rig.discarded == (Ids{1, 4, 5}));
	CHECK(!rig.mode->toggle(rig.queue));
}

void test_ratio_count_releases_batches_one_delay_apart()
{
	ProfileOptions options = options_for(PacketDelayMode::ratio, 100);
	options.ratio		   = 2;
	Rig rig(options);
	rig.feed(1000, 1);
	rig.feed(1010, 2);
	rig.feed(1020, 3);
	rig.feed(1030, 4);
	rig.feed(1040, 5);
	CHECK(rig.release(1099).empty());
	CHECK(rig.release(1100) == (Ids{1, 2}));
	CHECK(rig.release(1199).empty());
	CHECK(rig.release(1200) == (Ids{3, 4}));
	CHECK(rig.release(1299).empty());
	CHECK(rig.release(1300) == (Ids{5}));

	// An empty queue starts a fresh batch relative to the new packet.
	rig.feed(2000, 6);
	CHECK(rig.release(2099).empty());
	CHECK(rig.release(2100) == (Ids{6}));
}

void test_ratio_percentage_selection()
{
	struct Case
	{
		RatioSelection selection;
		Ids			   sent;
		Ids			   kept;
	};
	const Case cases[] = {
		{RatioSelection::first, {1, 2}, {3, 4}},
		{RatioSelection::last, {3, 4}, {1, 2}},
	};
	for (const Case& test_case : cases)
	{
		ProfileOptions options = options_for(PacketDelayMode::ratio, 100);
		options.ratio_percent  = true;
		options.ratio		   = 50;
		options.ratio_selection = test_case.selection;
		Rig rig(options);
		for (int64_t id = 1; id <= 4; ++id)
			rig.feed(1000, id);
		CHECK(rig.release(1000) == test_case.sent);
		CHECK(rig.flush() == test_case.kept);
	}

	ProfileOptions options	= options_for(PacketDelayMode::ratio, 100);
	options.ratio_percent	= true;
	options.ratio			= 50;
	options.ratio_selection = RatioSelection::random;
	Rig rig(options);
	for (int64_t id = 1; id <= 4; ++id)
		rig.feed(1000, id);
	Ids sent = rig.release(1000);
	CHECK(sent.size() == 2);
	Ids all = sent;
	for (const int64_t id : rig.flush())
		all.push_back(id);
	CHECK(sorted(all) == (Ids{1, 2, 3, 4}));
}

void test_ratio_percentage_sends_at_least_one_packet()
{
	ProfileOptions options = options_for(PacketDelayMode::ratio, 100);
	options.ratio_percent  = true;
	options.ratio		   = 10;
	Rig rig(options);
	rig.feed(1000, 1);
	CHECK(rig.release(1000) == (Ids{1}));

	rig.feed(2000, 2);
	rig.feed(2000, 3);
	CHECK(rig.release(2000) == (Ids{2}));
	CHECK(rig.release(2000) == (Ids{3}));
	CHECK(rig.release(2000).empty());
}

void test_ratio_percentage_rounds_up_and_can_send_everything()
{
	ProfileOptions options = options_for(PacketDelayMode::ratio, 100);
	options.ratio_percent  = true;
	options.ratio		   = 25;
	Rig rig(options);
	for (int64_t id = 1; id <= 10; ++id)
		rig.feed(1000, id);
	CHECK(rig.release(1000) == (Ids{1, 2, 3}));
	CHECK(rig.flush().size() == 7);

	options.ratio = 100;
	Rig everything(options);
	for (int64_t id = 1; id <= 4; ++id)
		everything.feed(1000, id);
	CHECK(everything.release(1000) == (Ids{1, 2, 3, 4}));
}

ProfileOptions group_options(int32_t groups, PacketGroupOrder order = PacketGroupOrder::fifo)
{
	ProfileOptions options = options_for(PacketDelayMode::packet_group_send);
	options.group_count	   = groups;
	options.group_order	   = order;
	return options;
}

void test_packet_group_send_sends_one_group_per_toggle()
{
	Rig rig(group_options(2));
	CHECK(rig.mode->status() == "Capturing group 1/2");
	rig.feed(100, 1);
	rig.feed(100, 2);
	CHECK(rig.release(kForever).empty());

	CHECK(!rig.mode->toggle(rig.queue));
	CHECK(rig.mode->status() == "Capturing group 2/2");
	rig.feed(100, 3);
	CHECK(rig.release(kForever).empty());

	CHECK(!rig.mode->toggle(rig.queue));
	CHECK(rig.mode->status() == "Sending group 1/2");
	CHECK(rig.release_and_complete(200, true) == (Ids{1, 2}));
	CHECK(rig.mode->status() == "Sent group 1/2");

	CHECK(rig.mode->toggle(rig.queue));
	CHECK(rig.mode->status() == "Sending group 2/2");
	CHECK(rig.release_and_complete(300, true) == (Ids{3}));
	CHECK(rig.mode->status() == "Sent group 2/2");
	CHECK(rig.queue.empty());
}

void test_packet_group_send_passes_later_packets_through()
{
	Rig rig(group_options(1));
	rig.feed(100, 1);
	CHECK(rig.mode->toggle(rig.queue));
	rig.feed(300, 9);
	CHECK(rig.release(300) == (Ids{1, 9}));
}

void test_packet_group_send_lifo_sends_the_last_group_first()
{
	Rig rig(group_options(2, PacketGroupOrder::lifo));
	rig.feed(100, 1);
	rig.mode->toggle(rig.queue);
	rig.feed(100, 2);
	CHECK(!rig.mode->toggle(rig.queue));
	CHECK(rig.mode->status() == "Sending group 2/2");
	CHECK(rig.release(200) == (Ids{2}));
	CHECK(rig.mode->toggle(rig.queue));
	CHECK(rig.mode->status() == "Sending group 1/2");
	CHECK(rig.release(300) == (Ids{1}));
}

void test_packet_group_send_random_sends_every_group_once()
{
	Rig rig(group_options(3, PacketGroupOrder::random));
	rig.feed(100, 1);
	rig.mode->toggle(rig.queue);
	rig.feed(100, 2);
	rig.mode->toggle(rig.queue);
	rig.feed(100, 3);

	Ids sent;
	CHECK(!rig.mode->toggle(rig.queue));
	for (const int64_t id : rig.release(200))
		sent.push_back(id);
	CHECK(!rig.mode->toggle(rig.queue));
	for (const int64_t id : rig.release(200))
		sent.push_back(id);
	CHECK(rig.mode->toggle(rig.queue));
	for (const int64_t id : rig.release(200))
		sent.push_back(id);
	CHECK(sent.size() == 3 && sorted(sent) == (Ids{1, 2, 3}));
}

void test_packet_group_send_empty_groups_are_reported_as_sent()
{
	Rig rig(group_options(2));
	rig.mode->toggle(rig.queue);
	rig.feed(100, 1);
	CHECK(!rig.mode->toggle(rig.queue));
	CHECK(rig.mode->status() == "Sent group 1/2");
	CHECK(rig.release(200).empty());
	CHECK(rig.mode->toggle(rig.queue));
	CHECK(rig.release(200) == (Ids{1}));
}

void test_packet_group_send_reports_failures()
{
	Rig rig(group_options(1));
	rig.feed(100, 1);
	rig.feed(100, 2);
	CHECK(rig.mode->toggle(rig.queue));
	CHECK(rig.release_and_complete(200, false) == (Ids{1, 2}));
	CHECK(rig.mode->status() == "Send failures group 1/1");

	// Packets that never belonged to a group do not affect the status.
	PacketNode loose{};
	rig.mode->packet_send_completed(loose, true);
	CHECK(rig.mode->status() == "Send failures group 1/1");
}

void test_packet_group_send_restarts_on_reset()
{
	Rig rig(group_options(1));
	rig.feed(100, 1);
	CHECK(rig.mode->toggle(rig.queue));
	CHECK(rig.release_and_complete(200, true) == (Ids{1}));
	CHECK(rig.mode->status() == "Sent group 1/1");

	rig.mode->reset();
	CHECK(rig.mode->status() == "Capturing group 1/1");
	rig.feed(300, 2);
	CHECK(rig.release(kForever).empty());
	CHECK(rig.flush() == (Ids{2}));
}

void test_modes_without_status_report_nothing()
{
	Rig rig(options_for(PacketDelayMode::from_timestamp, 10));
	CHECK(rig.mode->status().empty());
	CHECK(!rig.mode->toggle(rig.queue));
}

void test_retransmissions_are_discarded_while_queued()
{
	struct Case
	{
		RetransmissionMode mode;
		Ids				   discarded;
	};
	// packets: 1 = (seq 100, ack 1); 2 = (100, 2); 3 = (200, 1); 4 = (100, 1)
	const Case cases[] = {
		{RetransmissionMode::none, {}},
		{RetransmissionMode::only_seq, {2, 4}},
		{RetransmissionMode::only_ack, {3, 4}},
		{RetransmissionMode::both, {4}},
	};
	for (const Case& test_case : cases)
	{
		ProfileOptions options	= options_for(PacketDelayMode::from_timestamp, 1000);
		options.retransmission_mode = test_case.mode;
		Rig rig(options);
		rig.feed(0, 1, tcp_packet(100, 1));
		rig.feed(0, 2, tcp_packet(100, 2));
		rig.feed(0, 3, tcp_packet(200, 1));
		rig.feed(0, 4, tcp_packet(100, 1));
		CHECK(rig.discarded == test_case.discarded);
		CHECK(rig.flush().size() == 4 - test_case.discarded.size());
	}
}

void test_retransmission_filter_ignores_released_and_non_tcp_packets()
{
	ProfileOptions options		= options_for(PacketDelayMode::from_timestamp, 100);
	options.retransmission_mode = RetransmissionMode::both;
	Rig rig(options);
	rig.feed(0, 1, tcp_packet(100, 1));
	CHECK(rig.release(100) == (Ids{1}));
	rig.feed(200, 2, tcp_packet(100, 1));
	CHECK(rig.release(300) == (Ids{2}));

	const Bytes udp = ipv4_packet(kUdp, udp_datagram(1, 2, 4));
	rig.feed(400, 3, udp);
	rig.feed(400, 4, udp);
	CHECK(rig.release(500) == (Ids{3, 4}));
	CHECK(rig.discarded.empty());
}

void test_ack_restoration_lets_pure_acks_bypass_the_mode()
{
	ProfileOptions options = options_for(PacketDelayMode::from_timestamp, 1000);
	options.ack_restoration = true;
	Rig rig(options);
	rig.feed(0, 1, tcp_packet(1, 1, kAck));
	rig.feed(0, 2, tcp_packet(2, 1, kAck | kPsh));
	CHECK(rig.release(0) == (Ids{1}));
	CHECK(rig.release(999).empty());
	CHECK(rig.release(1000) == (Ids{2}));

	Rig plain(options_for(PacketDelayMode::from_timestamp, 1000));
	plain.feed(0, 1, tcp_packet(1, 1, kAck));
	CHECK(plain.release(0).empty());
}

uint32_t acknowledgment_after_send(PacketMode& mode, Bytes packet)
{
	mode.prepare_packet_for_send(packet.data(), static_cast<uint32_t>(packet.size()), nullptr);
	uint32_t sequence = 0, acknowledgment = 0;
	CHECK(get_tcp_numbers(packet.data(), static_cast<uint32_t>(packet.size()), sequence, acknowledgment));
	return acknowledgment;
}

void test_ack_restoration_never_lets_the_ack_go_backwards()
{
	ProfileOptions options = options_for(PacketDelayMode::from_timestamp, 100);
	options.ack_restoration = true;
	std::unique_ptr<PacketMode> mode = create_packet_mode(options);
	checksum_calls					 = 0;

	CHECK(acknowledgment_after_send(*mode, tcp_packet(1, 1000, kAck | kPsh)) == 1000);
	CHECK(checksum_calls == 0);
	CHECK(acknowledgment_after_send(*mode, tcp_packet(2, 900, kAck | kPsh)) == 1000);
	CHECK(checksum_calls == 1);

	// Only PSH packets are rewritten, and an equal or lower ACK without PSH does not move the high-water mark.
	CHECK(acknowledgment_after_send(*mode, tcp_packet(3, 800, kAck)) == 800);
	CHECK(acknowledgment_after_send(*mode, tcp_packet(4, 1000, kAck | kPsh)) == 1000);
	CHECK(acknowledgment_after_send(*mode, tcp_packet(5, 950, kAck | kPsh)) == 1000);
	CHECK(checksum_calls == 2);

	CHECK(acknowledgment_after_send(*mode, tcp_packet(6, 1200, kAck)) == 1200);
	CHECK(acknowledgment_after_send(*mode, tcp_packet(7, 1100, kAck | kPsh)) == 1200);
	CHECK(checksum_calls == 3);

	// Flows are tracked independently, by addresses and ports.
	CHECK(acknowledgment_after_send(*mode, tcp_packet(1, 5, kAck | kPsh, 1111, 2000)) == 5);
	CHECK(acknowledgment_after_send(*mode, ipv4_packet(kTcp, tcp_segment(1000, 2000, 1, 5, kAck | kPsh), {10, 0, 0, 9}, {192, 168, 1, 20})) == 5);
	CHECK(checksum_calls == 3);

	// Packets without the ACK flag are not tracked, and UDP is left alone.
	CHECK(acknowledgment_after_send(*mode, tcp_packet(1, 10, kSyn, 3333, 2000)) == 10);
	CHECK(acknowledgment_after_send(*mode, tcp_packet(1, 5, kAck | kPsh, 3333, 2000)) == 5);
	Bytes udp = ipv4_packet(kUdp, udp_datagram(1, 2, 4));
	mode->prepare_packet_for_send(udp.data(), static_cast<uint32_t>(udp.size()), nullptr);
	CHECK(checksum_calls == 3);

	mode->reset();
	CHECK(acknowledgment_after_send(*mode, tcp_packet(8, 10, kAck | kPsh)) == 10);
	CHECK(checksum_calls == 3);
}

void test_ack_restoration_is_off_by_default()
{
	std::unique_ptr<PacketMode> mode = create_packet_mode(options_for(PacketDelayMode::from_timestamp, 100));
	checksum_calls					 = 0;
	CHECK(acknowledgment_after_send(*mode, tcp_packet(1, 1000, kAck | kPsh)) == 1000);
	CHECK(acknowledgment_after_send(*mode, tcp_packet(2, 900, kAck | kPsh)) == 900);
	CHECK(checksum_calls == 0);
}
}  // namespace

int main(int argc, char** argv)
{
	logging::set_level(logging::level::error);
	static const test::TestCase cases[] = {
		{"factory_creates_every_mode", test_factory_creates_every_mode},
		{"make_packet_node_copies_its_inputs", test_make_packet_node_copies_its_inputs},
		{"collect_due_packets_orders_by_release_then_receive", test_collect_due_packets_orders_by_release_then_receive},
		{"collect_due_packets_discards_malformed_entries", test_collect_due_packets_discards_malformed_entries},
		{"get_tcp_numbers", test_get_tcp_numbers},
		{"from_timestamp_delays_each_packet", test_from_timestamp_delays_each_packet},
		{"from_timestamp_without_delay_holds_until_flush", test_from_timestamp_without_delay_holds_until_flush},
		{"flush_returns_everything_in_release_order", test_flush_returns_everything_in_release_order},
		{"send_all_after_delay_releases_the_batch_together", test_send_all_after_delay_releases_the_batch_together},
		{"send_all_after_delay_without_delay_holds_until_flush", test_send_all_after_delay_without_delay_holds_until_flush},
		{"drop_discards_everything", test_drop_discards_everything},
		{"discarding_without_a_sink_is_harmless", test_discarding_without_a_sink_is_harmless},
		{"drop_and_send_drops_the_first_ratio_packets_of_a_batch", test_drop_and_send_drops_the_first_ratio_packets_of_a_batch},
		{"drop_and_send_percentage_rounds_up", test_drop_and_send_percentage_rounds_up},
		{"drop_and_send_cannot_drop_more_than_it_has", test_drop_and_send_cannot_drop_more_than_it_has},
		{"drop_and_send_applies_the_ratio_when_flushing", test_drop_and_send_applies_the_ratio_when_flushing},
		{"hold_and_send_holds_the_first_packets", test_hold_and_send_holds_the_first_packets},
		{"hold_and_send_holds_retransmissions_of_held_packets", test_hold_and_send_holds_retransmissions_of_held_packets},
		{"hold_and_send_counts_non_tcp_packets_and_resets", test_hold_and_send_counts_non_tcp_packets_and_resets},
		{"hold_until_deactivation_releases_everything_on_toggle", test_hold_until_deactivation_releases_everything_on_toggle},
		{"hold_until_deactivation_releases_an_amount_at_a_time", test_hold_until_deactivation_releases_an_amount_at_a_time},
		{"hold_until_deactivation_flush_returns_the_rest", test_hold_until_deactivation_flush_returns_the_rest},
		{"drop_until_toggle_phases", test_drop_until_toggle_phases},
		{"ratio_count_releases_batches_one_delay_apart", test_ratio_count_releases_batches_one_delay_apart},
		{"ratio_percentage_selection", test_ratio_percentage_selection},
		{"ratio_percentage_sends_at_least_one_packet", test_ratio_percentage_sends_at_least_one_packet},
		{"ratio_percentage_rounds_up_and_can_send_everything", test_ratio_percentage_rounds_up_and_can_send_everything},
		{"packet_group_send_sends_one_group_per_toggle", test_packet_group_send_sends_one_group_per_toggle},
		{"packet_group_send_passes_later_packets_through", test_packet_group_send_passes_later_packets_through},
		{"packet_group_send_lifo_sends_the_last_group_first", test_packet_group_send_lifo_sends_the_last_group_first},
		{"packet_group_send_random_sends_every_group_once", test_packet_group_send_random_sends_every_group_once},
		{"packet_group_send_empty_groups_are_reported_as_sent", test_packet_group_send_empty_groups_are_reported_as_sent},
		{"packet_group_send_reports_failures", test_packet_group_send_reports_failures},
		{"packet_group_send_restarts_on_reset", test_packet_group_send_restarts_on_reset},
		{"modes_without_status_report_nothing", test_modes_without_status_report_nothing},
		{"retransmissions_are_discarded_while_queued", test_retransmissions_are_discarded_while_queued},
		{"retransmission_filter_ignores_released_and_non_tcp_packets", test_retransmission_filter_ignores_released_and_non_tcp_packets},
		{"ack_restoration_lets_pure_acks_bypass_the_mode", test_ack_restoration_lets_pure_acks_bypass_the_mode},
		{"ack_restoration_never_lets_the_ack_go_backwards", test_ack_restoration_never_lets_the_ack_go_backwards},
		{"ack_restoration_is_off_by_default", test_ack_restoration_is_off_by_default},
	};
	return test::run_tests("modes", cases, argc, argv);
}
