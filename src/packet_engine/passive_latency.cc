#include "internal.h"

#ifdef LAGSW_FEATURE_PASSIVE_LATENCY

#include <random>

#include "log.h"

LOG_DEFAULT_GROUP(logging::group::passive_latency)

namespace {
/// Sends one packet immediately, logging the outcome. Used for both the fail-open overflow path and final flush.
void send_passive_packet(backend::PacketChannel& handle, const uint8_t* packet, uint32_t length, const backend::PacketMeta& address, const char* reason)
{
	uint32_t	sent = 0;
	std::string io_error;
	if (handle.send(packet, length, address, sent, io_error) != backend::IoStatus::ok)
	{
		LOG_ERROR("Passive latency %s: failed: %s", reason, io_error.c_str());
		return;
	}
	if (sent == 0)
		return;
	const PacketAddresses addresses = packet_addresses(packet, length);
	LOG_DEBUG_GROUP(logging::group::passive_latency_packet, "Passive latency %s: Length = %u, Src = %s, Dst = %s, SendLen = %u",
			  reason,
			  length,
			  addresses.source.c_str(),
			  addresses.destination.c_str(),
			  sent);
}
}  // namespace

void PacketEngine::start_passive_latency()
{
	const PassiveLatencyOptions& passive = options_.features.passive_latency;
	if (!passive.enabled)
		return;

	DelayModelOptions model_options;
	model_options.kind			  = DelayModelKind::fixed;
	model_options.preserve_order = true;
	const int32_t max_delay_ms	  = passive.max_delay_ms > 0 ? passive.max_delay_ms : passive.delay_ms;
	for (DirectionDelay& direction : model_options.directions)
		direction = {passive.delay_ms, 0, max_delay_ms};
	state_->passive_latency_model = std::make_unique<DelayModel>(model_options, std::random_device{}());

	state_->passive_latency_stopping = false;
	backend::OpenOptions open_options;
	open_options.filter   = passive.filter.value_or(options_.global_filter);
	open_options.priority = 100;
	std::string open_error;
	state_->passive_latency_handle = backend::open(open_options, open_error);
	if (!state_->passive_latency_handle)
	{
		LOG_ERROR("Passive latency setup: failed to open capture channel: %s", open_error.c_str());
		return;
	}
	LOG_INFO("Passive latency active: delay = %dms (max %dms), filter = %s",
			 passive.delay_ms,
			 max_delay_ms,
			 open_options.filter.c_str());
	state_->passive_latency_recv_thread = std::thread(&PacketEngine::passive_latency_recv, this);
	state_->passive_latency_send_thread = std::thread(&PacketEngine::passive_latency_send, this);
}

void PacketEngine::stop_passive_latency()
{
	if (!state_->passive_latency_handle)
		return;
	state_->passive_latency_stopping = true;
	state_->passive_latency_handle->shutdown_recv();
	state_->passive_latency_changed.notify_all();
	if (state_->passive_latency_recv_thread.joinable())
		state_->passive_latency_recv_thread.join();
	if (state_->passive_latency_send_thread.joinable())
		state_->passive_latency_send_thread.join();
	flush_passive_latency_queue();
	state_->passive_latency_handle->close();
	state_->passive_latency_handle.reset();
	state_->passive_latency_model.reset();
}

void PacketEngine::passive_latency_recv()
{
	const PassiveLatencyOptions& passive = options_.features.passive_latency;
	uint8_t						packet_data[0xFFFF];
	while (!state_->passive_latency_stopping && !shutdown_)
	{
		backend::PacketMeta address;
		uint32_t			received_length = 0;
		std::string			io_error;
		const backend::IoStatus status =
			state_->passive_latency_handle->recv(packet_data, sizeof(packet_data), received_length, address, io_error);
		if (status != backend::IoStatus::ok)
		{
			if (!state_->passive_latency_stopping && !shutdown_ && status == backend::IoStatus::error)
				LOG_ERROR("Passive latency recv: %s", io_error.c_str());
			continue;
		}

		std::lock_guard<std::mutex> lock(state_->passive_latency_mutex);
		if (state_->passive_latency_stopping)
		{
			send_passive_packet(*state_->passive_latency_handle, packet_data, received_length, address, "send: stopping");
			continue;
		}
		if (state_->passive_latency_queue.size() >= passive.max_queued_packets)
		{
			LOG_WARN("Passive latency queue is full (%u packets); releasing a packet immediately", passive.max_queued_packets);
			send_passive_packet(*state_->passive_latency_handle, packet_data, received_length, address, "send: queue full");
			continue;
		}

		const DelayDirection direction = address.outbound ? DelayDirection::outbound : DelayDirection::inbound;
		const uint64_t		 now		= platform::tick_ms();
		const uint64_t		 release_at = state_->passive_latency_model->release_at(direction, now);
		state_->passive_latency_queue.push(
			make_packet_node(packet_data, received_length, address, 0, release_at, state_->passive_latency_next_receive_order++));
		state_->passive_latency_changed.notify_one();
	}
}

void PacketEngine::passive_latency_send()
{
	while (!state_->passive_latency_stopping && !shutdown_)
	{
		std::vector<PacketNode*> ready_packets;
		{
			std::unique_lock<std::mutex> lock(state_->passive_latency_mutex);
			while (state_->passive_latency_queue.empty() && !state_->passive_latency_stopping && !shutdown_)
				state_->passive_latency_changed.wait(lock);
			if (state_->passive_latency_stopping || shutdown_)
				return;

			const uint64_t now = platform::tick_ms();
			collect_due_packets(state_->passive_latency_queue, now, ready_packets);
			if (ready_packets.empty())
			{
				const uint64_t next_release = state_->passive_latency_queue.top()->release_at;
				const uint64_t wait_ms		 = next_release > now ? next_release - now : 0;
				state_->passive_latency_changed.wait_for(lock, std::chrono::milliseconds(wait_ms));
				continue;
			}
		}
		for (PacketNode* node : ready_packets)
		{
			send_passive_packet(*state_->passive_latency_handle, node->packet, node->length, *node->address, "send: delayed packet");
			destroy_packet_node(node);
		}
	}
}

void PacketEngine::flush_passive_latency_queue()
{
	std::vector<PacketNode*> pending_packets;
	{
		std::lock_guard<std::mutex> lock(state_->passive_latency_mutex);
		while (!state_->passive_latency_queue.empty())
		{
			pending_packets.push_back(state_->passive_latency_queue.top());
			state_->passive_latency_queue.pop();
		}
	}
	for (PacketNode* node : pending_packets)
	{
		send_passive_packet(*state_->passive_latency_handle, node->packet, node->length, *node->address, "flush: sent packet");
		destroy_packet_node(node);
	}
}

bool PacketEngine::is_passive_latency_enabled() const
{
	return options_.features.passive_latency.enabled;
}

#endif
