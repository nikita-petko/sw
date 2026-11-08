#include "internal.h"

#ifdef LAGSW_FEATURE_PASSIVE_LATENCY

#	include <random>

#	include "log.h"

LOG_DEFAULT_GROUP(logging::group::passive_latency)

namespace {
/// Logs the outcome of one passive-latency send.
void log_passive_send(const char*			  reason,
					  const uint8_t*		  packet,
					  uint32_t				  length,
					  const backend::IoStatus status,
					  uint32_t				  sent,
					  const std::string&	  io_error)
{
	if (status != backend::IoStatus::ok)
	{
		LOG_ERROR("Passive latency %s: failed: %s", reason, io_error.c_str());
		return;
	}
	if (sent == 0)
		return;
	if (!logging::group_accepts(logging::group::passive_latency_packet, logging::level::debug))
		return;
	const PacketAddresses addresses = packet_addresses(packet, length);
	LOG_DEBUG_GROUP(logging::group::passive_latency_packet,
					"Passive latency %s: Length = %u, Src = %s, Dst = %s, SendLen = %u",
					reason,
					length,
					addresses.source.c_str(),
					addresses.destination.c_str(),
					sent);
}

/// Sends one packet immediately, logging the outcome. Used for the fail-open overflow path and delayed releases.
void send_passive_packet(backend::PacketChannel&	handle,
						 const uint8_t*				packet,
						 uint32_t					length,
						 const backend::PacketMeta& address,
						 const char*				reason)
{
	uint32_t				sent = 0;
	std::string				io_error;
	const backend::IoStatus status = handle.send(packet, length, address, sent, io_error);
	log_passive_send(reason, packet, length, status, sent, io_error);
}
}  // namespace

void PacketEngine::start_passive_latency()
{
	const PassiveLatencyOptions& passive = options_.features.passive_latency;
	if (!passive.enabled)
		return;

	DelayModelOptions model_options;
	switch (passive.mode)
	{
		case PassiveLatencyMode::fixed:
			model_options.kind = DelayModelKind::fixed;
			break;
		case PassiveLatencyMode::uniform:
			model_options.kind = DelayModelKind::uniform;
			break;
		case PassiveLatencyMode::normal:
			model_options.kind = DelayModelKind::normal;
			break;
	}
	model_options.preserve_order = passive.preserve_order;
	for (const bool outbound : {false, true})
	{
		const DelayDirection direction						  = outbound ? DelayDirection::outbound : DelayDirection::inbound;
		model_options.directions[static_cast<int>(direction)] = {passive.effective_delay_ms(outbound),
																 passive.effective_jitter_ms(outbound),
																 passive.effective_max_delay_ms(outbound)};
	}
	state_->passive_latency_model = std::make_unique<DelayModel>(model_options, std::random_device{}());

	state_->passive_latency_stopping = false;
	if (options_.features.linux_bpf.tier != LinuxTier::nfqueue)
	{
		backend::ShapeSpec spec;
		spec.filter			 = passive.filter.value_or(options_.global_filter);
		spec.include_forward = true;
		spec.behaviour		 = backend::ShapeBehaviour::baseline;
		spec.model			 = passive.mode == PassiveLatencyMode::fixed	 ? backend::ShapeModel::fixed
							   : passive.mode == PassiveLatencyMode::uniform ? backend::ShapeModel::uniform
																			 : backend::ShapeModel::normal;
		spec.delay_ms		 = static_cast<uint32_t>((std::max)(passive.effective_delay_ms(true), 0));
		spec.jitter_ms		 = static_cast<uint32_t>((std::max)(passive.effective_jitter_ms(true), 0));
		spec.max_delay_ms	 = static_cast<uint32_t>((std::max)(passive.effective_max_delay_ms(true), 0));
		spec.preserve_order	 = passive.preserve_order;
		spec.ignore_inbound	 = true;
		spec.label			 = "passive latency";
		std::string reason;
		// Packets arriving at this host are not seen by an egress program, so an inbound delay keeps the whole feature in user space.
		std::unique_ptr<backend::ShapeStage> shape;
		if (passive.effective_delay_ms(false) != 0)
			reason = "the baseline also delays inbound packets";
		else
			shape = backend::open_shape_stage(spec, reason);
		if (shape && !shape->activate(reason))
			shape.reset();
		if (shape)
		{
			state_->passive_latency_shape = std::move(shape);
			LOG_INFO("Passive latency active in the kernel (eBPF + fq): %s", describe_passive_latency().c_str());
			LOG_INFO("Passive latency filter: %s", spec.filter.c_str());
			return;
		}
		if (options_.features.linux_bpf.tier == LinuxTier::bpf)
		{
			LOG_ERROR("Passive latency requires kernel shaping (linux_bpf tier bpf) but it is unavailable: %s", reason.c_str());
			return;
		}
		LOG_DEBUG("Passive latency uses NFQUEUE, not kernel shaping: %s", reason.c_str());
	}
	backend::OpenOptions open_options;
	open_options.filter			 = passive.filter.value_or(options_.global_filter);
	open_options.priority		 = backend::priority::passive_latency;
	open_options.include_forward = true;
	std::string open_error;
	state_->passive_latency_handle = backend::open(open_options, open_error);
	if (!state_->passive_latency_handle)
	{
		LOG_ERROR("Passive latency setup: failed to open capture channel: %s", open_error.c_str());
		return;
	}
	LOG_INFO("Passive latency active: %s", describe_passive_latency().c_str());
	LOG_INFO("Passive latency filter: %s", open_options.filter.c_str());
	state_->passive_latency_recv_thread = std::thread(&PacketEngine::passive_latency_recv, this);
	state_->passive_latency_send_thread = std::thread(&PacketEngine::passive_latency_send, this);
}

void PacketEngine::stop_passive_latency()
{
	if (state_->passive_latency_shape)
	{
		state_->passive_latency_shape->deactivate();
		state_->passive_latency_shape.reset();
		state_->passive_latency_model.reset();
		return;
	}
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
	uint8_t						 packet_data[0xFFFF];
	while (!state_->passive_latency_stopping && !shutdown_)
	{
		backend::PacketMeta		address;
		uint32_t				received_length = 0;
		std::string				io_error;
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
		if (state_->passive_latency_paused)
		{
			send_passive_packet(*state_->passive_latency_handle, packet_data, received_length, address, "send: paused");
			continue;
		}
		if (is_probe_traffic(packet_data, received_length))
		{
			send_passive_packet(*state_->passive_latency_handle, packet_data, received_length, address, "send: probe traffic");
			continue;
		}
		if (state_->passive_latency_queue.size() >= passive.max_queued_packets)
		{
			LOG_WARN("Passive latency queue is full (%u packets); releasing a packet immediately", passive.max_queued_packets);
			send_passive_packet(*state_->passive_latency_handle, packet_data, received_length, address, "send: queue full");
			continue;
		}

		const DelayDirection direction	= address.outbound ? DelayDirection::outbound : DelayDirection::inbound;
		const uint64_t		 now		= platform::tick_ms();
		const uint64_t		 release_at = state_->passive_latency_model->release_at(direction, now);
		if (logging::group_accepts(logging::group::passive_latency_packet, logging::level::debug))
		{
			const PacketAddresses addresses = packet_addresses(packet_data, received_length);
			LOG_DEBUG_GROUP(logging::group::passive_latency_packet,
							"Passive latency recv: %s packet (delaying for %llums): Length = %u, Src = %s, Dst = %s",
							address.outbound ? "outbound" : "inbound",
							static_cast<unsigned long long>(release_at - now),
							received_length,
							addresses.source.c_str(),
							addresses.destination.c_str());
		}
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
				const uint64_t wait_ms		= next_release > now ? next_release - now : 0;
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

bool PacketEngine::is_probe_traffic([[maybe_unused]] const uint8_t* packet, [[maybe_unused]] uint32_t length) const
{
#	ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
	const RegionEnforcementOptions& region = options_.features.region_enforcement;
	if (!region.enabled || region.probe_port == 0)
		return false;
	ParsedPacket parsed;
	if (!parse_packet(packet, length, parsed))
		return false;
	if (parsed.tcp != nullptr)
		return swap_u16(parsed.tcp->SrcPort) == region.probe_port || swap_u16(parsed.tcp->DstPort) == region.probe_port;
	if (parsed.udp != nullptr)
		return swap_u16(parsed.udp->SrcPort) == region.probe_port || swap_u16(parsed.udp->DstPort) == region.probe_port;
#	endif
	return false;
}

void PacketEngine::toggle_passive_latency_pause()
{
	if (!state_->passive_latency_handle && !state_->passive_latency_shape)
		return;
	{
		std::lock_guard<std::mutex> lock(state_->passive_latency_mutex);
		state_->passive_latency_paused = !state_->passive_latency_paused;
		if (state_->passive_latency_shape)
		{
			// Packets already stamped by the kernel still leave on their original schedule; only new packets are affected.
			std::string error;
			if (state_->passive_latency_paused)
				state_->passive_latency_shape->deactivate();
			else if (!state_->passive_latency_shape->activate(error))
				LOG_ERROR("Passive latency: cannot resume: %s", error.c_str());
			LOG_INFO("Passive latency %s", state_->passive_latency_paused ? "paused" : "resumed");
			return;
		}
		if (!state_->passive_latency_paused)
		{
			state_->passive_latency_model->reset();
			LOG_INFO("Passive latency resumed");
			return;
		}
		LOG_INFO("Passive latency paused");
	}
	flush_passive_latency_queue();
}

std::optional<int> PacketEngine::passive_latency_pause_key() const
{
	return options_.features.passive_latency.pause_key;
}

bool PacketEngine::is_passive_latency_paused() const
{
	std::lock_guard<std::mutex> lock(state_->passive_latency_mutex);
	return state_->passive_latency_paused;
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
	std::vector<backend::SendItem> items(pending_packets.size());
	for (size_t index = 0; index < pending_packets.size(); ++index)
	{
		items[index].packet = pending_packets[index]->packet;
		items[index].length = pending_packets[index]->length;
		items[index].meta	= pending_packets[index]->address;
	}
	state_->passive_latency_handle->send_batch(items.data(), items.size());
	for (size_t index = 0; index < pending_packets.size(); ++index)
	{
		log_passive_send("flush: sent packet",
						 items[index].packet,
						 items[index].length,
						 items[index].status,
						 items[index].sent,
						 items[index].error);
		destroy_packet_node(pending_packets[index]);
	}
}

std::string PacketEngine::describe_passive_latency() const
{
	const PassiveLatencyOptions& passive = options_.features.passive_latency;
	const char*					 mode	 = passive.mode == PassiveLatencyMode::fixed	 ? "fixed"
										   : passive.mode == PassiveLatencyMode::uniform ? "uniform"
																						 : "normal";
	std::string					 text	 = mode;
	for (const bool outbound : {true, false})
	{
		const int32_t mean = passive.effective_delay_ms(outbound);
		text += outbound ? ", out " : ", in ";
		if (mean == 0)
		{
			text += "off";
			continue;
		}
		text += std::to_string(mean) + "ms";
		if (passive.effective_jitter_ms(outbound) != 0)
			text += " +/-" + std::to_string(passive.effective_jitter_ms(outbound));
		text += " (max " + std::to_string(passive.effective_max_delay_ms(outbound)) + ")";
	}
	if (!passive.preserve_order)
		text += ", unordered";
	return text;
}

std::string PacketEngine::passive_latency_status() const
{
	const PassiveLatencyOptions& passive = options_.features.passive_latency;
	if (is_passive_latency_paused())
		return "paused";
	auto part = [&](bool outbound) {
		const int32_t mean = passive.effective_delay_ms(outbound);
		std::string	  text = std::to_string(mean) + "ms";
		if (passive.effective_jitter_ms(outbound) != 0)
			text += "+/-" + std::to_string(passive.effective_jitter_ms(outbound));
		return text;
	};
	const bool out_on = passive.effective_delay_ms(true) != 0;
	const bool in_on  = passive.effective_delay_ms(false) != 0;
	if (out_on && in_on && part(true) == part(false))
		return part(true) + " (both)";
	std::string text;
	if (out_on)
		text += part(true) + " out";
	if (in_on)
		text += std::string(text.empty() ? "" : ", ") + part(false) + " in";
	return text;
}

bool PacketEngine::is_passive_latency_enabled() const
{
	return options_.features.passive_latency.enabled;
}

#endif
