#include "internal.h"

#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY

#include "log.h"

namespace {
using AddressCounts = std::unordered_map<std::string, uint64_t>;

/// Counts a packet seen on the forwarded-address-discovery capture. Returns false when the packet is ignored.
bool count_forwarded_address(const uint8_t*			packet_data,
							 uint32_t				received_length,
							 const backend::PacketMeta& address,
							 uint32_t				inbound_if_idx,
							 uint32_t				outbound_if_idx,
							 AddressCounts&			destination_counts,
							 AddressCounts&			source_counts)
{
	const bool is_inbound_interface	 = address.if_index == inbound_if_idx;
	const bool is_outbound_interface = address.if_index == outbound_if_idx;
	if (!is_inbound_interface && !is_outbound_interface)
	{
		LOG_DEBUG_GROUP(logging::group::forwarded_packet, "Forwarded address discovery: ignoring packet on unrelated ifIdx %u (outbound=%d)", address.if_index, address.outbound);
		return false;
	}
	ParsedPacket parsed;
	if (!parse_packet(packet_data, received_length, parsed))
	{
		LOG_DEBUG_GROUP(logging::group::forwarded_packet,
						"Forwarded address discovery: failed to parse packet on ifIdx %u (%s)",
						address.if_index,
						is_inbound_interface ? "inbound" : "outbound");
		return false;
	}
	const std::string address_text = endpoint_address(parsed, is_inbound_interface);
	if (address_text.empty())
	{
		LOG_DEBUG_GROUP(logging::group::forwarded_packet,
						"Forwarded address discovery: packet on ifIdx %u (%s) had no IPv4/IPv6 header",
						address.if_index,
						is_inbound_interface ? "inbound" : "outbound");
		return false;
	}
	auto& counts = is_inbound_interface ? destination_counts : source_counts;
	++counts[address_text];
	LOG_DEBUG_GROUP(logging::group::forwarded_packet,
					"Forwarded address discovery: observed %s = %s on ifIdx %u (outbound=%d) [count=%llu]",
					is_inbound_interface ? "dst" : "src",
					address_text.c_str(),
					address.if_index,
					address.outbound,
					static_cast<unsigned long long>(counts[address_text]));
	return true;
}
}  // namespace

void PacketEngine::start_forwarded_address_worker()
{
	const uint32_t	  inbound_if_idx  = *options_.features.forwarded_address_discovery.inbound_if_idx;
	const uint32_t	  outbound_if_idx = *options_.features.forwarded_address_discovery.outbound_if_idx;
	const uint16_t	  port			  = options_.features.forwarded_address_discovery.port;
	const std::string filter		  = backend::filters::forwarded_address(inbound_if_idx, outbound_if_idx, port);
	LOG_DEBUG_GROUP(logging::group::forwarded, "Forwarded address discovery setup: opening filter '%s'", filter.c_str());
	// a dedicated priority avoids losing packets to other priority-0 handles (server discovery, profiles) with overlapping filters
	backend::OpenOptions open_options;
	open_options.filter	  = filter;
	open_options.sniff	  = true;
	open_options.priority = 1000;
	std::string open_error;
	state_->fad_handle = backend::open(open_options, open_error);
	if (!state_->fad_handle)
	{
		LOG_ERROR_GROUP(logging::group::forwarded, "Forwarded address discovery setup: failed to open capture channel: %s", open_error.c_str());
		return;
	}
	LOG_INFO("Forwarded address discovery enabled (inbound ifIdx %u, outbound ifIdx %u)", inbound_if_idx, outbound_if_idx);
	state_->fad_thread = std::thread(&PacketEngine::forwarded_address_discovery_recv, this);
}

void PacketEngine::apply_forwarded_address_winner(AddressCounts& counts, bool is_destination)
{
	const uint64_t window_ms = options_.features.forwarded_address_discovery.window_ms;
	const char*	   label	 = is_destination ? "client destination address (inbound)" : "client source address (outbound)";
	if (counts.empty())
	{
		LOG_DEBUG_GROUP(logging::group::forwarded,
						"Forwarded address discovery: no packets observed for %s in the last %s window",
						label,
						logging::format_duration(window_ms).c_str());
		return;
	}
	const auto winner = std::max_element(counts.begin(), counts.end(), [](const auto& left, const auto& right) {
		return left.second < right.second;
	});
	LOG_DEBUG_GROUP(logging::group::forwarded,
					"Forwarded address discovery: %s window closed with %zu candidate address(es); winner '%s' with %llu packet(s)",
					label,
					counts.size(),
					winner->first.c_str(),
					static_cast<unsigned long long>(winner->second));
	std::string previous;
	bool		changed = false;
	{
		std::lock_guard<std::mutex> lock(state_->fad_mutex);
		std::string&				target = is_destination ? state_->fad_client_destination_address : state_->fad_client_source_address;
		if (target != winner->first)
		{
			previous = target;
			target	 = winner->first;
			changed	 = true;
		}
	}
	if (!changed)
		return;
	LOG_SERVER("Forwarded address discovery: %s changed from '%s' to '%s' (%llu packets in %s)",
			   label,
			   previous.empty() ? "none" : previous.c_str(),
			   winner->first.c_str(),
			   static_cast<unsigned long long>(winner->second),
			   logging::format_duration(window_ms).c_str());

	std::vector<int> active_profiles;
	{
		std::lock_guard<std::mutex> lifecycle_lock(state_->lifecycle_mutex);
		for (size_t index = 0; index < state_->active_profiles.size(); ++index)
			if (state_->active_profiles[index])
				active_profiles.push_back(static_cast<int>(index + 1));
	}
	for (const int profile : active_profiles)
		teardown(profile);
	for (const int profile : active_profiles)
		setup(profile);
}

void PacketEngine::forwarded_address_discovery_recv()
{
	const uint32_t inbound_if_idx  = *options_.features.forwarded_address_discovery.inbound_if_idx;
	const uint32_t outbound_if_idx = *options_.features.forwarded_address_discovery.outbound_if_idx;
	const uint64_t window_ms	   = options_.features.forwarded_address_discovery.window_ms;

	AddressCounts destination_counts;
	AddressCounts source_counts;
	uint64_t	  window_started = platform::tick_ms();
	uint8_t		  packet_data[0xFFFF];
	while (!shutdown_)
	{
		backend::PacketMeta address;
		uint32_t			received_length = 0;
		std::string			io_error;
		const backend::IoStatus recv_status =
			state_->fad_handle->recv(packet_data, sizeof(packet_data), received_length, address, io_error);
		if (recv_status == backend::IoStatus::ok)
		{
			if (!count_forwarded_address(packet_data, received_length, address, inbound_if_idx, outbound_if_idx, destination_counts, source_counts))
				continue;
		}
		else if (!shutdown_ && recv_status == backend::IoStatus::error)
		{
			LOG_ERROR_GROUP(logging::group::forwarded, "Forwarded address discovery recv: %s", io_error.c_str());
		}

		const uint64_t now = platform::tick_ms();
		if (now - window_started < window_ms)
			continue;
		LOG_DEBUG_GROUP(logging::group::forwarded,
						"Forwarded address discovery: window closed after %s (dst candidates=%zu, src candidates=%zu)",
						logging::format_duration(now - window_started).c_str(),
						destination_counts.size(),
						source_counts.size());
		apply_forwarded_address_winner(destination_counts, true);
		apply_forwarded_address_winner(source_counts, false);
		destination_counts.clear();
		source_counts.clear();
		window_started = now;
	}
}

bool PacketEngine::is_forwarded_address_discovery_enabled() const
{
	return options_.features.forwarded_address_discovery.enabled;
}

std::string PacketEngine::forwarded_address_discovery_status() const
{
	if (!options_.features.forwarded_address_discovery.enabled)
		return {};

	std::lock_guard<std::mutex> lock(state_->fad_mutex);
	const std::string			 source		 = state_->fad_client_source_address.empty() ? "unknown" : state_->fad_client_source_address;
	const std::string			 destination = state_->fad_client_destination_address.empty() ? "unknown" : state_->fad_client_destination_address;
	return "src: " + source + ", dst: " + destination;
}

#endif
