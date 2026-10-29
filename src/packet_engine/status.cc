#include "internal.h"

#include <algorithm>
#include <limits>

#include "log.h"
#include "platform.h"

std::string PacketEngine::forwarded_address_discovery_status() const
{
	if (!options_.features.forwarded_address_discovery.enabled)
		return {};

	std::lock_guard<std::mutex> lock(state_->fad_mutex);
	const std::string			 source		 = state_->fad_client_source_address.empty() ? "unknown" : state_->fad_client_source_address;
	const std::string			 destination = state_->fad_client_destination_address.empty() ? "unknown" : state_->fad_client_destination_address;
	return "src: " + source + ", dst: " + destination;
}

std::optional<std::string> PacketEngine::effective_client_source_address() const
{
	if (options_.features.forwarded_address_discovery.enabled)
	{
		std::lock_guard<std::mutex> lock(state_->fad_mutex);
		if (!state_->fad_client_source_address.empty())
			return state_->fad_client_source_address;
	}
	return options_.client_source_address;
}

std::optional<std::string> PacketEngine::effective_client_destination_address() const
{
	if (options_.features.forwarded_address_discovery.enabled)
	{
		std::lock_guard<std::mutex> lock(state_->fad_mutex);
		if (!state_->fad_client_destination_address.empty())
			return state_->fad_client_destination_address;
	}
	return options_.client_destination_address;
}

std::string PacketEngine::region_enforcement_status() const
{
	if (!options_.features.region_enforcement.enabled)
		return {};

	std::lock_guard<std::mutex> lock(state_->probe_mutex);
	if (!state_->probe_received)
		return "Waiting for probes...";

	const uint64_t now = platform::tick_ms();
	if (now >= state_->next_check_time)
		return "~0s";

	const uint64_t remaining_ms = state_->next_check_time - now;
	return "~" + logging::format_duration(remaining_ms);
}

uint64_t PacketEngine::running_time_ms() const
{
	const uint64_t				now = platform::tick_ms();
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	uint64_t					earliest_enabled   = now;
	bool						has_active_profile = false;
	for (size_t index = 0; index < options_.profiles.size(); ++index)
	{
		if (state_->active_profiles[index])
		{
			has_active_profile = true;
			earliest_enabled   = (std::min)(earliest_enabled, state_->profile_stats[index].enabled_since);
		}
	}
	return has_active_profile ? now - earliest_enabled : 0;
}

uint64_t PacketEngine::profile_running_time_ms(int profile) const
{
	if (profile < 1 || static_cast<size_t>(profile) > options_.profiles.size())
		return 0;
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	const size_t				index = static_cast<size_t>(profile - 1);
	return state_->active_profiles[index] ? platform::tick_ms() - state_->profile_stats[index].enabled_since : 0;
}

std::string PacketEngine::profile_packet_status(int profile) const
{
	if (profile < 1 || static_cast<size_t>(profile) > options_.profiles.size())
		return {};
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	const std::shared_ptr<Session>& session = state_->active_sessions[profile - 1];
	if (!session)
		return {};
	std::lock_guard<std::mutex> packet_lock(session->packet_mutex);
	return session->mode->status();
}

std::optional<uint64_t> PacketEngine::profile_desync_countdown_ms(int profile) const
{
	if (profile < 1 || static_cast<size_t>(profile) > options_.profiles.size())
		return std::nullopt;
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	const size_t				index = static_cast<size_t>(profile - 1);
	const State::ProfileStats& stats = state_->profile_stats[index];
	const bool hide_while_active = options_.features.desync_countdown.display == DesyncCountdownDisplay::until_reactivated;
	if ((hide_while_active && state_->active_profiles[index]) || stats.enabled_count == 0 || stats.last_disabled_at == 0)
		return std::nullopt;
	const uint64_t duration_percent = options_.features.desync_countdown.duration_percent;
	const uint64_t estimate_ms = (stats.last_enabled_time / 100) * duration_percent +
								  (stats.last_enabled_time % 100) * duration_percent / 100;
	const uint64_t elapsed_ms = platform::tick_ms() - stats.last_disabled_at;
	if (elapsed_ms >= estimate_ms)
		return std::nullopt;
	return estimate_ms - elapsed_ms;
}

size_t PacketEngine::pending_packets() const
{
	size_t						pending = 0;
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	for (const auto& session : state_->active_sessions)
		if (session)
		{
			std::lock_guard<std::mutex> session_lock(session->packet_mutex);
			pending += session->delayed_packets.size();
		}
	return pending;
}

uint64_t PacketEngine::next_batch_in_ms() const
{
	uint64_t					next_release	   = (std::numeric_limits<uint64_t>::max)();
	bool						has_queued_packets = false;
	const uint64_t				now				   = platform::tick_ms();
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	for (const auto& session : state_->active_sessions)
		if (session)
		{
			std::lock_guard<std::mutex> session_lock(session->packet_mutex);
			if (!session->delayed_packets.empty())
			{
				has_queued_packets = true;
				next_release	   = (std::min)(next_release, session->delayed_packets.top()->release_at);
			}
		}
	if (!has_queued_packets)
		return 0;
	if (next_release == (std::numeric_limits<uint64_t>::max)())
		return (std::numeric_limits<uint64_t>::max)();
	return next_release > now ? next_release - now : 0;
}
