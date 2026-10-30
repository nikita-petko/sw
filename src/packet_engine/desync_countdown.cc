#include "internal.h"

#ifdef LAGSW_FEATURE_DESYNC_COUNTDOWN

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

#endif
