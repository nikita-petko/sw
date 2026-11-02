#include "delay_model.h"

#include <algorithm>
#include <cmath>

DelayModel::DelayModel(const DelayModelOptions& options, uint64_t seed) : options_(options), rng_(seed)
{
}

uint64_t DelayModel::sample(DelayDirection direction)
{
	const DirectionDelay& params = options_.directions[static_cast<int>(direction)];
	double				  value	 = params.delay_ms;
	if (params.jitter_ms > 0)
	{
		switch (options_.kind)
		{
			case DelayModelKind::fixed:
				break;
			case DelayModelKind::uniform:
				value += std::uniform_real_distribution<double>(-params.jitter_ms, params.jitter_ms)(rng_);
				break;
			case DelayModelKind::normal:
				value += std::normal_distribution<double>(0.0, params.jitter_ms)(rng_);
				break;
		}
	}
	const double clamped = std::clamp(std::round(value), 0.0, static_cast<double>((std::max)(params.max_delay_ms, 0)));
	return static_cast<uint64_t>(clamped);
}

uint64_t DelayModel::release_at(DelayDirection direction, uint64_t now)
{
	uint64_t release = now + sample(direction);
	if (options_.preserve_order)
	{
		uint64_t& last = last_release_[static_cast<int>(direction)];
		release		   = (std::max)(release, last);
		last		   = release;
	}
	return release;
}

void DelayModel::reset()
{
	last_release_[0] = 0;
	last_release_[1] = 0;
}
