#ifndef DELAY_MODEL_H_
#define DELAY_MODEL_H_

#include <cstdint>
#include <random>

/// Distribution used to draw a packet's baseline delay (see pocs/passive_latency.md).
enum class DelayModelKind
{
	fixed,	  ///< Always the configured delay.
	uniform,  ///< Delay plus a uniform offset in [-jitter, +jitter].
	normal,	  ///< Delay plus a normally distributed offset with the jitter as standard deviation.
};

/// Which way a packet travels relative to this machine.
enum class DelayDirection
{
	outbound = 0,
	inbound	 = 1,
};

/// Delay parameters for one direction, in milliseconds.
struct DirectionDelay
{
	/// Fixed delay, or the mean for uniform and normal models.
	int32_t delay_ms = 0;
	/// Uniform half-range or normal standard deviation. Ignored by the fixed model.
	int32_t jitter_ms = 0;
	/// Upper clamp applied after sampling.
	int32_t max_delay_ms = 0;
};

/// Complete delay-model configuration.
struct DelayModelOptions
{
	DelayModelKind kind = DelayModelKind::fixed;
	/// Per-direction parameters, indexed by DelayDirection.
	DirectionDelay directions[2];
	/// Never release a packet before an earlier packet of the same direction.
	bool preserve_order = true;
};

/// Draws per-packet release times. Not thread-safe: use one instance per owning thread or guard it externally.
class DelayModel
{
public:
	/// Creates a model; the same options and seed always yield the same sequence.
	DelayModel(const DelayModelOptions& options, uint64_t seed);

	/// Samples a delay in milliseconds, clamped to [0, max_delay_ms], without touching ordering state.
	uint64_t sample(DelayDirection direction);
	/// Returns the release time for a packet seen at `now`, honoring preserve_order.
	uint64_t release_at(DelayDirection direction, uint64_t now);
	/// Forgets ordering state, for example after a pause flushes the queue.
	void reset();

private:
	DelayModelOptions options_;
	std::mt19937_64	  rng_;
	uint64_t		  last_release_[2] = {0, 0};
};

#endif
