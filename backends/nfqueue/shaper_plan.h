#ifndef NFQUEUE_SHAPER_PLAN_H_
#define NFQUEUE_SHAPER_PLAN_H_

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "filter_compiler.h"
#include "shaper/bpf_shared.h"

/// Translates a compiled capture filter plus a shaping behaviour into the data the egress eBPF program evaluates, or says
/// why it cannot. Pure: no kernel access, so the rules for "never silently approximate" are unit-testable.
namespace nfq::shaping {

/// What the egress program does with matching packets.
enum class Behaviour
{
	fixed_delay,  ///< Hold each packet for `delay_ms` (profile `from_timestamp`).
	drop,		  ///< Drop every packet (profile `drop`).
	batch_delay,  ///< The first packet opens a batch; all of its packets leave `delay_ms` later (`send_all_after_delay`).
	baseline,	  ///< Per-packet delay drawn from a model (passive latency).
};

enum class Model
{
	fixed,
	uniform,
	normal,
};

struct StageSpec
{
	std::vector<CompiledRule> rules;
	Behaviour				  behaviour		 = Behaviour::fixed_delay;
	Model					  model			 = Model::fixed;
	uint32_t				  delay_ms		 = 0;
	uint32_t				  jitter_ms		 = 0;
	uint32_t				  max_delay_ms	 = 0;
	bool					  preserve_order = true;
	/// Inbound packets are not shaped by this stage (their delay is zero), so input-hook rules can be ignored.
	bool					  ignore_inbound = false;
};

/// Longest delay the egress tier accepts, and so the horizon the `fq` qdisc needs.
inline constexpr uint32_t kMaxDelayMs = 600000;
/// Address sets one stage may use; set ids are `set_base + index`.
inline constexpr uint32_t kMaxSetsPerStage = 256;

struct AddressSet
{
	uint32_t			  id = 0;
	std::vector<uint32_t> addrs;  ///< Host byte order, sorted, unique.
};

struct Plan
{
	bool					ok = false;
	/// Why the stage cannot run on the egress tier; empty when `ok`.
	std::string				reason;
	lagsw_stage				stage{};
	std::vector<AddressSet> sets;
};

/// Builds the program configuration for a stage. `set_base` is the first set id the stage may use. The stage is returned
/// inactive.
Plan plan_stage(const StageSpec& spec, uint32_t set_base);

/// Standard scores at the midpoints of 1024 equal-probability slices of the normal distribution, multiplied by
/// LAGSW_NORMAL_SCALE; the program picks one at random per packet.
std::array<int32_t, LAGSW_NORMAL_STEPS> normal_scores();

}  // namespace nfq::shaping

#endif
