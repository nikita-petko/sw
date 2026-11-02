// Unit tests for the egress-tier planner (backends/nfqueue/shaper_plan.*): which stages the eBPF program can serve, and the exact data it
// receives. No kernel, libbpf or privilege is involved.
#include <arpa/inet.h>

#include <cmath>
#include <cstdint>
#include <string>
#include <vector>

#include "filter_compiler.h"
#include "shaper_plan.h"
#include "support/test.h"

namespace {
using namespace nfq::shaping;

StageSpec spec_for(const std::string& filter, bool forward = false, bool include_forward = false)
{
	StageSpec	spec;
	std::string error;
	uint32_t	position = 0;
	CHECK(nfq::compile_filter(filter, forward, spec.rules, error, position, include_forward));
	spec.delay_ms = 100;
	return spec;
}

void test_forward_and_output_rules_become_hook_bits()
{
	const Plan forward = plan_stage(spec_for("tcp.DstPort == 443", true), 0);
	CHECK(forward.ok && forward.stage.rule_count == 1);
	CHECK(forward.stage.rules[0].hooks == LAGSW_HOOK_FORWARD);
	const Plan local = plan_stage(spec_for("tcp.DstPort == 443 and outbound"), 0);
	CHECK(local.ok && local.stage.rule_count == 1 && local.stage.rules[0].hooks == LAGSW_HOOK_LOCAL);
	const Plan both = plan_stage(spec_for("tcp.DstPort == 443 and outbound", false, true), 0);
	CHECK(both.ok && both.stage.rule_count == 2);
	CHECK(both.stage.rules[0].hooks == LAGSW_HOOK_LOCAL && both.stage.rules[1].hooks == LAGSW_HOOK_FORWARD);
}

void test_inbound_traffic_cannot_be_served_unless_it_is_ignored()
{
	StageSpec  spec	   = spec_for("tcp");
	const Plan refused = plan_stage(spec, 0);
	CHECK(!refused.ok && refused.reason.find("inbound") != std::string::npos);

	spec.ignore_inbound = true;
	const Plan ignored	= plan_stage(spec, 0);
	CHECK(ignored.ok && ignored.stage.rule_count == 1);	 // only the output-hook rule is left

	StageSpec only_inbound		= spec_for("tcp and inbound");
	only_inbound.ignore_inbound = true;
	const Plan none				= plan_stage(only_inbound, 0);
	CHECK(!none.ok && none.reason.find("only inbound") != std::string::npos);
}

void test_matches_are_translated_exactly()
{
	StageSpec  spec = spec_for("tcp.Syn and not tcp.Ack and tcp.SrcPort != 80 and ip.DstAddr == 10.1.2.3 and ifIdx == 7", true);
	const Plan plan = plan_stage(spec, 0);
	CHECK(plan.ok);
	if (!plan.ok)
		return;
	// forward traffic matches the interface on either side, so the interface condition splits the clause in two
	CHECK(plan.stage.rule_count == 2);
	const lagsw_rule& rule = plan.stage.rules[0];
	CHECK(rule.count == 6);
	CHECK(rule.matches[0].kind == LAGSW_MATCH_PROTOCOL && rule.matches[0].proto == IPPROTO_TCP && !rule.matches[0].negated);
	CHECK(rule.matches[1].kind == LAGSW_MATCH_TCP_FLAG && rule.matches[1].flag == 0x02 && !rule.matches[1].negated);
	CHECK(rule.matches[2].kind == LAGSW_MATCH_TCP_FLAG && rule.matches[2].flag == 0x10 && rule.matches[2].negated);
	CHECK(rule.matches[3].kind == LAGSW_MATCH_PORT && rule.matches[3].endpoint == 0 && rule.matches[3].port == 80 &&
		  rule.matches[3].negated);
	CHECK(rule.matches[4].kind == LAGSW_MATCH_ADDRESS && rule.matches[4].endpoint == 1 && !rule.matches[4].is_set &&
		  rule.matches[4].value == htonl(0x0A010203));
	CHECK(rule.matches[5].kind == LAGSW_MATCH_IIF && rule.matches[5].value == 7);
	CHECK(plan.stage.rules[1].matches[5].kind == LAGSW_MATCH_OIF);
}

void test_address_lists_become_shared_sets()
{
	const Plan plan = plan_stage(spec_for("(ip.DstAddr == 3.3.3.3 or ip.DstAddr == 1.1.1.1 or ip.DstAddr == 3.3.3.3) and outbound"), 512);
	CHECK(plan.ok);
	CHECK(plan.sets.size() == 1);
	if (plan.sets.size() == 1)
	{
		CHECK(plan.sets[0].id == 512 && plan.sets[0].addrs == (std::vector<uint32_t>{0x01010101, 0x03030303}));
		CHECK(plan.stage.rules[0].matches[0].is_set && plan.stage.rules[0].matches[0].value == 512);
	}
	// the same list on the other side reuses the set
	const Plan sides = plan_stage(spec_for("(ip.Addr == 1.1.1.1 or ip.Addr == 2.2.2.2) and outbound"), 0);
	CHECK(sides.ok && sides.sets.size() == 1 && sides.stage.rule_count == 2);
}

void test_behaviours_and_delays()
{
	StageSpec spec	= spec_for("tcp and outbound");
	spec.behaviour	= Behaviour::drop;
	spec.delay_ms	= 0;
	const Plan drop = plan_stage(spec, 0);
	CHECK(drop.ok && drop.stage.mode == LAGSW_MODE_DROP && drop.stage.active == 0);

	spec.behaviour	= Behaviour::fixed_delay;
	const Plan zero = plan_stage(spec, 0);
	CHECK(!zero.ok && zero.reason.find("until deactivation") != std::string::npos);

	spec.delay_ms	 = 250;
	const Plan fixed = plan_stage(spec, 0);
	CHECK(fixed.ok && fixed.stage.mode == LAGSW_MODE_DELAY && fixed.stage.delay_ns == 250000000ull &&
		  fixed.stage.max_delay_ns == 250000000ull);
	CHECK(fixed.stage.preserve_order == 0 && fixed.stage.jitter_ns == 0);

	spec.behaviour	 = Behaviour::batch_delay;
	const Plan batch = plan_stage(spec, 0);
	CHECK(batch.ok && batch.stage.mode == LAGSW_MODE_BATCH);

	spec.delay_ms = kMaxDelayMs + 1;
	CHECK(!plan_stage(spec, 0).ok);
	spec.delay_ms = kMaxDelayMs;
	CHECK(plan_stage(spec, 0).ok);
}

void test_the_baseline_carries_its_model()
{
	StageSpec spec		= spec_for("tcp and outbound");
	spec.behaviour		= Behaviour::baseline;
	spec.model			= Model::normal;
	spec.delay_ms		= 80;
	spec.jitter_ms		= 15;
	spec.max_delay_ms	= 125;
	spec.preserve_order = true;
	const Plan plan		= plan_stage(spec, 0);
	CHECK(plan.ok && plan.stage.model == LAGSW_MODEL_NORMAL && plan.stage.preserve_order == 1);
	CHECK(plan.stage.delay_ns == 80000000ull && plan.stage.jitter_ns == 15000000ull && plan.stage.max_delay_ns == 125000000ull);

	spec.model = Model::fixed;
	CHECK(plan_stage(spec, 0).stage.jitter_ns == 0);
	spec.delay_ms = 0;
	CHECK(!plan_stage(spec, 0).ok);
}

void test_limits_are_reported_not_approximated()
{
	std::string filter;
	for (int index = 0; index < 20; ++index)
		filter += (index == 0 ? "" : " or ") + std::string("tcp.DstPort == ") + std::to_string(1000 + index);
	const Plan too_many_rules = plan_stage(spec_for("(" + filter + ") and outbound"), 0);
	CHECK(!too_many_rules.ok && too_many_rules.reason.find("rules") != std::string::npos);

	const Plan too_many_conditions = plan_stage(spec_for("tcp.Syn and not tcp.Ack and not tcp.Fin and not tcp.Rst and not tcp.Psh and not "
														 "tcp.Urg and tcp.DstPort == 1 and ip.DstAddr == 1.2.3.4 and outbound"),
												0);
	CHECK(!too_many_conditions.ok && too_many_conditions.reason.find("conditions") != std::string::npos);
}

void test_normal_scores_follow_the_standard_normal_distribution()
{
	const auto scores = normal_scores();
	double	   sum = 0, square = 0;
	for (const int32_t score : scores)
	{
		sum += score;
		square += static_cast<double>(score) * score;
	}
	const double mean = sum / scores.size() / LAGSW_NORMAL_SCALE;
	const double sd	  = std::sqrt(square / scores.size()) / LAGSW_NORMAL_SCALE;
	CHECK(std::fabs(mean) < 1e-4);
	CHECK(sd > 0.98 && sd < 1.0);  // the midpoint table cuts the tails at about 3.3 sigma
	for (size_t index = 1; index < scores.size(); ++index)
		CHECK(scores[index] >= scores[index - 1]);
	CHECK(scores.front() < -3000000 && scores.back() > 3000000);
	CHECK(std::abs(scores[scores.size() / 2 - 1] + scores[scores.size() / 2]) < 3000);
	// the 84.13th percentile is one standard deviation above the mean
	CHECK(std::abs(scores[static_cast<size_t>(0.8413 * scores.size())] - 1000000) < 15000);
}
}  // namespace

int main(int argc, char** argv)
{
	static const test::TestCase cases[] = {
		{"forward_and_output_rules_become_hook_bits", test_forward_and_output_rules_become_hook_bits},
		{"inbound_traffic_cannot_be_served_unless_it_is_ignored", test_inbound_traffic_cannot_be_served_unless_it_is_ignored},
		{"matches_are_translated_exactly", test_matches_are_translated_exactly},
		{"address_lists_become_shared_sets", test_address_lists_become_shared_sets},
		{"behaviours_and_delays", test_behaviours_and_delays},
		{"the_baseline_carries_its_model", test_the_baseline_carries_its_model},
		{"limits_are_reported_not_approximated", test_limits_are_reported_not_approximated},
		{"normal_scores_follow_the_standard_normal_distribution", test_normal_scores_follow_the_standard_normal_distribution},
	};
	return test::run_tests("shaper_plan", cases, argc, argv);
}
