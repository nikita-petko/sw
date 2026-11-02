#include "shaper_plan.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <algorithm>
#include <cmath>
#include <map>

namespace nfq::shaping {
namespace {
Plan failed(std::string reason)
{
	Plan plan;
	plan.reason = std::move(reason);
	return plan;
}

uint8_t protocol_number(Transport transport)
{
	return transport == Transport::tcp ? IPPROTO_TCP : IPPROTO_UDP;
}

std::vector<uint32_t> normalized(std::vector<uint32_t> addrs)
{
	std::sort(addrs.begin(), addrs.end());
	addrs.erase(std::unique(addrs.begin(), addrs.end()), addrs.end());
	return addrs;
}

/// Inverse of the standard normal distribution function (Acklam's rational approximation, relative error below 1.2e-9).
double normal_quantile(double p)
{
	static const double a[] = {-3.969683028665376e+01, 2.209460984245205e+02, -2.759285104469687e+02, 1.383577518672690e+02, -3.066479806614716e+01, 2.506628277459239e+00};
	static const double b[] = {-5.447609879822406e+01, 1.615858368580409e+02, -1.556989798598866e+02, 6.680131188771972e+01, -1.328068155288572e+01};
	static const double c[] = {-7.784894002430293e-03, -3.223964580411365e-01, -2.400758277161838e+00, -2.549732539343734e+00, 4.374664141464968e+00, 2.938163982698783e+00};
	static const double d[] = {7.784695709041462e-03, 3.224671290700398e-01, 2.445134137142996e+00, 3.754408661907416e+00};
	const double		low = 0.02425;
	if (p < low)
	{
		const double q = std::sqrt(-2 * std::log(p));
		return (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1);
	}
	if (p > 1 - low)
	{
		const double q = std::sqrt(-2 * std::log(1 - p));
		return -(((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1);
	}
	const double q = p - 0.5;
	const double r = q * q;
	return (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5]) * q / (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1);
}
}  // namespace

std::array<int32_t, LAGSW_NORMAL_STEPS> normal_scores()
{
	std::array<int32_t, LAGSW_NORMAL_STEPS> scores{};
	for (uint32_t index = 0; index < LAGSW_NORMAL_STEPS; ++index)
		scores[index] = static_cast<int32_t>(std::lround(normal_quantile((index + 0.5) / LAGSW_NORMAL_STEPS) * LAGSW_NORMAL_SCALE));
	return scores;
}

Plan plan_stage(const StageSpec& spec, uint32_t set_base)
{
	Plan plan;
	if (spec.behaviour == Behaviour::fixed_delay || spec.behaviour == Behaviour::batch_delay)
	{
		// A mode without a delay holds packets until the profile ends, which a timestamp cannot express.
		if (spec.delay_ms == 0)
			return failed("a delay of 0 holds packets until deactivation, which needs the user-space queue");
	}
	if (spec.delay_ms > kMaxDelayMs || spec.max_delay_ms > kMaxDelayMs)
		return failed("a delay above " + std::to_string(kMaxDelayMs) + " ms exceeds what the egress qdisc can schedule");
	if (spec.behaviour == Behaviour::baseline && spec.delay_ms == 0)
		return failed("the baseline has no delay");

	lagsw_stage& stage = plan.stage;
	switch (spec.behaviour)
	{
		case Behaviour::fixed_delay:
			stage.mode = LAGSW_MODE_DELAY;
			break;
		case Behaviour::drop:
			stage.mode = LAGSW_MODE_DROP;
			break;
		case Behaviour::batch_delay:
			stage.mode = LAGSW_MODE_BATCH;
			break;
		case Behaviour::baseline:
			stage.mode = LAGSW_MODE_DELAY;
			break;
	}
	stage.model			 = spec.model == Model::uniform ? LAGSW_MODEL_UNIFORM : spec.model == Model::normal ? LAGSW_MODEL_NORMAL : LAGSW_MODEL_FIXED;
	stage.preserve_order = spec.behaviour == Behaviour::baseline && spec.preserve_order ? 1 : 0;
	stage.delay_ns		 = static_cast<uint64_t>(spec.delay_ms) * 1000000ull;
	stage.jitter_ns		 = spec.model == Model::fixed ? 0 : static_cast<uint64_t>(spec.jitter_ms) * 1000000ull;
	stage.max_delay_ns	 = static_cast<uint64_t>(spec.behaviour == Behaviour::baseline ? spec.max_delay_ms : spec.delay_ms) * 1000000ull;

	std::map<std::vector<uint32_t>, uint32_t> set_ids;
	uint32_t								 rule_count = 0;
	bool									 saw_inbound = false;
	for (const CompiledRule& compiled : spec.rules)
	{
		if (compiled.hook == Hook::input)
		{
			saw_inbound = true;
			if (spec.ignore_inbound)
				continue;
			return failed("the filter also matches inbound traffic, which an egress program never sees (use `outbound: true` or `forward: true`)");
		}
		if (rule_count == LAGSW_MAX_RULES)
			return failed("the filter expands to more than " + std::to_string(LAGSW_MAX_RULES) + " rules");
		lagsw_rule& rule = stage.rules[rule_count];
		rule.hooks		 = compiled.hook == Hook::forward ? LAGSW_HOOK_FORWARD : LAGSW_HOOK_LOCAL;
		for (const Match& match : compiled.matches)
		{
			if (match.kind == MatchKind::nfproto_ipv4)
				continue;
			if (rule.count == LAGSW_MAX_MATCHES)
				return failed("a filter clause has more than " + std::to_string(LAGSW_MAX_MATCHES) + " conditions");
			lagsw_match& out = rule.matches[rule.count++];
			out.negated		 = match.negated ? 1 : 0;
			switch (match.kind)
			{
				case MatchKind::nfproto_ipv4:
					break;
				case MatchKind::ip_protocol:
					out.kind  = LAGSW_MATCH_PROTOCOL;
					out.proto = protocol_number(match.transport);
					break;
				case MatchKind::tcp_flag:
					out.kind = LAGSW_MATCH_TCP_FLAG;
					out.flag = match.tcp_flag;
					break;
				case MatchKind::ip_addr:
				{
					out.kind	 = LAGSW_MATCH_ADDRESS;
					out.endpoint = match.endpoint == Endpoint::destination ? 1 : 0;
					const std::vector<uint32_t> addrs = normalized(match.addrs);
					if (addrs.size() == 1)
					{
						out.value = htonl(addrs.front());
						break;
					}
					auto found = set_ids.find(addrs);
					if (found == set_ids.end())
					{
						if (set_ids.size() == kMaxSetsPerStage)
							return failed("the filter uses more than " + std::to_string(kMaxSetsPerStage) + " distinct address lists");
						found = set_ids.emplace(addrs, set_base + static_cast<uint32_t>(set_ids.size())).first;
						plan.sets.push_back({found->second, addrs});
					}
					out.is_set = 1;
					out.value  = found->second;
					break;
				}
				case MatchKind::port:
					out.kind	 = LAGSW_MATCH_PORT;
					out.proto	 = protocol_number(match.transport);
					out.endpoint = match.endpoint == Endpoint::destination ? 1 : 0;
					out.port	 = match.port;
					break;
				case MatchKind::interface:
					out.kind  = match.output ? LAGSW_MATCH_OIF : LAGSW_MATCH_IIF;
					out.value = match.index;
					break;
			}
		}
		++rule_count;
	}
	if (rule_count == 0)
		return failed(saw_inbound ? "the filter matches only inbound traffic" : "the filter matches no packets");
	stage.rule_count = rule_count;
	plan.ok			 = true;
	return plan;
}

}  // namespace nfq::shaping
