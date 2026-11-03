#include "filter_program.h"

#include <algorithm>
#include <map>

#include "../nfqueue/filter_compiler.h"

namespace kmodf {
namespace {
	swdiv_insn test(uint16_t op, uint16_t src, uint32_t a, uint32_t b = 0)
	{
		swdiv_insn insn = {};
		insn.op			= op;
		insn.src		= src;
		insn.a			= a;
		insn.b			= b;
		return insn;
	}

	uint16_t port_source(const nfq::Match& match)
	{
		const bool tcp = match.transport == nfq::Transport::tcp;
		const bool src = match.endpoint == nfq::Endpoint::source;
		return tcp ? (src ? SWDIV_SRC_TCP_SPORT : SWDIV_SRC_TCP_DPORT) : (src ? SWDIV_SRC_UDP_SPORT : SWDIV_SRC_UDP_DPORT);
	}
}  // namespace

bool compile_program(const std::string& filter, Program& out, std::string& error, uint32_t& position)
{
	std::vector<nfq::CompiledRule> rules;
	if (!nfq::compile_filter(filter, true, rules, error, position))
		return false;

	Program								  program;
	std::map<std::vector<uint32_t>, uint32_t> address_sets;
	for (const nfq::CompiledRule& rule : rules)
	{
		const size_t first = program.insns.size();
		for (const nfq::Match& match : rule.matches)
		{
			switch (match.kind)
			{
				case nfq::MatchKind::nfproto_ipv4:
					break;	// every packet of the IPv4 hook is IPv4; the VM fails every field test of anything else
				case nfq::MatchKind::ip_protocol:
					program.insns.push_back(test(match.negated ? SWDIV_OP_NE : SWDIV_OP_EQ, SWDIV_SRC_IP_PROTO, match.transport == nfq::Transport::tcp ? 6 : 17));
					break;
				case nfq::MatchKind::tcp_flag:
					program.insns.push_back(test(SWDIV_OP_MASK_EQ, SWDIV_SRC_TCP_FLAGS, match.tcp_flag, match.negated ? 0 : match.tcp_flag));
					break;
				case nfq::MatchKind::ip_addr:
					{
						const uint16_t src = match.endpoint == nfq::Endpoint::source ? SWDIV_SRC_IP_SRC : SWDIV_SRC_IP_DST;
						std::vector<uint32_t> addrs = match.addrs;
						std::sort(addrs.begin(), addrs.end());
						addrs.erase(std::unique(addrs.begin(), addrs.end()), addrs.end());
						if (addrs.size() == 1)
						{
							program.insns.push_back(test(match.negated ? SWDIV_OP_NE : SWDIV_OP_EQ, src, addrs.front()));
							break;
						}
						if (addrs.size() > SWDIV_MAX_SET_ELEMS)
						{
							error	 = "address list is too long for the kernel filter (more than " + std::to_string(SWDIV_MAX_SET_ELEMS) + " addresses)";
							position = 0;
							return false;
						}
						auto found = address_sets.find(addrs);
						if (found == address_sets.end())
						{
							if (program.sets.size() >= SWDIV_MAX_SETS)
							{
								error	 = "filter has too many different address lists for the kernel filter (more than " + std::to_string(SWDIV_MAX_SETS) + ")";
								position = 0;
								return false;
							}
							found = address_sets.emplace(addrs, static_cast<uint32_t>(program.sets.size())).first;
							program.sets.push_back({SWDIV_SET_IPV4, addrs});
						}
						program.insns.push_back(test(match.negated ? SWDIV_OP_NOT_IN_SET : SWDIV_OP_IN_SET, src, found->second));
						break;
					}
				case nfq::MatchKind::port:
					program.insns.push_back(test(match.negated ? SWDIV_OP_NE : SWDIV_OP_EQ, port_source(match), match.port));
					break;
				case nfq::MatchKind::interface:
					program.insns.push_back(test(match.negated ? SWDIV_OP_NE : SWDIV_OP_EQ, match.output ? SWDIV_SRC_OUT_IFINDEX : SWDIV_SRC_IN_IFINDEX, match.index));
					break;
			}
		}
		program.insns.push_back(swdiv_insn{SWDIV_OP_ACCEPT, 0, 0, 0, 0, 0});
		// A failing test of this clause continues with the next clause
		const uint16_t next = static_cast<uint16_t>(std::min<size_t>(program.insns.size(), 0xFFFF));
		for (size_t index = first; index + 1 < program.insns.size(); ++index)
			program.insns[index].fail = next;
		if (program.insns.size() > SWDIV_MAX_INSNS)
		{
			error	 = "filter is too complex for the kernel filter (more than " + std::to_string(SWDIV_MAX_INSNS) + " instructions)";
			position = 0;
			return false;
		}
	}
	out = std::move(program);
	return true;
}

std::vector<swdiv_vm_set> vm_sets(const Program& program)
{
	std::vector<swdiv_vm_set> sets;
	for (const SetData& set : program.sets)
	{
		const uint32_t per_element = set.kind == SWDIV_SET_PORTS ? 2 : 1;
		sets.push_back({set.kind, static_cast<uint32_t>(set.elems.size() / per_element), set.elems.data()});
	}
	return sets;
}

std::string verify_program(const Program& program)
{
	if (program.sets.size() > SWDIV_MAX_SETS)
		return "too many sets";
	uint64_t total = 0;
	for (const SetData& set : program.sets)
	{
		const size_t per_element = set.kind == SWDIV_SET_PORTS ? 2 : 1;
		if (set.elems.size() % per_element != 0)
			return "a port set needs pairs";
		total += set.elems.size();
		if (swdiv_vm_verify_set(set.kind, static_cast<uint32_t>(set.elems.size() / per_element), set.elems.data()) != 0)
			return "a set is not sorted, has duplicates or overlapping ranges";
	}
	if (total > SWDIV_MAX_TOTAL_ELEMS)
		return "the sets are too large together";
	const std::vector<swdiv_vm_set> sets = vm_sets(program);
	if (swdiv_vm_verify(program.insns.data(), static_cast<uint32_t>(program.insns.size()), sets.data(), static_cast<uint32_t>(sets.size())) != 0)
		return "the program was refused by the verifier";
	return "";
}

}  // namespace kmodf
