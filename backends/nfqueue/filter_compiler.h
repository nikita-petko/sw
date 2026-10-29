#ifndef NFQUEUE_FILTER_COMPILER_H_
#define NFQUEUE_FILTER_COMPILER_H_

#include <cstdint>
#include <string>
#include <vector>

/// Translates the boolean capture-filter subset used by profiles into nftables rules.
///
/// nftables has no free-form boolean expressions, so the filter is parsed, converted to disjunctive
/// normal form and emitted as one rule per conjunction and hook. Nothing from the input text is copied
/// into the output: addresses, ports and flags are parsed into numbers and re-rendered.
///
/// Supported grammar (`and`/`&&`, `or`/`||`, `not`/`!`, parentheses):
///   true, false, ip, ipv6, tcp, udp, outbound, inbound
///   tcp.Fin|Syn|Rst|Psh|Ack|Urg [== 0|1]
///   ip.SrcAddr|DstAddr|Addr (==|!=) <IPv4 address>
///   tcp|udp.SrcPort|DstPort (==|!=) <port>
///   ifIdx (==|!=) <interface index>
/// Fields of an absent protocol never match, so negated TCP flag and port tests also require TCP.
namespace nfq {

/// Netfilter hook a rule is attached to.
enum class Hook
{
	input,
	output,
	forward,
};

/// nftables hook keyword, also used in chain names.
const char* hook_name(Hook hook);

/// One nftables rule body (everything before the verdict statement).
struct CompiledRule
{
	Hook		hook;
	std::string match;
};

/// Compiles `filter` for the local (input/output) or forwarded traffic path. An empty filter matches all IPv4 packets.
/// On failure `error` and `position` (byte offset into `filter`) describe the problem.
/// `include_forward` additionally hooks forwarded traffic when `forward` is false.
bool compile_filter(const std::string& filter,
					bool			 forward,
					std::vector<CompiledRule>& rules,
					std::string&	 error,
					uint32_t&		 position,
					bool			 include_forward = false);

}  // namespace nfq

#endif
