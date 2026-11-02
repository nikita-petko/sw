#ifndef NFQUEUE_FILTER_COMPILER_H_
#define NFQUEUE_FILTER_COMPILER_H_

#include <cstdint>
#include <string>
#include <vector>

/// Translates the boolean capture-filter subset used by profiles into nftables rules.
///
/// nftables has no free-form boolean expressions, so the filter is parsed, converted to disjunctive
/// normal form and emitted as one rule per conjunction and hook. Each rule is a list of typed `Match`
/// conditions (plus a text rendering for logs). Nothing from the input text is copied into the output:
/// addresses, ports and flags are parsed into numbers.
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

/// One typed condition of a rule. The netlink backend turns these into nf_tables expressions directly; they are
/// never rendered into a command line.
enum class MatchKind
{
	nfproto_ipv4,  ///< meta nfproto ipv4
	ip_protocol,   ///< ip protocol [!=] tcp|udp
	tcp_flag,	   ///< tcp flags & <flag> == <flag> (or == 0 when negated)
	ip_addr,	   ///< ip saddr|daddr [!=] { addresses }
	port,		   ///< tcp|udp sport|dport [!=] <port>
	interface,	   ///< meta iif|oif [!=] <ifindex>
};

enum class Transport : uint8_t
{
	tcp,
	udp,
};

enum class Endpoint : uint8_t
{
	source,
	destination,
};

struct Match
{
	MatchKind			  kind		= MatchKind::nfproto_ipv4;
	bool				  negated	= false;
	Transport			  transport = Transport::tcp;	 ///< ip_protocol, port
	Endpoint			  endpoint	= Endpoint::source;	 ///< ip_addr, port
	uint8_t				  tcp_flag	= 0;				 ///< tcp_flag: the TCP header flag bit (for example 0x02 for SYN)
	uint16_t			  port		= 0;				 ///< port, host byte order
	uint32_t			  index		= 0;				 ///< interface: ifindex
	bool				  output	= false;			 ///< interface: match the output interface instead of the input one
	std::vector<uint32_t> addrs;						 ///< ip_addr: IPv4 addresses, host byte order
};

/// Name of a TCP flag bit as nft spells it ("syn"), or "" for an unknown value.
const char* tcp_flag_name(uint8_t flag);

/// nft-syntax text for one condition, used for logging and tests only.
std::string render_match(const Match& match);

/// One nftables rule body (everything before the verdict statement). `match` is the text form of `matches`.
struct CompiledRule
{
	Hook			   hook;
	std::string		   match;
	std::vector<Match> matches;
};

/// Compiles `filter` for the local (input/output) or forwarded traffic path. An empty filter matches all IPv4 packets.
/// On failure `error` and `position` (byte offset into `filter`) describe the problem.
/// `include_forward` additionally hooks forwarded traffic when `forward` is false.
bool compile_filter(const std::string&		   filter,
					bool					   forward,
					std::vector<CompiledRule>& rules,
					std::string&			   error,
					uint32_t&				   position,
					bool					   include_forward = false);

}  // namespace nfq

#endif
