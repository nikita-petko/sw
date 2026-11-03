// Decodes the nf_tables netlink batches built by backends/nfqueue/nft_batch.cc with libnftnl's parsers and compares them with the
// expected tables, chains, sets and expressions. No socket, kernel or privilege is involved.
#include <libmnl/libmnl.h>
#include <libnftnl/chain.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>
#include <libnftnl/set.h>
#include <libnftnl/table.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "filter_compiler.h"
#include "nft_batch.h"
#include "support/test.h"

namespace {
using Lines = std::vector<std::string>;

std::string hex(const void* data, uint32_t length)
{
	std::string text;
	char		byte[3];
	for (uint32_t index = 0; index < length; ++index)
	{
		std::snprintf(byte, sizeof(byte), "%02x", static_cast<const uint8_t*>(data)[index]);
		text += byte;
	}
	return text;
}

std::string data_of(const nftnl_expr* expr, uint16_t attribute)
{
	uint32_t	length = 0;
	const void* data   = nftnl_expr_get(expr, attribute, &length);
	return hex(data, length);
}

int describe_expr(nftnl_expr* expr, void* user)
{
	std::string&	  text = *static_cast<std::string*>(user);
	const char* const name = nftnl_expr_get_str(expr, NFTNL_EXPR_NAME);
	std::string		  line = name;
	if (line == "meta")
		line += " key=" + std::to_string(nftnl_expr_get_u32(expr, NFTNL_EXPR_META_KEY));
	else if (line == "payload")
		line += " base=" + std::to_string(nftnl_expr_get_u32(expr, NFTNL_EXPR_PAYLOAD_BASE)) +
				" off=" + std::to_string(nftnl_expr_get_u32(expr, NFTNL_EXPR_PAYLOAD_OFFSET)) +
				" len=" + std::to_string(nftnl_expr_get_u32(expr, NFTNL_EXPR_PAYLOAD_LEN));
	else if (line == "cmp")
		line +=
			std::string(nftnl_expr_get_u32(expr, NFTNL_EXPR_CMP_OP) == NFT_CMP_EQ ? " eq " : " neq ") + data_of(expr, NFTNL_EXPR_CMP_DATA);
	else if (line == "bitwise")
		line += " mask=" + data_of(expr, NFTNL_EXPR_BITWISE_MASK) + " xor=" + data_of(expr, NFTNL_EXPR_BITWISE_XOR);
	else if (line == "lookup")
		line += std::string(" set=") + nftnl_expr_get_str(expr, NFTNL_EXPR_LOOKUP_SET) +
				(nftnl_expr_is_set(expr, NFTNL_EXPR_LOOKUP_FLAGS) ? " inv" : "");
	else if (line == "immediate")
		line += " verdict=" + std::to_string(static_cast<int32_t>(nftnl_expr_get_u32(expr, NFTNL_EXPR_IMM_VERDICT)));
	else if (line == "queue")
		line += " num=" + std::to_string(nftnl_expr_get_u16(expr, NFTNL_EXPR_QUEUE_NUM)) +
				" total=" + std::to_string(nftnl_expr_get_u16(expr, NFTNL_EXPR_QUEUE_TOTAL)) +
				" flags=" + std::to_string(nftnl_expr_get_u16(expr, NFTNL_EXPR_QUEUE_FLAGS));
	text += (text.empty() ? "" : "; ") + line;
	return MNL_CB_OK;
}

/// libnftnl's own parser rejects lists with several elements, so the element message is walked attribute by attribute.
std::string describe_elements(const nlmsghdr* header)
{
	std::string name;
	std::string keys;
	const auto	children = [](const nlattr* parent, auto&& visit) {
		const char* payload = static_cast<const char*>(mnl_attr_get_payload(parent));
		int			left	= static_cast<int>(mnl_attr_get_payload_len(parent));
		for (const nlattr* child = reinterpret_cast<const nlattr*>(payload); mnl_attr_ok(child, left); child = mnl_attr_next(child))
		{
			left = static_cast<int>(payload + mnl_attr_get_payload_len(parent) - reinterpret_cast<const char*>(child)) -
				   static_cast<int>(MNL_ALIGN(child->nla_len));
			visit(child);
		}
	};
	const char* first = static_cast<const char*>(mnl_nlmsg_get_payload_offset(header, sizeof(nfgenmsg)));
	int			left  = static_cast<int>(mnl_nlmsg_get_payload_len(header) - sizeof(nfgenmsg));
	for (const nlattr* attribute = reinterpret_cast<const nlattr*>(first); mnl_attr_ok(attribute, left);
		 attribute				 = mnl_attr_next(attribute))
	{
		left -= static_cast<int>(MNL_ALIGN(attribute->nla_len));
		if (mnl_attr_get_type(attribute) == NFTA_SET_ELEM_LIST_SET)
			name = mnl_attr_get_str(attribute);
		if (mnl_attr_get_type(attribute) != NFTA_SET_ELEM_LIST_ELEMENTS)
			continue;
		children(attribute, [&](const nlattr* element) {
			children(element, [&](const nlattr* field) {
				if (mnl_attr_get_type(field) != NFTA_SET_ELEM_KEY)
					return;
				children(field, [&](const nlattr* value) {
					if (mnl_attr_get_type(value) == NFTA_DATA_VALUE)
						keys += (keys.empty() ? "" : ",") + hex(mnl_attr_get_payload(value), mnl_attr_get_payload_len(value));
				});
			});
		});
	}
	return name + " " + keys;
}

/// One line per message, in order, with the batch markers included.
Lines decode(const std::vector<uint8_t>& bytes)
{
	Lines lines;
	int	  length = static_cast<int>(bytes.size());
	for (const nlmsghdr* header = reinterpret_cast<const nlmsghdr*>(bytes.data()); mnl_nlmsg_ok(header, length);
		 header					= mnl_nlmsg_next(header, &length))
	{
		const std::string ack = (header->nlmsg_flags & NLM_F_ACK) != 0 ? " [ack]" : "";
		if (header->nlmsg_type == NFNL_MSG_BATCH_BEGIN)
		{
			lines.push_back("begin");
			continue;
		}
		if (header->nlmsg_type == NFNL_MSG_BATCH_END)
		{
			lines.push_back("end");
			continue;
		}
		CHECK((header->nlmsg_type >> 8) == NFNL_SUBSYS_NFTABLES);
		switch (header->nlmsg_type & 0xFF)
		{
			case NFT_MSG_NEWTABLE:
			case NFT_MSG_DELTABLE:
				{
					nftnl_table* table = nftnl_table_alloc();
					CHECK(nftnl_table_nlmsg_parse(header, table) == 0);
					const bool add = (header->nlmsg_type & 0xFF) == NFT_MSG_NEWTABLE;
					lines.push_back(
						std::string(add ? "add table " : "delete table ") + nftnl_table_get_str(table, NFTNL_TABLE_NAME) + " flags=" +
						std::to_string(nftnl_table_is_set(table, NFTNL_TABLE_FLAGS) ? nftnl_table_get_u32(table, NFTNL_TABLE_FLAGS) : 0) +
						ack);
					nftnl_table_free(table);
					break;
				}
			case NFT_MSG_NEWSET:
			case NFT_MSG_DELSET:
				{
					nftnl_set* set = nftnl_set_alloc();
					CHECK(nftnl_set_nlmsg_parse(header, set) == 0);
					lines.push_back(std::string((header->nlmsg_type & 0xFF) == NFT_MSG_NEWSET ? "add set " : "delete set ") +
									nftnl_set_get_str(set, NFTNL_SET_NAME) +
									(nftnl_set_is_set(set, NFTNL_SET_KEY_LEN)
										 ? " keylen=" + std::to_string(nftnl_set_get_u32(set, NFTNL_SET_KEY_LEN))
										 : "") +
									ack);
					nftnl_set_free(set);
					break;
				}
			case NFT_MSG_NEWSETELEM:
				{
					lines.push_back("add elements " + describe_elements(header) + ack);
					break;
				}
			case NFT_MSG_NEWCHAIN:
			case NFT_MSG_DELCHAIN:
				{
					nftnl_chain* chain = nftnl_chain_alloc();
					CHECK(nftnl_chain_nlmsg_parse(header, chain) == 0);
					std::string line = std::string((header->nlmsg_type & 0xFF) == NFT_MSG_NEWCHAIN ? "add chain " : "delete chain ") +
									   nftnl_chain_get_str(chain, NFTNL_CHAIN_NAME);
					if (nftnl_chain_is_set(chain, NFTNL_CHAIN_HOOKNUM))
						line += " hook=" + std::to_string(nftnl_chain_get_u32(chain, NFTNL_CHAIN_HOOKNUM)) +
								" prio=" + std::to_string(nftnl_chain_get_s32(chain, NFTNL_CHAIN_PRIO)) +
								" type=" + nftnl_chain_get_str(chain, NFTNL_CHAIN_TYPE) +
								" policy=" + std::to_string(nftnl_chain_get_u32(chain, NFTNL_CHAIN_POLICY));
					lines.push_back(line + ack);
					nftnl_chain_free(chain);
					break;
				}
			case NFT_MSG_NEWRULE:
			case NFT_MSG_DELRULE:
				{
					nftnl_rule* rule = nftnl_rule_alloc();
					CHECK(nftnl_rule_nlmsg_parse(header, rule) == 0);
					std::string expressions;
					nftnl_expr_foreach(rule, describe_expr, &expressions);
					lines.push_back(std::string((header->nlmsg_type & 0xFF) == NFT_MSG_NEWRULE ? "add rule " : "delete rules ") +
									nftnl_rule_get_str(rule, NFTNL_RULE_CHAIN) + (expressions.empty() ? "" : ": " + expressions) + ack);
					nftnl_rule_free(rule);
					break;
				}
			default:
				lines.push_back("unexpected message type " + std::to_string(header->nlmsg_type & 0xFF));
		}
	}
	return lines;
}

std::vector<linux_shared::CompiledRule> compile(const std::string& filter, bool forward = false, bool include_forward = false)
{
	std::vector<linux_shared::CompiledRule> rules;
	std::string					   error;
	uint32_t					   position = 0;
	CHECK(linux_shared::compile_filter(filter, forward, rules, error, position, include_forward));
	return rules;
}

const std::string kNfproto = "meta key=" + std::to_string(NFT_META_NFPROTO) + "; cmp eq 02";
const std::string kQueue   = "queue num=10 total=1 flags=1";

std::string net(uint32_t offset, uint32_t length)
{
	return "payload base=1 off=" + std::to_string(offset) + " len=" + std::to_string(length);
}

std::string transport(uint32_t offset, uint32_t length)
{
	return "payload base=2 off=" + std::to_string(offset) + " len=" + std::to_string(length);
}

Lines channel_lines(const std::string& filter, bool forward = false, bool include_forward = false, nfq::ChannelChains* out = nullptr)
{
	nfq::NftBatch	   batch(100);
	nfq::ChannelChains chains;
	batch.add_channel(0, 10, -150, compile(filter, forward, include_forward), chains);
	CHECK(batch.finish());
	if (out != nullptr)
		*out = chains;
	return decode(batch.bytes());
}

void test_owner_table_replacement_batch()
{
	nfq::NftBatch batch(7);
	batch.add_table(false);
	batch.delete_table();
	batch.add_table(true);
	CHECK(batch.finish());
	CHECK(batch.first_seq() == 7);
	CHECK(batch.last_seq() == 10);
	CHECK(batch.message_count() == 5);
	const Lines expected = {"begin",
							"add table lagsw flags=0",
							"delete table lagsw flags=0",
							"add table lagsw flags=" + std::to_string(NFT_TABLE_F_OWNER) + " [ack]",
							"end"};
	CHECK(decode(batch.bytes()) == expected);

	// Sequence numbers run consecutively from the first one.
	int		 length = static_cast<int>(batch.bytes().size());
	uint32_t seq	= 7;
	for (const nlmsghdr* header = reinterpret_cast<const nlmsghdr*>(batch.bytes().data()); mnl_nlmsg_ok(header, length);
		 header					= mnl_nlmsg_next(header, &length))
		CHECK(header->nlmsg_seq == seq++);
	CHECK(seq == 12);
}

void test_simple_filter_builds_typed_expressions()
{
	const std::string p		   = "ch0_output";
	const Lines		  expected = {
		"begin",
		"add chain " + p + " hook=3 prio=-150 type=filter policy=1",
		"add rule " + p + ": " + kNfproto + "; " + net(9, 1) + "; cmp eq 06; " + transport(2, 2) + "; cmp eq 0050; " + kQueue + " [ack]",
		"end",
	};
	CHECK(channel_lines("tcp.DstPort == 80 and outbound") == expected);
}

void test_flags_ports_and_interfaces()
{
	const Lines flags	 = channel_lines("tcp.Syn and not tcp.Ack and inbound");
	const Lines expected = {
		"begin",
		"add chain ch0_input hook=1 prio=-150 type=filter policy=1",
		"add rule ch0_input: " + kNfproto + "; " + net(9, 1) + "; cmp eq 06; " + transport(13, 1) +
			"; bitwise mask=02 xor=00; cmp eq 02; " + transport(13, 1) + "; bitwise mask=10 xor=00; cmp eq 00; " + kQueue + " [ack]",
		"end",
	};
	CHECK(flags == expected);

	const Lines udp			 = channel_lines("udp.SrcPort != 53 and outbound and ifIdx == 5");
	const Lines expected_udp = {
		"begin",
		"add chain ch0_output hook=3 prio=-150 type=filter policy=1",
		"add rule ch0_output: " + kNfproto + "; " + net(9, 1) + "; cmp eq 11; " + transport(0, 2) +
			"; cmp neq 0035; meta key=" + std::to_string(NFT_META_OIF) + "; cmp eq 05000000; " + kQueue + " [ack]",
		"end",
	};
	CHECK(udp == expected_udp);
}

void test_single_addresses_are_compared_and_lists_become_sets()
{
	const Lines single = channel_lines("ip.DstAddr == 1.2.3.4 and outbound");
	CHECK(single.size() == 4);
	CHECK(single[2] == "add rule ch0_output: " + kNfproto + "; " + net(16, 4) + "; cmp eq 01020304; " + kQueue + " [ack]");

	nfq::ChannelChains chains;
	const Lines		   list =
		channel_lines("(ip.Addr == 3.3.3.3 or ip.Addr == 1.1.1.1 or ip.Addr == 3.3.3.3) and not ip.SrcAddr == 9.9.9.9 and outbound",
					  false,
					  false,
					  &chains);
	// The same address list is one set no matter which side or clause uses it; duplicates collapse and order is normalised.
	CHECK(chains.sets == (std::vector<std::string>{"ch0_a0"}));
	const Lines expected = {
		"begin",
		"add set ch0_a0 keylen=4",
		"add elements ch0_a0 01010101,03030303",
		"add chain ch0_output hook=3 prio=-150 type=filter policy=1",
		"add rule ch0_output: " + kNfproto + "; " + net(12, 4) + "; lookup set=ch0_a0; " + net(12, 4) + "; cmp neq 09090909; " + kQueue,
		"add rule ch0_output: " + kNfproto + "; " + net(16, 4) + "; lookup set=ch0_a0; " + net(12, 4) + "; cmp neq 09090909; " + kQueue +
			" [ack]",
		"end",
	};
	CHECK(list == expected);

	const Lines negated	 = channel_lines("ip.DstAddr != 1.1.1.1 and ip.DstAddr != 2.2.2.2 and outbound");
	bool		inverted = false;
	for (const std::string& line : negated)
		inverted = inverted || line.find("lookup set=") != std::string::npos;
	CHECK(!inverted);  // two separate single-address comparisons, not a set
}

void test_negated_lists_invert_the_lookup()
{
	nfq::ChannelChains chains;
	const Lines		   lines = channel_lines("(ip.SrcAddr == 1.1.1.1 or ip.SrcAddr == 2.2.2.2) and outbound", false, false, &chains);
	CHECK(chains.sets.size() == 1);
	CHECK(lines[4].find("lookup set=ch0_a0;") != std::string::npos);

	std::vector<linux_shared::CompiledRule> rules = compile("outbound");
	linux_shared::Match					   match;
	match.kind	  = linux_shared::MatchKind::ip_addr;
	match.negated = true;
	match.addrs	  = {0x01010101, 0x02020202};
	rules[0].matches.push_back(match);
	nfq::NftBatch	   batch(1);
	nfq::ChannelChains created;
	batch.add_channel(0, 10, -150, rules, created);
	CHECK(batch.finish());
	bool found = false;
	for (const std::string& line : decode(batch.bytes()))
		found = found || line.find("lookup set=ch0_a0 inv") != std::string::npos;
	CHECK(found);
}

void test_release_guard_leads_every_chain()
{
	nfq::NftBatch	   batch(1);
	nfq::ChannelChains chains;
	// Loopback traffic crosses the output and the input hook; the guard keeps a released packet from being queued twice.
	batch.add_channel(0, 10, -150, compile("tcp.DstPort == 80"), chains, 0x01000000u);
	CHECK(batch.finish());
	const std::string guard	   = "meta key=" + std::to_string(NFT_META_MARK) +
								 "; bitwise mask=00000001 xor=00000000; cmp neq 00000000; immediate verdict=" + std::to_string(NFT_RETURN);
	const Lines		  expected = {
		"begin",
		"add chain ch0_input hook=1 prio=-150 type=filter policy=1",
		"add rule ch0_input: " + guard,
		"add rule ch0_input: " + kNfproto + "; " + net(9, 1) + "; cmp eq 06; " + transport(2, 2) + "; cmp eq 0050; " + kQueue,
		"add chain ch0_output hook=3 prio=-150 type=filter policy=1",
		"add rule ch0_output: " + guard,
		"add rule ch0_output: " + kNfproto + "; " + net(9, 1) + "; cmp eq 06; " + transport(2, 2) + "; cmp eq 0050; " + kQueue + " [ack]",
		"end",
	};
	CHECK(decode(batch.bytes()) == expected);
}

void test_no_guard_without_a_release_bit()
{
	for (const std::string& line : channel_lines("tcp"))
		CHECK(line.find("immediate") == std::string::npos);
}

void test_forward_hook_and_priority()
{
	nfq::NftBatch	   batch(1);
	nfq::ChannelChains chains;
	batch.add_channel(3, 13, -149, compile("tcp", true), chains);
	CHECK(batch.finish());
	const Lines lines = decode(batch.bytes());
	CHECK(lines.size() == 4);
	CHECK(lines[1] == "add chain ch3_forward hook=2 prio=-149 type=filter policy=1");
	CHECK(lines[2].find("queue num=13 total=1 flags=1") != std::string::npos);
	CHECK(chains.names == (std::vector<std::string>{"ch3_forward"}));
}

void test_channel_removal_batch()
{
	nfq::ChannelChains chains;
	channel_lines("(ip.Addr == 1.1.1.1 or ip.Addr == 2.2.2.2) and tcp", false, false, &chains);
	CHECK(chains.names.size() == 2);

	nfq::NftBatch batch(50);
	batch.delete_channel(chains);
	CHECK(batch.finish());
	const Lines expected = {
		"begin",
		"delete rules ch0_input",
		"delete chain ch0_input",
		"delete rules ch0_output",
		"delete chain ch0_output",
		"delete set ch0_a0 [ack]",
		"end",
	};
	CHECK(decode(batch.bytes()) == expected);
}

void test_long_address_lists_are_split_across_messages()
{
	std::string filter = "(";
	for (int index = 0; index < 600; ++index)
		filter += (index == 0 ? "" : " or ") + std::string("ip.DstAddr == 10.") + std::to_string(index / 250) + "." +
				  std::to_string(index % 250) + ".1";
	filter += ") and outbound";
	const Lines lines			 = channel_lines(filter);
	size_t		element_messages = 0;
	for (const std::string& line : lines)
		element_messages += line.rfind("add elements ch0_a0", 0) == 0 ? 1 : 0;
	CHECK(element_messages == 3);
}

void test_oversized_batches_are_rejected()
{
	// One rule is a few hundred bytes, so a few thousand copies exceed what a single sendto may carry.
	std::vector<linux_shared::CompiledRule> rules = compile("tcp.DstPort == 80 and outbound");
	CHECK(rules.size() == 1);
	rules.assign(6000, rules.front());
	nfq::NftBatch	   batch(1);
	nfq::ChannelChains chains;
	batch.add_channel(0, 10, -150, rules, chains);
	CHECK(!batch.finish());
	CHECK(batch.error().find("too large") != std::string::npos);
}

void test_get_table_request()
{
	const std::vector<uint8_t> request = nfq::build_get_table_request(42);
	CHECK(!request.empty());
	const nlmsghdr* header = reinterpret_cast<const nlmsghdr*>(request.data());
	CHECK(header->nlmsg_seq == 42);
	CHECK((header->nlmsg_type & 0xFF) == NFT_MSG_GETTABLE);
	CHECK((header->nlmsg_flags & NLM_F_ACK) != 0);
	CHECK(header->nlmsg_len == request.size());
}
}  // namespace

int main(int argc, char** argv)
{
	static const test::TestCase cases[] = {
		{"owner_table_replacement_batch", test_owner_table_replacement_batch},
		{"simple_filter_builds_typed_expressions", test_simple_filter_builds_typed_expressions},
		{"flags_ports_and_interfaces", test_flags_ports_and_interfaces},
		{"single_addresses_are_compared_and_lists_become_sets", test_single_addresses_are_compared_and_lists_become_sets},
		{"negated_lists_invert_the_lookup", test_negated_lists_invert_the_lookup},
		{"release_guard_leads_every_chain", test_release_guard_leads_every_chain},
		{"no_guard_without_a_release_bit", test_no_guard_without_a_release_bit},
		{"forward_hook_and_priority", test_forward_hook_and_priority},
		{"channel_removal_batch", test_channel_removal_batch},
		{"long_address_lists_are_split_across_messages", test_long_address_lists_are_split_across_messages},
		{"oversized_batches_are_rejected", test_oversized_batches_are_rejected},
		{"get_table_request", test_get_table_request},
	};
	return test::run_tests("nft_batch", cases, argc, argv);
}
