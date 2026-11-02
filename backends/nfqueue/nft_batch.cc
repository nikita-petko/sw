#include "nft_batch.h"

#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <libnftnl/chain.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>
#include <libnftnl/set.h>
#include <libnftnl/table.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <netinet/in.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <new>

namespace nfq {
namespace {
constexpr size_t   kScratchBytes	 = 64 * 1024;
constexpr size_t   kAddressesPerMessage = 256;
constexpr uint32_t kTypeIpv4Addr	 = 7;  // nft's ipv4_addr data type; informational for the kernel
constexpr uint16_t kFamily			 = NFPROTO_INET;

template <typename T, void (*Free)(T*)>
struct Deleter
{
	void operator()(T* object) const { Free(object); }
};

void free_table(nftnl_table* object) { nftnl_table_free(object); }
void free_chain(nftnl_chain* object) { nftnl_chain_free(object); }
void free_set(nftnl_set* object) { nftnl_set_free(object); }
void free_rule(nftnl_rule* object) { nftnl_rule_free(object); }

using TablePtr = std::unique_ptr<nftnl_table, Deleter<nftnl_table, free_table>>;
using ChainPtr = std::unique_ptr<nftnl_chain, Deleter<nftnl_chain, free_chain>>;
using SetPtr   = std::unique_ptr<nftnl_set, Deleter<nftnl_set, free_set>>;
using RulePtr  = std::unique_ptr<nftnl_rule, Deleter<nftnl_rule, free_rule>>;

uint32_t hook_number(Hook hook)
{
	switch (hook)
	{
		case Hook::input:
			return NF_INET_LOCAL_IN;
		case Hook::output:
			return NF_INET_LOCAL_OUT;
		case Hook::forward:
			return NF_INET_FORWARD;
	}
	return NF_INET_LOCAL_IN;
}

nftnl_expr* make_expr(const char* name)
{
	nftnl_expr* expr = nftnl_expr_alloc(name);
	if (expr == nullptr)
		throw std::bad_alloc();
	return expr;
}

/// Expressions are handed to the rule, which owns and frees them.
void add_meta_load(nftnl_rule* rule, uint32_t key)
{
	nftnl_expr* expr = make_expr("meta");
	nftnl_expr_set_u32(expr, NFTNL_EXPR_META_KEY, key);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_META_DREG, NFT_REG_1);
	nftnl_rule_add_expr(rule, expr);
}

void add_payload_load(nftnl_rule* rule, uint32_t base, uint32_t offset, uint32_t length)
{
	nftnl_expr* expr = make_expr("payload");
	nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_BASE, base);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_1);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_OFFSET, offset);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_LEN, length);
	nftnl_rule_add_expr(rule, expr);
}

void add_compare(nftnl_rule* rule, bool negated, const void* data, uint32_t length)
{
	nftnl_expr* expr = make_expr("cmp");
	nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_OP, negated ? NFT_CMP_NEQ : NFT_CMP_EQ);
	nftnl_expr_set(expr, NFTNL_EXPR_CMP_DATA, data, length);
	nftnl_rule_add_expr(rule, expr);
}

void add_byte_mask(nftnl_rule* rule, uint8_t mask)
{
	const uint8_t xor_value = 0;
	nftnl_expr*	  expr		= make_expr("bitwise");
	nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_SREG, NFT_REG_1);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_DREG, NFT_REG_1);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_LEN, 1);
	nftnl_expr_set(expr, NFTNL_EXPR_BITWISE_MASK, &mask, 1);
	nftnl_expr_set(expr, NFTNL_EXPR_BITWISE_XOR, &xor_value, 1);
	nftnl_rule_add_expr(rule, expr);
}

void add_set_lookup(nftnl_rule* rule, bool negated, const std::string& name, uint32_t id)
{
	nftnl_expr* expr = make_expr("lookup");
	nftnl_expr_set_u32(expr, NFTNL_EXPR_LOOKUP_SREG, NFT_REG_1);
	nftnl_expr_set_str(expr, NFTNL_EXPR_LOOKUP_SET, name.c_str());
	nftnl_expr_set_u32(expr, NFTNL_EXPR_LOOKUP_SET_ID, id);
	if (negated)
		nftnl_expr_set_u32(expr, NFTNL_EXPR_LOOKUP_FLAGS, NFT_LOOKUP_F_INV);
	nftnl_rule_add_expr(rule, expr);
}

void add_mask32(nftnl_rule* rule, uint32_t mask)
{
	const uint32_t xor_value = 0;
	nftnl_expr*	   expr		 = make_expr("bitwise");
	nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_SREG, NFT_REG_1);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_DREG, NFT_REG_1);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_LEN, sizeof(uint32_t));
	nftnl_expr_set(expr, NFTNL_EXPR_BITWISE_MASK, &mask, sizeof(mask));
	nftnl_expr_set(expr, NFTNL_EXPR_BITWISE_XOR, &xor_value, sizeof(xor_value));
	nftnl_rule_add_expr(rule, expr);
}

void add_verdict(nftnl_rule* rule, uint32_t verdict)
{
	nftnl_expr* expr = make_expr("immediate");
	nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_VERDICT, verdict);
	nftnl_rule_add_expr(rule, expr);
}

void add_queue(nftnl_rule* rule, uint16_t queue_number)
{
	nftnl_expr* expr = make_expr("queue");
	nftnl_expr_set_u16(expr, NFTNL_EXPR_QUEUE_NUM, queue_number);
	nftnl_expr_set_u16(expr, NFTNL_EXPR_QUEUE_TOTAL, 1);
	nftnl_expr_set_u16(expr, NFTNL_EXPR_QUEUE_FLAGS, NFT_QUEUE_FLAG_BYPASS);
	nftnl_rule_add_expr(rule, expr);
}

/// Distinct sorted address list, so equal lists from different clauses share one set.
std::vector<uint32_t> normalized(std::vector<uint32_t> addrs)
{
	std::sort(addrs.begin(), addrs.end());
	addrs.erase(std::unique(addrs.begin(), addrs.end()), addrs.end());
	return addrs;
}

uint8_t transport_protocol(Transport transport)
{
	return transport == Transport::tcp ? IPPROTO_TCP : IPPROTO_UDP;
}
}  // namespace

NftBatch::NftBatch(uint32_t first_seq) : scratch_(kScratchBytes), first_seq_(first_seq), seq_(first_seq), last_seq_(first_seq)
{
	commit(nftnl_batch_begin(scratch_.data(), seq_++));
}

nlmsghdr* NftBatch::header(uint16_t type, uint16_t flags)
{
	last_seq_ = seq_;
	return nftnl_nlmsg_build_hdr(scratch_.data(), type, kFamily, flags, seq_++);
}

void NftBatch::commit(const nlmsghdr* message)
{
	if (message->nlmsg_len > scratch_.size())
	{
		fail("an nf_tables message exceeded the build buffer");
		return;
	}
	offsets_.push_back(bytes_.size());
	const uint8_t* begin = reinterpret_cast<const uint8_t*>(message);
	bytes_.insert(bytes_.end(), begin, begin + MNL_ALIGN(message->nlmsg_len));
	++messages_;
}

void NftBatch::fail(const std::string& message)
{
	if (error_.empty())
		error_ = message;
}

void NftBatch::add_table(bool owner)
{
	TablePtr table(nftnl_table_alloc());
	if (!table)
		return fail("out of memory");
	nftnl_table_set_str(table.get(), NFTNL_TABLE_NAME, kTableName);
	nftnl_table_set_u32(table.get(), NFTNL_TABLE_FAMILY, kFamily);
	if (owner)
		nftnl_table_set_u32(table.get(), NFTNL_TABLE_FLAGS, NFT_TABLE_F_OWNER);
	nlmsghdr* message = header(NFT_MSG_NEWTABLE, NLM_F_CREATE);
	nftnl_table_nlmsg_build_payload(message, table.get());
	commit(message);
}

void NftBatch::delete_table()
{
	TablePtr table(nftnl_table_alloc());
	if (!table)
		return fail("out of memory");
	nftnl_table_set_str(table.get(), NFTNL_TABLE_NAME, kTableName);
	nftnl_table_set_u32(table.get(), NFTNL_TABLE_FAMILY, kFamily);
	nlmsghdr* message = header(NFT_MSG_DELTABLE, 0);
	nftnl_table_nlmsg_build_payload(message, table.get());
	commit(message);
}

void NftBatch::add_set(const std::string& name, uint32_t id, const std::vector<uint32_t>& addrs)
{
	SetPtr set(nftnl_set_alloc());
	if (!set)
		return fail("out of memory");
	nftnl_set_set_str(set.get(), NFTNL_SET_TABLE, kTableName);
	nftnl_set_set_str(set.get(), NFTNL_SET_NAME, name.c_str());
	nftnl_set_set_u32(set.get(), NFTNL_SET_FAMILY, kFamily);
	nftnl_set_set_u32(set.get(), NFTNL_SET_KEY_TYPE, kTypeIpv4Addr);
	nftnl_set_set_u32(set.get(), NFTNL_SET_KEY_LEN, sizeof(uint32_t));
	nftnl_set_set_u32(set.get(), NFTNL_SET_ID, id);
	nlmsghdr* message = header(NFT_MSG_NEWSET, NLM_F_CREATE);
	nftnl_set_nlmsg_build_payload(message, set.get());
	commit(message);

	// Elements are sent in bounded messages so a long server list never overflows one netlink message.
	for (size_t first = 0; first < addrs.size(); first += kAddressesPerMessage)
	{
		SetPtr chunk(nftnl_set_alloc());
		if (!chunk)
			return fail("out of memory");
		nftnl_set_set_str(chunk.get(), NFTNL_SET_TABLE, kTableName);
		nftnl_set_set_str(chunk.get(), NFTNL_SET_NAME, name.c_str());
		nftnl_set_set_u32(chunk.get(), NFTNL_SET_FAMILY, kFamily);
		nftnl_set_set_u32(chunk.get(), NFTNL_SET_ID, id);
		const size_t last = std::min(addrs.size(), first + kAddressesPerMessage);
		for (size_t index = first; index < last; ++index)
		{
			nftnl_set_elem* element = nftnl_set_elem_alloc();
			if (element == nullptr)
				return fail("out of memory");
			const uint32_t key = htonl(addrs[index]);
			nftnl_set_elem_set(element, NFTNL_SET_ELEM_KEY, &key, sizeof(key));
			nftnl_set_elem_add(chunk.get(), element);
		}
		nlmsghdr* elements = header(NFT_MSG_NEWSETELEM, NLM_F_CREATE);
		nftnl_set_elems_nlmsg_build_payload(elements, chunk.get());
		commit(elements);
	}
}

void NftBatch::add_chain(const std::string& name, Hook hook, int priority)
{
	ChainPtr chain(nftnl_chain_alloc());
	if (!chain)
		return fail("out of memory");
	nftnl_chain_set_str(chain.get(), NFTNL_CHAIN_TABLE, kTableName);
	nftnl_chain_set_str(chain.get(), NFTNL_CHAIN_NAME, name.c_str());
	nftnl_chain_set_u32(chain.get(), NFTNL_CHAIN_HOOKNUM, hook_number(hook));
	nftnl_chain_set_s32(chain.get(), NFTNL_CHAIN_PRIO, priority);
	nftnl_chain_set_str(chain.get(), NFTNL_CHAIN_TYPE, "filter");
	nftnl_chain_set_u32(chain.get(), NFTNL_CHAIN_POLICY, NF_ACCEPT);
	nlmsghdr* message = header(NFT_MSG_NEWCHAIN, NLM_F_CREATE);
	nftnl_chain_nlmsg_build_payload(message, chain.get());
	commit(message);
}

void NftBatch::add_release_guard(const std::string& chain, uint32_t release_bit)
{
	RulePtr rule(nftnl_rule_alloc());
	if (!rule)
		return fail("out of memory");
	nftnl_rule_set_u32(rule.get(), NFTNL_RULE_FAMILY, kFamily);
	nftnl_rule_set_str(rule.get(), NFTNL_RULE_TABLE, kTableName);
	nftnl_rule_set_str(rule.get(), NFTNL_RULE_CHAIN, chain.c_str());
	const uint32_t zero = 0;
	add_meta_load(rule.get(), NFT_META_MARK);
	add_mask32(rule.get(), release_bit);
	add_compare(rule.get(), true, &zero, sizeof(zero));
	add_verdict(rule.get(), NFT_RETURN);
	nlmsghdr* message = header(NFT_MSG_NEWRULE, NLM_F_CREATE | NLM_F_APPEND);
	nftnl_rule_nlmsg_build_payload(message, rule.get());
	commit(message);
}

void NftBatch::add_queue_rule(const std::string& chain, const CompiledRule& compiled, uint16_t queue_number, const AddressSets& sets)
{
	RulePtr rule(nftnl_rule_alloc());
	if (!rule)
		return fail("out of memory");
	nftnl_rule_set_u32(rule.get(), NFTNL_RULE_FAMILY, kFamily);
	nftnl_rule_set_str(rule.get(), NFTNL_RULE_TABLE, kTableName);
	nftnl_rule_set_str(rule.get(), NFTNL_RULE_CHAIN, chain.c_str());
	for (const Match& match : compiled.matches)
	{
		switch (match.kind)
		{
			case MatchKind::nfproto_ipv4:
			{
				const uint8_t family = NFPROTO_IPV4;
				add_meta_load(rule.get(), NFT_META_NFPROTO);
				add_compare(rule.get(), false, &family, sizeof(family));
				break;
			}
			case MatchKind::ip_protocol:
			{
				const uint8_t protocol = transport_protocol(match.transport);
				add_payload_load(rule.get(), NFT_PAYLOAD_NETWORK_HEADER, 9, 1);
				add_compare(rule.get(), match.negated, &protocol, sizeof(protocol));
				break;
			}
			case MatchKind::tcp_flag:
			{
				const uint8_t expected = match.negated ? 0 : match.tcp_flag;
				add_payload_load(rule.get(), NFT_PAYLOAD_TRANSPORT_HEADER, 13, 1);
				add_byte_mask(rule.get(), match.tcp_flag);
				add_compare(rule.get(), false, &expected, sizeof(expected));
				break;
			}
			case MatchKind::ip_addr:
			{
				add_payload_load(rule.get(), NFT_PAYLOAD_NETWORK_HEADER, match.endpoint == Endpoint::source ? 12 : 16, 4);
				const std::vector<uint32_t> addrs = normalized(match.addrs);
				if (addrs.size() == 1)
				{
					const uint32_t address = htonl(addrs.front());
					add_compare(rule.get(), match.negated, &address, sizeof(address));
				}
				else
				{
					const auto found = sets.find(addrs);
					if (found == sets.end())
						return fail("internal error: address set was not created");
					add_set_lookup(rule.get(), match.negated, found->second.name, found->second.id);
				}
				break;
			}
			case MatchKind::port:
			{
				const uint16_t port = htons(match.port);
				add_payload_load(rule.get(), NFT_PAYLOAD_TRANSPORT_HEADER, match.endpoint == Endpoint::source ? 0 : 2, 2);
				add_compare(rule.get(), match.negated, &port, sizeof(port));
				break;
			}
			case MatchKind::interface:
			{
				const uint32_t index = match.index;
				add_meta_load(rule.get(), match.output ? NFT_META_OIF : NFT_META_IIF);
				add_compare(rule.get(), match.negated, &index, sizeof(index));
				break;
			}
		}
	}
	add_queue(rule.get(), queue_number);
	nlmsghdr* message = header(NFT_MSG_NEWRULE, NLM_F_CREATE | NLM_F_APPEND);
	nftnl_rule_nlmsg_build_payload(message, rule.get());
	commit(message);
}

void NftBatch::add_channel(uint32_t channel_id, uint16_t queue_number, int priority, const std::vector<CompiledRule>& rules, ChannelChains& chains, uint32_t release_bit)
{
	try
	{
		AddressSets sets;
		for (const CompiledRule& rule : rules)
		{
			for (const Match& match : rule.matches)
			{
				if (match.kind != MatchKind::ip_addr)
					continue;
				std::vector<uint32_t> addrs = normalized(match.addrs);
				if (addrs.size() < 2 || sets.count(addrs) != 0)
					continue;
				SetRef ref{"ch" + std::to_string(channel_id) + "_a" + std::to_string(sets.size()), next_set_id_++};
				add_set(ref.name, ref.id, addrs);
				chains.sets.push_back(ref.name);
				sets.emplace(std::move(addrs), std::move(ref));
			}
		}
		for (const Hook hook : {Hook::input, Hook::output, Hook::forward})
		{
			bool used = false;
			for (const CompiledRule& rule : rules)
				used = used || rule.hook == hook;
			if (!used)
				continue;
			const std::string chain = "ch" + std::to_string(channel_id) + "_" + hook_name(hook);
			add_chain(chain, hook, priority);
			if (release_bit != 0)
				add_release_guard(chain, release_bit);
			for (const CompiledRule& rule : rules)
				if (rule.hook == hook)
					add_queue_rule(chain, rule, queue_number, sets);
			chains.names.push_back(chain);
		}
	}
	catch (const std::bad_alloc&)
	{
		fail("out of memory");
	}
}

void NftBatch::delete_channel(const ChannelChains& chains)
{
	for (const std::string& name : chains.names)
	{
		RulePtr rule(nftnl_rule_alloc());
		ChainPtr chain(nftnl_chain_alloc());
		if (!rule || !chain)
			return fail("out of memory");
		// A rule delete without a handle removes every rule of the chain.
		nftnl_rule_set_u32(rule.get(), NFTNL_RULE_FAMILY, kFamily);
		nftnl_rule_set_str(rule.get(), NFTNL_RULE_TABLE, kTableName);
		nftnl_rule_set_str(rule.get(), NFTNL_RULE_CHAIN, name.c_str());
		nlmsghdr* flush = header(NFT_MSG_DELRULE, 0);
		nftnl_rule_nlmsg_build_payload(flush, rule.get());
		commit(flush);

		nftnl_chain_set_str(chain.get(), NFTNL_CHAIN_TABLE, kTableName);
		nftnl_chain_set_str(chain.get(), NFTNL_CHAIN_NAME, name.c_str());
		nlmsghdr* remove = header(NFT_MSG_DELCHAIN, 0);
		nftnl_chain_nlmsg_build_payload(remove, chain.get());
		commit(remove);
	}
	for (const std::string& name : chains.sets)
	{
		SetPtr set(nftnl_set_alloc());
		if (!set)
			return fail("out of memory");
		nftnl_set_set_str(set.get(), NFTNL_SET_TABLE, kTableName);
		nftnl_set_set_str(set.get(), NFTNL_SET_NAME, name.c_str());
		nftnl_set_set_u32(set.get(), NFTNL_SET_FAMILY, kFamily);
		nlmsghdr* message = header(NFT_MSG_DELSET, 0);
		nftnl_set_nlmsg_build_payload(message, set.get());
		commit(message);
	}
}

bool NftBatch::finish()
{
	if (!finished_)
	{
		finished_ = true;
		if (ok())
		{
			commit(nftnl_batch_end(scratch_.data(), seq_++));
			// Only the final message asks for an acknowledgement; errors are always reported.
			if (messages_ > 2)
			{
				nlmsghdr* last = reinterpret_cast<nlmsghdr*>(bytes_.data() + offsets_[offsets_.size() - 2]);
				last->nlmsg_flags |= NLM_F_ACK;
			}
		}
	}
	if (ok() && bytes_.size() > kMaxBytes)
		fail("the nf_tables batch is too large (" + std::to_string(bytes_.size()) + " bytes); the capture filter is too complex");
	return ok();
}

std::vector<uint8_t> build_get_table_request(uint32_t seq)
{
	TablePtr table(nftnl_table_alloc());
	if (!table)
		return {};
	nftnl_table_set_str(table.get(), NFTNL_TABLE_NAME, kTableName);
	nftnl_table_set_u32(table.get(), NFTNL_TABLE_FAMILY, kFamily);
	std::vector<char> buffer(4096);
	nlmsghdr*		  message = nftnl_nlmsg_build_hdr(buffer.data(), NFT_MSG_GETTABLE, kFamily, NLM_F_ACK, seq);
	nftnl_table_nlmsg_build_payload(message, table.get());
	const uint8_t* begin = reinterpret_cast<const uint8_t*>(message);
	return std::vector<uint8_t>(begin, begin + message->nlmsg_len);
}

}  // namespace nfq
