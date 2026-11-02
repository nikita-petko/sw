#ifndef NFQUEUE_NFT_BATCH_H_
#define NFQUEUE_NFT_BATCH_H_

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "filter_compiler.h"

/// Typed nf_tables netlink messages. Rules are built as expression structs (libnftnl) and serialised into one
/// `NFNL_MSG_BATCH_BEGIN ... END` batch that the kernel commits atomically. No command text is ever produced.
struct nlmsghdr;

namespace nfq {

inline constexpr const char* kTableName = "lagsw";

/// Chains and sets created for one capture channel; removed together.
struct ChannelChains
{
	std::vector<std::string> names;
	std::vector<std::string> sets;
};

class NftBatch
{
public:
	/// Message sequence numbers run from `first_seq` (batch begin) up to `last_seq()` + 1 (batch end).
	explicit NftBatch(uint32_t first_seq);

	/// `add table inet lagsw`. With `owner`, the table is tied to the creating netlink socket and the kernel deletes
	/// it when that socket closes. Adding an existing table with the same flags succeeds without changes.
	void add_table(bool owner);
	void delete_table();

	/// Adds one base chain and a `queue flags bypass to <queue_number>` rule per compiled rule for every hook used,
	/// and one set per distinct address list with several members. Fills `chains` for later removal.
	/// With a non-zero `release_bit`, every chain starts with `meta mark & <bit> != 0 return`: the channel sets that bit on
	/// the packets it releases, so a released packet is not queued a second time by another chain of the same channel
	/// (for example on loopback, which crosses both the output and the input hook). Other channels ignore the bit.
	void add_channel(uint32_t						  channel_id,
					 uint16_t						  queue_number,
					 int							  priority,
					 const std::vector<CompiledRule>& rules,
					 ChannelChains&					  chains,
					 uint32_t						  release_bit = 0);

	/// Deletes the rules, chains and sets of a channel.
	void delete_channel(const ChannelChains& chains);

	/// Finishes the batch. Returns false and sets `error()` if a message could not be built or the batch is too large.
	bool			   finish();
	bool			   ok() const { return error_.empty(); }
	const std::string& error() const { return error_; }

	/// Serialised batch; valid after a successful finish().
	const std::vector<uint8_t>& bytes() const { return bytes_; }
	/// Sequence number of the last message before the batch end; only this message requests an acknowledgement.
	uint32_t last_seq() const { return last_seq_; }
	uint32_t first_seq() const { return first_seq_; }
	size_t	 message_count() const { return messages_; }
	/// Largest batch the sender can submit in one `sendto`.
	static constexpr size_t kMaxBytes = 1u << 20;

private:
	struct SetRef
	{
		std::string name;
		uint32_t	id;
	};
	using AddressSets = std::map<std::vector<uint32_t>, SetRef>;

	nlmsghdr* header(uint16_t type, uint16_t flags);
	void	  commit(const nlmsghdr* message);
	void	  fail(const std::string& message);
	void	  add_set(const std::string& name, uint32_t id, const std::vector<uint32_t>& addrs);
	void	  add_chain(const std::string& name, Hook hook, int priority);
	void	  add_release_guard(const std::string& chain, uint32_t release_bit);
	void	  add_queue_rule(const std::string& chain, const CompiledRule& rule, uint16_t queue_number, const AddressSets& sets);

	std::vector<uint8_t> bytes_;
	std::vector<char>	 scratch_;
	std::vector<size_t>	 offsets_;
	std::string			 error_;
	uint32_t			 first_seq_;
	uint32_t			 seq_;
	uint32_t			 last_seq_;
	uint32_t			 next_set_id_ = 1;
	size_t				 messages_	  = 0;
	bool				 finished_	  = false;
};

/// Builds a request for the table object; the kernel answers with the table or an error.
std::vector<uint8_t> build_get_table_request(uint32_t seq);

}  // namespace nfq

#endif
