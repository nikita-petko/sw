#ifndef NFQUEUE_NFT_TABLE_H_
#define NFQUEUE_NFT_TABLE_H_

#include <cstdint>
#include <string>
#include <vector>

#include "filter_compiler.h"

/// Owns the single nftables table (`inet lagsw`) that holds every capture rule. Other tables are never touched.
namespace nfq {

/// Applies an nftables script atomically through `nft -f -` (no shell involved).
bool run_nft(const std::string& script, std::string& error);

/// Creates the table if this process has not done so yet, replacing a stale one left by a previous run.
/// The table is deleted again when the process exits normally.
bool ensure_table(std::string& error);

/// Whether the table that ensure_table() created is still present. Reports true when this process has not created it.
bool table_present();

/// Deletes the table now (idempotent).
void remove_table();

/// Chains created for one capture channel; removed together.
struct ChannelChains
{
	std::vector<std::string> names;
};

/// Creates one chain per hook used by `rules` and a queue-to-`queue_number` rule for each entry.
/// `priority` is the nftables chain priority (lower runs first). Rules use `bypass`, so packets are
/// accepted whenever no program is bound to the queue.
bool add_channel_rules(uint32_t				  channel_id,
					   uint16_t				  queue_number,
					   int					  priority,
					   const std::vector<CompiledRule>& rules,
					   ChannelChains&		  chains,
					   std::string&			  error);

/// Removes the chains of a channel. Failures are ignored; the table is deleted on exit anyway.
void remove_channel_rules(ChannelChains& chains);

}  // namespace nfq

#endif
