#ifndef NFQUEUE_NFT_TABLE_H_
#define NFQUEUE_NFT_TABLE_H_

#include <cstdint>
#include <string>
#include <vector>

#include "filter_compiler.h"
#include "nft_batch.h"

/// Owns the single nftables table (`inet lagsw`) that holds every capture rule. Other tables are never touched.
///
/// Rules are programmed over one long-lived NETLINK_NETFILTER socket (libmnl + libnftnl) in atomic batches, so no
/// `nft` binary or spawned process is involved and the process needs only CAP_NET_ADMIN.
namespace nfq {

/// Creates the table if this process has not done so yet, replacing a stale one left by a previous run.
/// The table is created with the `owner` flag where the kernel supports it (Linux 5.12+): it is tied to this process's
/// netlink socket and the kernel removes it when the process exits for any reason, including SIGKILL. Older kernels get
/// an ordinary table that is deleted on normal exit.
bool ensure_table(std::string& error);

/// Whether the table that ensure_table() created is still present. Reports true when this process has not created it.
bool table_present();

/// Deletes the table now (idempotent).
void remove_table();

/// Creates one chain per hook used by `rules` and a queue-to-`queue_number` rule for each entry. Address lists with
/// several members become named sets, shared by every rule of the channel that uses the same list.
/// `priority` is the nftables chain priority (lower runs first). Rules use `bypass`, so packets are
/// accepted whenever no program is bound to the queue. A non-zero `release_bit` adds the "already released by this
/// channel" guard described at NftBatch::add_channel().
bool add_channel_rules(uint32_t				  channel_id,
					   uint16_t				  queue_number,
					   int					  priority,
					   const std::vector<CompiledRule>& rules,
					   ChannelChains&		  chains,
					   std::string&			  error,
					   uint32_t				  release_bit = 0);

/// Removes the chains and sets of a channel. Failures are ignored; the table is deleted on exit anyway.
void remove_channel_rules(ChannelChains& chains);

}  // namespace nfq

#endif
