#include "nft_table.h"

#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <poll.h>
#include <sys/socket.h>

#include <cerrno>
#include <cstring>
#include <ctime>
#include <mutex>

#include "log.h"

LOG_DEFAULT_GROUP(logging::group::nft)

#ifndef NETLINK_EXT_ACK
#define NETLINK_EXT_ACK 11
#endif
#ifndef NETLINK_CAP_ACK
#define NETLINK_CAP_ACK 10
#endif

namespace nfq {
namespace {
constexpr int kAckTimeoutMs		= 5000;
constexpr int kFailureDrainMs	= 50;
constexpr int kSendBufferBytes	= 2 * 1024 * 1024;
constexpr size_t kReceiveBytes	= 64 * 1024;

/// The socket that creates an owner table must stay open as long as the table should exist, and is the only one allowed
/// to change it. Every transaction therefore goes through this one socket, serialised by `table_mutex`.
std::mutex table_mutex;
mnl_socket* netlink		 = nullptr;
uint32_t	next_seq	 = 0;
bool		table_created = false;
bool		table_owned	  = false;

struct SendResult
{
	bool		ok		  = false;
	int			code	  = 0;
	std::string message;
};

std::string extended_ack_text(const nlmsghdr* header, const nlmsgerr* error)
{
	if ((header->nlmsg_flags & NLM_F_ACK_TLVS) == 0)
		return {};
	// The kernel echoes the failing request unless NLM_F_CAPPED says it only sent the header; attributes follow it.
	size_t offset = sizeof(nlmsgerr);
	if ((header->nlmsg_flags & NLM_F_CAPPED) == 0)
		offset += mnl_nlmsg_get_payload_len(&error->msg);
	const size_t payload = mnl_nlmsg_get_payload_len(header);
	if (offset >= payload)
		return {};
	const char* cursor = reinterpret_cast<const char*>(error) + offset;
	size_t		left   = payload - offset;
	while (left >= sizeof(nlattr))
	{
		const nlattr* attribute = reinterpret_cast<const nlattr*>(cursor);
		if (attribute->nla_len < sizeof(nlattr) || attribute->nla_len > left)
			break;
		if ((attribute->nla_type & NLA_TYPE_MASK) == NLMSGERR_ATTR_MSG)
			return std::string(cursor + NLA_HDRLEN, ::strnlen(cursor + NLA_HDRLEN, attribute->nla_len - NLA_HDRLEN));
		const size_t step = NLA_ALIGN(attribute->nla_len);
		if (step >= left)
			break;
		cursor += step;
		left -= step;
	}
	return {};
}

bool open_socket(std::string& error)
{
	if (netlink != nullptr)
		return true;
	netlink = mnl_socket_open2(NETLINK_NETFILTER, SOCK_CLOEXEC);
	if (netlink == nullptr)
	{
		error = std::string("cannot open a netfilter netlink socket: ") + std::strerror(errno);
		return false;
	}
	if (mnl_socket_bind(netlink, 0, MNL_SOCKET_AUTOPID) < 0)
	{
		error = std::string("cannot bind the netfilter netlink socket: ") + std::strerror(errno);
		mnl_socket_close(netlink);
		netlink = nullptr;
		return false;
	}
	const int enable = 1;
	if (mnl_socket_setsockopt(netlink, NETLINK_EXT_ACK, const_cast<int*>(&enable), sizeof(enable)) < 0)
		LOG_DEBUG("NETLINK_EXT_ACK is not supported; kernel error details will be limited");
	mnl_socket_setsockopt(netlink, NETLINK_CAP_ACK, const_cast<int*>(&enable), sizeof(enable));
	// A whole ruleset is submitted as one datagram, which must fit the socket's send buffer.
	const int fd	 = mnl_socket_get_fd(netlink);
	int		  buffer = kSendBufferBytes;
	if (::setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &buffer, sizeof(buffer)) < 0)
		::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buffer, sizeof(buffer));
	next_seq = static_cast<uint32_t>(std::time(nullptr));
	LOG_DEBUG("opened the netfilter netlink socket (port id %u)", mnl_socket_get_portid(netlink));
	return true;
}

void close_socket()
{
	if (netlink == nullptr)
		return;
	mnl_socket_close(netlink);
	netlink = nullptr;
}

/// Reads replies until the acknowledgement of `ack_seq` arrives or a failure has been reported. Messages whose sequence
/// number is outside [first_seq, ack_seq] are ignored.
SendResult wait_for_reply(uint32_t first_seq, uint32_t ack_seq)
{
	SendResult		  result;
	std::vector<char> buffer(kReceiveBytes);
	pollfd			  descriptor{mnl_socket_get_fd(netlink), POLLIN, 0};
	for (;;)
	{
		const int ready = ::poll(&descriptor, 1, result.code != 0 ? kFailureDrainMs : kAckTimeoutMs);
		if (ready < 0 && errno == EINTR)
			continue;
		if (ready == 0)
		{
			if (result.code == 0)
			{
				result.code		= ETIMEDOUT;
				result.message = "timed out waiting for the kernel to answer";
			}
			return result;
		}
		if (ready < 0)
		{
			result.code		= errno;
			result.message = std::string("poll failed: ") + std::strerror(errno);
			return result;
		}
		const ssize_t received = mnl_socket_recvfrom(netlink, buffer.data(), buffer.size());
		if (received < 0)
		{
			if (errno == EINTR || errno == ENOBUFS)
				continue;
			result.code	   = errno;
			result.message = std::string("netlink receive failed: ") + std::strerror(errno);
			return result;
		}
		int length = static_cast<int>(received);
		for (const nlmsghdr* header = reinterpret_cast<const nlmsghdr*>(buffer.data()); mnl_nlmsg_ok(header, length); header = mnl_nlmsg_next(header, &length))
		{
			if (header->nlmsg_seq - first_seq > ack_seq - first_seq || header->nlmsg_type != NLMSG_ERROR)
				continue;
			if (mnl_nlmsg_get_payload_len(header) < sizeof(nlmsgerr))
				continue;
			const nlmsgerr* error = static_cast<const nlmsgerr*>(mnl_nlmsg_get_payload(header));
			if (error->error == 0)
			{
				if (header->nlmsg_seq == ack_seq && result.code == 0)
				{
					result.ok = true;
					return result;
				}
				continue;
			}
			if (result.code == 0)
			{
				result.code	   = -error->error;
				result.message = std::strerror(result.code);
				const std::string detail = extended_ack_text(header, error);
				if (!detail.empty())
					result.message += ": " + detail;
			}
			if (header->nlmsg_seq == ack_seq)
				return result;
		}
	}
}

SendResult send_request(const std::vector<uint8_t>& bytes, uint32_t first_seq, uint32_t ack_seq)
{
	SendResult result;
	if (netlink == nullptr)
	{
		result.code		= ENOTCONN;
		result.message = "the netlink socket is closed";
		return result;
	}
	if (mnl_socket_sendto(netlink, bytes.data(), bytes.size()) < 0)
	{
		result.code		= errno;
		result.message = std::string("netlink send failed: ") + std::strerror(errno);
		return result;
	}
	return wait_for_reply(first_seq, ack_seq);
}

/// Sends a finished batch and waits for the kernel's verdict on the whole transaction.
SendResult run_batch(NftBatch& batch)
{
	SendResult result;
	if (!batch.finish())
	{
		result.code	   = EMSGSIZE;
		result.message = batch.error();
		return result;
	}
	LOG_DEBUG_GROUP(logging::group::nft_script, "nft: sending a batch of %zu message(s), %zu bytes", batch.message_count(), batch.bytes().size());
	result = send_request(batch.bytes(), batch.first_seq(), batch.last_seq());
	next_seq = batch.last_seq() + 2;
	if (result.ok)
		LOG_DEBUG_GROUP(logging::group::nft_script, "nft: batch committed");
	else
		LOG_DEBUG_GROUP(logging::group::nft_script, "nft: batch failed (%d): %s", result.code, result.message.c_str());
	return result;
}

struct TableGuard
{
	~TableGuard() { remove_table(); }
};
}  // namespace

bool ensure_table(std::string& error)
{
	static TableGuard			guard;
	std::lock_guard<std::mutex> lock(table_mutex);
	if (table_created)
		return true;
	LOG_DEBUG("preparing the nftables table inet %s (replacing any stale copy)", kTableName);
	if (!open_socket(error))
	{
		LOG_ERROR("failed to open the netlink socket for nftables: %s", error.c_str());
		return false;
	}
	SendResult result;
	for (const bool owner : {true, false})
	{
		// add + delete + add replaces a leftover table atomically and succeeds when none exists. The first add must not
		// carry flags: an existing table cannot change its owner flag.
		NftBatch batch(next_seq);
		batch.add_table(false);
		batch.delete_table();
		batch.add_table(owner);
		result = run_batch(batch);
		if (result.ok)
		{
			table_created = true;
			table_owned	  = owner;
			break;
		}
		if (owner && result.code == EOPNOTSUPP)
		{
			LOG_WARN("this kernel does not support owner tables (Linux 5.12+); the nftables table will outlive the process after SIGKILL");
			continue;
		}
		break;
	}
	if (!table_created)
	{
		error = result.message;
		// An owner table can only be changed by the socket that created it, so a second running instance is refused.
		if (result.code == EPERM || result.code == EOPNOTSUPP)
			error += " (another lagsw instance may already own the inet lagsw table, or CAP_NET_ADMIN / nf_tables is unavailable)";
		LOG_ERROR("failed to create the nftables table inet %s: %s", kTableName, error.c_str());
		close_socket();
		return false;
	}
	LOG_DEBUG("nftables table inet %s created (owner flag = %d)", kTableName, table_owned ? 1 : 0);
	return true;
}

bool table_present()
{
	std::lock_guard<std::mutex> lock(table_mutex);
	if (!table_created)
		return true;
	const uint32_t			   seq	   = next_seq++;
	const std::vector<uint8_t> request = build_get_table_request(seq);
	if (request.empty())
		return false;
	return send_request(request, seq, seq).ok;
}

void remove_table()
{
	std::lock_guard<std::mutex> lock(table_mutex);
	if (!table_created)
	{
		close_socket();
		return;
	}
	LOG_DEBUG("removing the nftables table inet %s", kTableName);
	NftBatch batch(next_seq);
	batch.delete_table();
	const SendResult result = run_batch(batch);
	if (!result.ok)
		LOG_WARN("failed to remove the nftables table inet %s: %s", kTableName, result.message.c_str());
	else
		LOG_DEBUG("nftables table inet %s removed", kTableName);
	table_created = false;
	table_owned	  = false;
	// Closing the socket also removes an owner table if the explicit delete failed.
	close_socket();
}

bool add_channel_rules(uint32_t channel_id,
					   uint16_t queue_number,
					   int		priority,
					   const std::vector<CompiledRule>& rules,
					   ChannelChains& chains,
					   std::string& error,
					   uint32_t release_bit)
{
	std::lock_guard<std::mutex> lock(table_mutex);
	if (!table_created)
	{
		error = "the nftables table has not been created";
		return false;
	}
	ChannelChains created;
	NftBatch	  batch(next_seq);
	batch.add_channel(channel_id, queue_number, priority, rules, created, release_bit);
	if (created.names.empty() && batch.ok())
		return true;
	for ([[maybe_unused]] const CompiledRule& rule : rules)
		LOG_DEBUG_GROUP(logging::group::nft_script, "nft: ch%u %s: %s queue flags bypass to %u", channel_id, hook_name(rule.hook), rule.match.c_str(), static_cast<unsigned>(queue_number));
	const SendResult result = run_batch(batch);
	if (result.ok)
	{
		chains = std::move(created);
		LOG_DEBUG("channel %u: installed %zu chain(s), %zu set(s) and %zu rule(s) feeding queue %u at priority %d",
				  channel_id,
				  chains.names.size(),
				  chains.sets.size(),
				  rules.size(),
				  static_cast<unsigned>(queue_number),
				  priority);
		return true;
	}
	error = result.message;
	LOG_ERROR("channel %u: failed to install nftables rules for queue %u: %s", channel_id, static_cast<unsigned>(queue_number), error.c_str());
	chains = {};
	return false;
}

void remove_channel_rules(ChannelChains& chains)
{
	if (chains.names.empty() && chains.sets.empty())
		return;
	std::lock_guard<std::mutex> lock(table_mutex);
	if (table_created)
	{
		NftBatch batch(next_seq);
		batch.delete_channel(chains);
		const SendResult result = run_batch(batch);
		if (!result.ok)
			LOG_WARN("failed to remove %zu nftables chain(s) and %zu set(s): %s", chains.names.size(), chains.sets.size(), result.message.c_str());
		else
			LOG_DEBUG("removed %zu nftables chain(s) and %zu set(s)", chains.names.size(), chains.sets.size());
	}
	chains = {};
}
}  // namespace nfq
