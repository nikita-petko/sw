// Linux packet backend: nftables selects the traffic and NFQUEUE hands it to user space, where each packet
// is held until the engine sends (accepts) or discards (drops) it. See pocs/linux_nfqueue_backend.md.
#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <linux/netlink.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstring>
#include <deque>
#include <mutex>
#include <sstream>

#include "filter_compiler.h"
#include "log.h"
#include "monitor.h"
#include "nft_table.h"
#include "packet_backend.h"
#include "privileges.h"

LOG_DEFAULT_GROUP(logging::group::nfq)

namespace backend {
namespace {
constexpr uint16_t kFirstQueueNumber = 10;
constexpr uint32_t kQueueMaxLength	 = 16384;
constexpr int	   kSocketBuffer	 = 8 * 1024 * 1024;
constexpr uint32_t kReceiveBuffer	 = 0x10000 + 4096;
constexpr uint32_t kMinIpv4Header	 = 20;
// Capture priorities run high-to-low; nftables chain priorities run low-to-high.
constexpr int kBasePriority = -150;

std::atomic<uint32_t> next_channel_id{0};

/// Backend-private state stored in PacketMeta::native.
struct NativeMeta
{
	uint32_t packet_id;
	uint32_t length;
	uint64_t payload_hash;
};
static_assert(sizeof(NativeMeta) <= sizeof(PacketMeta::native), "PacketMeta::native is too small");

uint64_t hash_payload(const uint8_t* data, uint32_t length)
{
	uint64_t hash = 1469598103934665603ull;
	for (uint32_t index = 0; index < length; ++index)
		hash = (hash ^ data[index]) * 1099511628211ull;
	return hash;
}

class NfqChannel final : public PacketChannel
{
public:
	NfqChannel(bool sniff, uint32_t channel_id) : sniff_(sniff), channel_id_(channel_id), receive_buffer_(kReceiveBuffer) {}

	~NfqChannel() override { close(); }

	bool start(uint16_t queue_number, int priority, const std::vector<nfq::CompiledRule>& rules, std::string& error)
	{
		LOG_DEBUG("channel %u: starting on queue %u (sniff = %d, priority = %d, %zu rule(s))", channel_id_, static_cast<unsigned>(queue_number), sniff_ ? 1 : 0, priority, rules.size());
		event_fd_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
		if (event_fd_ < 0)
		{
			LOG_ERROR("channel %u: eventfd failed: %s", channel_id_, std::strerror(errno));
			error = std::string("eventfd failed: ") + std::strerror(errno);
			return false;
		}
		handle_ = nfq_open();
		if (handle_ == nullptr)
		{
			LOG_ERROR("channel %u: nfq_open failed: %s", channel_id_, std::strerror(errno));
			error = std::string("nfq_open failed: ") + std::strerror(errno) + " (CAP_NET_ADMIN is required)";
			return false;
		}
		queue_ = nfq_create_queue(handle_, queue_number, &NfqChannel::on_packet, this);
		if (queue_ == nullptr)
		{
			LOG_ERROR("channel %u: could not create queue %u: %s", channel_id_, static_cast<unsigned>(queue_number), std::strerror(errno));
			error = "nfq_create_queue(" + std::to_string(queue_number) + ") failed: " + std::strerror(errno);
			return false;
		}
		if (nfq_set_mode(queue_, NFQNL_COPY_PACKET, 0xFFFF) < 0)
		{
			LOG_ERROR("channel %u: nfq_set_mode failed: %s", channel_id_, std::strerror(errno));
			error = std::string("nfq_set_mode failed: ") + std::strerror(errno);
			return false;
		}
		LOG_DEBUG("channel %u: queue %u bound (copy packet, max length %u)", channel_id_, static_cast<unsigned>(queue_number), kQueueMaxLength);
		nfq_set_queue_maxlen(queue_, kQueueMaxLength);
		// Fail open when the queue overflows; GSO lets the kernel pass large offloaded packets instead of dropping them.
		if (nfq_set_queue_flags(queue_, NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_GSO, NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_GSO) < 0)
			LOG_WARN("channel %u: kernel lacks the fail-open/GSO queue flags; a full queue will drop packets", channel_id_);
		fd_ = nfq_fd(handle_);
		int enable = 1;
		if (::setsockopt(fd_, SOL_NETLINK, NETLINK_NO_ENOBUFS, &enable, sizeof(enable)) < 0)
			LOG_DEBUG("channel %u: NETLINK_NO_ENOBUFS failed: %s", channel_id_, std::strerror(errno));
		int buffer = kSocketBuffer;
		if (::setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &buffer, sizeof(buffer)) < 0)
			LOG_DEBUG("channel %u: SO_RCVBUF %d failed: %s", channel_id_, buffer, std::strerror(errno));

		// The queue exists before the rules that feed it, so no packet is ever bypassed during setup.
		return nfq::add_channel_rules(channel_id_, queue_number, priority, rules, chains_, error);
	}

	IoStatus recv(uint8_t* buffer, uint32_t capacity, uint32_t& length, PacketMeta& meta, std::string& error) override
	{
		length = 0;
		for (;;)
		{
			if (shutdown_.load())
				return IoStatus::closed;
			while (!pending_.empty())
			{
				Pending packet = std::move(pending_.front());
				pending_.pop_front();
				const NativeMeta* native = reinterpret_cast<const NativeMeta*>(packet.meta.native);
				if (packet.data.size() > capacity)
				{
					LOG_WARN("channel %u: accepting a %zu byte packet larger than the %u byte receive buffer unchanged", channel_id_, packet.data.size(), capacity);
					verdict(native->packet_id, NF_ACCEPT, nullptr, 0);
					continue;
				}
				std::memcpy(buffer, packet.data.data(), packet.data.size());
				length = static_cast<uint32_t>(packet.data.size());
				meta   = packet.meta;
				// A sniffing channel only observes: the packet is released before the engine sees it.
				if (sniff_)
					verdict(native->packet_id, NF_ACCEPT, nullptr, 0);
				return IoStatus::ok;
			}

			pollfd fds[2] = {{fd_, POLLIN, 0}, {event_fd_, POLLIN, 0}};
			if (::poll(fds, 2, -1) < 0)
			{
				if (errno == EINTR)
					continue;
				LOG_ERROR("channel %u: poll failed: %s", channel_id_, std::strerror(errno));
				error = std::string("poll failed: ") + std::strerror(errno);
				return IoStatus::error;
			}
			if ((fds[1].revents & POLLIN) != 0 || shutdown_.load())
			{
				LOG_DEBUG("channel %u: receive loop woken for shutdown", channel_id_);
				return IoStatus::closed;
			}
			if ((fds[0].revents & POLLIN) == 0)
				continue;
			const ssize_t count = ::recv(fd_, receive_buffer_.data(), receive_buffer_.size(), 0);
			if (count < 0)
			{
				if (errno == ENOBUFS)
					LOG_WARN("channel %u: the netlink socket overflowed; queue notifications were lost", channel_id_);
				if (errno == EINTR || errno == ENOBUFS || errno == EAGAIN)
					continue;
				LOG_ERROR("channel %u: netlink recv failed: %s", channel_id_, std::strerror(errno));
				error = std::string("netlink recv failed: ") + std::strerror(errno);
				return IoStatus::error;
			}
			nfq_handle_packet(handle_, reinterpret_cast<char*>(receive_buffer_.data()), static_cast<int>(count));
		}
	}

	IoStatus send(const uint8_t* packet, uint32_t length, const PacketMeta& meta, uint32_t& sent, std::string& error) override
	{
		sent = 0;
		if (sniff_)
		{
			sent = length;
			return IoStatus::ok;
		}
		const NativeMeta* native = reinterpret_cast<const NativeMeta*>(meta.native);
		// An unmodified packet is accepted as-is so the kernel keeps its offload and checksum state.
		const bool unchanged = length == native->length && hash_payload(packet, length) == native->payload_hash;
		LOG_DEBUG_GROUP(logging::group::nfq_packet, "channel %u: accept packet id %u (%u bytes, %s)", channel_id_, native->packet_id, length, unchanged ? "unchanged" : "modified");
		if (!verdict(native->packet_id, NF_ACCEPT, unchanged ? nullptr : packet, unchanged ? 0 : length))
		{
			LOG_ERROR("channel %u: failed to accept packet id %u: %s", channel_id_, native->packet_id, std::strerror(errno));
			error = std::string("nfq_set_verdict failed: ") + std::strerror(errno);
			return IoStatus::error;
		}
		sent = length;
		return IoStatus::ok;
	}

	void discard(const PacketMeta& meta) override
	{
		if (sniff_)
			return;
		const uint32_t packet_id = reinterpret_cast<const NativeMeta*>(meta.native)->packet_id;
		LOG_DEBUG_GROUP(logging::group::nfq_packet, "channel %u: drop packet id %u", channel_id_, packet_id);
		if (!verdict(packet_id, NF_DROP, nullptr, 0))
			LOG_ERROR("channel %u: failed to drop packet id %u: %s", channel_id_, packet_id, std::strerror(errno));
	}

	void shutdown_recv() override
	{
		shutdown_.store(true);
		if (event_fd_ >= 0)
		{
			const uint64_t one = 1;
			if (::write(event_fd_, &one, sizeof(one)) < 0)
				LOG_DEBUG("channel %u: failed to wake the receive loop", channel_id_);
		}
	}

	void close() override
	{
		if (closed_.exchange(true))
			return;
		LOG_DEBUG("channel %u: closing", channel_id_);
		shutdown_recv();
		// Remove the rules first so traffic stops being queued before the queue disappears.
		nfq::remove_channel_rules(chains_);
		{
			std::lock_guard<std::mutex> lock(verdict_mutex_);
			if (queue_ != nullptr)
				nfq_destroy_queue(queue_);
			queue_ = nullptr;
			if (handle_ != nullptr)
				nfq_close(handle_);
			handle_ = nullptr;
		}
		if (event_fd_ >= 0)
			::close(event_fd_);
		event_fd_ = -1;
		LOG_DEBUG("channel %u: closed", channel_id_);
	}

private:
	struct Pending
	{
		std::vector<uint8_t> data;
		PacketMeta			 meta;
	};

	bool verdict(uint32_t packet_id, uint32_t decision, const uint8_t* payload, uint32_t length)
	{
		std::lock_guard<std::mutex> lock(verdict_mutex_);
		if (queue_ == nullptr)
		{
			errno = EBADF;
			return false;
		}
		return nfq_set_verdict(queue_, packet_id, decision, length, payload) >= 0;
	}

	static int on_packet(nfq_q_handle*, nfgenmsg*, nfq_data* data, void* user)
	{
		static_cast<NfqChannel*>(user)->handle_packet(data);
		return 0;
	}

	void handle_packet(nfq_data* data)
	{
		const nfqnl_msg_packet_hdr* header = nfq_get_msg_packet_hdr(data);
		if (header == nullptr)
		{
			LOG_DEBUG_GROUP(logging::group::nfq_packet, "channel %u: queued message without a packet header, ignoring", channel_id_);
			return;
		}
		const uint32_t packet_id = ntohl(header->packet_id);
		unsigned char* payload	 = nullptr;
		const int	   length	 = nfq_get_payload(data, &payload);
		// Only well-formed IPv4 packets are handed to the engine; everything else is let through untouched.
		if (length < static_cast<int>(kMinIpv4Header) || payload == nullptr || (payload[0] >> 4) != 4)
		{
			LOG_DEBUG_GROUP(logging::group::nfq_packet, "channel %u: accept packet id %u untouched (not well-formed IPv4, length = %d)", channel_id_, packet_id, length);
			verdict(packet_id, NF_ACCEPT, nullptr, 0);
			return;
		}
		Pending packet;
		packet.data.assign(payload, payload + length);
		packet.meta.outbound = header->hook == NF_INET_LOCAL_OUT || header->hook == NF_INET_FORWARD;
		packet.meta.if_index = header->hook == NF_INET_LOCAL_OUT ? nfq_get_outdev(data) : nfq_get_indev(data);
		timeval stamp{};
		if (nfq_get_timestamp(data, &stamp) == 0)
			packet.meta.timestamp = static_cast<int64_t>(stamp.tv_sec) * 1000000 + stamp.tv_usec;
		NativeMeta native{packet_id, static_cast<uint32_t>(length), hash_payload(payload, static_cast<uint32_t>(length))};
		std::memcpy(packet.meta.native, &native, sizeof(native));
		LOG_DEBUG_GROUP(logging::group::nfq_packet, "channel %u: queued packet id %u (%d bytes, hook = %u, outbound = %d)", channel_id_, packet_id, length, static_cast<unsigned>(header->hook), packet.meta.outbound ? 1 : 0);
		pending_.push_back(std::move(packet));
	}

	const bool				sniff_;
	const uint32_t			channel_id_;
	nfq_handle*				handle_	  = nullptr;
	nfq_q_handle*			queue_	  = nullptr;
	int						fd_		  = -1;
	int						event_fd_ = -1;
	std::atomic<bool>		shutdown_{false};
	std::atomic<bool>		closed_{false};
	std::mutex				verdict_mutex_;
	std::deque<Pending>		pending_;
	std::vector<uint8_t>	receive_buffer_;
	nfq::ChannelChains		chains_;
};

std::string address_chain(const char* field, const std::vector<std::string>& addresses)
{
	std::string chain;
	for (const std::string& address : addresses)
	{
		if (!chain.empty())
			chain += " or ";
		chain += field + std::string(" == ") + address;
	}
	return chain;
}

std::string port_expression(uint16_t port)
{
	const std::string text = std::to_string(port);
	return "tcp.DstPort == " + text + " or tcp.SrcPort == " + text + " or udp.DstPort == " + text + " or udp.SrcPort == " + text;
}
}  // namespace

const char* name()
{
	return "nfqueue";
}

bool initialize()
{
	// Privileges are verified by check_privileges() after option parsing, so --help and config checks work unprivileged.
	return true;
}

bool check_privileges(std::string& error)
{
	return nfq::check_privileges(error);
}

std::unique_ptr<PacketChannel> open(const OpenOptions& options, std::string& error)
{
	std::vector<nfq::CompiledRule> rules;
	uint32_t					   position = 0;
	if (!nfq::compile_filter(options.filter, options.forward, rules, error, position, options.include_forward))
	{
		error += " (at position " + std::to_string(position) + ")";
		LOG_ERROR_GROUP(logging::group::nfq_filter, "could not compile filter '%s': %s", options.filter.c_str(), error.c_str());
		return nullptr;
	}
	LOG_DEBUG_GROUP(logging::group::nfq_filter, "compiled filter '%s' (forward = %d, include_forward = %d) into %zu rule(s)", options.filter.c_str(), options.forward ? 1 : 0, options.include_forward ? 1 : 0, rules.size());
	for ([[maybe_unused]] const nfq::CompiledRule& rule : rules)
		LOG_DEBUG_GROUP(logging::group::nfq_filter, "  %s", rule.match.c_str());
	if (!nfq::ensure_table(error))
	{
		LOG_ERROR("nfqueue: could not prepare the nftables table: %s", error.c_str());
		error = "failed to prepare the nftables table (is nft installed and CAP_NET_ADMIN granted?): " + error;
		return nullptr;
	}
	const uint32_t channel_id	= next_channel_id.fetch_add(1);
	const int	   priority		= kBasePriority - static_cast<int>(options.priority);
	auto		   channel		= std::make_unique<NfqChannel>(options.sniff, channel_id);
	if (!channel->start(static_cast<uint16_t>(kFirstQueueNumber + channel_id), priority, rules, error))
	{
		LOG_ERROR("nfqueue: channel %u failed to start: %s", channel_id, error.c_str());
		return nullptr;
	}
	LOG_DEBUG("nfqueue: opened channel %u on queue %u for filter '%s'", channel_id, static_cast<unsigned>(kFirstQueueNumber + channel_id), options.filter.c_str());
	return channel;
}

bool validate_filter(const std::string& filter, bool forward, std::string& error, uint32_t& position)
{
	std::vector<nfq::CompiledRule> rules;
	return nfq::compile_filter(filter, forward, rules, error, position);
}

void calc_checksums(uint8_t* packet, uint32_t length)
{
	if (length < kMinIpv4Header || (packet[0] >> 4) != 4)
		return;
	const uint32_t ip_length = (packet[0] & 0x0F) * 4u;
	if (ip_length < kMinIpv4Header || ip_length > length)
		return;

	auto sum16 = [](const uint8_t* data, uint32_t size, uint32_t initial) {
		uint32_t sum = initial;
		for (; size > 1; size -= 2, data += 2)
			sum += static_cast<uint32_t>(data[0]) << 8 | data[1];
		if (size == 1)
			sum += static_cast<uint32_t>(data[0]) << 8;
		while (sum >> 16)
			sum = (sum & 0xFFFF) + (sum >> 16);
		return sum;
	};

	packet[10] = packet[11] = 0;
	const uint16_t ip_sum	= static_cast<uint16_t>(~sum16(packet, ip_length, 0));
	packet[10]				= ip_sum >> 8;
	packet[11]				= ip_sum & 0xFF;

	const uint8_t  protocol		= packet[9];
	const uint32_t total_length = (static_cast<uint32_t>(packet[2]) << 8 | packet[3]);
	const uint32_t end			= total_length != 0 && total_length <= length ? total_length : length;
	if (end <= ip_length)
		return;
	const uint32_t segment_length = end - ip_length;
	uint32_t	   checksum_offset;
	if (protocol == 6)
		checksum_offset = 16;
	else if (protocol == 17)
		checksum_offset = 6;
	else
		return;
	if (segment_length < checksum_offset + 2)
		return;
	uint8_t* segment = packet + ip_length;
	segment[checksum_offset] = segment[checksum_offset + 1] = 0;
	uint32_t sum = sum16(packet + 12, 8, 0) + protocol + segment_length;
	sum			 = sum16(segment, segment_length, sum);
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	uint16_t result = static_cast<uint16_t>(~sum);
	// A computed UDP checksum of zero is transmitted as all ones.
	if (protocol == 17 && result == 0)
		result = 0xFFFF;
	segment[checksum_offset]	 = result >> 8;
	segment[checksum_offset + 1] = result & 0xFF;
}

namespace filters {
std::string profile(const ProfileFilter& spec)
{
	std::string filter = spec.user_filter;
	if (spec.include_bare_acks)
		filter = "(" + filter + ") or (tcp.Ack and not tcp.Psh)";

	std::string client_filter;
	if (spec.client_enforcement == ClientAddressEnforcement::source || spec.client_enforcement == ClientAddressEnforcement::both)
		if (spec.client_source)
			client_filter = "ip.SrcAddr == " + *spec.client_source;
	if (spec.client_enforcement == ClientAddressEnforcement::destination || spec.client_enforcement == ClientAddressEnforcement::both)
		if (spec.client_destination)
		{
			if (!client_filter.empty())
				client_filter += " or ";
			client_filter += "ip.DstAddr == " + *spec.client_destination;
		}
	if (!client_filter.empty())
		filter = "(" + filter + ") and (" + client_filter + ")";

	if (spec.server_direction && !spec.server_addresses.empty())
	{
		const char* address_field = "ip.Addr";
		switch (*spec.server_direction)
		{
			case ServerDirection::source:
				address_field = "ip.SrcAddr";
				break;
			case ServerDirection::destination:
				address_field = "ip.DstAddr";
				break;
			case ServerDirection::both:
				break;
		}
		filter = "(" + filter + ") and (" + address_chain(address_field, spec.server_addresses) + ")";
	}
	return spec.outbound ? "outbound and (" + filter + ")" : filter;
}

std::string port(uint16_t port)
{
	return port_expression(port);
}

#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
std::string syn_probe(uint16_t port)
{
	const std::string text = std::to_string(port);
	return "tcp.Syn and (tcp.DstPort == " + text + " or tcp.SrcPort == " + text + ")";
}

std::string region_enforcement(const std::vector<std::string>& server_addresses, uint16_t port)
{
	if (server_addresses.empty())
		return {};
	return "tcp.Psh and (" + address_chain("ip.SrcAddr", server_addresses) + ") and tcp.SrcPort == " + std::to_string(port);
}
#endif

#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
std::string forwarded_address(uint32_t inbound_if_index, uint32_t outbound_if_index, uint16_t port)
{
	return "outbound and (ifIdx == " + std::to_string(inbound_if_index) + " or ifIdx == " + std::to_string(outbound_if_index) + ") and (" +
		   port_expression(port) + ")";
}
#endif
}  // namespace filters
#ifdef LAGSW_FEATURE_NETFILTER_MONITOR
std::string monitor_status(uint64_t interval_ms, uint32_t backlog_threshold)
{
	return nfq::monitor_status(kFirstQueueNumber, next_channel_id.load(), interval_ms, backlog_threshold);
}
#endif

}  // namespace backend
