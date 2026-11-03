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
#include <unordered_set>

#include "filter_compiler.h"
#include "log.h"
#include "monitor.h"
#include "nft_table.h"
#include "packet_backend.h"
#include "privileges.h"
#include "shaper/shaper.h"
#include "verdict_tracker.h"

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

	// Mark bits reserved for released packets, one per live intercepting channel (see NftBatch::add_channel). They sit in
	// the top byte, which is rarely used by other tooling; channels beyond the eighth simply run without the guard.
	constexpr uint32_t kReleaseMarkPool = 0xFF000000u;

	std::atomic<uint32_t> next_channel_id{0};
	std::mutex			  release_mark_mutex;
	uint32_t			  release_marks_in_use = 0;

	uint32_t acquire_release_bit()
	{
		std::lock_guard<std::mutex> lock(release_mark_mutex);
		for (uint32_t bit = 1u << 24; (bit & kReleaseMarkPool) != 0; bit <<= 1)
		{
			if ((release_marks_in_use & bit) == 0)
			{
				release_marks_in_use |= bit;
				return bit;
			}
		}
		return 0;
	}

	void release_release_bit(uint32_t bit)
	{
		std::lock_guard<std::mutex> lock(release_mark_mutex);
		release_marks_in_use &= ~bit;
	}

	/// Backend-private state stored in PacketMeta::native.
	struct NativeMeta
	{
		uint32_t packet_id;
		uint32_t length;
		uint64_t payload_hash;
		uint32_t nfmark;
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

		~NfqChannel() override
		{
			close();
			if (release_bit_ != 0)
				release_release_bit(release_bit_);
		}

		/// Packets this channel accepts are marked with `bit`, which the channel's own rules test to avoid queueing them again.
		void set_release_bit(uint32_t bit) { release_bit_ = bit; }

		bool start(uint16_t queue_number, int priority, const std::vector<linux_shared::CompiledRule>& rules, std::string& error)
		{
			LOG_DEBUG("channel %u: starting on queue %u (sniff = %d, priority = %d, %zu rule(s))",
					  channel_id_,
					  static_cast<unsigned>(queue_number),
					  sniff_ ? 1 : 0,
					  priority,
					  rules.size());
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
				LOG_ERROR("channel %u: could not create queue %u: %s",
						  channel_id_,
						  static_cast<unsigned>(queue_number),
						  std::strerror(errno));
				error = "nfq_create_queue(" + std::to_string(queue_number) + ") failed: " + std::strerror(errno);
				return false;
			}
			if (nfq_set_mode(queue_, NFQNL_COPY_PACKET, 0xFFFF) < 0)
			{
				LOG_ERROR("channel %u: nfq_set_mode failed: %s", channel_id_, std::strerror(errno));
				error = std::string("nfq_set_mode failed: ") + std::strerror(errno);
				return false;
			}
			LOG_DEBUG("channel %u: queue %u bound (copy packet, max length %u)",
					  channel_id_,
					  static_cast<unsigned>(queue_number),
					  kQueueMaxLength);
			nfq_set_queue_maxlen(queue_, kQueueMaxLength);
			// Fail open when the queue overflows; GSO lets the kernel pass large offloaded packets instead of dropping them.
			if (nfq_set_queue_flags(queue_, NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_GSO, NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_GSO) < 0)
				LOG_WARN("channel %u: kernel lacks the fail-open/GSO queue flags; a full queue will drop packets", channel_id_);
			fd_		   = nfq_fd(handle_);
			int enable = 1;
			if (::setsockopt(fd_, SOL_NETLINK, NETLINK_NO_ENOBUFS, &enable, sizeof(enable)) < 0)
				LOG_DEBUG("channel %u: NETLINK_NO_ENOBUFS failed: %s", channel_id_, std::strerror(errno));
			int buffer = kSocketBuffer;
			if (::setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &buffer, sizeof(buffer)) < 0)
				LOG_DEBUG("channel %u: SO_RCVBUF %d failed: %s", channel_id_, buffer, std::strerror(errno));

			// The queue exists before the rules that feed it, so no packet is ever bypassed during setup.
			return nfq::add_channel_rules(channel_id_, queue_number, priority, rules, chains_, error, release_bit_);
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
						LOG_WARN("channel %u: accepting a %zu byte packet larger than the %u byte receive buffer unchanged",
								 channel_id_,
								 packet.data.size(),
								 capacity);
						verdict(native->packet_id, NF_ACCEPT, nullptr, 0, native->nfmark);
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
			LOG_DEBUG_GROUP(logging::group::nfq_packet,
							"channel %u: accept packet id %u (%u bytes, %s)",
							channel_id_,
							native->packet_id,
							length,
							unchanged ? "unchanged" : "modified");
			if (!verdict(native->packet_id, NF_ACCEPT, unchanged ? nullptr : packet, unchanged ? 0 : length, native->nfmark))
			{
				LOG_ERROR("channel %u: failed to accept packet id %u: %s", channel_id_, native->packet_id, std::strerror(errno));
				error = std::string("nfq_set_verdict failed: ") + std::strerror(errno);
				return IoStatus::error;
			}
			sent = length;
			return IoStatus::ok;
		}

		// Packets that are still waiting for a verdict and are released together in order need one netlink message, not one each:
		// a batch verdict accepts every waiting packet up to an id. It is used only for the oldest waiting packets (so nothing
		// that is held for another reason is released by accident), only for unmodified packets, and only when they share
		// one netfilter mark. Everything else is sent individually, in order.
		void send_batch(SendItem* items, size_t count) override
		{
			std::vector<bool> handled(count, false);
			if (!sniff_ && count >= 2)
			{
				std::vector<uint32_t> candidates;
				std::vector<size_t>	  candidate_items;
				for (size_t index = 0; index < count; ++index)
				{
					const NativeMeta* native = reinterpret_cast<const NativeMeta*>(items[index].meta->native);
					if (items[index].length == native->length &&
						hash_payload(items[index].packet, items[index].length) == native->payload_hash)
					{
						candidates.push_back(native->packet_id);
						candidate_items.push_back(index);
					}
				}
				std::lock_guard<std::mutex> lock(verdict_mutex_);
				VerdictRun					run;
				if (queue_ != nullptr)
				{
					std::lock_guard<std::mutex> tracker_lock(tracker_mutex_);
					run = tracker_.plan(candidates);
				}
				if (run.ids.size() >= 2)
				{
					const uint32_t mark = run.mark | release_bit_;
					const int	   rc	= release_bit_ != 0 ? nfq_set_verdict_batch2(queue_, run.last_id, NF_ACCEPT, mark)
															: nfq_set_verdict_batch(queue_, run.last_id, NF_ACCEPT);
					if (rc >= 0)
					{
						LOG_DEBUG("channel %u: batch accept of %zu packets up to id %u", channel_id_, run.ids.size(), run.last_id);
						std::unordered_set<uint32_t> released(run.ids.begin(), run.ids.end());
						{
							std::lock_guard<std::mutex> tracker_lock(tracker_mutex_);
							for (const uint32_t id : run.ids)
								tracker_.remove(id);
						}
						for (size_t position = 0; position < candidates.size(); ++position)
						{
							if (released.count(candidates[position]) == 0)
								continue;
							SendItem& item					   = items[candidate_items[position]];
							item.status						   = IoStatus::ok;
							item.sent						   = item.length;
							handled[candidate_items[position]] = true;
						}
						batch_verdicts_.fetch_add(1);
						batched_packets_.fetch_add(run.ids.size());
					}
					else
						LOG_DEBUG_GROUP(logging::group::nfq_packet,
										"channel %u: batch verdict failed (%s); sending individually",
										channel_id_,
										std::strerror(errno));
				}
			}
			for (size_t index = 0; index < count; ++index)
			{
				if (handled[index])
					continue;
				items[index].status =
					send(items[index].packet, items[index].length, *items[index].meta, items[index].sent, items[index].error);
			}
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

		std::string description() const override { return description_; }

		void set_description(std::string description) { description_ = std::move(description); }

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
			LOG_DEBUG("channel %u: closed (%llu batch verdict(s) released %llu packet(s))",
					  channel_id_,
					  static_cast<unsigned long long>(batch_verdicts_.load()),
					  static_cast<unsigned long long>(batched_packets_.load()));
		}

	private:
		struct Pending
		{
			std::vector<uint8_t> data;
			PacketMeta			 meta;
		};

		using VerdictRun = nfq::VerdictTracker::Run;

		// `nfmark` is the packet's original mark; accepted packets keep it and gain the channel's release bit.
		bool verdict(uint32_t packet_id, uint32_t decision, const uint8_t* payload, uint32_t length, uint32_t nfmark = 0)
		{
			std::lock_guard<std::mutex> lock(verdict_mutex_);
			if (queue_ == nullptr)
			{
				errno = EBADF;
				return false;
			}
			const bool mark_release = decision == NF_ACCEPT && release_bit_ != 0 && !sniff_;
			const int  rc			= mark_release ? nfq_set_verdict2(queue_, packet_id, decision, nfmark | release_bit_, length, payload)
												   : nfq_set_verdict(queue_, packet_id, decision, length, payload);
			if (rc < 0)
				return false;
			std::lock_guard<std::mutex> tracker_lock(tracker_mutex_);
			tracker_.remove(packet_id);
			return true;
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
				LOG_DEBUG_GROUP(logging::group::nfq_packet,
								"channel %u: accept packet id %u untouched (not well-formed IPv4, length = %d)",
								channel_id_,
								packet_id,
								length);
				verdict(packet_id, NF_ACCEPT, nullptr, 0, nfq_get_nfmark(data));
				return;
			}
			Pending packet;
			packet.data.assign(payload, payload + length);
			packet.meta.outbound = header->hook == NF_INET_LOCAL_OUT || header->hook == NF_INET_FORWARD;
			packet.meta.if_index = header->hook == NF_INET_LOCAL_OUT ? nfq_get_outdev(data) : nfq_get_indev(data);
			timeval stamp{};
			if (nfq_get_timestamp(data, &stamp) == 0)
				packet.meta.timestamp = static_cast<int64_t>(stamp.tv_sec) * 1000000 + stamp.tv_usec;
			NativeMeta native{packet_id,
							  static_cast<uint32_t>(length),
							  hash_payload(payload, static_cast<uint32_t>(length)),
							  nfq_get_nfmark(data)};
			std::memcpy(packet.meta.native, &native, sizeof(native));
			LOG_DEBUG_GROUP(logging::group::nfq_packet,
							"channel %u: queued packet id %u (%d bytes, hook = %u, outbound = %d)",
							channel_id_,
							packet_id,
							length,
							static_cast<unsigned>(header->hook),
							packet.meta.outbound ? 1 : 0);
			if (!sniff_)
			{
				// Not verdict_mutex_: close() holds it while the library waits for the kernel and may re-enter this callback.
				std::lock_guard<std::mutex> lock(tracker_mutex_);
				tracker_.add(packet_id, native.nfmark);
			}
			pending_.push_back(std::move(packet));
		}

		const bool			 sniff_;
		const uint32_t		 channel_id_;
		std::string			 description_;
		nfq_handle*			 handle_   = nullptr;
		nfq_q_handle*		 queue_	   = nullptr;
		int					 fd_	   = -1;
		int					 event_fd_ = -1;
		std::atomic<bool>	 shutdown_{false};
		std::atomic<bool>	 closed_{false};
		std::mutex			 verdict_mutex_;
		std::deque<Pending>	 pending_;
		std::vector<uint8_t> receive_buffer_;
		nfq::ChannelChains	 chains_;
		// Lock order: verdict_mutex_, then tracker_mutex_. Nothing may call into libnetfilter_queue while holding tracker_mutex_.
		std::mutex			  tracker_mutex_;
		nfq::VerdictTracker	  tracker_;	 ///< Guarded by tracker_mutex_.
		uint32_t			  release_bit_ = 0;
		std::atomic<uint64_t> batch_verdicts_{0};
		std::atomic<uint64_t> batched_packets_{0};
	};
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
	return linux_shared::check_privileges(error);
}

std::unique_ptr<PacketChannel> open(const OpenOptions& options, std::string& error)
{
	std::vector<linux_shared::CompiledRule> rules;
	uint32_t					   position = 0;
	if (!linux_shared::compile_filter(options.filter, options.forward, rules, error, position, options.include_forward))
	{
		error += " (at position " + std::to_string(position) + ")";
		LOG_ERROR_GROUP(logging::group::nfq_filter, "could not compile filter '%s': %s", options.filter.c_str(), error.c_str());
		return nullptr;
	}
	LOG_DEBUG_GROUP(logging::group::nfq_filter,
					"compiled filter '%s' (forward = %d, include_forward = %d) into %zu rule(s)",
					options.filter.c_str(),
					options.forward ? 1 : 0,
					options.include_forward ? 1 : 0,
					rules.size());
	for ([[maybe_unused]] const linux_shared::CompiledRule& rule : rules)
		LOG_DEBUG_GROUP(logging::group::nfq_filter, "  %s", rule.match.c_str());
	if (!nfq::ensure_table(error))
	{
		LOG_ERROR("nfqueue: could not prepare the nftables table: %s", error.c_str());
		error = "failed to prepare the nftables table (is CAP_NET_ADMIN granted and nf_tables available?): " + error;
		return nullptr;
	}
	const uint32_t channel_id = next_channel_id.fetch_add(1);
	const int	   priority	  = kBasePriority - static_cast<int>(options.priority);
	auto		   channel	  = std::make_unique<NfqChannel>(options.sniff, channel_id);
	// Only channels that hold and release packets need the guard; a sniffer accepts before the engine looks at the packet.
	if (!options.sniff)
	{
		const uint32_t release_bit = acquire_release_bit();
		if (release_bit == 0)
			LOG_WARN("nfqueue: all %d release mark bits are in use; channel %u runs without loop protection",
					 __builtin_popcount(kReleaseMarkPool),
					 channel_id);
		channel->set_release_bit(release_bit);
	}
	channel->set_description(options.forward		   ? "forward hook"
							 : options.include_forward ? "input/output + forward hooks"
													   : "input/output hooks");
	if (!channel->start(static_cast<uint16_t>(kFirstQueueNumber + channel_id), priority, rules, error))
	{
		LOG_ERROR("nfqueue: channel %u failed to start: %s", channel_id, error.c_str());
		return nullptr;
	}
	LOG_DEBUG("nfqueue: opened channel %u on queue %u for filter '%s'",
			  channel_id,
			  static_cast<unsigned>(kFirstQueueNumber + channel_id),
			  options.filter.c_str());
	return channel;
}

void configure_shaping(const ShapingConfig& config)
{
	nfq::shaper::configure(config);
}

std::unique_ptr<ShapeStage> open_shape_stage(const ShapeSpec& spec, std::string& reason)
{
	return nfq::shaper::open_stage(spec, reason);
}

bool validate_filter(const std::string& filter, bool forward, std::string& error, uint32_t& position)
{
	std::vector<linux_shared::CompiledRule> rules;
	return linux_shared::compile_filter(filter, forward, rules, error, position);
}

#ifdef LAGSW_FEATURE_NETFILTER_MONITOR
std::string monitor_status(uint64_t interval_ms, uint32_t backlog_threshold)
{
	std::string line = nfq::monitor_status(kFirstQueueNumber, next_channel_id.load(), interval_ms, backlog_threshold);
	// Kernel-shaping counters are cheap to read (a few per-CPU map lookups), so they are not cached.
	const std::string shaping = nfq::shaper::status_text();
	if (shaping.empty())
		return line;
	const size_t alert = line.size() >= 4 && line.compare(line.size() - 4, 4, " [!]") == 0 ? 4 : 0;
	return line.substr(0, line.size() - alert) + " | " + shaping + line.substr(line.size() - alert);
}
#endif

}  // namespace backend
