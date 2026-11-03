// Linux packet backend on the swdivert kernel module (pocs/linux_kernel_module_backend.md): the module matches packets with a filter
// program, copies them into a ring shared with this process and, for a channel that does not only sniff, holds the original until
// the engine sends (resumes) or discards (drops) it. The same contract as the NFQUEUE backend, without the netlink round trip per
// packet and without nftables.
#include <fcntl.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <vector>

#include "filter_program.h"
#include "log.h"
#include "module.h"
#include "packet_backend.h"
#include "swdivert_abi.h"
#include "swdivert_ring.h"

#include "../linux_shared/privileges.h"

LOG_DEFAULT_GROUP(logging::group::kmod)

namespace backend {
namespace {
	// The ring only has to absorb the bursts between two reads of the engine's reader thread: a slot is free again as soon as it is read,
	// not when its packet gets a verdict. A packet that does not fit a slot is let through unchanged (see recv()).
	constexpr uint32_t kSlots	  = 2048;
	constexpr uint32_t kSlotBytes = 4096;
	// How long the module keeps a packet nobody answered for before it lets it go (its fail-open horizon), and how many packets one
	// channel may hold at once; the NFQUEUE backend's queue is 16384 packets long and has no time limit.
	constexpr uint32_t kHoldMs	= 60000;
	constexpr uint32_t kMaxHeld = 16384;
	constexpr uint32_t kMinIpv4 = 20;

	/// Backend-private state stored in PacketMeta::native.
	struct NativeMeta
	{
		uint64_t id;
		uint64_t payload_hash;
		uint32_t length;
	};
	static_assert(sizeof(NativeMeta) <= sizeof(PacketMeta::native), "PacketMeta::native is too small");

	uint64_t hash_payload(const uint8_t* data, uint32_t length)
	{
		uint64_t hash = 1469598103934665603ull;
		for (uint32_t index = 0; index < length; ++index)
			hash = (hash ^ data[index]) * 1099511628211ull;
		return hash;
	}

	std::string describe_layers(uint32_t layers)
	{
		std::string text;
		auto		add = [&](const char* name) {
			if (!text.empty())
				text += " + ";
			text += name;
		};
		if (layers & SWDIV_OPEN_LOCAL_IN)
			add("input");
		if (layers & SWDIV_OPEN_LOCAL_OUT)
			add("output");
		if (layers & SWDIV_OPEN_FORWARD)
			add("forward");
		return text.empty() ? "no hook" : text + (text.find('+') == std::string::npos ? " hook" : " hooks");
	}

	class KmodChannel;
	std::mutex				  channels_mutex;
	std::vector<KmodChannel*> channels;

	class KmodChannel final : public PacketChannel
	{
	public:
		explicit KmodChannel(bool sniff) : sniff_(sniff) {}

		~KmodChannel() override { close(); }

		bool start(const OpenOptions& options, const kmodf::Program& program, std::string& error)
		{
			fd_ = ::open(kmodb::kDevicePath, O_RDWR | O_CLOEXEC);
			if (fd_ < 0)
			{
				error = std::string("cannot open ") + kmodb::kDevicePath + ": " + std::strerror(errno);
				return false;
			}
			event_fd_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
			if (event_fd_ < 0)
			{
				error = std::string("eventfd failed: ") + std::strerror(errno);
				return false;
			}

			swdiv_open_args open_args = {};
			open_args.slots			  = kSlots;
			open_args.slot_bytes	  = kSlotBytes;
			// A filter that matches nothing has no layer; the module's default one then serves its empty program
			open_args.flags	   = program.layers | (sniff_ ? 0 : SWDIV_OPEN_HOLD);
			open_args.priority = options.priority;
			open_args.hold_ms  = kHoldMs;
			open_args.max_held = kMaxHeld;
			if (::ioctl(fd_, SWDIVERT_IOC_OPEN, &open_args) < 0)
			{
				error = std::string("SWDIVERT_IOC_OPEN failed: ") + std::strerror(errno) +
						(errno == EPERM ? " (CAP_NET_ADMIN is required)" : "");
				return false;
			}
			data_		= ::mmap(nullptr, open_args.data_bytes, PROT_READ, MAP_SHARED, fd_, 0);
			data_bytes_ = open_args.data_bytes;
			if (data_ == MAP_FAILED)
			{
				data_ = nullptr;
				error = std::string("mapping the ring failed: ") + std::strerror(errno);
				return false;
			}
			cons_bytes_ = static_cast<size_t>(::sysconf(_SC_PAGESIZE));
			cons_		= ::mmap(nullptr, cons_bytes_, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, static_cast<off_t>(open_args.cons_offset));
			if (cons_ == MAP_FAILED)
			{
				cons_ = nullptr;
				error = std::string("mapping the consumer page failed: ") + std::strerror(errno);
				return false;
			}
			swdiv_ring_view_init(&view_, data_, open_args.hdr_bytes, static_cast<swdiv_cons*>(cons_));

			// The program is in place before the handle is started, so no packet is ever offered to a half-set-up filter
			if (kmodf::install_program(fd_, program) < 0)
			{
				error = std::string("the module refused the filter program: ") + std::strerror(errno);
				return false;
			}
			if (::ioctl(fd_, SWDIVERT_IOC_START) < 0)
			{
				error = std::string("SWDIVERT_IOC_START failed: ") + std::strerror(errno);
				return false;
			}
			description_ = describe_layers(program.layers);
			started_	 = true;
			std::lock_guard<std::mutex> lock(channels_mutex);
			channels.push_back(this);
			return true;
		}

		/// Single consumer: one thread at a time reads a channel.
		IoStatus recv(uint8_t* buffer, uint32_t capacity, uint32_t& length, PacketMeta& meta, std::string& error) override
		{
			length = 0;
			for (;;)
			{
				if (shutdown_.load())
					return IoStatus::closed;
				while (swdiv_ring_avail(&view_) != 0)
				{
					const swdiv_slot_hdr* slot	 = swdiv_ring_slot(&view_, 0);
					const uint8_t*		  data	 = swdiv_slot_data(slot);
					const uint32_t		  caplen = swdiv_slot_caplen(&view_, slot);
					const bool			  held	 = (slot->flags & SWDIV_SLOT_F_HELD) != 0;
					const uint64_t		  id	 = slot->id;
					// Only whole, well-formed IPv4 packets that fit the engine's buffer are handed over; the rest goes on unchanged
					if ((slot->flags & SWDIV_SLOT_F_TRUNCATED) != 0 || caplen != slot->len || caplen < kMinIpv4 || (data[0] >> 4) != 4 ||
						caplen > capacity)
					{
						LOG_DEBUG_GROUP(logging::group::kmod_packet,
										"packet %llu (%u bytes, captured %u) not handed to the engine: letting it through unchanged",
										static_cast<unsigned long long>(id),
										slot->len,
										caplen);
						swdiv_ring_release(&view_, 1);
						++passed_through_;
						if (held)
							resume_unchanged(id);
						continue;
					}
					std::memcpy(buffer, data, caplen);
					length		  = caplen;
					meta		  = PacketMeta{};
					meta.outbound = slot->hook != 1;  // NF_INET_LOCAL_IN
					meta.if_index =
						slot->hook == 3 ? slot->ifindex_out : slot->ifindex_in;	 // NF_INET_LOCAL_OUT leaves through the out device
					meta.timestamp = static_cast<int64_t>(slot->timestamp_ns / 1000);
					const NativeMeta native{id, hash_payload(data, caplen), caplen};
					std::memcpy(meta.native, &native, sizeof(native));
					swdiv_ring_release(&view_, 1);
					return IoStatus::ok;
				}

				pollfd fds[2] = {{fd_, POLLIN, 0}, {event_fd_, POLLIN, 0}};
				if (::poll(fds, 2, -1) < 0)
				{
					if (errno == EINTR)
						continue;
					error = std::string("poll failed: ") + std::strerror(errno);
					LOG_ERROR("swdivert channel: %s", error.c_str());
					return IoStatus::error;
				}
				if ((fds[1].revents & POLLIN) != 0 || shutdown_.load())
					return IoStatus::closed;
				if ((fds[0].revents & (POLLERR | POLLNVAL)) != 0)
				{
					error = "the swdivert device reported an error";
					LOG_ERROR("swdivert channel: %s", error.c_str());
					return IoStatus::error;
				}
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
			swdiv_verdict  item	  = make_resume(packet, length, meta);
			const IoStatus status = submit(&item, 1, error);
			if (status != IoStatus::ok)
				return status;
			return finish(item, length, sent, error);
		}

		// One ioctl releases up to SWDIV_MAX_VERDICTS packets, in order
		void send_batch(SendItem* items, size_t count) override
		{
			if (sniff_)
			{
				for (size_t index = 0; index < count; ++index)
				{
					items[index].status = IoStatus::ok;
					items[index].sent	= items[index].length;
				}
				return;
			}
			if (count >= 2)
				LOG_DEBUG("swdivert channel: batch resume of %zu packets", count);
			std::vector<swdiv_verdict> verdicts(count);
			for (size_t index = 0; index < count; ++index)
				verdicts[index] = make_resume(items[index].packet, items[index].length, *items[index].meta);
			for (size_t first = 0; first < count; first += SWDIV_MAX_VERDICTS)
			{
				const size_t   chunk = std::min<size_t>(SWDIV_MAX_VERDICTS, count - first);
				std::string	   error;
				const IoStatus status = submit(verdicts.data() + first, chunk, error);
				for (size_t index = first; index < first + chunk; ++index)
				{
					SendItem& item = items[index];
					item.status	   = status;
					if (status != IoStatus::ok)
					{
						item.error = error;
						continue;
					}
					item.status = finish(verdicts[index], item.length, item.sent, item.error);
				}
			}
		}

		void discard(const PacketMeta& meta) override
		{
			if (sniff_)
				return;
			swdiv_verdict item = {};
			item.id			   = reinterpret_cast<const NativeMeta*>(meta.native)->id;
			item.verdict	   = SWDIV_V_DROP;
			std::string error;
			if (submit(&item, 1, error) == IoStatus::ok && item.status != 0 && item.status != ENOENT)
				LOG_WARN("swdivert channel: dropping packet %llu failed: %s",
						 static_cast<unsigned long long>(item.id),
						 std::strerror(static_cast<int>(item.status)));
		}

		std::string description() const override { return description_; }

		void shutdown_recv() override
		{
			shutdown_.store(true);
			if (event_fd_ >= 0)
			{
				const uint64_t				   one	   = 1;
				[[maybe_unused]] const ssize_t written = ::write(event_fd_, &one, sizeof(one));
			}
		}

		void close() override
		{
			if (closed_.exchange(true))
				return;
			shutdown_recv();
			{
				std::lock_guard<std::mutex> lock(channels_mutex);
				for (size_t index = 0; index < channels.size(); ++index)
					if (channels[index] == this)
					{
						channels.erase(channels.begin() + static_cast<long>(index));
						break;
					}
			}
			// Stopping resumes everything still held, so nothing is left behind when the channel goes away
			if (fd_ >= 0 && started_)
				::ioctl(fd_, SWDIVERT_IOC_STOP);
			if (data_ != nullptr)
				::munmap(data_, data_bytes_);
			if (cons_ != nullptr)
				::munmap(cons_, cons_bytes_);
			data_ = cons_ = nullptr;
			if (fd_ >= 0)
				::close(fd_);
			if (event_fd_ >= 0)
				::close(event_fd_);
			fd_ = event_fd_ = -1;
			LOG_DEBUG("swdivert channel closed (%llu packets passed through unchanged, %llu verdicts came too late)",
					  static_cast<unsigned long long>(passed_through_.load()),
					  static_cast<unsigned long long>(late_.load()));
		}

		bool	 read_stats(swdiv_stats& stats) const { return fd_ >= 0 && ::ioctl(fd_, SWDIVERT_IOC_STATS, &stats) == 0; }
		uint64_t late() const { return late_.load(); }
		uint64_t passed_through() const { return passed_through_.load(); }

	private:
		// An unchanged packet resumes as it is, so the kernel keeps its offload and checksum state; changed bytes replace it. The engine
		// has already recomputed the checksums of what it changed.
		swdiv_verdict make_resume(const uint8_t* packet, uint32_t length, const PacketMeta& meta) const
		{
			const NativeMeta* native  = reinterpret_cast<const NativeMeta*>(meta.native);
			swdiv_verdict	  verdict = {};
			verdict.id				  = native->id;
			if (length == native->length && hash_payload(packet, length) == native->payload_hash)
			{
				verdict.verdict = SWDIV_V_RESUME;
				return verdict;
			}
			verdict.verdict = SWDIV_V_RESUME_MOD;
			verdict.data	= static_cast<__u64>(reinterpret_cast<uintptr_t>(packet));
			verdict.len		= length;
			return verdict;
		}

		IoStatus submit(swdiv_verdict* items, size_t count, std::string& error)
		{
			swdiv_verdict_args args = {};
			args.items				= static_cast<__u64>(reinterpret_cast<uintptr_t>(items));
			args.count				= static_cast<__u32>(count);
			if (::ioctl(fd_, SWDIVERT_IOC_VERDICT, &args) < 0)
			{
				error = std::string("SWDIVERT_IOC_VERDICT failed: ") + std::strerror(errno);
				LOG_ERROR("swdivert channel: %s", error.c_str());
				return IoStatus::error;
			}
			return IoStatus::ok;
		}

		IoStatus finish(const swdiv_verdict& item, uint32_t length, uint32_t& sent, std::string& error)
		{
			if (item.status == 0)
			{
				sent = length;
				return IoStatus::ok;
			}
			if (item.status == ENOENT)
			{
				// The packet was already released: the fail-open horizon passed (or the channel is closing). It left unchanged and
				// late; there is nothing more to do for it.
				++late_;
				LOG_WARN("swdivert channel: packet %llu was already released by the module (held longer than %u ms?)",
						 static_cast<unsigned long long>(item.id),
						 kHoldMs);
				sent = length;
				return IoStatus::ok;
			}
			// The module refused the new bytes (not a whole IPv4 packet) and still holds the original: let that go
			resume_unchanged(item.id);
			error = std::string("the module refused the packet: ") + std::strerror(static_cast<int>(item.status));
			LOG_ERROR("swdivert channel: %s (packet %llu)", error.c_str(), static_cast<unsigned long long>(item.id));
			return IoStatus::error;
		}

		void resume_unchanged(uint64_t id)
		{
			swdiv_verdict item = {};
			item.id			   = id;
			item.verdict	   = SWDIV_V_RESUME;
			std::string ignored;
			submit(&item, 1, ignored);
		}

		const bool			  sniff_;
		int					  fd_		  = -1;
		int					  event_fd_	  = -1;
		void*				  data_		  = nullptr;
		size_t				  data_bytes_ = 0;
		void*				  cons_		  = nullptr;
		size_t				  cons_bytes_ = 0;
		swdiv_ring_view		  view_		  = {};
		bool				  started_	  = false;
		std::string			  description_;
		std::atomic<bool>	  shutdown_{false};
		std::atomic<bool>	  closed_{false};
		std::atomic<uint64_t> late_{0};
		std::atomic<uint64_t> passed_through_{0};
	};

	void unload_at_exit()
	{
		kmodb::unload_if_loaded_here();
	}
}  // namespace

const char* name()
{
	return "kmod";
}

bool initialize()
{
	// The module is loaded by check_privileges(), after the options are parsed, so --help and config errors never touch the kernel.
	return true;
}

bool check_privileges(std::string& error)
{
	if (!linux_shared::check_privileges(error))
		return false;
	if (!kmodb::ensure_module(error))
		return false;
	static std::once_flag registered;
	std::call_once(registered, [] { std::atexit(unload_at_exit); });
	return true;
}

std::unique_ptr<PacketChannel> open(const OpenOptions& options, std::string& error)
{
	kmodf::Program program;
	uint32_t	   position = 0;
	if (!kmodf::compile_program(options.filter, program, error, position, options.forward, options.include_forward))
	{
		error += " (at position " + std::to_string(position) + ")";
		LOG_ERROR_GROUP(logging::group::kmod_filter, "could not compile filter '%s': %s", options.filter.c_str(), error.c_str());
		return nullptr;
	}
	if (const std::string refusal = kmodf::verify_program(program); !refusal.empty())
	{
		error = refusal;
		LOG_ERROR_GROUP(logging::group::kmod_filter, "filter '%s' cannot be used: %s", options.filter.c_str(), error.c_str());
		return nullptr;
	}
	LOG_DEBUG_GROUP(logging::group::kmod_filter,
					"compiled filter '%s' (forward = %d, include_forward = %d) into %zu instruction(s), %zu set(s), %s",
					options.filter.c_str(),
					options.forward ? 1 : 0,
					options.include_forward ? 1 : 0,
					program.insns.size(),
					program.sets.size(),
					describe_layers(program.layers).c_str());
	auto channel = std::make_unique<KmodChannel>(options.sniff);
	if (!channel->start(options, program, error))
	{
		LOG_ERROR("swdivert: could not open a channel for filter '%s': %s", options.filter.c_str(), error.c_str());
		return nullptr;
	}
	LOG_DEBUG("swdivert: opened a %s channel on %s for filter '%s' (priority %d)",
			  options.sniff ? "sniffing" : "holding",
			  channel->description().c_str(),
			  options.filter.c_str(),
			  static_cast<int>(options.priority));
	return channel;
}

void configure_shaping(const ShapingConfig&)
{
}

std::unique_ptr<ShapeStage> open_shape_stage(const ShapeSpec&, std::string& reason)
{
	reason = "the swdivert module backend has no kernel shaping stage; packets are held in the module and released by the engine";
	return nullptr;
}

bool validate_filter(const std::string& filter, bool forward, std::string& error, uint32_t& position)
{
	kmodf::Program program;
	if (!kmodf::compile_program(filter, program, error, position, forward, false))
		return false;
	const std::string refusal = kmodf::verify_program(program);
	if (!refusal.empty())
	{
		error	 = refusal;
		position = 0;
		return false;
	}
	return true;
}

#ifdef LAGSW_FEATURE_BACKEND_MONITOR
std::string monitor_status(uint64_t /*interval_ms*/, uint32_t backlog_threshold)
{
	static std::mutex mutex;
	static uint64_t	  previous_lost	   = 0;
	static uint64_t	  previous_expired = 0;
	static bool		  previous_backlog = false;
	// The module's counters are a handful of per-CPU sums per handle, cheap enough to read at every refresh
	uint64_t handles = 0, held_now = 0, lost = 0, expired = 0, passed = 0, late = 0;
	{
		std::lock_guard<std::mutex> lock(channels_mutex);
		for (const KmodChannel* channel : channels)
		{
			swdiv_stats stats = {};
			if (!channel->read_stats(stats))
				continue;
			++handles;
			held_now += stats.held_now;
			// A packet the ring or the hold limit had no room for went on unheld: the engine never saw it
			lost += stats.dropped_full + stats.pass_limit;
			expired += stats.expired;
			passed += channel->passed_through();
			late += channel->late();
		}
	}
	std::lock_guard<std::mutex> lock(mutex);
	const bool					losing	 = lost > previous_lost;
	const bool					expiring = expired > previous_expired;
	const bool					backlog	 = held_now >= backlog_threshold;
	if (losing)
		LOG_WARN_GROUP(logging::group::kmod_monitor,
					   "the swdivert module let %llu packets through unheld (ring or hold limit full)",
					   static_cast<unsigned long long>(lost - previous_lost));
	if (expiring)
		LOG_WARN_GROUP(logging::group::kmod_monitor,
					   "the swdivert module released %llu held packets on its own (no verdict in time)",
					   static_cast<unsigned long long>(expired - previous_expired));
	if (backlog && !previous_backlog)
		LOG_WARN_GROUP(logging::group::kmod_monitor,
					   "%llu packets are held in the swdivert module (threshold %u)",
					   static_cast<unsigned long long>(held_now),
					   backlog_threshold);
	else if (!backlog && previous_backlog)
		LOG_INFO_GROUP(logging::group::kmod_monitor, "the swdivert backlog cleared (%llu held)", static_cast<unsigned long long>(held_now));
	previous_lost	 = lost;
	previous_expired = expired;
	previous_backlog = backlog;
	std::string line = "kmod: " + std::to_string(handles) + " handle(s) held " + std::to_string(held_now) + " unheld " +
					   std::to_string(lost) + " expired " + std::to_string(expired) + " passed " + std::to_string(passed) + " late " +
					   std::to_string(late);
	return losing || expiring || backlog ? line + " [!]" : line;
}
#endif

}  // namespace backend
