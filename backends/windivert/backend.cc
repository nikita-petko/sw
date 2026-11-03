#include "packet_backend.h"

#if !defined(_WIN32)
#	error "The WinDivert backend is only available on Windows"
#endif

#include <windows.h>

#include <condition_variable>
#include <cstring>
#include <deque>
#include <mutex>
#include <thread>
#include <vector>

#include "log.h"
#include "monitor.h"
#include "runtime.h"

LOG_DEFAULT_GROUP(logging::group::backend)

namespace backend {
namespace {
	constexpr uint64_t kQueueLength = 4096;
	constexpr uint64_t kQueueTimeMs = 1024;

	static_assert(sizeof(WINDIVERT_ADDRESS) <= sizeof(PacketMeta::native), "PacketMeta::native is too small for WINDIVERT_ADDRESS");
	static_assert(alignof(PacketMeta) >= alignof(WINDIVERT_ADDRESS), "PacketMeta is under-aligned for WINDIVERT_ADDRESS");

	std::string format_error(DWORD error)
	{
		char*		message = nullptr;
		const DWORD length	= FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
											 nullptr,
											 error,
											 0,
											 reinterpret_cast<char*>(&message),
											 0,
											 nullptr);
		std::string text	= length == 0 ? "unknown error" : std::string(message, length);
		if (message != nullptr)
			LocalFree(message);
		while (!text.empty() && (text.back() == '\r' || text.back() == '\n'))
			text.pop_back();
		return std::to_string(error) + ": " + text;
	}

	/// Maps the Win32 error left by a failed WinDivert call to a status, filling `error` for real failures.
	IoStatus classify_failure(std::string& error)
	{
		const DWORD code = GetLastError();
		if (code == ERROR_INVALID_HANDLE || code == ERROR_OPERATION_ABORTED)
			return IoStatus::closed;
		error = format_error(code);
		return IoStatus::error;
	}

	class WinDivertChannel final : public PacketChannel
	{
	public:
		WinDivertChannel(HANDLE handle, std::string description) : handle_(handle), description_(std::move(description)) {}
		~WinDivertChannel() override { close(); }

		std::string description() const override { return description_; }

		IoStatus recv(uint8_t* buffer, uint32_t capacity, uint32_t& length, PacketMeta& meta, std::string& error) override
		{
			WINDIVERT_ADDRESS address = {};
			length					  = 0;
			if (!WinDivertRecv(handle_, buffer, capacity, &length, &address))
			{
				const IoStatus status = classify_failure(error);
				if (status == IoStatus::error)
					stats_.recv_failed();
				return status;
			}
			stats_.received(address.Timestamp);
			meta		   = {};
			meta.outbound  = address.Outbound != 0;
			meta.if_index  = address.Network.IfIdx;
			meta.timestamp = address.Timestamp;
			std::memcpy(meta.native, &address, sizeof(address));
			return IoStatus::ok;
		}

		IoStatus send(const uint8_t* packet, uint32_t length, const PacketMeta& meta, uint32_t& sent, std::string& error) override
		{
			WINDIVERT_ADDRESS address;
			std::memcpy(&address, meta.native, sizeof(address));
			sent = 0;
			if (!WinDivertSend(handle_, packet, length, &sent, &address))
			{
				const IoStatus status = classify_failure(error);
				if (status == IoStatus::error)
					stats_.send_failed();
				return status;
			}
			stats_.sent();
			return IoStatus::ok;
		}

		void shutdown_recv() override
		{
			if (handle_ != INVALID_HANDLE_VALUE)
				WinDivertShutdown(handle_, WINDIVERT_SHUTDOWN_RECV);
		}

		void close() override
		{
			if (handle_ != INVALID_HANDLE_VALUE)
			{
				WinDivertClose(handle_);
				handle_ = INVALID_HANDLE_VALUE;
			}
		}

	private:
		HANDLE			 handle_;
		std::string		 description_;
		wd::ChannelStats stats_;
	};

	/// Combines a local-traffic channel and a forwarded-traffic channel into one. WinDivert handles are bound to a single
	/// layer, so each one gets a receive thread feeding a shared queue; send() routes back by the packet's layer.
	class MultiLayerChannel final : public PacketChannel
	{
	public:
		MultiLayerChannel(std::unique_ptr<PacketChannel> local, std::unique_ptr<PacketChannel> forwarded)
		: local_(std::move(local))
		, forwarded_(std::move(forwarded))
		{
			running_ = 2;
			pumps_.emplace_back(&MultiLayerChannel::pump, this, local_.get());
			pumps_.emplace_back(&MultiLayerChannel::pump, this, forwarded_.get());
		}
		~MultiLayerChannel() override { close(); }

		std::string description() const override { return "network + forward layers"; }

		IoStatus recv(uint8_t* buffer, uint32_t capacity, uint32_t& length, PacketMeta& meta, std::string& error) override
		{
			length = 0;
			std::unique_lock<std::mutex> lock(mutex_);
			ready_.wait(lock, [this] { return !queue_.empty() || running_ == 0 || shutdown_; });
			if (queue_.empty())
				return IoStatus::closed;
			Item item = std::move(queue_.front());
			queue_.pop_front();
			stats_.set_queued(queue_.size());
			lock.unlock();
			space_.notify_all();

			if (item.status != IoStatus::ok)
			{
				error = std::move(item.error);
				return item.status;
			}
			if (item.data.size() > capacity)
			{
				error = "packet larger than the receive buffer";
				return IoStatus::error;
			}
			std::memcpy(buffer, item.data.data(), item.data.size());
			length = static_cast<uint32_t>(item.data.size());
			meta   = item.meta;
			return IoStatus::ok;
		}

		IoStatus send(const uint8_t* packet, uint32_t length, const PacketMeta& meta, uint32_t& sent, std::string& error) override
		{
			WINDIVERT_ADDRESS address;
			std::memcpy(&address, meta.native, sizeof(address));
			PacketChannel& target = address.Layer == WINDIVERT_LAYER_NETWORK_FORWARD ? *forwarded_ : *local_;
			return target.send(packet, length, meta, sent, error);
		}

		void shutdown_recv() override
		{
			local_->shutdown_recv();
			forwarded_->shutdown_recv();
			{
				std::lock_guard<std::mutex> lock(mutex_);
				shutdown_ = true;
			}
			ready_.notify_all();
			space_.notify_all();
		}

		void close() override
		{
			shutdown_recv();
			for (std::thread& pump : pumps_)
				if (pump.joinable())
					pump.join();
			local_->close();
			forwarded_->close();
		}

	private:
		struct Item
		{
			std::vector<uint8_t> data;
			PacketMeta			 meta;
			IoStatus			 status = IoStatus::ok;
			std::string			 error;
		};

		static constexpr size_t kMaxQueued = 8192;

		void pump(PacketChannel* source)
		{
			std::vector<uint8_t> buffer(0xFFFF);
			for (;;)
			{
				Item	 item;
				uint32_t length = 0;
				item.status		= source->recv(buffer.data(), static_cast<uint32_t>(buffer.size()), length, item.meta, item.error);
				if (item.status == IoStatus::closed)
					break;
				if (item.status == IoStatus::ok)
					item.data.assign(buffer.begin(), buffer.begin() + length);

				std::unique_lock<std::mutex> lock(mutex_);
				space_.wait(lock, [this] { return queue_.size() < kMaxQueued || shutdown_; });
				if (shutdown_)
					break;
				const bool failed = item.status == IoStatus::error;
				queue_.push_back(std::move(item));
				stats_.set_queued(queue_.size());
				lock.unlock();
				ready_.notify_one();
				if (failed)
					break;
			}
			{
				std::lock_guard<std::mutex> lock(mutex_);
				--running_;
			}
			ready_.notify_all();
		}

		std::unique_ptr<PacketChannel> local_;
		std::unique_ptr<PacketChannel> forwarded_;
		std::vector<std::thread>	   pumps_;
		std::mutex					   mutex_;
		std::condition_variable		   ready_;
		std::condition_variable		   space_;
		std::deque<Item>			   queue_;
		wd::ChannelStats			   stats_{false};
		int							   running_	 = 0;
		bool						   shutdown_ = false;
	};

	std::unique_ptr<PacketChannel> open_layer(const OpenOptions& options, WINDIVERT_LAYER layer, std::string& error)
	{
		const UINT64 flags	= options.sniff ? WINDIVERT_FLAG_SNIFF : 0;
		HANDLE		 handle = WinDivertOpen(options.filter.c_str(), layer, options.priority, flags);
		if (handle == INVALID_HANDLE_VALUE)
		{
			error = format_error(GetLastError());
			return nullptr;
		}
		WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LENGTH, kQueueLength);
		WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, kQueueTimeMs);
		return std::make_unique<WinDivertChannel>(handle, layer == WINDIVERT_LAYER_NETWORK_FORWARD ? "forward layer" : "network layer");
	}

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
	return "WinDivert";
}

bool initialize()
{
	return initialize_windivert();
}

bool check_privileges(std::string& error)
{
	// Elevation is enforced by the UAC manifest.
	(void)error;
	return true;
}

std::unique_ptr<PacketChannel> open(const OpenOptions& options, std::string& error)
{
	std::unique_ptr<PacketChannel> local =
		open_layer(options, options.forward ? WINDIVERT_LAYER_NETWORK_FORWARD : WINDIVERT_LAYER_NETWORK, error);
	if (!local || options.forward || !options.include_forward)
		return local;

	// Forwarded traffic is optional: not every filter compiles for the forward layer, and local capture still works without it.
	std::string					   forward_error;
	std::unique_ptr<PacketChannel> forwarded = open_layer(options, WINDIVERT_LAYER_NETWORK_FORWARD, forward_error);
	if (!forwarded)
	{
		LOG_WARN("WinDivert: forwarded traffic is not captured, the forward layer could not be opened: %s", forward_error.c_str());
		return local;
	}
	return std::make_unique<MultiLayerChannel>(std::move(local), std::move(forwarded));
}

void configure_shaping(const ShapingConfig&)
{
}

std::unique_ptr<ShapeStage> open_shape_stage(const ShapeSpec&, std::string& reason)
{
	reason = "kernel shaping is not available on this platform";
	return nullptr;
}

bool validate_filter(const std::string& filter, bool forward, std::string& error, uint32_t& position)
{
	const char* message		   = nullptr;
	UINT		error_position = 0;
	if (WinDivertHelperCompileFilter(filter.c_str(),
									 forward ? WINDIVERT_LAYER_NETWORK_FORWARD : WINDIVERT_LAYER_NETWORK,
									 nullptr,
									 0,
									 &message,
									 &error_position))
		return true;
	error	 = message != nullptr ? message : "unknown error";
	position = error_position;
	return false;
}

void calc_checksums(uint8_t* packet, uint32_t length)
{
	WinDivertHelperCalcChecksums(packet, length, nullptr, 0);
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
			// WinDivert has no ip.Addr field, so "both" matches either address field.
			std::string address_filter;
			switch (*spec.server_direction)
			{
				case ServerDirection::source:
					address_filter = address_chain("ip.SrcAddr", spec.server_addresses);
					break;
				case ServerDirection::destination:
					address_filter = address_chain("ip.DstAddr", spec.server_addresses);
					break;
				case ServerDirection::both:
					address_filter =
						address_chain("ip.SrcAddr", spec.server_addresses) + " or " + address_chain("ip.DstAddr", spec.server_addresses);
					break;
			}
			filter = "(" + filter + ") and (" + address_filter + ")";
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
		const std::string source_port = " and tcp.SrcPort == " + std::to_string(port);
		if (server_addresses.size() == 1)
			return "tcp.Psh and ip.SrcAddr == " + server_addresses[0] + source_port;
		return "tcp.Psh and (" + address_chain("ip.SrcAddr", server_addresses) + ")" + source_port;
	}
#endif

#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
	std::string forwarded_address(uint32_t inbound_if_index, uint32_t outbound_if_index, uint16_t port)
	{
		return "outbound and (ifIdx == " + std::to_string(inbound_if_index) + " or ifIdx == " + std::to_string(outbound_if_index) +
			   ") and (" + port_expression(port) + ")";
	}
#endif
}  // namespace filters
#ifdef LAGSW_FEATURE_BACKEND_MONITOR
std::string monitor_status(uint64_t interval_ms, uint32_t backlog_threshold)
{
	return wd::monitor_status(interval_ms, backlog_threshold);
}
#endif

}  // namespace backend
