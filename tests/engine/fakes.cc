#include "fakes.h"

#include <atomic>
#include <cstring>

namespace fakes {
namespace {
std::mutex											   registry_mutex;
std::vector<std::shared_ptr<ChannelState>>			   registry;
std::vector<backend::ProfileFilter>					   specs;
std::string											   next_open_failure;
std::function<platform::HttpResponse(const std::string&, const std::string&)> http_handler;
std::vector<std::string>							   requested_paths;
std::atomic<int>									   timer_begins{0};
std::atomic<int>									   timer_ends{0};
}  // namespace

/// The engine-owned half of a channel.
class FakeChannel : public backend::PacketChannel
{
public:
	explicit FakeChannel(std::shared_ptr<ChannelState> state) : state_(std::move(state)) {}

	backend::IoStatus recv(uint8_t* buffer, uint32_t capacity, uint32_t& length, backend::PacketMeta& meta, std::string& error) override
	{
		std::unique_lock<std::mutex> lock(state_->m_);
		state_->cv_.wait(lock, [&] { return state_->recv_shutdown_ || !state_->inbound_.empty(); });
		if (state_->recv_shutdown_)
			return backend::IoStatus::closed;
		ChannelState::Inbound packet = std::move(state_->inbound_.front());
		state_->inbound_.pop_front();
		++state_->consumed_;
		if (packet.data.size() > capacity)
		{
			error = "packet larger than the receive buffer";
			return backend::IoStatus::error;
		}
		std::memcpy(buffer, packet.data.data(), packet.data.size());
		length = static_cast<uint32_t>(packet.data.size());
		meta   = packet.meta;
		return backend::IoStatus::ok;
	}

	backend::IoStatus send(const uint8_t* packet, uint32_t length, const backend::PacketMeta& meta, uint32_t& sent, std::string& error) override
	{
		std::lock_guard<std::mutex> lock(state_->m_);
		if (state_->closed_ || state_->fail_sends_)
		{
			error = "send failed (fake)";
			return backend::IoStatus::error;
		}
		state_->sent_.push_back({std::vector<uint8_t>(packet, packet + length), meta});
		sent = length;
		return backend::IoStatus::ok;
	}

	void discard(const backend::PacketMeta& meta) override
	{
		std::lock_guard<std::mutex> lock(state_->m_);
		state_->discarded_.push_back(meta.timestamp);
	}

	void shutdown_recv() override
	{
		{
			std::lock_guard<std::mutex> lock(state_->m_);
			state_->recv_shutdown_ = true;
		}
		state_->cv_.notify_all();
	}

	void close() override
	{
		{
			std::lock_guard<std::mutex> lock(state_->m_);
			state_->closed_		   = true;
			state_->recv_shutdown_ = true;
		}
		state_->cv_.notify_all();
	}

private:
	std::shared_ptr<ChannelState> state_;
};

void ChannelState::inject(const std::vector<uint8_t>& packet, int64_t id, bool outbound, uint32_t if_index)
{
	Inbound inbound;
	inbound.data			= packet;
	inbound.meta.timestamp = id;
	inbound.meta.outbound  = outbound;
	inbound.meta.if_index  = if_index;
	{
		std::lock_guard<std::mutex> lock(m_);
		inbound_.push_back(std::move(inbound));
	}
	cv_.notify_all();
}

void ChannelState::fail_sends(bool fail)
{
	std::lock_guard<std::mutex> lock(m_);
	fail_sends_ = fail;
}

size_t ChannelState::sent_count() const
{
	std::lock_guard<std::mutex> lock(m_);
	return sent_.size();
}

std::vector<SentPacket> ChannelState::sent_packets() const
{
	std::lock_guard<std::mutex> lock(m_);
	return sent_;
}

std::vector<int64_t> ChannelState::discarded() const
{
	std::lock_guard<std::mutex> lock(m_);
	return discarded_;
}

size_t ChannelState::consumed() const
{
	std::lock_guard<std::mutex> lock(m_);
	return consumed_;
}

bool ChannelState::closed() const
{
	std::lock_guard<std::mutex> lock(m_);
	return closed_;
}

bool ChannelState::recv_shut_down() const
{
	std::lock_guard<std::mutex> lock(m_);
	return recv_shutdown_;
}

void reset()
{
	std::lock_guard<std::mutex> lock(registry_mutex);
	registry.clear();
	specs.clear();
	next_open_failure.clear();
	http_handler = nullptr;
	requested_paths.clear();
	timer_begins = 0;
	timer_ends	 = 0;
}

std::vector<std::shared_ptr<ChannelState>> channels()
{
	std::lock_guard<std::mutex> lock(registry_mutex);
	return registry;
}

std::shared_ptr<ChannelState> channel(size_t index)
{
	std::lock_guard<std::mutex> lock(registry_mutex);
	return index < registry.size() ? registry[index] : nullptr;
}

std::shared_ptr<ChannelState> channel_with_filter(const std::string& filter)
{
	std::lock_guard<std::mutex> lock(registry_mutex);
	for (auto found = registry.rbegin(); found != registry.rend(); ++found)
		if ((*found)->filter == filter)
			return *found;
	return nullptr;
}

void fail_next_open(const std::string& message)
{
	std::lock_guard<std::mutex> lock(registry_mutex);
	next_open_failure = message;
}

std::vector<backend::ProfileFilter> profile_specs()
{
	std::lock_guard<std::mutex> lock(registry_mutex);
	return specs;
}

backend::ProfileFilter last_profile_spec()
{
	std::lock_guard<std::mutex> lock(registry_mutex);
	return specs.empty() ? backend::ProfileFilter{} : specs.back();
}

int timer_resolution_begins()
{
	return timer_begins;
}

int timer_resolution_ends()
{
	return timer_ends;
}

void set_http_handler(std::function<platform::HttpResponse(const std::string&, const std::string&)> handler)
{
	std::lock_guard<std::mutex> lock(registry_mutex);
	http_handler = std::move(handler);
}

std::vector<std::string> http_requests()
{
	std::lock_guard<std::mutex> lock(registry_mutex);
	return requested_paths;
}
}  // namespace fakes

namespace backend {
const char* name()
{
	return "fake";
}

bool initialize()
{
	return true;
}

bool check_privileges(std::string&)
{
	return true;
}

std::unique_ptr<PacketChannel> open(const OpenOptions& options, std::string& error)
{
	std::lock_guard<std::mutex> lock(fakes::registry_mutex);
	if (!fakes::next_open_failure.empty())
	{
		error = fakes::next_open_failure;
		fakes::next_open_failure.clear();
		return nullptr;
	}
	auto state		= std::make_shared<fakes::ChannelState>();
	state->options	= options;
	state->filter	= options.filter;
	fakes::registry.push_back(state);
	return std::make_unique<fakes::FakeChannel>(state);
}

bool validate_filter(const std::string&, bool, std::string&, uint32_t&)
{
	return true;
}

void calc_checksums(uint8_t*, uint32_t) {}

namespace filters {
std::string profile(const ProfileFilter& spec)
{
	std::lock_guard<std::mutex> lock(fakes::registry_mutex);
	fakes::specs.push_back(spec);
	return "profile#" + std::to_string(fakes::specs.size() - 1);
}

std::string port(uint16_t port)
{
	return "port:" + std::to_string(port);
}

#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
std::string syn_probe(uint16_t port)
{
	return "syn:" + std::to_string(port);
}

std::string region_enforcement(const std::vector<std::string>& server_addresses, uint16_t port)
{
	std::string text = "region_enforcement:";
	for (const std::string& address : server_addresses)
		text += address + ",";
	return text + ":" + std::to_string(port);
}
#endif

#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
std::string forwarded_address(uint32_t inbound_if_index, uint32_t outbound_if_index, uint16_t port)
{
	return "forwarded:" + std::to_string(inbound_if_index) + ":" + std::to_string(outbound_if_index) + ":" + std::to_string(port);
}
#endif
}  // namespace filters
}  // namespace backend

namespace platform {
uint64_t tick_ms()
{
	// Offset so that "never happened" (0) can be told apart from the first instant.
	static const auto start = std::chrono::steady_clock::now();
	return 1000 + static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count());
}

void sleep_ms(uint32_t milliseconds)
{
	std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

void begin_timer_resolution()
{
	++fakes::timer_begins;
}

void end_timer_resolution()
{
	++fakes::timer_ends;
}

std::string generate_guid()
{
	return "00000000-0000-0000-0000-000000000000";
}

std::string data_directory()
{
	return {};
}

void make_directory(const std::string&) {}

bool replace_file(const std::string&, const std::string&)
{
	return false;
}

HttpResponse https_get(const std::string& host, const std::string& path)
{
	std::function<HttpResponse(const std::string&, const std::string&)> handler;
	{
		std::lock_guard<std::mutex> lock(fakes::registry_mutex);
		fakes::requested_paths.push_back(path);
		handler = fakes::http_handler;
	}
	return handler ? handler(host, path) : HttpResponse{};
}
}  // namespace platform
