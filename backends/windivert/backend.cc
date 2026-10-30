#include "packet_backend.h"

#if !defined(_WIN32)
#	error "The WinDivert backend is only available on Windows"
#endif

#include <windows.h>

#include <cstring>

#include "runtime.h"

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
	explicit WinDivertChannel(HANDLE handle) : handle_(handle) {}
	~WinDivertChannel() override { close(); }

	IoStatus recv(uint8_t* buffer, uint32_t capacity, uint32_t& length, PacketMeta& meta, std::string& error) override
	{
		WINDIVERT_ADDRESS address = {};
		length					  = 0;
		if (!WinDivertRecv(handle_, buffer, capacity, &length, &address))
			return classify_failure(error);
		meta			= {};
		meta.outbound	= address.Outbound != 0;
		meta.if_index	= address.Network.IfIdx;
		meta.timestamp	= address.Timestamp;
		std::memcpy(meta.native, &address, sizeof(address));
		return IoStatus::ok;
	}

	IoStatus send(const uint8_t* packet, uint32_t length, const PacketMeta& meta, uint32_t& sent, std::string& error) override
	{
		WINDIVERT_ADDRESS address;
		std::memcpy(&address, meta.native, sizeof(address));
		sent = 0;
		if (!WinDivertSend(handle_, packet, length, &sent, &address))
			return classify_failure(error);
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
	HANDLE handle_;
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
	return "WinDivert";
}

bool initialize()
{
	return initialize_windivert();
}

std::unique_ptr<PacketChannel> open(const OpenOptions& options, std::string& error)
{
	const WINDIVERT_LAYER layer = options.forward ? WINDIVERT_LAYER_NETWORK_FORWARD : WINDIVERT_LAYER_NETWORK;
	const UINT64		  flags = options.sniff ? WINDIVERT_FLAG_SNIFF : 0;
	HANDLE				  handle = WinDivertOpen(options.filter.c_str(), layer, options.priority, flags);
	if (handle == INVALID_HANDLE_VALUE)
	{
		error = format_error(GetLastError());
		return nullptr;
	}
	WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LENGTH, kQueueLength);
	WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, kQueueTimeMs);
	return std::make_unique<WinDivertChannel>(handle);
}

bool validate_filter(const std::string& filter, bool forward, std::string& error, uint32_t& position)
{
	const char* message = nullptr;
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
	const std::string source_port = " and tcp.SrcPort == " + std::to_string(port);
	if (server_addresses.size() == 1)
		return "tcp.Psh and ip.SrcAddr == " + server_addresses[0] + source_port;
	return "tcp.Psh and (" + address_chain("ip.SrcAddr", server_addresses) + ")" + source_port;
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
}  // namespace backend
