// Placeholder packet backend for platforms without a real capture implementation yet (Linux, until nfqueue lands).
// Everything outside of packet capture (options, key handling, logging, region lookup, ...) works normally;
// opening a capture channel fails with a "not implemented" error instead of crashing.
#include "packet_backend.h"

#include <sstream>

#include "log.h"

namespace backend {
namespace {
constexpr const char* kNotImplemented = "packet capture is not implemented on this platform (stub backend)";
}

const char* name()
{
	return "stub";
}

bool initialize()
{
	LOG_WARN("The stub capture backend is in use: %s. Packet delaying/dropping is disabled.", kNotImplemented);
	return true;
}

bool check_privileges(std::string& error)
{
	(void)error;
	return true;
}

std::unique_ptr<PacketChannel> open(const OpenOptions& options, std::string& error)
{
	LOG_DEBUG_GROUP(logging::group::backend, "stub backend: open requested for filter '%s'", options.filter.c_str());
	(void)options;
	error = kNotImplemented;
	return nullptr;
}

bool validate_filter(const std::string& filter, bool forward, std::string& error, uint32_t& position)
{
	// No filter language to validate against; accept everything so configs can still be tested.
	(void)filter;
	(void)forward;
	(void)error;
	position = 0;
	return true;
}

void calc_checksums(uint8_t* packet, uint32_t length)
{
	(void)packet;
	(void)length;
}

namespace filters {
std::string profile(const ProfileFilter& spec)
{
	std::ostringstream out;
	out << "stub-profile(" << (spec.user_filter.empty() ? "true" : spec.user_filter) << ")";
	for (const std::string& address : spec.server_addresses)
		out << " server=" << address;
	return out.str();
}

std::string port(uint16_t port)
{
	return "stub-port(" + std::to_string(port) + ")";
}

#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
std::string syn_probe(uint16_t port)
{
	return "stub-syn(" + std::to_string(port) + ")";
}

std::string region_enforcement(const std::vector<std::string>& server_addresses, uint16_t port)
{
	return "stub-region(" + std::to_string(server_addresses.size()) + "," + std::to_string(port) + ")";
}
#endif

#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
std::string forwarded_address(uint32_t inbound_if_index, uint32_t outbound_if_index, uint16_t port)
{
	return "stub-forwarded(" + std::to_string(inbound_if_index) + "," + std::to_string(outbound_if_index) + "," + std::to_string(port) + ")";
}
#endif
}  // namespace filters
#ifdef LAGSW_FEATURE_NETFILTER_MONITOR
std::string monitor_status(uint64_t, uint32_t)
{
	return {};
}
#endif

}  // namespace backend
