#ifndef PACKET_BACKEND_H_
#define PACKET_BACKEND_H_

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

/// Platform-neutral packet capture/reinjection interface.
///
/// Exactly one backend implementation is linked into the binary (selected by the build system).
/// Everything that is specific to a capture technology (driver loading, filter syntax, native
/// address metadata, checksum helpers) lives behind this header, under backends/<name>/.
namespace backend {

/// Which client address fields to enforce when filtering profile packets.
enum class ClientAddressEnforcement
{
	none,        ///< Do not enforce client addresses.
	source,      ///< Enforce the client source address.
	destination, ///< Enforce the client destination address.
	both,        ///< Enforce both client addresses.
};

/// Which packet endpoint is matched against the selected server.
enum class ServerDirection
{
	source,      ///< Match the source address.
	destination, ///< Match the destination address.
	both,        ///< Match either endpoint.
};

/// Per-packet metadata. The neutral fields are filled in by recv(); `native` is opaque backend
/// storage that must round-trip unchanged back into send().
struct PacketMeta
{
	/// Whether the packet was travelling out of the host.
	bool		  outbound	= false;
	/// Index of the interface the packet was seen on (0 when unknown).
	uint32_t	  if_index	= 0;
	/// Backend timestamp of the capture (backend-defined units; 0 when unavailable).
	int64_t		  timestamp = 0;
	/// Opaque backend-owned data.
	alignas(8) unsigned char native[96] = {};
};

/// Outcome of a blocking receive or send.
enum class IoStatus
{
	ok,     ///< The operation succeeded.
	closed, ///< The channel was shut down or closed; not an error worth reporting.
	error,  ///< The operation failed; see the error message.
};

/// Options for opening a capture channel.
struct OpenOptions
{
	/// Filter expression in the active backend's syntax (see the `filters` namespace helpers).
	std::string filter;
	/// Capture forwarded traffic instead of locally originated/terminated traffic.
	bool		forward	 = false;
	/// Observe packets without removing them from the network path.
	bool		sniff	 = false;
	/// Relative priority; lower values are processed first by the backend.
	int16_t		priority = 0;
};

/// An open capture channel. Implementations must allow recv() to run concurrently with
/// shutdown_recv() and send() from other threads.
class PacketChannel
{
public:
	virtual ~PacketChannel() = default;

	/// Blocks until a packet is available. `error` is set when the status is IoStatus::error.
	virtual IoStatus recv(uint8_t* buffer, uint32_t capacity, uint32_t& length, PacketMeta& meta, std::string& error) = 0;
	/// Reinjects a packet. `sent` receives the number of bytes sent.
	virtual IoStatus send(const uint8_t* packet, uint32_t length, const PacketMeta& meta, uint32_t& sent, std::string& error) = 0;
	/// Tells the backend a received packet is intentionally never sent. Backends that hold packets until a
	/// verdict (for example NFQUEUE) must release it as dropped; capture-and-reinject backends need nothing.
	virtual void	 discard(const PacketMeta& meta) { (void)meta; }
	/// Unblocks pending and future recv() calls.
	virtual void	 shutdown_recv() = 0;
	/// Releases the channel. Safe to call more than once.
	virtual void	 close() = 0;
};

/// Returns a short backend name for logging.
const char* name();
/// Prepares the backend for use (for example, loading a driver). Returns false after logging an error.
bool		initialize();
/// Opens a capture channel; returns nullptr and fills `error` on failure.
std::unique_ptr<PacketChannel> open(const OpenOptions& options, std::string& error);
/// Checks a filter without opening a channel. On failure, `error` and `position` describe the problem.
bool		validate_filter(const std::string& filter, bool forward, std::string& error, uint32_t& position);
/// Recomputes IP/TCP/UDP checksums of a modified packet in place.
void		calc_checksums(uint8_t* packet, uint32_t length);

/// Everything needed to describe the traffic a profile captures.
struct ProfileFilter
{
	/// User-supplied expression from the profile/global configuration, in backend syntax.
	std::string				   user_filter;
	/// Also capture bare TCP ACKs (needed for ACK restoration).
	bool					   include_bare_acks = false;
	ClientAddressEnforcement   client_enforcement = ClientAddressEnforcement::both;
	std::optional<std::string> client_source;
	std::optional<std::string> client_destination;
	/// How server addresses are matched; no server restriction is applied when unset.
	std::optional<ServerDirection> server_direction;
	/// Addresses of the selected server (or server group); empty when no server is selected.
	std::vector<std::string>   server_addresses;
	/// Restrict to outbound packets.
	bool					   outbound = false;
};

/// Builders for the filter expressions the engine needs, rendered in the backend's syntax.
namespace filters {
/// Profile capture filter.
std::string profile(const ProfileFilter& spec);
/// Any TCP or UDP packet whose source or destination port equals `port`.
std::string port(uint16_t port);
/// TCP SYN packets whose source or destination port equals `port`.
std::string syn_probe(uint16_t port);
/// Outbound TCP/UDP packets on `port` seen on either of the two interfaces.
std::string forwarded_address(uint32_t inbound_if_index, uint32_t outbound_if_index, uint16_t port);
/// TCP PSH packets coming from any of `server_addresses` on `port`.
std::string region_enforcement(const std::vector<std::string>& server_addresses, uint16_t port);
}  // namespace filters

}  // namespace backend

#endif
