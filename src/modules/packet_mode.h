#ifndef PACKET_MODE_H_
#define PACKET_MODE_H_

#include "packet_engine.h"
#include "packet_backend.h"
#include "packet_headers.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <queue>
#include <string>
#include <utility>
#include <vector>

/// An owned packet and the metadata needed to release it in order.
struct PacketNode
{
	/// Owned packet bytes.
	uint8_t*			 packet;
	/// Packet size in bytes.
	uint32_t			 length;
	/// Owned capture metadata.
	backend::PacketMeta* address;
	/// Profile number associated with the packet.
	int				   profile;
	/// Earliest time the packet may be released.
	uint64_t		   release_at;
	/// Receive-order tie breaker for packets with equal release times.
	uint64_t		   receive_order;
	/// Zero-based packet group, used by packet_group_send mode.
	size_t			   group_index = 0;
	/// Whether this packet belongs to an explicit packet group.
	bool			   grouped = false;
};

/// Priority-queue comparator ordering packets by release time, then receive order.
struct PacketReleaseEarlier
{
	/// Orders earlier release times and receive-order values ahead of later ones.
	bool operator()(const PacketNode* left, const PacketNode* right) const
	{
		if (left->release_at != right->release_at)
			return left->release_at > right->release_at;
		return left->receive_order > right->receive_order;
	}
};

using PacketQueue = std::priority_queue<PacketNode*, std::vector<PacketNode*>, PacketReleaseEarlier>;

/// Copies a packet and its metadata into a new queue node.
PacketNode* make_packet_node(const uint8_t*				   packet,
							 uint32_t					   length,
							 const backend::PacketMeta& address,
							 int						   profile,
							 uint64_t					   release_at,
							 uint64_t					   receive_order);
/// Frees a packet node and its owned packet and address data.
void		destroy_packet_node(PacketNode* node);
/// Moves due packets into the ready list, discarding malformed queue entries.
void		collect_due_packets(PacketQueue& packets, uint64_t now, std::vector<PacketNode*>& ready_packets);
/// Extracts TCP sequence and acknowledgment numbers from a packet.
/// Returns false when the packet does not contain a parseable TCP header.
bool		get_tcp_numbers(const uint8_t* packet, uint32_t length, uint32_t& sequence, uint32_t& acknowledgment);

/// Base class for profile-specific packet scheduling and release behavior.
class PacketMode
{
public:
	/// Initializes the mode with a copy of its profile options and a display name.
	PacketMode(ProfileOptions options, const char* mode_name);
	/// Virtual destructor for derived packet modes.
	virtual ~PacketMode();

	/// Applies common packet processing before delegating to capture_packet().
	virtual void capture(const uint8_t*				 packet,
						 uint32_t					 length,
						 const backend::PacketMeta& address,
						 int						 profile,
						 uint64_t					 now,
						 uint64_t					 receive_order,
						 PacketQueue&				 packets);
	/// Releases due packets according to the mode's scheduling policy.
	virtual void release(PacketQueue& packets, uint64_t now, std::vector<PacketNode*>& ready_packets) = 0;
	/// Resets packet-mode tracking state.
	virtual void reset()
	{
		last_sent_ack_[0]	  = 0;
		last_sent_ack_[1]	  = 0;
		has_last_sent_ack_[0] = false;
		has_last_sent_ack_[1] = false;
	}
	/// Callback invoked for each packet the mode drops instead of sending.
	using DiscardSink = std::function<void(const backend::PacketMeta&)>;
	/// Installs the sink that tells the capture backend about dropped packets; call before packets are captured.
	void		 set_discard_sink(DiscardSink sink) { discard_sink_ = std::move(sink); }
	/// Applies configured TCP acknowledgment restoration before sending a packet.
	void		 prepare_packet_for_send(uint8_t* packet, uint32_t length, const backend::PacketMeta* address);
	/// Toggles mode-specific behavior when supported; returns whether it changed state.
	virtual bool toggle(PacketQueue&) { return false; }
	/// Flushes mode-specific queued packets on demand when supported.
	virtual void flush_on_demand(PacketQueue&) {}
	/// Notifies the mode after a released packet has been processed by the backend send.
	virtual void packet_send_completed(const PacketNode&, bool) {}
	/// Returns optional mode-specific state for the profile status bar.
	virtual std::string status() const { return {}; }
	/// Moves or releases all remaining queued packets during teardown.
	virtual void flush(PacketQueue& packets, std::vector<PacketNode*>& pending_packets) = 0;

	/// Implements the scheduling behavior for one captured packet.
	virtual void capture_packet(const uint8_t*			   packet,
								uint32_t				   length,
								const backend::PacketMeta& address,
								int						   profile,
								uint64_t				   now,
								uint64_t				   receive_order,
								PacketQueue&			   packets) = 0;

protected:
	/// Reports a packet that will never be sent so the backend can release it as dropped.
	void discard(const backend::PacketMeta& address) const
	{
		if (discard_sink_)
			discard_sink_(address);
	}

	DiscardSink	   discard_sink_;
	ProfileOptions options_;
	const char*	   mode_name_;
	uint32_t	   last_sent_ack_[2]	 = {};
	bool		   has_last_sent_ack_[2] = {};
};

/// Constructs the concrete packet mode selected by the profile options.
std::unique_ptr<PacketMode> create_packet_mode(const ProfileOptions& options);

#endif
