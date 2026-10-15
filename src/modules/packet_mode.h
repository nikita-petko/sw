#ifndef PACKET_MODE_H_
#define PACKET_MODE_H_

#include "packet_engine.h"
#include "windivert_runtime.h"

#include <windows.h>

#include <cstdint>
#include <memory>
#include <queue>
#include <utility>
#include <vector>

/// An owned packet and the metadata needed to release it in order.
struct PacketNode
{
	/// Owned packet bytes.
	BYTE*			   packet;
	/// Packet size in bytes.
	UINT			   length;
	/// Owned WinDivert address metadata.
	WINDIVERT_ADDRESS* address;
	/// Profile number associated with the packet.
	int				   profile;
	/// Earliest time the packet may be released.
	uint64_t		   release_at;
	/// Receive-order tie breaker for packets with equal release times.
	uint64_t		   receive_order;
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
PacketNode* make_packet_node(const BYTE*			  packet,
							 UINT					  length,
							 const WINDIVERT_ADDRESS& address,
							 int					  profile,
							 uint64_t				  release_at,
							 uint64_t				  receive_order);
/// Frees a packet node and its owned packet and address data.
void		destroy_packet_node(PacketNode* node);
/// Moves due packets into the ready list, discarding malformed queue entries.
void		collect_due_packets(PacketQueue& packets, uint64_t now, std::vector<PacketNode*>& ready_packets);
/// Extracts TCP sequence and acknowledgment numbers from a packet.
/// Returns false when the packet does not contain a parseable TCP header.
bool		get_tcp_numbers(const BYTE* packet, UINT length, uint32_t& sequence, uint32_t& acknowledgment);

/// Base class for profile-specific packet scheduling and release behavior.
class PacketMode
{
public:
	/// Initializes the mode with a copy of its profile options and a display name.
	PacketMode(ProfileOptions options, const char* mode_name);
	/// Virtual destructor for derived packet modes.
	virtual ~PacketMode();

	/// Applies common packet processing before delegating to capture_packet().
	virtual void capture(const BYTE*			  packet,
						 UINT					  length,
						 const WINDIVERT_ADDRESS& address,
						 int					  profile,
						 uint64_t				  now,
						 uint64_t				  receive_order,
						 PacketQueue&			  packets);
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
	/// Applies configured TCP acknowledgment restoration before sending a packet.
	void		 prepare_packet_for_send(BYTE* packet, UINT length, const WINDIVERT_ADDRESS* address);
	/// Toggles mode-specific behavior when supported; returns whether it changed state.
	virtual bool toggle(PacketQueue&) { return false; }
	/// Flushes mode-specific queued packets on demand when supported.
	virtual void flush_on_demand(PacketQueue&) {}
	/// Moves or releases all remaining queued packets during teardown.
	virtual void flush(PacketQueue& packets, std::vector<PacketNode*>& pending_packets) = 0;

	/// Implements the scheduling behavior for one captured packet.
	virtual void capture_packet(const BYTE*				 packet,
								UINT					 length,
								const WINDIVERT_ADDRESS& address,
								int						 profile,
								uint64_t				 now,
								uint64_t				 receive_order,
								PacketQueue&			 packets) = 0;

protected:
	ProfileOptions options_;
	const char*	   mode_name_;
	uint32_t	   last_sent_ack_[2]	 = {};
	bool		   has_last_sent_ack_[2] = {};
};

/// Constructs the concrete packet mode selected by the profile options.
std::unique_ptr<PacketMode> create_packet_mode(const ProfileOptions& options);

#endif
