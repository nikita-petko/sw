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

struct PacketNode
{
	BYTE*			   packet;
	UINT			   length;
	WINDIVERT_ADDRESS* address;
	int				   profile;
	uint64_t		   release_at;
	uint64_t		   receive_order;
};

struct PacketReleaseEarlier
{
	bool operator()(const PacketNode* left, const PacketNode* right) const
	{
		if (left->release_at != right->release_at)
			return left->release_at > right->release_at;
		return left->receive_order > right->receive_order;
	}
};

using PacketQueue = std::priority_queue<PacketNode*, std::vector<PacketNode*>, PacketReleaseEarlier>;

PacketNode* make_packet_node(const BYTE*			  packet,
							 UINT					  length,
							 const WINDIVERT_ADDRESS& address,
							 int					  profile,
							 uint64_t				  release_at,
							 uint64_t				  receive_order);
void		destroy_packet_node(PacketNode* node);
void		collect_due_packets(PacketQueue& packets, uint64_t now, std::vector<PacketNode*>& ready_packets);
bool		get_tcp_numbers(const BYTE* packet, UINT length, uint32_t& sequence, uint32_t& acknowledgment);

class PacketMode
{
public:
	PacketMode(ProfileOptions options, const char* mode_name);
	virtual ~PacketMode();

	virtual void capture(const BYTE*			  packet,
						 UINT					  length,
						 const WINDIVERT_ADDRESS& address,
						 int					  profile,
						 uint64_t				  now,
						 uint64_t				  receive_order,
						 PacketQueue&			  packets);
	virtual void release(PacketQueue& packets, uint64_t now, std::vector<PacketNode*>& ready_packets) = 0;
	virtual void reset()
	{
		last_sent_ack_[0]	  = 0;
		last_sent_ack_[1]	  = 0;
		has_last_sent_ack_[0] = false;
		has_last_sent_ack_[1] = false;
	}
	void		 prepare_packet_for_send(BYTE* packet, UINT length, const WINDIVERT_ADDRESS* address);
	virtual bool toggle(PacketQueue&) { return false; }
	virtual void flush(PacketQueue& packets, std::vector<PacketNode*>& pending_packets) = 0;

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

std::unique_ptr<PacketMode> create_packet_mode(const ProfileOptions& options);

#endif
