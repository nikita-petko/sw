/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SWDIVERT_INTERNAL_H_
#define SWDIVERT_INTERNAL_H_

#include <linux/mutex.h>
#include <linux/netfilter.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/wait.h>

#include "swdivert_abi.h"

struct net;
struct sk_buff;

struct swdiv_cpu_stats {
	u64 seen;
	u64 matched;
	u64 copied;
	u64 dropped_full;
	u64 truncated;
};

/* The shared ring. Producers (the hook, on any CPU) are serialised by `lock`; the one consumer is user space. */
struct swdiv_ring {
	struct swdiv_ring_hdr	*hdr;		/* vmalloc_user area: header, then the slots */
	u8			*slots;
	struct swdiv_cons	*cons;		/* page mapped writable into user space */
	struct page		*cons_page;
	spinlock_t		lock;
	u32			prod;		/* authoritative producer count (hdr->prod is its published copy) */
	u32			mask;
	u32			slot_bytes;
	u32			hdr_bytes;
	size_t			data_bytes;
};

struct swdiv_handle {
	struct mutex		lock;		/* control plane: ioctl, mmap, release */
	struct net		*net;
	struct swdiv_ring	ring;
	bool			ring_ready;
	bool			started;
	struct swdiv_tuple	tuple;
	struct nf_hook_ops	ops;
	wait_queue_head_t	wq;
	struct swdiv_cpu_stats __percpu *stats;
};

int  swdiv_ring_alloc(struct swdiv_ring *ring, u32 slots, u32 slot_bytes);
void swdiv_ring_free(struct swdiv_ring *ring);
/* Publishes one packet. Returns 0, -ENOSPC when the ring is full. `*truncated` tells whether the copy was cut short. */
int  swdiv_ring_push(struct swdiv_ring *ring, const struct sk_buff *skb, const struct nf_hook_state *state, bool *truncated);
bool swdiv_ring_nonempty(struct swdiv_ring *ring);

int  swdiv_hook_start(struct swdiv_handle *handle);
void swdiv_hook_stop(struct swdiv_handle *handle);

#endif
