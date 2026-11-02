/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SWDIVERT_INTERNAL_H_
#define SWDIVERT_INTERNAL_H_

#include <linux/atomic.h>
#include <linux/hrtimer.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/netfilter.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/xarray.h>

#include "swdivert_abi.h"

struct net;
struct sk_buff;
struct net_device;

struct swdiv_cpu_stats {
	u64 seen;
	u64 matched;
	u64 copied;
	u64 dropped_full;
	u64 truncated;
	u64 wakeups;
	u64 held;
	u64 resumed;
	u64 verdict_dropped;
	u64 expired;
	u64 flushed;
	u64 dev_dropped;
	u64 resume_lost;
	u64 pass_unsupported;
	u64 pass_limit;
};

/*
 * A packet taken out of the stack (NF_STOLEN) and parked until a verdict. The entry owns the skb, a copy of the hook state
 * it was stolen with (the continuation: which hook, which devices, which okfn) and a reference on each network device.
 */
struct swdiv_held {
	struct sk_buff		*skb;
	struct nf_hook_state	state;
	unsigned long		expires;	/* jiffies */
	u64			id;
	/*
	 * False while the hook is still copying the packet into the ring. Set (release) under the ring lock, right before the slot
	 * is published, and never touched by the hook afterwards: from then on any CPU may take the entry and resume or drop it,
	 * even while the hook is still on its way back out. Everything that takes entries (verdicts, expiry, flush, device removal)
	 * ignores entries that are not ready.
	 */
	bool			ready;
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
	struct mutex		lock;		/* control plane: ioctl, mmap */
	struct list_head	node;		/* swdiv_handles, for the network device notifier */
	struct net		*net;
	struct swdiv_ring	ring;
	bool			ring_ready;
	bool			started;
	bool			hold_mode;
	struct swdiv_tuple	tuple;
	struct nf_hook_ops	ops;
	wait_queue_head_t	wq;
	/* Batched reader wake-up (see swdiv_notify) */
	struct hrtimer		wake_timer;
	atomic_t		wake_armed;
	atomic_t		unwoken;	/* packets published since the last wake-up */
	/* Held packets (HOLD handles) */
	struct xarray		held;		/* id -> struct swdiv_held; its lock also protects `closing` */
	bool			closing;	/* no new packets are held (stop/close in progress) */
	atomic64_t		next_id;
	atomic_t		held_count;
	struct delayed_work	expiry;
	struct swdiv_cpu_stats __percpu *stats;
};

extern unsigned int swdiv_hold_ms;
extern unsigned int swdiv_max_held;

int  swdiv_ring_alloc(struct swdiv_ring *ring, u32 slots, u32 slot_bytes);
void swdiv_ring_free(struct swdiv_ring *ring);
/*
 * Publishes one packet. Returns 0, or -ENOSPC when the ring is full. `*truncated` tells whether the copy was cut short. With
 * `entry`, the entry is marked ready under the ring lock just before the slot becomes visible (see struct swdiv_held).
 */
int  swdiv_ring_push(struct swdiv_ring *ring, const struct sk_buff *skb, const struct nf_hook_state *state, bool *truncated,
		     u64 id, struct swdiv_held *entry);
bool swdiv_ring_nonempty(struct swdiv_ring *ring);

/* Reader wake-up (hook.c) */
void swdiv_notify(struct swdiv_handle *handle);
void swdiv_wake_timer_init(struct swdiv_handle *handle);
void swdiv_wake_timer_cancel(struct swdiv_handle *handle);

int  swdiv_hook_start(struct swdiv_handle *handle);
void swdiv_hook_stop(struct swdiv_handle *handle);
/* The netfilter hook; hold.c finds the position of this handle in the hook chain by its address */
unsigned int swdiv_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

/* Held packets (hold.c) */
int  swdiv_hold_module_init(void);
void swdiv_hold_module_exit(void);
void swdiv_hold_register(struct swdiv_handle *handle);
void swdiv_hold_unregister(struct swdiv_handle *handle);
void swdiv_hold_init(struct swdiv_handle *handle);
/* Steals the packet if it can be held. Returns the netfilter verdict for the hook (NF_STOLEN, or NF_ACCEPT when it was not held). */
unsigned int swdiv_hold_packet(struct swdiv_handle *handle, struct sk_buff *skb, const struct nf_hook_state *state);
/* Resumes every held packet and stops holding new ones; the hook stays registered until the caller unregisters it. */
void swdiv_hold_flush(struct swdiv_handle *handle);
void swdiv_hold_reopen(struct swdiv_handle *handle);
/* Hook registration: lets the network device notifier find the handles of a namespace */
void swdiv_hold_destroy(struct swdiv_handle *handle);
int  swdiv_hold_verdicts(struct swdiv_handle *handle, void __user *argp);

#endif
