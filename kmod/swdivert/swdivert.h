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
struct swdiv_prog;

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
	u64 modified;
	u64 mod_dropped;
	u64 ct_detached;
	u64 injected;
	u64 inject_failed;
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
	struct swdiv_prog __rcu	*prog;		/* the filter; replaced atomically (RCU), never NULL while the handle is open */
	s32			priority;	/* as given by the user: higher is served first */
	struct nf_hook_ops	ops[3];		/* one per layer the handle is attached to */
	unsigned int		n_ops;
	u32			layers;		/* SWDIV_OPEN_LOCAL_IN | _LOCAL_OUT | _FORWARD */
	int			nf_priority;	/* netfilter priority of every hook of the handle: lower runs earlier */
	u32			release_bit;	/* HOLD handles: the skb->mark bit set on a packet the handle resumed; the handle's hooks leave such a packet alone */
	wait_queue_head_t	wq;
	/* Batched reader wake-up (see swdiv_notify) */
	struct hrtimer		wake_timer;
	atomic_t		wake_armed;
	atomic_t		unwoken;	/* packets published since the last wake-up */
	/* Held packets (HOLD handles) */
	struct xarray		held;		/* id -> struct swdiv_held; its lock also protects `closing` */
	bool			closing;	/* no new packets are held (stop/close in progress) */
	unsigned int		hold_ms;	/* this handle's fail-open horizon (never 0 once the handle is open) */
	unsigned int		max_held;
	atomic64_t		next_id;
	atomic_t		held_count;
	struct delayed_work	expiry;
	struct swdiv_cpu_stats __percpu *stats;
};

/* The skb->mark bits handles may claim as their release bit (module parameter release_marks) */
extern unsigned int swdiv_release_marks;
u32  swdiv_release_bit_get(void);
void swdiv_release_bit_put(u32 bit);

extern unsigned int swdiv_hold_ms;
extern unsigned int swdiv_max_held;

/*
 * The handle that is injecting a packet on this CPU, while it does (BH disabled around the call). Hooks of that handle and of
 * handles served before it skip the packet; see SWDIVERT_IOC_INJECT.
 */
DECLARE_PER_CPU(const struct swdiv_handle *, swdiv_injector);

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

/* prog.c: filter programs */
struct swdiv_prog *swdiv_prog_from_user(const struct swdiv_program_args *args);
struct swdiv_prog *swdiv_prog_from_tuple(const struct swdiv_tuple *tuple);
void swdiv_prog_install(struct swdiv_handle *handle, struct swdiv_prog *prog);
void swdiv_prog_free(struct swdiv_handle *handle);
bool swdiv_prog_match(const struct swdiv_handle *handle, const struct sk_buff *skb, const struct nf_hook_state *state);

/* inject.c */
int  swdiv_inject(struct swdiv_handle *handle, void __user *argp);
/* Checks the bytes of a whole IPv4 packet; returns the length to use (the IP total length) or a negative errno. */
int  swdiv_packet_check(const u8 *data, u32 len);
/* Recomputes the checksums asked for in SWDIV_CALC_* on a linear skb that starts at the IP header. */
void swdiv_packet_checksums(struct sk_buff *skb, u32 flags);

#endif
