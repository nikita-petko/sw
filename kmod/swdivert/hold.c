// SPDX-License-Identifier: GPL-2.0
/*
 * Held packets: stealing a packet in the hook, parking it until user space gives a verdict, and resuming or dropping it.
 *
 * A held packet is an skb the hook returned NF_STOLEN for. Resuming it means running the hooks that sort after ours and then the
 * okfn the original caller passed (ip_forward_finish for FORWARD), exactly what nf_hook() would have done had our hook accepted.
 * nf_reinject() cannot be used: it needs the packet to have gone through nf_queue(), and the one nf_queue handler of the system
 * belongs to nfnetlink_queue (the shipped NFQUEUE backend).
 *
 * Every way a held packet can leave goes through swdiv_take()/swdiv_take_id(), which remove it from the table under its lock, so
 * a packet is resumed or dropped exactly once. Nothing that holds packets may ever lose one: stop, close (including SIGKILL of
 * the reader) and a reader that stops answering all resume the packets (the "fail open" requirement of the design).
 */
#include <linux/ip.h>
#include <linux/jiffies.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/netdev_features.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/uaccess.h>
#include <net/dst.h>
#include <net/gso.h>
#include <net/ip.h>
#include <net/inet_dscp.h>
#include <net/net_namespace.h>
#include <net/route.h>

#include "swdivert.h"

#if BITS_PER_LONG != 64
#error "swdivert keys the held packets by a 64-bit id in an xarray: 64-bit kernels only"
#endif

unsigned int swdiv_hold_ms = 2000;
module_param_named(hold_ms, swdiv_hold_ms, uint, 0644);
MODULE_PARM_DESC(hold_ms, "resume a held packet nobody gave a verdict for after this many milliseconds (default 2000)");

unsigned int swdiv_max_held = 4096;
module_param_named(max_held, swdiv_max_held, uint, 0644);
MODULE_PARM_DESC(max_held, "most packets one handle holds at a time; further packets pass unheld (default 4096)");

/*
 * A packet this handle resumed carries the handle's release bit in skb->mark, and the handle's hooks leave it alone from then on. Without
 * it a packet that crosses two of the handle's hooks (loopback traffic: LOCAL_OUT, then LOCAL_IN) would be held at each of them, so a
 * delay would apply twice. The bits come from a pool the user can move (top byte by default, rarely used by anything else, as in the
 * NFQUEUE backend); a handle that finds none runs without the guard.
 */
unsigned int swdiv_release_marks = 0xFF000000;
module_param_named(release_marks, swdiv_release_marks, uint, 0444);
MODULE_PARM_DESC(release_marks, "skb->mark bits that holding handles may use to recognise the packets they resumed (default 0xff000000)");
static u32 swdiv_release_used;

static struct kmem_cache *swdiv_held_cache;
static LIST_HEAD(swdiv_handles);
static DEFINE_MUTEX(swdiv_handles_lock);

static void swdiv_entry_free(struct swdiv_held *e)
{
	if (e->state.in)
		dev_put(e->state.in);
	if (e->state.out)
		dev_put(e->state.out);
	if (e->state.sk)
		sock_put(e->state.sk);
	kmem_cache_free(swdiv_held_cache, e);
}

static void swdiv_entry_drop(struct swdiv_held *e)
{
	kfree_skb(e->skb);
	swdiv_entry_free(e);
}

/* Where to continue in the hook chain: right after this handle's hook */
static unsigned int swdiv_resume_index(const struct nf_hook_entries *hooks, const struct swdiv_handle *h)
{
	struct nf_hook_ops **ops;
	unsigned int i;

	for (i = 0; i < hooks->num_hook_entries; i++)
		if (hooks->hooks[i].hook == swdiv_hook && hooks->hooks[i].priv == h)
			return i + 1;

	/* The hook is already unregistered (only after a stop raced with a resume): continue after everything that sorts before it */
	ops = nf_hook_entries_get_hook_ops(hooks);
	for (i = 0; i < hooks->num_hook_entries; i++)
		if (ops[i]->priority > h->nf_priority)
			return i;
	return hooks->num_hook_entries;
}

/*
 * Runs the hooks after this handle's and then the okfn: what nf_hook() would have done had our hook accepted the packet. Process
 * context or the hook itself.
 */
static void swdiv_continue(struct swdiv_handle *h, struct sk_buff *skb, struct nf_hook_state *state)
{
	struct net *net = state->net;
	const struct nf_hook_entries *hooks;
	int ret = 1;

	skb->mark |= READ_ONCE(h->release_bit);
	/* The packet path expects softirq conditions: BH off and inside an RCU read-side section, as nf_hook() runs it */
	local_bh_disable();
	rcu_read_lock();
	hooks = rcu_dereference(net->nf.hooks_ipv4[state->hook]);
	if (hooks)
		ret = nf_hook_slow(skb, state, hooks, swdiv_resume_index(hooks, h));
	if (ret == 1)
		state->okfn(net, state->sk, skb);
	rcu_read_unlock();
	local_bh_enable();
}

/* Gives a held packet back to the stack and frees the entry. */
static void swdiv_entry_resume(struct swdiv_handle *h, struct swdiv_held *e)
{
	swdiv_continue(h, e->skb, &e->state);
	swdiv_entry_free(e);
}

/* The 5-tuple of an IPv4 packet; ports are 0 unless it is a TCP or UDP packet that is not a later fragment */
struct swdiv_tuple4 {
	__be32 saddr, daddr;
	__be16 sport, dport;
	u8 proto;
};

static void swdiv_tuple_of(const struct sk_buff *skb, const u8 *linear, struct swdiv_tuple4 *t)
{
	const struct iphdr *iph = (const struct iphdr *)(linear ? linear : skb_network_header(skb));
	const u32 ihl = iph->ihl * 4;
	__be16 ports[2];
	const __be16 *p = NULL;

	t->saddr = iph->saddr;
	t->daddr = iph->daddr;
	t->proto = iph->protocol;
	t->sport = t->dport = 0;
	if ((iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) || (iph->frag_off & htons(IP_OFFSET)))
		return;
	if (linear)
		p = (const __be16 *)(linear + ihl);
	else
		p = skb_header_pointer(skb, skb_network_offset(skb) + ihl, sizeof(ports), ports);
	if (p) {
		t->sport = p[0];
		t->dport = p[1];
	}
}

/*
 * Resumes a held packet with `data[len]` (a whole IPv4 packet that swdiv_packet_check() accepted) in place of its bytes. The
 * skb keeps everything else it carries: what the stack knows about the packet's route, connection and device is only adjusted
 * where the new bytes contradict it: a changed destination address is routed again, a changed 5-tuple detaches the connection
 * tracking entry (its NAT mapping and state were made for the old tuple, so the rest of the path treats the packet as untracked).
 * Failure here (no memory, no route) drops the packet, counted as mod_dropped.
 */
static void swdiv_entry_resume_mod(struct swdiv_handle *h, struct swdiv_held *e, const u8 *data, u32 len, u32 flags)
{
	struct sk_buff *skb = e->skb;
	struct swdiv_tuple4 before, after;
	struct iphdr *iph;
	int err = -EINVAL;

	local_bh_disable();
	rcu_read_lock();

	/* At the hooks this module serves the packet starts at the IP header; anything else is not something this knows how to rewrite */
	if (skb_network_offset(skb) != 0)
		goto fail;
	swdiv_tuple_of(skb, NULL, &before);
	err = skb_linearize(skb);
	if (!err)
		err = skb_unclone(skb, GFP_ATOMIC);
	if (!err && len > skb->len)
		err = pskb_expand_head(skb, 0, len - skb->len, GFP_ATOMIC);
	if (err)
		goto fail;
	if (len > skb->len)
		skb_put(skb, len - skb->len);
	else if (len < skb->len)
		skb_trim(skb, len);
	memcpy(skb->data, data, len);
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	skb_set_transport_header(skb, iph->ihl * 4);

	swdiv_packet_checksums(skb, flags);
	/*
	 * The checksum state of the skb (verified by the device, computed over the old bytes, or left to the device to fill in) describes
	 * the old bytes. The packet user space wrote is complete, as for nf_queue, so it is treated as an ordinary unverified packet.
	 */
	skb->ip_summed = CHECKSUM_NONE;

	swdiv_tuple_of(skb, NULL, &after);
	if (memcmp(&before, &after, sizeof(before))) {
		nf_reset_ct(skb);
		this_cpu_inc(h->stats->ct_detached);
	}
	/*
	 * A changed destination is routed again where the route is still to be decided for the packet: on its way out of this host and
	 * when it is forwarded. A packet for this host is delivered whatever its destination says.
	 */
	if (before.daddr != after.daddr && e->state.hook != NF_INET_LOCAL_IN) {
		struct net_device *out;

		skb_dst_drop(skb);
		if (e->state.hook == NF_INET_LOCAL_OUT)
			err = ip_route_me_harder(e->state.net, e->state.sk, skb, RTN_UNSPEC);
		else
			err = ip_route_input(skb, iph->daddr, iph->saddr, inet_dsfield_to_dscp(iph->tos), e->state.in);
		if (err) {
			err = -ENETUNREACH;
			goto fail;
		}
		/* The hooks after this one are told the device the packet leaves through */
		out = skb_dst(skb)->dev;
		if (out != e->state.out) {
			dev_hold(out);
			if (e->state.out)
				dev_put(e->state.out);
			e->state.out = out;
		}
	}

	this_cpu_inc(h->stats->modified);
	swdiv_continue(h, skb, &e->state);
	rcu_read_unlock();
	local_bh_enable();
	swdiv_entry_free(e);
	return;

fail:
	rcu_read_unlock();
	local_bh_enable();
	this_cpu_inc(h->stats->mod_dropped);
	swdiv_entry_drop(e);
}

typedef bool (*swdiv_pred)(const struct swdiv_held *e, const void *arg);

/*
 * Removes one entry that satisfies `pred` (any when NULL) and returns it, or NULL when there is none. Entries that are still
 * being set up by the hook are waited for, never skipped, so that "NULL" means "nothing left": the hook finishes within
 * microseconds and either makes the entry ready or removes it itself.
 */
static struct swdiv_held *swdiv_take(struct swdiv_handle *h, swdiv_pred pred, const void *arg)
{
	struct swdiv_held *e;
	unsigned long id;
	bool busy;

	for (;;) {
		busy = false;
		xa_lock_bh(&h->held);
		xa_for_each(&h->held, id, e) {
			if (pred && !pred(e, arg))
				continue;
			if (!smp_load_acquire(&e->ready)) {
				busy = true;
				continue;
			}
			__xa_erase(&h->held, id);
			atomic_dec(&h->held_count);
			xa_unlock_bh(&h->held);
			return e;
		}
		xa_unlock_bh(&h->held);
		if (!busy)
			return NULL;
		cond_resched();
	}
}

/* Removes the entry with this id. An id that is unknown, gone, or not yet published (guessed by a misbehaving reader) is NULL. */
static struct swdiv_held *swdiv_take_id(struct swdiv_handle *h, u64 id)
{
	struct swdiv_held *e;

	xa_lock_bh(&h->held);
	e = xa_load(&h->held, id);
	if (e && smp_load_acquire(&e->ready)) {
		__xa_erase(&h->held, id);
		atomic_dec(&h->held_count);
	} else {
		e = NULL;
	}
	xa_unlock_bh(&h->held);
	return e;
}

static bool swdiv_pred_expired(const struct swdiv_held *e, const void *arg)
{
	return time_after_eq(jiffies, e->expires);
}

static bool swdiv_pred_dev(const struct swdiv_held *e, const void *arg)
{
	const struct net_device *dev = arg;

	return e->state.in == dev || e->state.out == dev || e->skb->dev == dev;
}

/* ---- the hook side ---- */

/*
 * Holds one ordinary packet. Returns NF_STOLEN, or NF_ACCEPT when the packet was not taken: it then still belongs to the caller.
 * Not held: packets without a refcounted route or whose socket is going away. The socket of a locally generated packet is kept
 * alive while the packet is held, as nf_queue does.

 */
static unsigned int swdiv_hold_one(struct swdiv_handle *h, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct swdiv_cpu_stats *stats = this_cpu_ptr(h->stats);
	struct swdiv_held *e;
	bool truncated = false;
	bool unsupported = false;
	int err;
	u64 id;

	if (!state->okfn) {
		stats->pass_unsupported++;
		return NF_ACCEPT;
	}
	if (atomic_read(&h->held_count) >= h->max_held) {
		stats->pass_limit++;
		return NF_ACCEPT;
	}
	e = kmem_cache_zalloc(swdiv_held_cache, GFP_ATOMIC);
	if (!e) {
		stats->pass_limit++;
		return NF_ACCEPT;
	}
	/* A route that is only valid inside this RCU section cannot be parked */
	if (!skb_dst_force(skb)) {
		kmem_cache_free(swdiv_held_cache, e);
		stats->pass_unsupported++;
		return NF_ACCEPT;
	}

	if (state->sk && !refcount_inc_not_zero(&state->sk->sk_refcnt)) {
		kmem_cache_free(swdiv_held_cache, e);
		stats->pass_unsupported++;
		return NF_ACCEPT;
	}

	e->skb = skb;
	e->state = *state;
	e->expires = jiffies + msecs_to_jiffies(h->hold_ms);
	id = atomic64_inc_return(&h->next_id);
	e->id = id;
	if (state->in)
		dev_hold(state->in);
	if (state->out)
		dev_hold(state->out);

	xa_lock_bh(&h->held);
	if (h->closing) {
		err = -EBUSY;
		unsupported = true;
	} else {
		err = __xa_insert(&h->held, id, e, GFP_ATOMIC);
		if (!err)
			atomic_inc(&h->held_count);
	}
	xa_unlock_bh(&h->held);
	if (err) {
		swdiv_entry_free(e);
		if (unsupported)
			stats->pass_unsupported++;
		else
			stats->pass_limit++;
		return NF_ACCEPT;
	}

	if (swdiv_ring_push(&h->ring, skb, state, &truncated, id, e)) {
		/*
		 * The ring is full: take the packet back and let it through. The id was never published and entries that are not
		 * ready are never taken by anyone else, so the entry is still ours.
		 */
		xa_lock_bh(&h->held);
		__xa_erase(&h->held, id);
		atomic_dec(&h->held_count);
		xa_unlock_bh(&h->held);
		swdiv_entry_free(e);
		stats->dropped_full++;
		return NF_ACCEPT;
	}

	/*
	 * From here on the entry and the skb belong to whoever takes them: only the handle is touched. A verdict may already be
	 * resuming the packet on another CPU while this hook is still returning, which is fine because nf_hook_slow() does not look
	 * at a stolen skb again.
	 */
	stats->copied++;
	stats->held++;
	if (truncated)
		stats->truncated++;
	if (!delayed_work_pending(&h->expiry))
		schedule_delayed_work(&h->expiry, msecs_to_jiffies(clamp(h->hold_ms / 8, 5U, 250U)));
	swdiv_notify(h);
	return NF_STOLEN;
}

/*
 * A GSO super-packet (a TCP segment train that veth or a NIC coalesced) is segmented first and every segment is held on its own,
 * as nf_queue does: the copy in the ring and a later resume then deal with ordinary packets, and a delay really delays every
 * segment. A segment that cannot be held (the limit was reached, the ring is full) continues at once, which can reorder segments
 * of one connection but loses nothing.
 */
static unsigned int swdiv_hold_gso(struct swdiv_handle *h, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct sk_buff *segs, *next;

	segs = skb_gso_segment(skb, 0);
	if (IS_ERR_OR_NULL(segs)) {
		this_cpu_inc(h->stats->pass_unsupported);
		return NF_ACCEPT;
	}
	consume_skb(skb);

	for (; segs; segs = next) {
		next = segs->next;
		skb_mark_not_on_list(segs);
		if (swdiv_hold_one(h, segs, state) != NF_STOLEN) {
			struct nf_hook_state st = *state;

			swdiv_continue(h, segs, &st);
		}
	}
	return NF_STOLEN;
}

unsigned int swdiv_hold_packet(struct swdiv_handle *h, struct sk_buff *skb, const struct nf_hook_state *state)
{
	if (skb_is_gso(skb))
		return swdiv_hold_gso(h, skb, state);
	return swdiv_hold_one(h, skb, state);
}

/* ---- timeout ---- */

static void swdiv_expiry_fn(struct work_struct *work)
{
	struct swdiv_handle *h = container_of(to_delayed_work(work), struct swdiv_handle, expiry);
	struct swdiv_held *e;

	while ((e = swdiv_take(h, swdiv_pred_expired, NULL))) {
		this_cpu_inc(h->stats->expired);
		swdiv_entry_resume(h, e);
	}
	if (atomic_read(&h->held_count) > 0)
		schedule_delayed_work(&h->expiry, msecs_to_jiffies(clamp(h->hold_ms / 8, 5U, 250U)));
}

/* ---- control side ---- */

void swdiv_hold_init(struct swdiv_handle *h)
{
	xa_init_flags(&h->held, XA_FLAGS_LOCK_BH);
	atomic64_set(&h->next_id, 0);
	atomic_set(&h->held_count, 0);
	h->closing = false;
	INIT_DELAYED_WORK(&h->expiry, swdiv_expiry_fn);
}

void swdiv_hold_destroy(struct swdiv_handle *h)
{
	cancel_delayed_work_sync(&h->expiry);
	WARN_ON(!xa_empty(&h->held));
	xa_destroy(&h->held);
}

void swdiv_hold_flush(struct swdiv_handle *h)
{
	struct swdiv_held *e;

	/* Under the table's lock, so that after this no hook can add an entry the loop below would miss */
	xa_lock_bh(&h->held);
	h->closing = true;
	xa_unlock_bh(&h->held);

	while ((e = swdiv_take(h, NULL, NULL))) {
		this_cpu_inc(h->stats->flushed);
		swdiv_entry_resume(h, e);
	}
}

void swdiv_hold_reopen(struct swdiv_handle *h)
{
	xa_lock_bh(&h->held);
	h->closing = false;
	xa_unlock_bh(&h->held);
}

int swdiv_hold_verdicts(struct swdiv_handle *h, void __user *argp)
{
	struct swdiv_verdict_args args;
	struct swdiv_verdict __user *items;
	u32 i;

	if (!h->hold_mode)
		return -EINVAL;
	if (copy_from_user(&args, argp, sizeof(args)))
		return -EFAULT;
	if (args.reserved || !args.count || args.count > SWDIV_MAX_VERDICTS)
		return -EINVAL;
	items = u64_to_user_ptr(args.items);

	for (i = 0; i < args.count; i++) {
		struct swdiv_verdict v;
		struct swdiv_held *e;
		u32 status = 0;

		if (copy_from_user(&v, &items[i], sizeof(v)))
			return -EFAULT;
		if (v.verdict == SWDIV_V_RESUME_MOD) {
			u8 *buf;
			int total;

			if (!v.len || v.len > SWDIV_MAX_PACKET || (v.flags & ~(SWDIV_CALC_IP | SWDIV_CALC_L4))) {
				status = EINVAL;
			} else if (IS_ERR(buf = memdup_user(u64_to_user_ptr(v.data), v.len))) {
				status = -PTR_ERR(buf);
			} else {
				/* Bad bytes are refused before the packet is taken: it stays held (and the timeout still applies) */
				total = swdiv_packet_check(buf, v.len);
				if (total < 0) {
					status = EINVAL;
				} else {
					e = swdiv_take_id(h, v.id);
					if (!e)
						status = ENOENT;
					else
						swdiv_entry_resume_mod(h, e, buf, total, v.flags);
				}
				kfree(buf);
			}
		} else if ((v.verdict != SWDIV_V_RESUME && v.verdict != SWDIV_V_DROP) || v.data || v.len || v.flags) {
			/* What a verdict does not use has to be 0, so that it can get a meaning later (see swdivert_abi.h) */
			status = EINVAL;
		} else {
			e = swdiv_take_id(h, v.id);
			if (!e) {
				status = ENOENT;
			} else if (v.verdict == SWDIV_V_RESUME) {
				this_cpu_inc(h->stats->resumed);
				swdiv_entry_resume(h, e);
			} else {
				this_cpu_inc(h->stats->verdict_dropped);
				swdiv_entry_drop(e);
			}
		}
		if (put_user(status, &items[i].status))
			return -EFAULT;
		if (!(i & 63))
			cond_resched();
	}
	return 0;
}

/* ---- network devices ---- */

/* A held packet pins its devices, which would stall the unregistration of a device that goes away while packets are held */
static int swdiv_netdev_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct swdiv_handle *h;
	struct swdiv_held *e;

	if (event != NETDEV_UNREGISTER)
		return NOTIFY_DONE;

	mutex_lock(&swdiv_handles_lock);
	list_for_each_entry(h, &swdiv_handles, node) {
		if (!net_eq(h->net, dev_net(dev)))
			continue;
		while ((e = swdiv_take(h, swdiv_pred_dev, dev))) {
			this_cpu_inc(h->stats->dev_dropped);
			swdiv_entry_drop(e);
		}
	}
	mutex_unlock(&swdiv_handles_lock);
	return NOTIFY_DONE;
}

static struct notifier_block swdiv_netdev_nb = {
	.notifier_call = swdiv_netdev_event,
};

u32 swdiv_release_bit_get(void)
{
	u32 avail, bit = 0;

	mutex_lock(&swdiv_handles_lock);
	avail = swdiv_release_marks & ~swdiv_release_used;
	if (avail) {
		bit = avail & -avail;
		swdiv_release_used |= bit;
	}
	mutex_unlock(&swdiv_handles_lock);
	return bit;
}

void swdiv_release_bit_put(u32 bit)
{
	mutex_lock(&swdiv_handles_lock);
	swdiv_release_used &= ~bit;
	mutex_unlock(&swdiv_handles_lock);
}

void swdiv_hold_register(struct swdiv_handle *h)
{
	mutex_lock(&swdiv_handles_lock);
	list_add(&h->node, &swdiv_handles);
	mutex_unlock(&swdiv_handles_lock);
}

void swdiv_hold_unregister(struct swdiv_handle *h)
{
	mutex_lock(&swdiv_handles_lock);
	list_del_init(&h->node);
	mutex_unlock(&swdiv_handles_lock);
}

int swdiv_hold_module_init(void)
{
	int ret;

	swdiv_held_cache = kmem_cache_create("swdivert_held", sizeof(struct swdiv_held), 0, 0, NULL);
	if (!swdiv_held_cache)
		return -ENOMEM;
	ret = register_netdevice_notifier(&swdiv_netdev_nb);
	if (ret) {
		kmem_cache_destroy(swdiv_held_cache);
		return ret;
	}
	return 0;
}

void swdiv_hold_module_exit(void)
{
	unregister_netdevice_notifier(&swdiv_netdev_nb);
	/* Warns if an entry leaked */
	kmem_cache_destroy(swdiv_held_cache);
}
