// SPDX-License-Identifier: GPL-2.0
/* The netfilter side: a FORWARD hook that matches one 5-tuple and copies matching packets to the ring (sniff only). */
#include <linux/ip.h>
#include <linux/moduleparam.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ip.h>
#include <net/net_namespace.h>

#include "swdivert.h"

unsigned int swdiv_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct swdiv_handle *handle = priv;
	struct swdiv_cpu_stats *stats = this_cpu_ptr(handle->stats);
	const struct swdiv_handle *injector = this_cpu_read(swdiv_injector);
	bool truncated = false;

	/* A packet this handle (or one served before it) injects is not offered to it again: that would loop */
	if (injector && handle->ops.priority <= injector->ops.priority)
		return NF_ACCEPT;

	stats->seen++;
	if (!swdiv_prog_match(handle, skb, state))
		return NF_ACCEPT;
	stats->matched++;

	if (handle->hold_mode)
		return swdiv_hold_packet(handle, skb, state);

	if (swdiv_ring_push(&handle->ring, skb, state, &truncated, 0, NULL)) {
		stats->dropped_full++;
		return NF_ACCEPT;
	}
	stats->copied++;
	if (truncated)
		stats->truncated++;
	swdiv_notify(handle);
	return NF_ACCEPT;
}

/*
 * Waking the reader for every packet costs a context switch and a poll() each, and the reader then drains one packet. Instead the
 * reader is woken when `wake_batch` packets are waiting, or `wake_us` microseconds after the first of them, whichever comes first.
 * wake_us = 0 restores the wake-up per packet (for comparison). A packet can therefore wait up to wake_us before a sleeping reader
 * sees it; a reader that is busy draining never sleeps and is not delayed at all.
 */
static unsigned int wake_batch = 32;
module_param(wake_batch, uint, 0644);
MODULE_PARM_DESC(wake_batch, "wake the reader after this many published packets (default 32)");
static unsigned int wake_us = 50;
module_param(wake_us, uint, 0644);
MODULE_PARM_DESC(wake_us, "sniffing handles: wake the reader at most this many microseconds after the first unannounced packet; 0 = wake per packet (default 50)");
/*
 * A held packet is waiting for a verdict, so batching its wake-up adds to its delay one for one. Measured (pocs/linux_kernel_module_backend.md):
 * waking per packet costs the reader little more CPU than batching and a fraction of NFQUEUE's, so held handles do not batch by default.
 */
static unsigned int hold_wake_us;
module_param(hold_wake_us, uint, 0644);
MODULE_PARM_DESC(hold_wake_us, "holding handles: the same as wake_us (default 0: wake per packet, the lowest added latency)");

static void swdiv_wake(struct swdiv_handle *handle)
{
	struct swdiv_cpu_stats *stats = this_cpu_ptr(handle->stats);

	atomic_set(&handle->unwoken, 0);
	stats->wakeups++;
	wake_up_interruptible(&handle->wq);
}

static enum hrtimer_restart swdiv_wake_timer_fn(struct hrtimer *timer)
{
	struct swdiv_handle *handle = container_of(timer, struct swdiv_handle, wake_timer);

	/* Clear first: a packet published from here on must be able to arm the timer again */
	atomic_set(&handle->wake_armed, 0);
	swdiv_wake(handle);
	return HRTIMER_NORESTART;
}

void swdiv_wake_timer_init(struct swdiv_handle *handle)
{
	hrtimer_setup(&handle->wake_timer, swdiv_wake_timer_fn, CLOCK_MONOTONIC, HRTIMER_MODE_REL_SOFT);
	atomic_set(&handle->wake_armed, 0);
	atomic_set(&handle->unwoken, 0);
}

void swdiv_wake_timer_cancel(struct swdiv_handle *handle)
{
	hrtimer_cancel(&handle->wake_timer);
}

void swdiv_notify(struct swdiv_handle *handle)
{
	const unsigned int delay_us = handle->hold_mode ? READ_ONCE(hold_wake_us) : READ_ONCE(wake_us);
	const unsigned int batch = READ_ONCE(wake_batch);

	/* A reader that is not asleep finds the packet by itself; wq_has_sleeper() is the barrier that pairs with poll_wait() */
	if (!wq_has_sleeper(&handle->wq))
		return;

	if (!delay_us || atomic_inc_return(&handle->unwoken) >= max(batch, 1U)) {
		swdiv_wake(handle);
		return;
	}
	/* Arm once: restarting a running timer on every packet would postpone the wake-up for as long as packets keep coming */
	if (atomic_cmpxchg(&handle->wake_armed, 0, 1) == 0)
		hrtimer_start(&handle->wake_timer, ns_to_ktime((u64)delay_us * NSEC_PER_USEC), HRTIMER_MODE_REL_SOFT);
}

int swdiv_hook_start(struct swdiv_handle *handle)
{
	handle->ops.hook = swdiv_hook;
	handle->ops.pf = NFPROTO_IPV4;
	handle->ops.hooknum = NF_INET_FORWARD;
	/* Higher user priority = lower netfilter priority number = earlier. NF_IP_PRI_FIRST is INT_MIN: the handles run before everything else */
	handle->ops.priority = NF_IP_PRI_FIRST + 30000 - handle->priority;
	handle->ops.priv = handle;
	return nf_register_net_hook(handle->net, &handle->ops);
}

void swdiv_hook_stop(struct swdiv_handle *handle)
{
	/* Returns after every running callback has finished, so the ring can be freed afterwards */
	nf_unregister_net_hook(handle->net, &handle->ops);
}
