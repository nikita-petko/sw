// SPDX-License-Identifier: GPL-2.0
/* The netfilter side: a FORWARD hook that matches one 5-tuple and copies matching packets to the ring (sniff only). */
#include <linux/ip.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ip.h>
#include <net/net_namespace.h>

#include "swdivert.h"

static bool swdiv_match(const struct swdiv_tuple *tuple, const struct sk_buff *skb)
{
	struct iphdr iph_buf;
	const struct iphdr *iph;
	__be16 ports[2];
	const __be16 *p;
	unsigned int off = skb_network_offset(skb);
	unsigned int ihl;

	iph = skb_header_pointer(skb, off, sizeof(iph_buf), &iph_buf);
	if (!iph || iph->version != 4)
		return false;
	if (tuple->proto && iph->protocol != tuple->proto)
		return false;
	if (tuple->saddr && iph->saddr != tuple->saddr)
		return false;
	if (tuple->daddr && iph->daddr != tuple->daddr)
		return false;
	if (!tuple->sport && !tuple->dport)
		return true;

	/* Ports exist only in the first fragment of TCP/UDP */
	if (iph->frag_off & htons(IP_OFFSET))
		return false;
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
		return false;
	ihl = iph->ihl * 4;
	if (ihl < sizeof(*iph))
		return false;
	p = skb_header_pointer(skb, off + ihl, sizeof(ports), ports);
	if (!p)
		return false;
	if (tuple->sport && p[0] != tuple->sport)
		return false;
	if (tuple->dport && p[1] != tuple->dport)
		return false;
	return true;
}

static unsigned int swdiv_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct swdiv_handle *handle = priv;
	struct swdiv_cpu_stats *stats = this_cpu_ptr(handle->stats);
	bool truncated = false;

	stats->seen++;
	if (!swdiv_match(&handle->tuple, skb))
		return NF_ACCEPT;
	stats->matched++;

	if (swdiv_ring_push(&handle->ring, skb, state, &truncated)) {
		stats->dropped_full++;
		return NF_ACCEPT;
	}
	stats->copied++;
	if (truncated)
		stats->truncated++;
	/* Cheap when the reader is busy: wq_has_sleeper() is a barrier and a list check */
	if (wq_has_sleeper(&handle->wq))
		wake_up_interruptible(&handle->wq);
	return NF_ACCEPT;
}

int swdiv_hook_start(struct swdiv_handle *handle)
{
	handle->ops.hook = swdiv_hook;
	handle->ops.pf = NFPROTO_IPV4;
	handle->ops.hooknum = NF_INET_FORWARD;
	handle->ops.priority = NF_IP_PRI_FIRST;
	handle->ops.priv = handle;
	return nf_register_net_hook(handle->net, &handle->ops);
}

void swdiv_hook_stop(struct swdiv_handle *handle)
{
	/* Returns after every running callback has finished, so the ring can be freed afterwards */
	nf_unregister_net_hook(handle->net, &handle->ops);
}
