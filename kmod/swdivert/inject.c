// SPDX-License-Identifier: GPL-2.0
/*
 * Packets that user space writes: validation and checksums of whole IPv4 packets (shared by RESUME_MOD and INJECT) and
 * SWDIVERT_IOC_INJECT, which delivers a packet that never went through the stack as if it had been received on an interface.
 */
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/uaccess.h>
#include <net/ip.h>
#include <net/net_namespace.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "swdivert.h"

DEFINE_PER_CPU(const struct swdiv_handle *, swdiv_injector);

int swdiv_packet_check(const u8 *data, u32 len)
{
	const struct iphdr *iph = (const struct iphdr *)data;
	u32 ihl, total;

	if (len < sizeof(*iph) || len > SWDIV_MAX_PACKET)
		return -EINVAL;
	if (iph->version != 4)
		return -EINVAL;
	ihl = iph->ihl * 4;
	if (ihl < sizeof(*iph) || ihl > len)
		return -EINVAL;
	total = ntohs(iph->tot_len);
	if (total < ihl || total > len)
		return -EINVAL;
	/* Bytes after the IP total length (padding) are not part of the packet */
	return total;
}

void swdiv_packet_checksums(struct sk_buff *skb, u32 flags)
{
	struct iphdr *iph = ip_hdr(skb);
	const u32 ihl = iph->ihl * 4;
	const u32 l4len = skb->len - ihl;

	if ((flags & SWDIV_CALC_L4) && !(iph->frag_off & htons(IP_MF | IP_OFFSET))) {
		if (iph->protocol == IPPROTO_TCP && l4len >= sizeof(struct tcphdr)) {
			struct tcphdr *th = (struct tcphdr *)((u8 *)iph + ihl);

			th->check = 0;
			th->check = tcp_v4_check(l4len, iph->saddr, iph->daddr, csum_partial(th, l4len, 0));
			/* The checksum is complete now: nothing is left for the device to finish */
			skb->ip_summed = CHECKSUM_NONE;
		} else if (iph->protocol == IPPROTO_UDP && l4len >= sizeof(struct udphdr)) {
			struct udphdr *uh = (struct udphdr *)((u8 *)iph + ihl);

			uh->check = 0;
			uh->check = udp_v4_check(l4len, iph->saddr, iph->daddr, csum_partial(uh, l4len, 0));
			if (!uh->check)
				uh->check = CSUM_MANGLED_0;
			skb->ip_summed = CHECKSUM_NONE;
		}
	}
	if (flags & SWDIV_CALC_IP)
		ip_send_check(iph);
}

int swdiv_inject(struct swdiv_handle *h, void __user *argp)
{
	struct swdiv_inject_args args;
	struct net_device *dev;
	struct sk_buff *skb;
	u8 *buf;
	int len, ret;

	/* The handle's priority (and with it its place in the chain) is only fixed once it is started */
	if (!h->started)
		return -EINVAL;
	if (copy_from_user(&args, argp, sizeof(args)))
		return -EFAULT;
	if (args.reserved || (args.flags & ~(SWDIV_CALC_IP | SWDIV_CALC_L4)) || !args.len || args.len > SWDIV_MAX_PACKET)
		return -EINVAL;

	buf = memdup_user(u64_to_user_ptr(args.data), args.len);
	if (IS_ERR(buf))
		return PTR_ERR(buf);
	len = swdiv_packet_check(buf, args.len);
	if (len < 0) {
		ret = len;
		goto out_free;
	}

	dev = dev_get_by_index(h->net, args.ifindex);
	if (!dev) {
		ret = -ENODEV;
		goto out_free;
	}
	if (!(dev->flags & IFF_UP)) {
		ret = -ENETDOWN;
		goto out_dev;
	}

	skb = alloc_skb(LL_MAX_HEADER + len, GFP_KERNEL);
	if (!skb) {
		ret = -ENOMEM;
		goto out_dev;
	}
	skb_reserve(skb, LL_MAX_HEADER);
	skb_put_data(skb, buf, len);
	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);
	skb->pkt_type = PACKET_HOST;
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	swdiv_packet_checksums(skb, args.flags);

	/*
	 * Received here and now, on this CPU, so that the marker the hooks look at covers the whole synchronous traversal. (With
	 * receive packet steering the packet could be queued to another CPU, where the marker is not set.)
	 */
	local_bh_disable();
	this_cpu_write(swdiv_injector, h);
	netif_receive_skb(skb);
	this_cpu_write(swdiv_injector, NULL);
	local_bh_enable();

	this_cpu_inc(h->stats->injected);
	ret = 0;
out_dev:
	dev_put(dev);
out_free:
	kfree(buf);
	if (ret)
		this_cpu_inc(h->stats->inject_failed);
	return ret;
}
