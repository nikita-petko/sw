// SPDX-License-Identifier: GPL-2.0
// Egress data plane of the Linux backend: classifies IPv4 TCP/UDP packets against the active stages and, instead of
// holding them in user space, stamps them with an earliest departure time that the `fq` qdisc honours (or drops them).
// Built with `clang -target bpf -mcpu=v3 -O2 -g` at package time and embedded in the binary; see backends/nfqueue/xmake.lua.
#include <stdbool.h>

// linux/bpf.h must precede the libbpf headers: they use __u32/__u64 without including it.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "bpf_shared.h"

char LICENSE[] SEC("license") = "GPL";

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, LAGSW_MAX_STAGES);
	__type(key, __u32);
	__type(value, struct lagsw_stage);
} stages SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, LAGSW_MAX_STAGES);
	__type(key, __u32);
	__type(value, struct lagsw_state);
} state SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, LAGSW_MAX_STAGES);
	__type(key, __u32);
	__type(value, struct lagsw_stats);
} stats SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, LAGSW_MAX_ADDRS);
	__type(key, struct lagsw_addr_key);
	__type(value, __u8);
} addrs SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, LAGSW_MAX_IFACES);
	__type(key, __u32);
	__type(value, struct lagsw_ifinfo);
} ifinfo SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, LAGSW_NORMAL_STEPS);
	__type(key, __u32);
	__type(value, __s32);
} normal_z SEC(".maps");

struct packet
{
	__u32 saddr; /* network byte order, as in the header */
	__u32 daddr;
	__u32 ifindex; /* egress interface */
	__u32 iif;	   /* interface the packet arrived on; 0 for locally generated packets */
	__u16 sport;   /* host byte order */
	__u16 dport;
	__u8  proto;
	__u8  tcp_flags;
	__u8  forwarded;
	__u8  has_l4; /* the transport header was readable (not a later fragment) */
};

struct tcp_prefix
{
	__be16 sport;
	__be16 dport;
	__be32 seq;
	__be32 ack;
	__u8   offset;
	__u8   flags;
} __attribute__((packed));

struct match_ctx
{
	const struct lagsw_rule* rule;
	const struct packet*	 pkt;
	__u32					 ok;
};

struct rule_ctx
{
	const struct lagsw_stage* stage;
	const struct packet*	  pkt;
	__u32					  matched;
};

struct stage_ctx
{
	const struct packet* pkt;
	__u64				 now;
	__u64				 delay; /* summed delay of the stages that matched so far */
	__u32				 drop;
};

static __always_inline bool evaluate(const struct lagsw_match* match, const struct packet* pkt)
{
	bool result;
	switch (match->kind)
	{
		case LAGSW_MATCH_PROTOCOL:
			result = pkt->proto == match->proto;
			return match->negated ? !result : result;
		case LAGSW_MATCH_TCP_FLAG:
			// Like nft, a transport match never holds for a packet without a readable transport header.
			if (!pkt->has_l4 || pkt->proto != IPPROTO_TCP)
				return false;
			result = (pkt->tcp_flags & match->flag) != 0;
			return match->negated ? !result : result;
		case LAGSW_MATCH_ADDRESS:
			{
				const __u32 address = match->endpoint ? pkt->daddr : pkt->saddr;
				if (match->is_set)
				{
					struct lagsw_addr_key key = {.set = match->value, .addr = address};
					result					  = bpf_map_lookup_elem(&addrs, &key) != NULL;
				}
				else
					result = address == match->value;
				return match->negated ? !result : result;
			}
		case LAGSW_MATCH_PORT:
			if (!pkt->has_l4 || pkt->proto != match->proto)
				return false;
			result = (match->endpoint ? pkt->dport : pkt->sport) == match->port;
			return match->negated ? !result : result;
		case LAGSW_MATCH_IIF:
			result = pkt->iif == match->value;
			return match->negated ? !result : result;
		case LAGSW_MATCH_OIF:
			result = pkt->ifindex == match->value;
			return match->negated ? !result : result;
	}
	return false;
}

static long match_callback(__u64 index, void* data)
{
	struct match_ctx* ctx = data;
	if (index >= LAGSW_MAX_MATCHES)
		return 1;
	if (!evaluate(&ctx->rule->matches[index], ctx->pkt))
	{
		ctx->ok = 0;
		return 1;
	}
	return 0;
}

static long rule_callback(__u64 index, void* data)
{
	struct rule_ctx* ctx = data;
	if (index >= LAGSW_MAX_RULES)
		return 1;
	const struct lagsw_rule* rule = &ctx->stage->rules[index];
	if ((rule->hooks & (ctx->pkt->forwarded ? LAGSW_HOOK_FORWARD : LAGSW_HOOK_LOCAL)) == 0)
		return 0;
	struct match_ctx match = {.rule = rule, .pkt = ctx->pkt, .ok = 1};
	bpf_loop(rule->count, match_callback, &match, 0);
	if (!match.ok)
		return 0;
	ctx->matched = 1;
	return 1;
}

/* Draws this packet's baseline delay in nanoseconds. */
static __always_inline __u64 sample_delay(const struct lagsw_stage* stage, bool* clamped)
{
	__s64 value = stage->delay_ns;
	if (stage->jitter_ns != 0)
	{
		if (stage->model == LAGSW_MODEL_UNIFORM)
		{
			const __u64 random = ((__u64)bpf_get_prandom_u32() << 32) | bpf_get_prandom_u32();
			value += (__s64)(random % (2 * stage->jitter_ns + 1)) - (__s64)stage->jitter_ns;
		}
		else if (stage->model == LAGSW_MODEL_NORMAL)
		{
			const __u32	 step  = bpf_get_prandom_u32() & (LAGSW_NORMAL_STEPS - 1);
			const __s32* score = bpf_map_lookup_elem(&normal_z, &step);
			if (score)
			{
				// The BPF target has no signed division, so scale the magnitude and apply the sign afterwards.
				const bool	negative  = *score < 0;
				const __u64 magnitude = negative ? (__u64)(-(__s64)*score) : (__u64)*score;
				const __u64 offset	  = (stage->jitter_ns * magnitude) / LAGSW_NORMAL_SCALE;
				value += negative ? -(__s64)offset : (__s64)offset;
			}
		}
	}
	*clamped = false;
	if (value < 0)
	{
		value	 = 0;
		*clamped = true;
	}
	else if ((__u64)value > stage->max_delay_ns)
	{
		value	 = stage->max_delay_ns;
		*clamped = true;
	}
	return value;
}

/* Never leave before an earlier packet of the same stage: raise `release` to the last release time and record it. */
static __always_inline __u64 keep_order(struct lagsw_state* st, __u64 release)
{
	for (int attempt = 0; attempt < 8; ++attempt)
	{
		const __u64 last = st->last_release;
		if (release <= last)
			return last;
		if (__sync_val_compare_and_swap(&st->last_release, last, release) == last)
			return release;
	}
	return release;
}

/* The first packet of a batch fixes its deadline; packets arriving before it share it. */
static __always_inline __u64 batch_release(struct lagsw_state* st, __u64 arrival, __u64 delay)
{
	for (int attempt = 0; attempt < 8; ++attempt)
	{
		const __u64 deadline = st->batch_deadline;
		if (deadline > arrival)
			return deadline;
		if (__sync_val_compare_and_swap(&st->batch_deadline, deadline, arrival + delay) == deadline)
			return arrival + delay;
	}
	return arrival + delay;
}

static long stage_callback(__u64 index, void* data)
{
	struct stage_ctx* ctx = data;
	const __u32		  key = index;
	if (index >= LAGSW_MAX_STAGES)
		return 1;
	const struct lagsw_stage* stage = bpf_map_lookup_elem(&stages, &key);
	if (!stage || !stage->active)
		return 0;
	struct rule_ctx rules = {.stage = stage, .pkt = ctx->pkt, .matched = 0};
	bpf_loop(stage->rule_count, rule_callback, &rules, 0);
	if (!rules.matched)
		return 0;

	struct lagsw_stats* counters = bpf_map_lookup_elem(&stats, &key);
	struct lagsw_state* st		 = bpf_map_lookup_elem(&state, &key);
	if (counters)
		counters->matched++;
	if (stage->mode == LAGSW_MODE_DROP)
	{
		if (counters)
			counters->dropped++;
		ctx->drop = 1;
		return 1;
	}
	if (!st)
		return 0;

	const __u64 arrival = ctx->now + ctx->delay;
	__u64		release;
	if (stage->mode == LAGSW_MODE_BATCH)
		release = batch_release(st, arrival, stage->delay_ns);
	else
	{
		bool		clamped;
		const __u64 sampled = sample_delay(stage, &clamped);
		if (counters && clamped)
			counters->clamped++;
		release = arrival + sampled;
		if (stage->preserve_order)
			release = keep_order(st, release);
	}
	if (release > arrival && counters)
		counters->delayed++;
	if (release > arrival)
		ctx->delay = release - ctx->now;
	return 0;
}

SEC("tcx/egress")
int lagsw_egress(struct __sk_buff* skb)
{
	const __u32				   ifindex = skb->ifindex;
	const struct lagsw_ifinfo* iface   = bpf_map_lookup_elem(&ifinfo, &ifindex);
	if (!iface || skb->protocol != bpf_htons(ETH_P_IP))
		return TCX_NEXT;

	struct
	{
		__u8   version_ihl;
		__u8   tos;
		__be16 total_length;
		__be16 id;
		__be16 frag_off;
		__u8   ttl;
		__u8   protocol;
		__be16 checksum;
		__be32 saddr;
		__be32 daddr;
	} __attribute__((packed)) ip;
	if (bpf_skb_load_bytes(skb, iface->l2_len, &ip, sizeof(ip)) < 0 || (ip.version_ihl >> 4) != 4 || (ip.version_ihl & 0x0F) < 5)
		return TCX_NEXT;

	struct packet pkt = {};
	pkt.saddr		  = ip.saddr;
	pkt.daddr		  = ip.daddr;
	pkt.ifindex		  = ifindex;
	pkt.iif			  = skb->ingress_ifindex;
	pkt.forwarded	  = skb->ingress_ifindex != 0;
	pkt.proto		  = ip.protocol;
	if ((ip.frag_off & bpf_htons(0x1FFF)) == 0)
	{
		const __u32 l4 = iface->l2_len + (ip.version_ihl & 0x0F) * 4;
		if (ip.protocol == IPPROTO_TCP)
		{
			struct tcp_prefix tcp;
			if (bpf_skb_load_bytes(skb, l4, &tcp, sizeof(tcp)) == 0)
			{
				pkt.sport	  = bpf_ntohs(tcp.sport);
				pkt.dport	  = bpf_ntohs(tcp.dport);
				pkt.tcp_flags = tcp.flags;
				pkt.has_l4	  = 1;
			}
		}
		else if (ip.protocol == IPPROTO_UDP)
		{
			__be16 ports[2];
			if (bpf_skb_load_bytes(skb, l4, ports, sizeof(ports)) == 0)
			{
				pkt.sport  = bpf_ntohs(ports[0]);
				pkt.dport  = bpf_ntohs(ports[1]);
				pkt.has_l4 = 1;
			}
		}
	}

	// A packet that already has a future departure time (TCP pacing) is delayed on top of it.
	__u64 now = bpf_ktime_get_ns();
	if (skb->tstamp_type == BPF_SKB_TSTAMP_DELIVERY_MONO && skb->tstamp > now)
		now = skb->tstamp;
	struct stage_ctx ctx = {.pkt = &pkt, .now = now, .delay = 0, .drop = 0};
	bpf_loop(LAGSW_MAX_STAGES, stage_callback, &ctx, 0);
	if (ctx.drop)
		return TCX_DROP;
	if (ctx.delay > LAGSW_TOTAL_DELAY_CAP_NS)
		ctx.delay = LAGSW_TOTAL_DELAY_CAP_NS;
	if (ctx.delay != 0)
		bpf_skb_set_tstamp(skb, now + ctx.delay, BPF_SKB_TSTAMP_DELIVERY_MONO);
	return TCX_NEXT;
}
