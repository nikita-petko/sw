// SPDX-License-Identifier: GPL-2.0
/*
 * Filter programs of the handles: taking one from user space (copy, then verify: nothing about it is trusted), turning the older 5-tuple
 * filter into one so that there is a single way to match, replacing a handle's program atomically, and running it on a packet.
 */
#include <linux/mm.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "swdivert.h"
#include "swdivert_vm.h"

/* One allocation: this header, then the sets, the instructions and the elements of all sets */
struct swdiv_prog {
	struct rcu_head		rcu;
	u32			n_insns;
	u32			n_sets;
	struct swdiv_vm_set	*sets;
	struct swdiv_insn	*insns;
	u32			*elems;
};

static struct swdiv_prog *swdiv_prog_alloc(u32 n_insns, u32 n_sets, u32 n_elems)
{
	size_t sets_off = ALIGN(sizeof(struct swdiv_prog), 8);
	size_t insns_off = sets_off + (size_t)n_sets * sizeof(struct swdiv_vm_set);
	size_t elems_off = insns_off + (size_t)n_insns * sizeof(struct swdiv_insn);
	size_t total = elems_off + (size_t)n_elems * sizeof(u32);
	struct swdiv_prog *prog = kvzalloc(total, GFP_KERNEL_ACCOUNT);

	if (!prog)
		return ERR_PTR(-ENOMEM);
	prog->n_insns = n_insns;
	prog->n_sets = n_sets;
	prog->sets = (struct swdiv_vm_set *)((u8 *)prog + sets_off);
	prog->insns = (struct swdiv_insn *)((u8 *)prog + insns_off);
	prog->elems = (u32 *)((u8 *)prog + elems_off);
	return prog;
}

struct swdiv_prog *swdiv_prog_from_user(const struct swdiv_program_args *args)
{
	struct swdiv_set_desc *descs = NULL;
	struct swdiv_prog *prog;
	u64 total = 0;
	u32 i, used = 0;
	int ret;

	if (args->reserved || args->n_insns > SWDIV_MAX_INSNS || args->n_sets > SWDIV_MAX_SETS)
		return ERR_PTR(-EINVAL);
	if (args->n_sets) {
		descs = memdup_array_user(u64_to_user_ptr(args->sets), args->n_sets, sizeof(*descs));
		if (IS_ERR(descs))
			return ERR_CAST(descs);
	}
	for (i = 0; i < args->n_sets; i++) {
		if ((descs[i].kind != SWDIV_SET_IPV4 && descs[i].kind != SWDIV_SET_PORTS) || descs[i].n > SWDIV_MAX_SET_ELEMS) {
			ret = -EINVAL;
			goto out_descs;
		}
		total += (u64)descs[i].n * (descs[i].kind == SWDIV_SET_PORTS ? 2 : 1);
		if (total > SWDIV_MAX_TOTAL_ELEMS) {
			ret = -EINVAL;
			goto out_descs;
		}
	}

	prog = swdiv_prog_alloc(args->n_insns, args->n_sets, (u32)total);
	if (IS_ERR(prog)) {
		ret = PTR_ERR(prog);
		goto out_descs;
	}
	/* Copy first, verify the copy: user space cannot change the program between the check and the use */
	if (args->n_insns && copy_from_user(prog->insns, u64_to_user_ptr(args->insns), (size_t)args->n_insns * sizeof(*prog->insns))) {
		ret = -EFAULT;
		goto out_prog;
	}
	for (i = 0; i < args->n_sets; i++) {
		const u32 per = descs[i].kind == SWDIV_SET_PORTS ? 2 : 1;
		u32 *dst = prog->elems + used;

		if (descs[i].n && copy_from_user(dst, u64_to_user_ptr(descs[i].elems), (size_t)descs[i].n * per * sizeof(u32))) {
			ret = -EFAULT;
			goto out_prog;
		}
		if (swdiv_vm_verify_set(descs[i].kind, descs[i].n, dst)) {
			ret = -EINVAL;
			goto out_prog;
		}
		prog->sets[i].kind = descs[i].kind;
		prog->sets[i].n = descs[i].n;
		prog->sets[i].elems = dst;
		used += descs[i].n * per;
	}
	if (swdiv_vm_verify(prog->insns, prog->n_insns, prog->sets, prog->n_sets)) {
		ret = -EINVAL;
		goto out_prog;
	}
	kfree(descs);
	return prog;

out_prog:
	kvfree(prog);
out_descs:
	kfree(descs);
	return ERR_PTR(ret);
}

/*
 * The 5-tuple of SWDIVERT_IOC_SET_FILTER as a program: one clause per protocol that can carry the ports asked for, every zero field a
 * wildcard. A port filter with a protocol other than TCP or UDP matches nothing.
 */
struct swdiv_prog *swdiv_prog_from_tuple(const struct swdiv_tuple *t)
{
	struct swdiv_insn insns[2 * 6];
	struct swdiv_prog *prog;
	u8 protos[2];
	unsigned int n = 0, clauses = 0, c;
	const bool ports = t->sport || t->dport;

	if (t->proto) {
		if (!ports || t->proto == IPPROTO_TCP || t->proto == IPPROTO_UDP)
			protos[clauses++] = t->proto;
	} else if (ports) {
		protos[clauses++] = IPPROTO_TCP;
		protos[clauses++] = IPPROTO_UDP;
	} else {
		protos[clauses++] = 0;
	}

	memset(insns, 0, sizeof(insns));
	for (c = 0; c < clauses; c++) {
		const unsigned int first = n;
		const u8 proto = protos[c];
		unsigned int i;

		if (proto)
			insns[n++] = (struct swdiv_insn){ .op = SWDIV_OP_EQ, .src = SWDIV_SRC_IP_PROTO, .a = proto };
		if (t->saddr)
			insns[n++] = (struct swdiv_insn){ .op = SWDIV_OP_EQ, .src = SWDIV_SRC_IP_SRC, .a = ntohl(t->saddr) };
		if (t->daddr)
			insns[n++] = (struct swdiv_insn){ .op = SWDIV_OP_EQ, .src = SWDIV_SRC_IP_DST, .a = ntohl(t->daddr) };
		if (t->sport)
			insns[n++] = (struct swdiv_insn){ .op = SWDIV_OP_EQ, .src = proto == IPPROTO_TCP ? SWDIV_SRC_TCP_SPORT : SWDIV_SRC_UDP_SPORT,
							  .a = ntohs(t->sport) };
		if (t->dport)
			insns[n++] = (struct swdiv_insn){ .op = SWDIV_OP_EQ, .src = proto == IPPROTO_TCP ? SWDIV_SRC_TCP_DPORT : SWDIV_SRC_UDP_DPORT,
							  .a = ntohs(t->dport) };
		insns[n++] = (struct swdiv_insn){ .op = SWDIV_OP_ACCEPT };
		/* A failing test of this clause continues with the next one */
		for (i = first; i + 1 < n; i++)
			insns[i].fail = n;
	}

	prog = swdiv_prog_alloc(n, 0, 0);
	if (IS_ERR(prog))
		return prog;
	memcpy(prog->insns, insns, n * sizeof(*insns));
	if (swdiv_vm_verify(prog->insns, prog->n_insns, prog->sets, 0)) {
		kvfree(prog);
		return ERR_PTR(-EINVAL);
	}
	return prog;
}

void swdiv_prog_install(struct swdiv_handle *h, struct swdiv_prog *prog)
{
	struct swdiv_prog *old = rcu_dereference_protected(h->prog, 1);

	/* Packets in flight finish with the program they started with: the old one is freed after a grace period */
	rcu_assign_pointer(h->prog, prog);
	if (old)
		kvfree_rcu(old, rcu);
}

void swdiv_prog_free(struct swdiv_handle *h)
{
	/* Only after the hook is unregistered, which waits for every callback that might still read it */
	struct swdiv_prog *prog = rcu_dereference_protected(h->prog, 1);

	RCU_INIT_POINTER(h->prog, NULL);
	kvfree(prog);
}

/* Does the packet match the handle's program? Called from the hook (softirq, inside an RCU read-side section); copies at most the prefix. */
bool swdiv_prog_match(const struct swdiv_handle *h, const struct sk_buff *skb, const struct nf_hook_state *state)
{
	const struct swdiv_prog *prog = rcu_dereference(h->prog);
	u8 buf[SWDIV_VM_PREFIX];
	struct swdiv_vm_ctx ctx = {};
	const int off = skb_network_offset(skb);
	u32 avail, n;

	if (!prog)
		return false;
	if (skb->len <= off)
		avail = 0;
	else
		avail = skb->len - off;
	n = min_t(u32, avail, SWDIV_VM_PREFIX);
	ctx.pkt = n ? skb_header_pointer(skb, off, n, buf) : buf;
	if (!ctx.pkt)
		n = 0, ctx.pkt = buf;
	ctx.len = n;
	ctx.total_len = avail;
	ctx.in_ifindex = state->in ? state->in->ifindex : 0;
	ctx.out_ifindex = state->out ? state->out->ifindex : 0;
	ctx.mark = skb->mark & ~swdiv_release_marks;
	/* Forwarded and locally generated packets count as outbound, as the NFQUEUE backend's compiler treats them */
	ctx.hook = state->hook;
	ctx.outbound = state->hook != NF_INET_LOCAL_IN;
	ctx.loopback = (state->in && (state->in->flags & IFF_LOOPBACK)) || (state->out && (state->out->flags & IFF_LOOPBACK));
	return swdiv_vm_run(prog->insns, prog->n_insns, prog->sets, prog->n_sets, &ctx);
}
