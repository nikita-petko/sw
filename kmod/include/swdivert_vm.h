/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The filter VM of the swdivert module (see swdivert_abi.h for the program format): a verifier and an interpreter.
 *
 * Header-only and free of kernel and libc dependencies on purpose: the kernel module includes it, and so do the user-space unit
 * tests and the fuzz harness, which run exactly this code under AddressSanitizer on random programs and packets. Nothing here
 * allocates, sleeps or reads outside the packet bytes it is given.
 *
 * Integers are read from the packet byte by byte (big endian on the wire), so the code does not depend on the host byte order.
 */
#ifndef SWDIVERT_VM_H_
#define SWDIVERT_VM_H_

#include <linux/types.h>

#include "swdivert_abi.h"

/* A set as the interpreter sees it: elements are borrowed (the kernel keeps them in one allocation with the program). */
struct swdiv_vm_set {
	__u32		kind;	/* SWDIV_SET_* */
	__u32		n;
	const __u32	*elems;
};

/* The packet and what the stack knows about it. `pkt` holds the first `len` (<= SWDIV_VM_PREFIX) bytes of the IP packet. */
struct swdiv_vm_ctx {
	const __u8	*pkt;
	__u32		len;		/* bytes available at pkt */
	__u32		total_len;	/* length of the whole packet (SWDIV_SRC_PKT_LEN) */
	__u32		in_ifindex;
	__u32		out_ifindex;
	__u32		mark;
	__u8		outbound;
	__u8		loopback;
	__u8		hook;		/* netfilter hook number: 1 LOCAL_IN, 2 FORWARD, 3 LOCAL_OUT (SWDIV_SRC_HOOK) */
};

/*
 * Test hook for the fuzz harness: called once per executed instruction. The kernel build leaves it empty. The harness counts the
 * calls to check that no verified program ever runs more than SWDIV_MAX_INSNS steps.
 */
#ifndef SWDIV_VM_STEP
#define SWDIV_VM_STEP() do { } while (0)
#endif

#define SWDIV_VM_EINVAL (-22)

static inline __u32 swdiv_vm_get16(const __u8 *p)
{
	return ((__u32)p[0] << 8) | p[1];
}

static inline __u32 swdiv_vm_get32(const __u8 *p)
{
	return ((__u32)p[0] << 24) | ((__u32)p[1] << 16) | ((__u32)p[2] << 8) | p[3];
}

static inline int swdiv_vm_src_valid(__u32 src)
{
	switch (src) {
	case SWDIV_SRC_IP_PROTO: case SWDIV_SRC_IP_SRC: case SWDIV_SRC_IP_DST: case SWDIV_SRC_IP_TTL:
	case SWDIV_SRC_IP_TOTLEN: case SWDIV_SRC_IP_FRAG: case SWDIV_SRC_RAW_BYTE:
	case SWDIV_SRC_TCP_SPORT: case SWDIV_SRC_TCP_DPORT: case SWDIV_SRC_UDP_SPORT: case SWDIV_SRC_UDP_DPORT:
	case SWDIV_SRC_TCP_FLAGS: case SWDIV_SRC_TCP_PAYLOAD_BYTE: case SWDIV_SRC_UDP_PAYLOAD_BYTE:
	case SWDIV_SRC_TCP_PAYLOAD_LEN: case SWDIV_SRC_UDP_PAYLOAD_LEN:
	case SWDIV_SRC_IN_IFINDEX: case SWDIV_SRC_OUT_IFINDEX: case SWDIV_SRC_MARK: case SWDIV_SRC_OUTBOUND:
	case SWDIV_SRC_LOOPBACK: case SWDIV_SRC_PKT_LEN: case SWDIV_SRC_HOOK:
		return 1;
	}
	return 0;
}

static inline int swdiv_vm_src_has_offset(__u32 src)
{
	return src == SWDIV_SRC_RAW_BYTE || src == SWDIV_SRC_TCP_PAYLOAD_BYTE || src == SWDIV_SRC_UDP_PAYLOAD_BYTE;
}

static inline int swdiv_vm_src_is_port(__u32 src)
{
	return src == SWDIV_SRC_TCP_SPORT || src == SWDIV_SRC_TCP_DPORT || src == SWDIV_SRC_UDP_SPORT || src == SWDIV_SRC_UDP_DPORT;
}

/* Checks the elements of one set: sorted, without duplicates, ranges that do not overlap. 0 or SWDIV_VM_EINVAL. */
static inline int swdiv_vm_verify_set(__u32 kind, __u32 n, const __u32 *elems)
{
	__u32 i;

	if (n > SWDIV_MAX_SET_ELEMS)
		return SWDIV_VM_EINVAL;
	if (kind == SWDIV_SET_IPV4) {
		for (i = 1; i < n; i++)
			if (elems[i - 1] >= elems[i])
				return SWDIV_VM_EINVAL;
		return 0;
	}
	if (kind == SWDIV_SET_PORTS) {
		for (i = 0; i < n; i++) {
			if (elems[2 * i] > elems[2 * i + 1] || elems[2 * i + 1] > 0xFFFF)
				return SWDIV_VM_EINVAL;
			if (i && elems[2 * (i - 1) + 1] >= elems[2 * i])
				return SWDIV_VM_EINVAL;
		}
		return 0;
	}
	return SWDIV_VM_EINVAL;
}

/*
 * Verifies a program against the sets it will run with (which must already have been verified with swdiv_vm_verify_set()).
 * A verified program terminates, reads only what the interpreter bounds-checks and names only sets that exist. 0 or SWDIV_VM_EINVAL.
 */
static inline int swdiv_vm_verify(const struct swdiv_insn *insns, __u32 n, const struct swdiv_vm_set *sets, __u32 nsets)
{
	__u32 i;

	if (n > SWDIV_MAX_INSNS || nsets > SWDIV_MAX_SETS)
		return SWDIV_VM_EINVAL;
	for (i = 0; i < n; i++) {
		const struct swdiv_insn *insn = &insns[i];

		if (insn->op == SWDIV_OP_ACCEPT) {
			if (insn->fail || insn->src || insn->k || insn->a || insn->b)
				return SWDIV_VM_EINVAL;
			continue;
		}
		if (insn->op < SWDIV_OP_EQ || insn->op > SWDIV_OP_NOT_IN_SET)
			return SWDIV_VM_EINVAL;
		/* Strictly forward: this is what makes every program terminate */
		if (insn->fail <= i || insn->fail > n)
			return SWDIV_VM_EINVAL;
		if (!swdiv_vm_src_valid(insn->src))
			return SWDIV_VM_EINVAL;
		if (swdiv_vm_src_has_offset(insn->src)) {
			if (insn->k >= SWDIV_VM_PREFIX)
				return SWDIV_VM_EINVAL;
		} else if (insn->k) {
			return SWDIV_VM_EINVAL;
		}
		switch (insn->op) {
		case SWDIV_OP_MASK_EQ:
			break;
		case SWDIV_OP_RANGE:
			if (insn->a > insn->b)
				return SWDIV_VM_EINVAL;
			break;
		case SWDIV_OP_IN_SET:
		case SWDIV_OP_NOT_IN_SET:
			if (insn->b || insn->a >= nsets)
				return SWDIV_VM_EINVAL;
			if (sets[insn->a].kind == SWDIV_SET_IPV4) {
				if (insn->src != SWDIV_SRC_IP_SRC && insn->src != SWDIV_SRC_IP_DST)
					return SWDIV_VM_EINVAL;
			} else if (sets[insn->a].kind == SWDIV_SET_PORTS) {
				if (!swdiv_vm_src_is_port(insn->src))
					return SWDIV_VM_EINVAL;
			} else {
				return SWDIV_VM_EINVAL;
			}
			break;
		default: /* EQ, NE, LT, LE, GT, GE */
			if (insn->b)
				return SWDIV_VM_EINVAL;
		}
	}
	return 0;
}

/* The length of the IPv4 header, or 0 when the prefix does not start with a plausible one. */
static inline __u32 swdiv_vm_ihl(const struct swdiv_vm_ctx *c)
{
	__u32 ihl;

	if (c->len < 20 || c->len > SWDIV_VM_PREFIX || (c->pkt[0] >> 4) != 4)
		return 0;
	ihl = (__u32)(c->pkt[0] & 0x0F) * 4;
	if (ihl < 20 || ihl > c->len)
		return 0;
	return ihl;
}

/*
 * Reads the value a test looks at. Returns 0 when the field is absent: the packet is not IPv4, it has another protocol, it is a
 * later fragment, the header or the byte lies beyond what is available, or the lengths in the header contradict each other.
 */
static inline int swdiv_vm_load(const struct swdiv_vm_ctx *c, __u32 src, __u32 k, __u32 *v)
{
	__u32 ihl, total, end, l4, proto, first_fragment, doff;

	switch (src) {
	case SWDIV_SRC_IN_IFINDEX:
		*v = c->in_ifindex;
		return 1;
	case SWDIV_SRC_OUT_IFINDEX:
		*v = c->out_ifindex;
		return 1;
	case SWDIV_SRC_MARK:
		*v = c->mark;
		return 1;
	case SWDIV_SRC_OUTBOUND:
		*v = c->outbound ? 1 : 0;
		return 1;
	case SWDIV_SRC_LOOPBACK:
		*v = c->loopback ? 1 : 0;
		return 1;
	case SWDIV_SRC_PKT_LEN:
		*v = c->total_len;
		return 1;
	case SWDIV_SRC_HOOK:
		*v = c->hook;
		return 1;
	}

	ihl = swdiv_vm_ihl(c);
	if (!ihl)
		return 0;
	total = swdiv_vm_get16(c->pkt + 2);
	if (total < ihl)
		return 0;
	/* Bytes after the IP total length are padding, not packet */
	end = total < c->len ? total : c->len;
	proto = c->pkt[9];
	first_fragment = (swdiv_vm_get16(c->pkt + 6) & 0x1FFF) == 0;
	l4 = ihl;

	switch (src) {
	case SWDIV_SRC_IP_PROTO:
		*v = proto;
		return 1;
	case SWDIV_SRC_IP_SRC:
		*v = swdiv_vm_get32(c->pkt + 12);
		return 1;
	case SWDIV_SRC_IP_DST:
		*v = swdiv_vm_get32(c->pkt + 16);
		return 1;
	case SWDIV_SRC_IP_TTL:
		*v = c->pkt[8];
		return 1;
	case SWDIV_SRC_IP_TOTLEN:
		*v = total;
		return 1;
	case SWDIV_SRC_IP_FRAG:
		*v = swdiv_vm_get16(c->pkt + 6) & 0x3FFF;
		return 1;
	case SWDIV_SRC_RAW_BYTE:
		if (k >= end)
			return 0;
		*v = c->pkt[k];
		return 1;

	case SWDIV_SRC_TCP_SPORT:
	case SWDIV_SRC_TCP_DPORT:
		if (proto != 6 || !first_fragment || end < l4 + 4)
			return 0;
		*v = swdiv_vm_get16(c->pkt + l4 + (src == SWDIV_SRC_TCP_DPORT ? 2 : 0));
		return 1;
	case SWDIV_SRC_UDP_SPORT:
	case SWDIV_SRC_UDP_DPORT:
		if (proto != 17 || !first_fragment || end < l4 + 4)
			return 0;
		*v = swdiv_vm_get16(c->pkt + l4 + (src == SWDIV_SRC_UDP_DPORT ? 2 : 0));
		return 1;
	case SWDIV_SRC_TCP_FLAGS:
		if (proto != 6 || !first_fragment || end < l4 + 14)
			return 0;
		*v = c->pkt[l4 + 13];
		return 1;

	case SWDIV_SRC_TCP_PAYLOAD_BYTE:
	case SWDIV_SRC_TCP_PAYLOAD_LEN:
		if (proto != 6 || !first_fragment || end < l4 + 20)
			return 0;
		doff = (__u32)(c->pkt[l4 + 12] >> 4) * 4;
		if (doff < 20 || l4 + doff > end)
			return 0;
		if (src == SWDIV_SRC_TCP_PAYLOAD_LEN) {
			if (total < l4 + doff)
				return 0;
			*v = total - l4 - doff;
			return 1;
		}
		if (l4 + doff + k >= end)
			return 0;
		*v = c->pkt[l4 + doff + k];
		return 1;
	case SWDIV_SRC_UDP_PAYLOAD_BYTE:
	case SWDIV_SRC_UDP_PAYLOAD_LEN:
		if (proto != 17 || !first_fragment || end < l4 + 8)
			return 0;
		if (src == SWDIV_SRC_UDP_PAYLOAD_LEN) {
			*v = total - l4 - 8;
			return 1;
		}
		if (l4 + 8 + k >= end)
			return 0;
		*v = c->pkt[l4 + 8 + k];
		return 1;
	}
	return 0;
}

/* Is `v` in the set? Binary search: O(log n), no allocation. */
static inline int swdiv_vm_in_set(const struct swdiv_vm_set *set, __u32 v)
{
	__u32 lo = 0, hi = set->n;

	if (set->kind == SWDIV_SET_IPV4) {
		while (lo < hi) {
			const __u32 mid = lo + (hi - lo) / 2;

			if (set->elems[mid] < v)
				lo = mid + 1;
			else
				hi = mid;
		}
		return lo < set->n && set->elems[lo] == v;
	}
	/* Anything but the two known kinds has no defined layout: it contains nothing (the verifier refuses such sets anyway) */
	if (set->kind != SWDIV_SET_PORTS)
		return 0;
	/* Ranges: the last one that starts at or before v is the only candidate */
	while (lo < hi) {
		const __u32 mid = lo + (hi - lo) / 2;

		if (set->elems[2 * mid] <= v)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo > 0 && v <= set->elems[2 * (lo - 1) + 1];
}

/* Runs a verified program on a packet. Returns 1 for a match, 0 for no match. */
static inline int swdiv_vm_run(const struct swdiv_insn *insns, __u32 n, const struct swdiv_vm_set *sets, __u32 nsets,
			       const struct swdiv_vm_ctx *ctx)
{
	__u32 pc = 0;

	while (pc < n) {
		const struct swdiv_insn *insn = &insns[pc];
		__u32 v = 0;
		int pass;

		SWDIV_VM_STEP();
		if (insn->op == SWDIV_OP_ACCEPT)
			return 1;
		/* The verifier guarantees this; it is checked again so that a bug there cannot become a loop */
		if (insn->fail <= pc || insn->fail > n)
			return 0;
		if (!swdiv_vm_load(ctx, insn->src, insn->k, &v)) {
			pc = insn->fail;
			continue;
		}
		switch (insn->op) {
		case SWDIV_OP_EQ:
			pass = v == insn->a;
			break;
		case SWDIV_OP_NE:
			pass = v != insn->a;
			break;
		case SWDIV_OP_LT:
			pass = v < insn->a;
			break;
		case SWDIV_OP_LE:
			pass = v <= insn->a;
			break;
		case SWDIV_OP_GT:
			pass = v > insn->a;
			break;
		case SWDIV_OP_GE:
			pass = v >= insn->a;
			break;
		case SWDIV_OP_MASK_EQ:
			pass = (v & insn->a) == insn->b;
			break;
		case SWDIV_OP_RANGE:
			pass = v >= insn->a && v <= insn->b;
			break;
		case SWDIV_OP_IN_SET:
		case SWDIV_OP_NOT_IN_SET:
			if (insn->a >= nsets)
				return 0;
			pass = swdiv_vm_in_set(&sets[insn->a], v);
			if (insn->op == SWDIV_OP_NOT_IN_SET)
				pass = !pass;
			break;
		default:
			return 0;
		}
		pc = pass ? pc + 1 : insn->fail;
	}
	return 0;
}

#endif
