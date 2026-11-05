/*
 * ABI of /dev/swdivert, shared by the kernel module and user space (only <linux/...> uapi headers are used).
 *
 * What it covers: the LOCAL_IN, LOCAL_OUT and FORWARD hooks (per handle), a filter program per handle (SET_PROGRAM, or the 5-tuple of
 * SET_FILTER, which is turned into a program). A handle either sniffs (copies matching packets into the ring and lets them go) or holds
 * (copies them into the ring and steals the original until user space gives a verdict: resume, resume with new bytes, or drop). Handles
 * have a priority and form a chain; a handle can also inject packets of its own.
 *
 * STABLE: this is ABI version 1, and what is in this file does not change within a version. The rules:
 *  - Struct layouts, field meanings, ioctl numbers, constants and limits stay as they are. The sizes and the ioctl numbers are asserted
 *    at the end of this file, in the module and in user space alike, so a change cannot be made by accident.
 *  - What may be added without a new version is what a program that does not ask for it can never meet: a new ioctl, a new flag or enum
 *    value, a new filter operation or source. The kernel refuses what it does not know (EINVAL for a flag, an operation or a source, ENOTTY
 *    for an ioctl), which is how user space finds out whether a feature exists.
 *  - Every field marked reserved, and every field a request does not use, has to be zero and is refused otherwise. That is what keeps
 *    them free to get a meaning later.
 *  - A struct that is the argument of an ioctl cannot grow (its size is part of the number): growth takes a new ioctl, the old one stays.
 *    swdiv_stats has reserved room for counters.
 *  - Anything else is a new SWDIVERT_ABI_VERSION. User space refuses a module whose version is not the one it was built for.
 */
#ifndef SWDIVERT_ABI_H_
#define SWDIVERT_ABI_H_

#include <linux/ioctl.h>
#include <linux/types.h>

#define SWDIVERT_DEVICE_NAME "swdivert"
#define SWDIVERT_ABI_VERSION 1

/* A packet filter: every field is a wildcard when zero. Addresses and ports are in network byte order. */
struct swdiv_tuple {
	__u8	proto;		/* IPPROTO_TCP / IPPROTO_UDP, 0 = any */
	__u8	reserved[3];	/* must be 0 */
	__be32	saddr;
	__be32	daddr;
	__be16	sport;
	__be16	dport;
};

/* swdiv_open_args.flags */
#define SWDIV_OPEN_HOLD		0x1	/* steal matching packets until a verdict (default: copy and let them go) */
/* The hooks the handle is attached to when it is started (default: FORWARD only). Programs tell the hooks apart by SWDIV_SRC_HOOK. */
#define SWDIV_OPEN_LOCAL_IN	0x2	/* packets for this host: NF_INET_LOCAL_IN */
#define SWDIV_OPEN_LOCAL_OUT	0x4	/* packets from this host: NF_INET_LOCAL_OUT */
#define SWDIV_OPEN_FORWARD	0x8	/* packets routed through this host: NF_INET_FORWARD */

/* SWDIVERT_IOC_OPEN: sizes the ring. `slots` is a power of two, `slot_bytes` a multiple of 16. */
struct swdiv_open_args {
	__u32	slots;		/* in:  64 .. 1048576 */
	__u32	slot_bytes;	/* in:  128 .. 65536, includes the 48-byte slot header */
	__u32	flags;		/* in:  SWDIV_OPEN_* */
	__s32	priority;	/* in:  -30000 .. 30000, higher is served first (as in WinDivert); handles of a namespace form a chain in
				 *      this order; handles of equal priority are served in the order they were started */
	__u64	data_bytes;	/* out: length of the read-only data mapping (offset 0) */
	__u64	cons_offset;	/* out: mmap offset of the consumer page (writable, one page) */
	__u32	hdr_bytes;	/* out: size of the header area in front of the slots (a page) */
	__u32	hold_ms;	/* in:  HOLD handles: resume a held packet nobody gave a verdict for after this long (the fail-open horizon);
				 *      0 = the module parameter hold_ms, at most SWDIV_MAX_HOLD_MS */
	__u32	max_held;	/* in:  HOLD handles: most packets held at once, further ones pass unheld; 0 = the module parameter max_held,
				 *      at most SWDIV_MAX_HELD */
	__u32	reserved3;	/* in:  must be 0 */
};
#define SWDIV_MAX_HOLD_MS	600000
#define SWDIV_MAX_HELD		65536

struct swdiv_stats {
	__u64	seen;		/* packets that reached the hook */
	__u64	matched;	/* ... and matched the filter */
	__u64	copied;		/* ... and were published to the ring */
	__u64	dropped_full;	/* matched but the ring had no free slot (the packet was let through) */
	__u64	truncated;	/* copied with caplen < len */
	__u64	wakeups;	/* wake_up() calls made for the reader (batched: far fewer than `copied`) */
	/* HOLD handles */
	__u64	held;		/* packets stolen */
	__u64	resumed;	/* held packets resumed by a RESUME verdict */
	__u64	verdict_dropped;/* held packets dropped by a DROP verdict */
	__u64	expired;	/* held packets resumed because nobody answered within hold_ms */
	__u64	flushed;	/* held packets resumed when the handle was stopped or closed */
	__u64	dev_dropped;	/* held packets dropped because their network device went away */
	__u64	resume_lost;	/* held packets dropped because the hook chain could not be resumed */
	__u64	pass_unsupported;/* matched but not held (owned by a socket, no route, segmentation failed): let through */
	__u64	pass_limit;	/* matched but not held because max_held was reached or memory was short: let through */
	__u64	held_now;	/* gauge: packets held right now */
	/* modify and inject */
	__u64	modified;	/* held packets resumed with new bytes */
	__u64	mod_dropped;	/* held packets dropped because a modification could not be applied (no memory, no route) */
	__u64	ct_detached;	/* modified packets whose 5-tuple changed: their connection tracking entry was detached */
	__u64	injected;	/* packets injected by this handle */
	__u64	inject_failed;
	__u64	reserved[8];	/* room for counters to come; always 0 (a struct that has to grow would need a new ioctl number) */
};

/* SWDIVERT_IOC_VERDICT: gives verdicts for held packets in one call */
#define SWDIV_V_RESUME		1	/* continue through the remaining hooks as if the packet had never been held */
#define SWDIV_V_DROP		2
#define SWDIV_V_RESUME_MOD	3	/* continue with the packet replaced by data[len] (a whole IPv4 packet) */

/* swdiv_verdict.flags and swdiv_inject_args.flags */
#define SWDIV_CALC_IP		0x1	/* recompute the IPv4 header checksum */
#define SWDIV_CALC_L4		0x2	/* recompute the TCP/UDP checksum (not for fragments) and drop any offload state */

struct swdiv_verdict {
	__u64	id;		/* swdiv_slot_hdr.id */
	__u32	verdict;	/* SWDIV_V_* */
	__u32	status;		/* out: 0, or an errno. ENOENT: no such held packet (already resumed, dropped or expired).
				 *      EINVAL: nothing was done and the packet stays held (an unknown verdict, a field a verdict does not use
				 *      that is not 0, or for RESUME_MOD bad bytes: not IPv4, lengths that do not fit) */
	__u64	data;		/* RESUME_MOD: user pointer to the packet; must be 0 for RESUME and DROP */
	__u32	len;		/* RESUME_MOD: bytes at `data`, at most SWDIV_MAX_PACKET; bytes beyond the IP total length are ignored; 0 for RESUME and DROP */
	__u32	flags;		/* RESUME_MOD: SWDIV_CALC_*; 0 for RESUME and DROP */
};
#define SWDIV_MAX_PACKET	65535

struct swdiv_verdict_args {
	__u64	items;		/* user pointer to struct swdiv_verdict[count] */
	__u32	count;		/* 1 .. SWDIV_MAX_VERDICTS */
	__u32	reserved;
};
#define SWDIV_MAX_VERDICTS	4096

/*
 * SWDIVERT_IOC_INJECT: delivers a packet that never went through the stack as if it had been received on `ifindex`: it goes
 * through PREROUTING, routing and, when it is forwarded, the FORWARD hooks. The injecting handle's own hook and every handle of
 * a higher or equal priority skip it; handles of a lower priority see it (WinDivert's "injected packets are diverted to the next priority
 * handle"). The handle must be started. The skip is by CPU and covers the synchronous part of the call, so it does not hold when
 * receive packet steering moves the packet to another CPU.
 */
struct swdiv_inject_args {
	__u64	data;		/* user pointer to the IPv4 packet */
	__u32	len;
	__u32	flags;		/* SWDIV_CALC_* */
	__u32	ifindex;	/* the interface it is received on, in the caller's network namespace */
	__u32	reserved;
};

/*
 * Filter programs. A program is a disjunction of clauses, each a conjunction of tests, as the user-space compiler produces from a
 * WinDivert-style filter string. Layout: an array of instructions executed from index 0; a test that holds goes on to the next
 * instruction, one that does not (or whose field is absent) jumps FORWARD to `fail`, which is the first instruction of the next
 * clause; ACCEPT ends the program with a match; running off the end means no match. Jumps only go forward, so every program
 * terminates within SWDIV_MAX_INSNS steps, and the kernel verifies that (and the rest below) before it accepts a program.
 *
 * Values are host-order integers: addresses as 0x0A0A0102 for 10.10.1.2, ports as 80. A field of a protocol the packet does not
 * have (a TCP port of a UDP packet, any L4 field of a later fragment or of a header cut short) is absent and every test of it fails,
 * whether it is ==, != or a range. Everything is read from the first SWDIV_VM_PREFIX bytes of the IP packet.
 */
#define SWDIV_MAX_INSNS		4096
#define SWDIV_MAX_SETS		64
#define SWDIV_MAX_SET_ELEMS	65536		/* per set (a port set counts its ranges) */
#define SWDIV_MAX_TOTAL_ELEMS	(1U << 20)	/* over all sets of a program */
#define SWDIV_VM_PREFIX		256

struct swdiv_insn {
	__u16	op;		/* SWDIV_OP_* */
	__u16	fail;		/* where to continue when the test fails: index > this one, <= n_insns (n_insns = no match) */
	__u16	src;		/* SWDIV_SRC_*: the value a test looks at */
	__u16	k;		/* RAW_BYTE and *_PAYLOAD_BYTE: the offset, < SWDIV_VM_PREFIX; zero otherwise */
	__u32	a;		/* the value to compare with, the mask, the lower bound or the set number */
	__u32	b;		/* MASK_EQ: the value the masked field must have; RANGE: the upper bound; zero otherwise */
};

#define SWDIV_OP_ACCEPT		1	/* the packet matches (all other fields zero) */
#define SWDIV_OP_EQ		2	/* src == a */
#define SWDIV_OP_NE		3
#define SWDIV_OP_LT		4
#define SWDIV_OP_LE		5
#define SWDIV_OP_GT		6
#define SWDIV_OP_GE		7
#define SWDIV_OP_MASK_EQ	8	/* (src & a) == b */
#define SWDIV_OP_RANGE		9	/* a <= src <= b */
#define SWDIV_OP_IN_SET		10	/* src is in set number a */
#define SWDIV_OP_NOT_IN_SET	11	/* src is present and not in set number a */

#define SWDIV_SRC_IP_PROTO	1
#define SWDIV_SRC_IP_SRC	2
#define SWDIV_SRC_IP_DST	3
#define SWDIV_SRC_IP_TTL	4
#define SWDIV_SRC_IP_TOTLEN	5
#define SWDIV_SRC_IP_FRAG	6	/* the flags and fragment offset word, masked with 0x3fff (more-fragments and offset) */
#define SWDIV_SRC_RAW_BYTE	7	/* byte k of the IP packet */
#define SWDIV_SRC_TCP_SPORT	10
#define SWDIV_SRC_TCP_DPORT	11
#define SWDIV_SRC_UDP_SPORT	12
#define SWDIV_SRC_UDP_DPORT	13
#define SWDIV_SRC_TCP_FLAGS	14
#define SWDIV_SRC_TCP_PAYLOAD_BYTE	15	/* byte k of the TCP payload (absent when it lies beyond the prefix or the packet) */
#define SWDIV_SRC_UDP_PAYLOAD_BYTE	16
#define SWDIV_SRC_TCP_PAYLOAD_LEN	17
#define SWDIV_SRC_UDP_PAYLOAD_LEN	18
#define SWDIV_SRC_IN_IFINDEX	30
#define SWDIV_SRC_OUT_IFINDEX	31
#define SWDIV_SRC_MARK		32
#define SWDIV_SRC_OUTBOUND	33	/* 1 on the FORWARD and LOCAL_OUT hooks, where a packet counts as outbound */
#define SWDIV_SRC_LOOPBACK	34
#define SWDIV_SRC_PKT_LEN	35	/* the whole packet's length, not only the prefix */
#define SWDIV_SRC_HOOK		36	/* the netfilter hook the packet is at: 1 LOCAL_IN, 2 FORWARD, 3 LOCAL_OUT */

#define SWDIV_SET_IPV4		1	/* n addresses, sorted ascending without duplicates */
#define SWDIV_SET_PORTS		2	/* n ranges as (lo, hi) pairs of u32, ascending, not overlapping, hi <= 65535 */

struct swdiv_set_desc {
	__u32	kind;		/* SWDIV_SET_* */
	__u32	n;
	__u64	elems;		/* user pointer to n u32 (IPv4) or 2n u32 (ports) */
};

/* SWDIVERT_IOC_SET_PROGRAM: replaces the handle's program atomically, also while it is started (packets in flight see the old or
 * the new program, never a mixture). The program is copied, then verified; nothing about it is trusted. */
struct swdiv_program_args {
	__u64	insns;		/* user pointer to struct swdiv_insn[n_insns]; n_insns = 0 is a program that matches nothing */
	__u32	n_insns;
	__u32	n_sets;
	__u64	sets;		/* user pointer to struct swdiv_set_desc[n_sets] */
	__u64	reserved;
};

#define SWDIVERT_IOC_VERSION	_IOR('s', 0x10, __u32)
#define SWDIVERT_IOC_OPEN	_IOWR('s', 0x11, struct swdiv_open_args)
#define SWDIVERT_IOC_SET_FILTER	_IOW('s', 0x12, struct swdiv_tuple)
#define SWDIVERT_IOC_START	_IO('s', 0x13)
#define SWDIVERT_IOC_STOP	_IO('s', 0x14)
#define SWDIVERT_IOC_STATS	_IOR('s', 0x15, struct swdiv_stats)
#define SWDIVERT_IOC_VERDICT	_IOWR('s', 0x16, struct swdiv_verdict_args)
#define SWDIVERT_IOC_INJECT	_IOW('s', 0x17, struct swdiv_inject_args)
#define SWDIVERT_IOC_SET_PROGRAM _IOW('s', 0x18, struct swdiv_program_args)

/*
 * Memory layout of the ring (mmap offset 0, read-only for user space):
 *   [ hdr_bytes: struct swdiv_ring_hdr ][ slots * slot_bytes ]
 * The consumer index lives on its own writable page (mmap offset `cons_offset`), so the kernel never has to trust a word
 * in memory that user space can write for anything but "how far has the reader got" (and clamps it).
 */
#define SWDIVERT_SLOT_HDR_BYTES 48

struct swdiv_ring_hdr {
	__u32	abi;
	__u32	slots;
	__u32	slot_bytes;
	__u32	reserved;
	__u8	pad0[48];
	__u32	prod __attribute__((aligned(64)));	/* free-running count of published slots */
	__u8	pad1[60];
};

#define SWDIV_SLOT_F_TRUNCATED	0x0001	/* caplen < len */
#define SWDIV_SLOT_F_HELD	0x0002	/* the packet is held: `id` takes a verdict */

struct swdiv_slot_hdr {
	__u64	timestamp_ns;	/* CLOCK_REALTIME at capture */
	__u64	id;		/* handle-unique, ascending; the key for SWDIVERT_IOC_VERDICT (0 when not held) */
	__u32	len;		/* IP packet length */
	__u32	caplen;		/* bytes that follow this header */
	__u32	ifindex_in;
	__u32	ifindex_out;
	__u16	flags;
	__u8	hook;		/* netfilter hook number */
	__u8	reserved0;
	__u32	reserved1;
	__u64	reserved2;
	/* caplen bytes of packet data follow, starting at the IP header */
};

struct swdiv_cons {
	__u32	cons;		/* free-running count of consumed slots; written by user space only */
};

/*
 * The layout, written down. These fail to compile when a struct or an ioctl number changes (the module and every user of this header
 * check the same values); changing one means changing the ABI, see the rules at the top.
 */
#ifdef __cplusplus
#define SWDIV_ABI_ASSERT(cond, what) static_assert(cond, what)
#else
#define SWDIV_ABI_ASSERT(cond, what) _Static_assert(cond, what)
#endif
SWDIV_ABI_ASSERT(sizeof(struct swdiv_tuple) == 16, "swdiv_tuple");
SWDIV_ABI_ASSERT(sizeof(struct swdiv_open_args) == 48, "swdiv_open_args");
SWDIV_ABI_ASSERT(sizeof(struct swdiv_stats) == 232, "swdiv_stats");
SWDIV_ABI_ASSERT(sizeof(struct swdiv_verdict) == 32, "swdiv_verdict");
SWDIV_ABI_ASSERT(sizeof(struct swdiv_verdict_args) == 16, "swdiv_verdict_args");
SWDIV_ABI_ASSERT(sizeof(struct swdiv_inject_args) == 24, "swdiv_inject_args");
SWDIV_ABI_ASSERT(sizeof(struct swdiv_insn) == 16, "swdiv_insn");
SWDIV_ABI_ASSERT(sizeof(struct swdiv_set_desc) == 16, "swdiv_set_desc");
SWDIV_ABI_ASSERT(sizeof(struct swdiv_program_args) == 32, "swdiv_program_args");
SWDIV_ABI_ASSERT(sizeof(struct swdiv_ring_hdr) == 128 && __builtin_offsetof(struct swdiv_ring_hdr, prod) == 64, "swdiv_ring_hdr");
SWDIV_ABI_ASSERT(sizeof(struct swdiv_slot_hdr) == 48, "swdiv_slot_hdr");
SWDIV_ABI_ASSERT(sizeof(struct swdiv_cons) == 4, "swdiv_cons");
SWDIV_ABI_ASSERT(SWDIVERT_IOC_VERSION == 0x80047310u && SWDIVERT_IOC_OPEN == 0xc0307311u && SWDIVERT_IOC_SET_FILTER == 0x40107312u &&
		 SWDIVERT_IOC_START == 0x7313u && SWDIVERT_IOC_STOP == 0x7314u && SWDIVERT_IOC_STATS == 0x80e87315u &&
		 SWDIVERT_IOC_VERDICT == 0xc0107316u && SWDIVERT_IOC_INJECT == 0x40187317u && SWDIVERT_IOC_SET_PROGRAM == 0x40207318u,
		 "ioctl numbers");

#endif
