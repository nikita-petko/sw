/*
 * ABI of /dev/swdivert, shared by the kernel module and user space (only <linux/...> uapi headers are used).
 *
 * SPIKE STATUS (Phases 2-5 of pocs/linux_kernel_module_backend.md): FORWARD hook, a filter program per handle (SET_PROGRAM, or the
 * 5-tuple of SET_FILTER, which is turned into a program). A handle either
 * sniffs (copies matching packets into the ring and lets them go) or holds (copies them into the ring and steals the original
 * until user space gives a verdict: resume, resume with new bytes, or drop). Handles have a priority and form a chain; a handle
 * can also inject packets of its own. SWDIVERT_ABI_VERSION stays 0 until the ABI is declared stable; user space refuses any
 * other value.
 */
#ifndef SWDIVERT_ABI_H_
#define SWDIVERT_ABI_H_

#include <linux/ioctl.h>
#include <linux/types.h>

#define SWDIVERT_DEVICE_NAME "swdivert"
#define SWDIVERT_ABI_VERSION 0

/* A packet filter: every field is a wildcard when zero. Addresses and ports are in network byte order. */
struct swdiv_tuple {
	__u8	proto;		/* IPPROTO_TCP / IPPROTO_UDP, 0 = any */
	__u8	reserved[3];
	__be32	saddr;
	__be32	daddr;
	__be16	sport;
	__be16	dport;
};

/* swdiv_open_args.flags */
#define SWDIV_OPEN_HOLD		0x1	/* steal matching packets until a verdict (default: copy and let them go) */

/* SWDIVERT_IOC_OPEN: sizes the ring. `slots` is a power of two, `slot_bytes` a multiple of 16. */
struct swdiv_open_args {
	__u32	slots;		/* in:  64 .. 1048576 */
	__u32	slot_bytes;	/* in:  128 .. 65536, includes the 48-byte slot header */
	__u32	flags;		/* in:  SWDIV_OPEN_* */
	__s32	priority;	/* in:  -30000 .. 30000, higher is served first (as in WinDivert); handles of a namespace form a chain in
				 *      this order and no two started handles may share a priority */
	__u64	data_bytes;	/* out: length of the read-only data mapping (offset 0) */
	__u64	cons_offset;	/* out: mmap offset of the consumer page (writable, one page) */
	__u32	hdr_bytes;	/* out: size of the header area in front of the slots (a page) */
	__u32	reserved2;
};

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
	/* Phase 4 */
	__u64	modified;	/* held packets resumed with new bytes */
	__u64	mod_dropped;	/* held packets dropped because a modification could not be applied (no memory, no route) */
	__u64	ct_detached;	/* modified packets whose 5-tuple changed: their connection tracking entry was detached */
	__u64	injected;	/* packets injected by this handle */
	__u64	inject_failed;
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
				 *      EINVAL: nothing was done and a RESUME_MOD packet stays held (bad bytes: not IPv4, lengths that do
				 *      not fit) */
	__u64	data;		/* RESUME_MOD: user pointer to the packet */
	__u32	len;		/* RESUME_MOD: bytes at `data`, at most SWDIV_MAX_PACKET; bytes beyond the IP total length are ignored */
	__u32	flags;		/* RESUME_MOD: SWDIV_CALC_* */
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
 * a higher priority skip it; handles of a lower priority see it (WinDivert's "injected packets are diverted to the next priority
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
#define SWDIV_SRC_OUTBOUND	33	/* 1 on the FORWARD hook, where every packet counts as outbound */
#define SWDIV_SRC_LOOPBACK	34
#define SWDIV_SRC_PKT_LEN	35	/* the whole packet's length, not only the prefix */

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

#endif
