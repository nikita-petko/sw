/*
 * ABI of /dev/swdivert, shared by the kernel module and user space (only <linux/...> uapi headers are used).
 *
 * SPIKE STATUS (Phase 2 of pocs/linux_kernel_module_backend.md): capture-only, sniff-only, FORWARD hook, one hard-coded
 * 5-tuple filter. SWDIVERT_ABI_VERSION stays 0 until the ABI is declared stable; user space refuses any other value.
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

/* SWDIVERT_IOC_OPEN: sizes the ring. `slots` is a power of two, `slot_bytes` a multiple of 64. */
struct swdiv_open_args {
	__u32	slots;		/* in:  64 .. 1048576 */
	__u32	slot_bytes;	/* in:  128 .. 65536, includes the 32-byte slot header */
	__u32	flags;		/* in:  must be 0 */
	__u32	reserved;
	__u64	data_bytes;	/* out: length of the read-only data mapping (offset 0) */
	__u64	cons_offset;	/* out: mmap offset of the consumer page (writable, one page) */
	__u32	hdr_bytes;	/* out: size of the header area in front of the slots (a page) */
	__u32	reserved2;
};

struct swdiv_stats {
	__u64	seen;		/* packets that reached the hook */
	__u64	matched;	/* ... and matched the filter */
	__u64	copied;		/* ... and were published to the ring */
	__u64	dropped_full;	/* matched but the ring had no free slot */
	__u64	truncated;	/* copied with caplen < len */
};

#define SWDIVERT_IOC_VERSION	_IOR('s', 0x10, __u32)
#define SWDIVERT_IOC_OPEN	_IOWR('s', 0x11, struct swdiv_open_args)
#define SWDIVERT_IOC_SET_FILTER	_IOW('s', 0x12, struct swdiv_tuple)
#define SWDIVERT_IOC_START	_IO('s', 0x13)
#define SWDIVERT_IOC_STOP	_IO('s', 0x14)
#define SWDIVERT_IOC_STATS	_IOR('s', 0x15, struct swdiv_stats)

/*
 * Memory layout of the ring (mmap offset 0, read-only for user space):
 *   [ hdr_bytes: struct swdiv_ring_hdr ][ slots * slot_bytes ]
 * The consumer index lives on its own writable page (mmap offset `cons_offset`), so the kernel never has to trust a word
 * in memory that user space can write for anything but "how far has the reader got" (and clamps it).
 */
#define SWDIVERT_SLOT_HDR_BYTES 32

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

struct swdiv_slot_hdr {
	__u64	timestamp_ns;	/* CLOCK_REALTIME at capture */
	__u32	len;		/* IP packet length */
	__u32	caplen;		/* bytes that follow this header */
	__u32	ifindex_in;
	__u32	ifindex_out;
	__u16	flags;
	__u8	hook;		/* netfilter hook number */
	__u8	reserved0;
	__u32	reserved1;
	/* caplen bytes of packet data follow, starting at the IP header */
};

struct swdiv_cons {
	__u32	cons;		/* free-running count of consumed slots; written by user space only */
};

#endif
