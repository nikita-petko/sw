/* User-space consumer of the swdivert ring (see swdivert_abi.h). Header-only so tests can drive it with a fake producer. */
#ifndef SWDIVERT_RING_H_
#define SWDIVERT_RING_H_

#include "swdivert_abi.h"

struct swdiv_ring_view {
	const struct swdiv_ring_hdr* hdr;
	const unsigned char*		 slots;
	struct swdiv_cons*			 cons_page;
	__u32						 mask;
	__u32						 slot_bytes;
	__u32						 local_cons;
};

static inline void swdiv_ring_view_init(struct swdiv_ring_view* view, const void* data, __u32 hdr_bytes, struct swdiv_cons* cons_page)
{
	view->hdr		 = (const struct swdiv_ring_hdr*)data;
	view->slots		 = (const unsigned char*)data + hdr_bytes;
	view->cons_page	 = cons_page;
	view->mask		 = view->hdr->slots - 1;
	view->slot_bytes = view->hdr->slot_bytes;
	view->local_cons = __atomic_load_n(&cons_page->cons, __ATOMIC_RELAXED);
}

/* Number of slots published and not yet released. */
static inline __u32 swdiv_ring_avail(const struct swdiv_ring_view* view)
{
	return __atomic_load_n(&view->hdr->prod, __ATOMIC_ACQUIRE) - view->local_cons;
}

/* The slot `ahead` positions after the oldest unreleased one (ahead < swdiv_ring_avail()). */
static inline const struct swdiv_slot_hdr* swdiv_ring_slot(const struct swdiv_ring_view* view, __u32 ahead)
{
	return (const struct swdiv_slot_hdr*)(view->slots + (size_t)((view->local_cons + ahead) & view->mask) * view->slot_bytes);
}

static inline const unsigned char* swdiv_slot_data(const struct swdiv_slot_hdr* slot)
{
	return (const unsigned char*)slot + SWDIVERT_SLOT_HDR_BYTES;
}

/* Capture length clamped to what fits in a slot, so a corrupt header can never make the reader run off the mapping. */
static inline __u32 swdiv_slot_caplen(const struct swdiv_ring_view* view, const struct swdiv_slot_hdr* slot)
{
	const __u32 limit = view->slot_bytes - SWDIVERT_SLOT_HDR_BYTES;
	return slot->caplen < limit ? slot->caplen : limit;
}

/* Hands `count` slots back to the kernel. */
static inline void swdiv_ring_release(struct swdiv_ring_view* view, __u32 count)
{
	view->local_cons += count;
	__atomic_store_n(&view->cons_page->cons, view->local_cons, __ATOMIC_RELEASE);
}

#endif
