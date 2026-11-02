// SPDX-License-Identifier: GPL-2.0
/* The shared-memory ring: allocation, and the kernel (producer) side of publishing a packet. */
#include <linux/gfp.h>
#include <linux/ktime.h>
#include <linux/minmax.h>
#include <linux/skbuff.h>
#include <linux/vmalloc.h>

#include "swdivert.h"

int swdiv_ring_alloc(struct swdiv_ring *ring, u32 slots, u32 slot_bytes)
{
	size_t hdr_bytes = PAGE_ALIGN(sizeof(struct swdiv_ring_hdr));
	size_t slot_area = (size_t)slots * slot_bytes;
	size_t total = PAGE_ALIGN(hdr_bytes + slot_area);
	struct page *cons_page;
	void *area;

	/* Zeroed, so no stale kernel memory is ever visible to the mapping */
	area = vmalloc_user(total);
	if (!area)
		return -ENOMEM;
	cons_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!cons_page) {
		vfree(area);
		return -ENOMEM;
	}

	ring->hdr = area;
	ring->hdr->abi = SWDIVERT_ABI_VERSION;
	ring->hdr->slots = slots;
	ring->hdr->slot_bytes = slot_bytes;
	ring->slots = (u8 *)area + hdr_bytes;
	ring->cons_page = cons_page;
	ring->cons = page_address(cons_page);
	spin_lock_init(&ring->lock);
	ring->prod = 0;
	ring->mask = slots - 1;
	ring->slot_bytes = slot_bytes;
	ring->hdr_bytes = hdr_bytes;
	ring->data_bytes = total;
	return 0;
}

void swdiv_ring_free(struct swdiv_ring *ring)
{
	if (ring->hdr)
		vfree(ring->hdr);
	if (ring->cons_page)
		__free_page(ring->cons_page);
	memset(ring, 0, sizeof(*ring));
}

int swdiv_ring_push(struct swdiv_ring *ring, const struct sk_buff *skb, const struct nf_hook_state *state, bool *truncated,
		     u64 id, struct swdiv_held *entry)
{
	const u32 capacity = ring->slot_bytes - SWDIVERT_SLOT_HDR_BYTES;
	/* Packets are copied from the IP header on, as WinDivert's network layer presents them */
	const int offset = skb_network_offset(skb);
	const u32 len = skb->len - offset;
	const u32 caplen = min(len, capacity);
	struct swdiv_slot_hdr *slot;
	u32 used;

	spin_lock_bh(&ring->lock);
	/* The consumer index is written by user space: anything beyond the producer count is nonsense and counts as "full" */
	used = ring->prod - READ_ONCE(ring->cons->cons);
	if (used >= ring->mask + 1) {
		spin_unlock_bh(&ring->lock);
		return -ENOSPC;
	}

	slot = (struct swdiv_slot_hdr *)(ring->slots + (size_t)(ring->prod & ring->mask) * ring->slot_bytes);
	if (skb_copy_bits(skb, offset, (u8 *)slot + SWDIVERT_SLOT_HDR_BYTES, caplen)) {
		spin_unlock_bh(&ring->lock);
		return -EFAULT;
	}
	slot->timestamp_ns = ktime_get_real_ns();
	slot->len = len;
	slot->caplen = caplen;
	slot->ifindex_in = state->in ? state->in->ifindex : 0;
	slot->ifindex_out = state->out ? state->out->ifindex : 0;
	slot->flags = (caplen < len ? SWDIV_SLOT_F_TRUNCATED : 0) | (entry ? SWDIV_SLOT_F_HELD : 0);
	slot->hook = state->hook;
	slot->id = id;
	slot->reserved0 = 0;
	slot->reserved1 = 0;
	slot->reserved2 = 0;

	/* From here the entry may be taken by another CPU: after this the hook must not touch it or the skb again */
	if (entry)
		smp_store_release(&entry->ready, true);

	ring->prod++;
	/* Orders the slot writes before the new producer count the reader acquires */
	smp_store_release(&ring->hdr->prod, ring->prod);
	spin_unlock_bh(&ring->lock);

	*truncated = caplen < len;
	return 0;
}

bool swdiv_ring_nonempty(struct swdiv_ring *ring)
{
	return smp_load_acquire(&ring->hdr->prod) != READ_ONCE(ring->cons->cons);
}
