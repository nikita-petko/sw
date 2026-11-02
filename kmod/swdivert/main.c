// SPDX-License-Identifier: GPL-2.0
/*
 * /dev/swdivert (Phase 2 spike): one open file is one handle. OPEN sizes the ring, SET_FILTER sets the 5-tuple, START
 * registers a FORWARD hook in the opener's network namespace, and the reader consumes the mmap'd ring (poll() to sleep).
 */
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/nsproxy.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <net/net_namespace.h>

#include "swdivert.h"

#define SWDIV_MIN_SLOTS		64
#define SWDIV_MAX_SLOTS		(1U << 20)
#define SWDIV_MIN_SLOT_BYTES	128
#define SWDIV_MAX_SLOT_BYTES	65536
#define SWDIV_MAX_RING_BYTES	(256UL << 20)

static int swdiv_open(struct inode *inode, struct file *file)
{
	struct net *net = current->nsproxy->net_ns;
	struct swdiv_handle *handle;

	/* The device node is root-only; this keeps the check right if the mode is ever relaxed */
	if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
		return -EPERM;

	handle = kzalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle)
		return -ENOMEM;
	handle->stats = alloc_percpu(struct swdiv_cpu_stats);
	if (!handle->stats) {
		kfree(handle);
		return -ENOMEM;
	}
	mutex_init(&handle->lock);
	init_waitqueue_head(&handle->wq);
	swdiv_wake_timer_init(handle);
	swdiv_hold_init(handle);
	handle->net = get_net(net);
	swdiv_hold_register(handle);
	file->private_data = handle;
	return 0;
}

/*
 * Stops the hook. Held packets are resumed first, while the hook is still registered: they continue after its position in the
 * hook chain, which is found by looking for it, and no new packet can be held once the flush has started.
 */
static void swdiv_stop(struct swdiv_handle *handle)
{
	if (!handle->started)
		return;
	if (handle->hold_mode)
		swdiv_hold_flush(handle);
	swdiv_hook_stop(handle);
	if (handle->hold_mode)
		swdiv_hold_reopen(handle);
	handle->started = false;
}

static int swdiv_release(struct inode *inode, struct file *file)
{
	struct swdiv_handle *handle = file->private_data;

	swdiv_stop(handle);
	/* The hook is gone, so nothing can arm the timer any more; a callback that is already running finishes first */
	swdiv_wake_timer_cancel(handle);
	swdiv_hold_unregister(handle);
	swdiv_hold_destroy(handle);
	if (handle->ring_ready)
		swdiv_ring_free(&handle->ring);
	put_net(handle->net);
	free_percpu(handle->stats);
	kfree(handle);
	return 0;
}

static int swdiv_do_open(struct swdiv_handle *handle, void __user *argp)
{
	struct swdiv_open_args args;
	int ret;

	if (copy_from_user(&args, argp, sizeof(args)))
		return -EFAULT;
	if ((args.flags & ~SWDIV_OPEN_HOLD) || args.reserved || args.reserved2)
		return -EINVAL;
	if (args.slots < SWDIV_MIN_SLOTS || args.slots > SWDIV_MAX_SLOTS || !is_power_of_2(args.slots))
		return -EINVAL;
	if (args.slot_bytes < SWDIV_MIN_SLOT_BYTES || args.slot_bytes > SWDIV_MAX_SLOT_BYTES || args.slot_bytes % 16)
		return -EINVAL;
	if ((unsigned long)args.slots * args.slot_bytes > SWDIV_MAX_RING_BYTES)
		return -EINVAL;
	if (handle->ring_ready)
		return -EBUSY;

	ret = swdiv_ring_alloc(&handle->ring, args.slots, args.slot_bytes);
	if (ret)
		return ret;
	handle->hold_mode = args.flags & SWDIV_OPEN_HOLD;
	/* Pairs with the acquire in swdiv_poll(), which does not take the lock */
	smp_store_release(&handle->ring_ready, true);

	args.data_bytes = handle->ring.data_bytes;
	args.hdr_bytes = handle->ring.hdr_bytes;
	/* A fixed offset far above any data mapping selects the consumer page in mmap() */
	args.cons_offset = (u64)SWDIV_MAX_RING_BYTES + PAGE_SIZE;
	if (copy_to_user(argp, &args, sizeof(args)))
		return -EFAULT;
	return 0;
}

static long swdiv_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct swdiv_handle *handle = file->private_data;
	void __user *argp = (void __user *)arg;
	long ret = 0;

	if (cmd == SWDIVERT_IOC_VERSION)
		return put_user((__u32)SWDIVERT_ABI_VERSION, (__u32 __user *)argp);

	mutex_lock(&handle->lock);
	switch (cmd) {
	case SWDIVERT_IOC_OPEN:
		ret = swdiv_do_open(handle, argp);
		break;
	case SWDIVERT_IOC_SET_FILTER: {
		struct swdiv_tuple tuple;

		if (handle->started) {
			ret = -EBUSY;
		} else if (copy_from_user(&tuple, argp, sizeof(tuple))) {
			ret = -EFAULT;
		} else {
			handle->tuple = tuple;
		}
		break;
	}
	case SWDIVERT_IOC_START:
		if (!handle->ring_ready)
			ret = -EINVAL;
		else if (handle->started)
			ret = -EBUSY;
		else if (!(ret = swdiv_hook_start(handle)))
			handle->started = true;
		break;
	case SWDIVERT_IOC_STOP:
		swdiv_stop(handle);
		break;
	case SWDIVERT_IOC_VERDICT:
		ret = swdiv_hold_verdicts(handle, argp);
		break;
	case SWDIVERT_IOC_STATS: {
		struct swdiv_stats stats = {};
		int cpu;

		for_each_possible_cpu(cpu) {
			const struct swdiv_cpu_stats *cs = per_cpu_ptr(handle->stats, cpu);

			stats.seen += cs->seen;
			stats.matched += cs->matched;
			stats.copied += cs->copied;
			stats.dropped_full += cs->dropped_full;
			stats.truncated += cs->truncated;
			stats.wakeups += cs->wakeups;
			stats.held += cs->held;
			stats.resumed += cs->resumed;
			stats.verdict_dropped += cs->verdict_dropped;
			stats.expired += cs->expired;
			stats.flushed += cs->flushed;
			stats.dev_dropped += cs->dev_dropped;
			stats.resume_lost += cs->resume_lost;
			stats.pass_unsupported += cs->pass_unsupported;
			stats.pass_limit += cs->pass_limit;
		}
		stats.held_now = atomic_read(&handle->held_count);
		if (copy_to_user(argp, &stats, sizeof(stats)))
			ret = -EFAULT;
		break;
	}
	default:
		ret = -ENOTTY;
	}
	mutex_unlock(&handle->lock);
	return ret;
}

static int swdiv_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct swdiv_handle *handle = file->private_data;
	const unsigned long length = vma->vm_end - vma->vm_start;
	const unsigned long cons_pgoff = ((unsigned long)SWDIV_MAX_RING_BYTES + PAGE_SIZE) >> PAGE_SHIFT;
	int ret = -EINVAL;

	mutex_lock(&handle->lock);
	if (!handle->ring_ready)
		goto out;

	if (vma->vm_pgoff == 0) {
		/* The ring itself is read-only for user space: the kernel is the only writer of slots and the producer count */
		if (length != handle->ring.data_bytes) {
			goto out;
		}
		if (vma->vm_flags & VM_WRITE) {
			ret = -EPERM;
			goto out;
		}
		vm_flags_clear(vma, VM_MAYWRITE);
		vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);
		ret = remap_vmalloc_range(vma, handle->ring.hdr, 0);
	} else if (vma->vm_pgoff == cons_pgoff) {
		if (length != PAGE_SIZE)
			goto out;
		vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);
		ret = vm_insert_page(vma, vma->vm_start, handle->ring.cons_page);
	}
out:
	mutex_unlock(&handle->lock);
	return ret;
}

static __poll_t swdiv_poll(struct file *file, poll_table *wait)
{
	struct swdiv_handle *handle = file->private_data;

	poll_wait(file, &handle->wq, wait);
	/* ring_ready only ever goes false -> true while the file is open; the ring is freed at release */
	if (smp_load_acquire(&handle->ring_ready) && swdiv_ring_nonempty(&handle->ring))
		return EPOLLIN | EPOLLRDNORM;
	return 0;
}

static const struct file_operations swdiv_fops = {
	.owner		= THIS_MODULE,
	.open		= swdiv_open,
	.release	= swdiv_release,
	.unlocked_ioctl	= swdiv_ioctl,
	.compat_ioctl	= compat_ptr_ioctl,
	.mmap		= swdiv_mmap,
	.poll		= swdiv_poll,
};

static struct miscdevice swdiv_device = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= SWDIVERT_DEVICE_NAME,
	.fops	= &swdiv_fops,
	.mode	= 0600,
};

static int __init swdiv_init(void)
{
	int ret = swdiv_hold_module_init();

	if (ret)
		return ret;
	ret = misc_register(&swdiv_device);
	if (ret) {
		swdiv_hold_module_exit();
		return ret;
	}
	pr_info("swdivert: /dev/%s ready (abi %d, spike)\n", SWDIVERT_DEVICE_NAME, SWDIVERT_ABI_VERSION);
	return 0;
}

static void __exit swdiv_exit(void)
{
	misc_deregister(&swdiv_device);
	swdiv_hold_module_exit();
	pr_info("swdivert: unloaded\n");
}

module_init(swdiv_init);
module_exit(swdiv_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("swdivert Phase 3 spike: FORWARD sniffer / holder with an mmap ring");
MODULE_VERSION("0");
