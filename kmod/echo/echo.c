// SPDX-License-Identifier: GPL-2.0
/*
 * /dev/swdivert_echo: a write replaces the stored message, a read returns it. Integration module for the xmake -> kbuild build.
 */
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>

#include "swdivert_echo_abi.h"

static DEFINE_MUTEX(echo_lock);
static char echo_data[SWDIVERT_ECHO_CAPACITY];
static size_t echo_len;

static ssize_t echo_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	ssize_t ret;

	mutex_lock(&echo_lock);
	ret = simple_read_from_buffer(buf, count, pos, echo_data, echo_len);
	mutex_unlock(&echo_lock);
	return ret;
}

static ssize_t echo_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
	if (count > SWDIVERT_ECHO_CAPACITY)
		return -EMSGSIZE;

	mutex_lock(&echo_lock);
	if (copy_from_user(echo_data, buf, count)) {
		mutex_unlock(&echo_lock);
		return -EFAULT;
	}
	echo_len = count;
	mutex_unlock(&echo_lock);
	return count;
}

static long echo_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case SWDIVERT_ECHO_IOC_VERSION:
		return put_user((__u32)SWDIVERT_ECHO_ABI_VERSION, (__u32 __user *)arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations echo_fops = {
	.owner		= THIS_MODULE,
	.read		= echo_read,
	.write		= echo_write,
	.unlocked_ioctl	= echo_ioctl,
	.compat_ioctl	= compat_ptr_ioctl,
	.llseek		= default_llseek,
};

static struct miscdevice echo_device = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= SWDIVERT_ECHO_DEVICE_NAME,
	.fops	= &echo_fops,
	.mode	= 0600,
};

static int __init echo_init(void)
{
	int ret = misc_register(&echo_device);

	if (ret)
		return ret;
	pr_info("swdivert_echo: /dev/%s ready (abi %d)\n", SWDIVERT_ECHO_DEVICE_NAME, SWDIVERT_ECHO_ABI_VERSION);
	return 0;
}

static void __exit echo_exit(void)
{
	misc_deregister(&echo_device);
	pr_info("swdivert_echo: unloaded\n");
}

module_init(echo_init);
module_exit(echo_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("swdivert build-system integration module: echoes what is written to it");
MODULE_VERSION("1");
