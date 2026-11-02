/* ABI of /dev/swdivert_echo, shared by the kernel module and its user-space test. Only <linux/...> uapi headers are used. */
#ifndef SWDIVERT_ECHO_ABI_H_
#define SWDIVERT_ECHO_ABI_H_

#include <linux/ioctl.h>
#include <linux/types.h>

#define SWDIVERT_ECHO_DEVICE_NAME "swdivert_echo"
#define SWDIVERT_ECHO_CAPACITY    4096

/* Returns the ABI version of the loaded module; the user-space side refuses a mismatch. */
#define SWDIVERT_ECHO_IOC_VERSION _IOR('s', 0x01, __u32)
#define SWDIVERT_ECHO_ABI_VERSION 1

#endif
