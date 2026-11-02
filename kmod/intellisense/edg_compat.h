/*
 * IntelliSense only; kbuild never sees this file (it is force-included by the compile commands that kmod/modules/kbuild.lua
 * hands to project generators).
 *
 * VS Code's C/C++ extension parses with the EDG front end, which lacks a few compiler features that kernel configurations
 * switch on, and then reports false syntax errors in perfectly valid kernel code. Turning the corresponding options off
 * before the kernel headers see them selects the portable code paths, which every compiler (and EDG) understands:
 */

/* x86 per-CPU variables use the named address space __seg_gs: "expected a ';'" on every `__percpu` pointer */
#undef CONFIG_USE_X86_SEG_SUPPORT

/* READ_ONCE()/smp_load_acquire() use __typeof_unqual__: "expected a ')'" */
#undef CONFIG_CC_HAS_TYPEOF_UNQUAL
