#ifndef KMOD_MODULE_H_
#define KMOD_MODULE_H_

#include <cstddef>
#include <cstdint>
#include <string>

namespace kmodb {

/// Path of the module's device node.
extern const char* const kDevicePath;

/// The running kernel's release (`uname -r`).
std::string kernel_release();

enum class LoadStatus
{
	loaded,
	already_loaded,	 ///< a module of that name is in the kernel already (EEXIST)
	failed,			 ///< `error` says why, with what to do about it
};

/// Loads a module from memory with init_module(2): no file, no helper program, so CAP_SYS_MODULE is all it takes. The kernel checks the
/// image's version magic and, where it enforces them (Secure Boot, lockdown, module.sig_enforce), its signature.
LoadStatus load_module_image(const uint8_t* data, size_t size, std::string& error);

/// Makes sure the swdivert module is loaded and speaks the ABI this build was made for (pocs/linux_kernel_module_backend.md, section 9.3).
///
/// When the device node is missing and the process can load modules (root, or CAP_SYS_MODULE), the module is loaded from the first
/// of these that works: $LAGSW_KMOD_PATH, the module embedded in the executable for the running kernel (loaded from memory, as WinDivert's
/// embedded driver is), an installed module (`modprobe swdivert`), swdivert.ko next to the executable. Without the privilege nothing is
/// loaded and the error says what to run. A module of another ABI version is an error; it is never replaced.
bool ensure_module(std::string& error);

/// With $LAGSW_KMOD_UNLOAD_ON_EXIT set, `rmmod swdivert` once the process is done, but only when ensure_module() loaded it. A module that
/// is still in use stays (the kernel refuses). Never unloaded otherwise: the module is host-wide and closing the handles already
/// releases everything it held.
void unload_if_loaded_here();

}  // namespace kmodb

#endif
