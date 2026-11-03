#ifndef KMOD_MODULE_H_
#define KMOD_MODULE_H_

#include <string>

namespace kmodb {

/// Path of the module's device node.
extern const char* const kDevicePath;

/// Makes sure the swdivert module is loaded and speaks the ABI this build was made for (pocs/linux_kernel_module_backend.md, section 9.3).
///
/// When the device node is missing and the process is root, the module is loaded: `modprobe swdivert` first (an installed module), then
/// `insmod` of a .ko given in $LAGSW_KMOD_PATH or found next to the executable (a development build). Loading goes through those
/// programs, not through finit_module(), so module signing, dependencies and the system's module policy apply unchanged. Without root
/// nothing is loaded and the error says which command to run. A module of another ABI version is an error; it is never replaced.
bool ensure_module(std::string& error);

/// With $LAGSW_KMOD_UNLOAD_ON_EXIT set, `rmmod swdivert` once the process is done, but only when ensure_module() loaded it. A module that
/// is still in use stays (the kernel refuses). Never unloaded otherwise: the module is host-wide and closing the handles already
/// releases everything it held.
void unload_if_loaded_here();

}  // namespace kmodb

#endif
