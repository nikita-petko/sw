#ifndef KMOD_EMBEDDED_H_
#define KMOD_EMBEDDED_H_

#include <vector>

#include "module_image.h"

namespace kmodb {

/// The kernel modules built into this executable (the build embeds the module it built for the configured kernel and any prebuilt
/// ones named by `--linux_kmod_extra`), one per kernel release. Empty when the build embedded none.
std::vector<ModuleImage> embedded_images();

}  // namespace kmodb

#endif
