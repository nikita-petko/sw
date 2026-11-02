#include "version.h"

// Defined by src/xmake.lua for this file only.
#ifndef LAGSW_VERSION
#define LAGSW_VERSION "unknown"
#endif
#ifndef LAGSW_GIT_HASH
#define LAGSW_GIT_HASH "unknown"
#endif

namespace version {
std::string banner()
{
	return "lagsw v" LAGSW_VERSION "@" LAGSW_GIT_HASH " by @nikita-petko";
}
}  // namespace version
