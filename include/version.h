#pragma once

#include <string>

namespace version {
/// "lagsw v<version>@<git short hash> by <author>", as pinned to the top right corner of every view.
std::string banner();
}  // namespace version
