#ifndef NFQUEUE_PRIVILEGES_H_
#define NFQUEUE_PRIVILEGES_H_

#include <string>

namespace nfq {

/// Verifies the process can install nftables rules and bind NFQUEUE queues, so a missing privilege is reported
/// once at startup instead of as a kernel error from the first capture channel. On failure `error` explains how to fix it.
/// Also logs a warning when keyboard devices exist but none is readable (hotkeys would not work).
bool check_privileges(std::string& error);

}  // namespace nfq

#endif
