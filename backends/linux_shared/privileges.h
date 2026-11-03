#ifndef LINUX_SHARED_PRIVILEGES_H_
#define LINUX_SHARED_PRIVILEGES_H_

#include <string>

namespace linux_shared {

/// Verifies the process holds CAP_NET_ADMIN, which is all that programming nf_tables over netlink and binding NFQUEUE
/// queues need (no spawned helper, so file capabilities are enough). A missing privilege is reported
/// once at startup instead of as a kernel error from the first capture channel. On failure `error` explains how to fix it.
/// Also logs a warning when keyboard devices exist but none is readable (hotkeys would not work).
bool check_privileges(std::string& error);

}  // namespace linux_shared

#endif
