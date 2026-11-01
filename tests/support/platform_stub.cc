// Stand-in for the platform services that sources under test reach through log.cc; tests have no console.
#include "platform.h"

namespace platform {
int console_width()
{
	return 0;
}
int console_height()
{
	return 0;
}
SystemCounters system_counters()
{
	return {};
}
}  // namespace platform
