// Stand-in for the platform services that sources under test reach through log.cc; tests have no console.
#include "platform.h"

namespace platform {
int console_width()
{
	return 0;
}
}  // namespace platform
