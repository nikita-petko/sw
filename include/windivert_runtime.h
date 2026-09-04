#ifndef WINDIVERT_RUNTIME_H_
#define WINDIVERT_RUNTIME_H_

#define WINDIVERTEXPORT extern
#include <windivert.h>
#undef WINDIVERTEXPORT

bool initialize_windivert();

#endif
