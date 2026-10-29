#ifndef WINDIVERT_RUNTIME_H_
#define WINDIVERT_RUNTIME_H_

#if !defined(_WIN32)
#	error "The WinDivert backend is only available on Windows"
#endif

#define WINDIVERTEXPORT extern
#include <windivert.h>
#undef WINDIVERTEXPORT

/// Extracts and loads the bundled WinDivert runtime for use by the process.
/// Returns false and logs an error if initialization fails.
bool initialize_windivert();

#endif
