#ifndef _WIN32
#error "platform/windows/keyboard.cc must only be built on Windows"
#endif

#include "platform.h"

#include <windows.h>
#include <conio.h>

namespace platform {

void ignore_interrupt()
{
	SetConsoleCtrlHandler(nullptr, TRUE);
}

int read_key()
{
	if (!_kbhit())
		return key::none;
	const int value = _getch();
	if (value != 0 && value != 0xE0)
		return value;
	switch (_getch())
	{
		case 0x4B:
			return key::left;
		case 0x4D:
			return key::right;
		case 0x49:
			return key::page_up;
		case 0x51:
			return key::page_down;
	}
	return key::none;
}

bool is_key_held(int key)
{
	return (::GetAsyncKeyState(key) & 0x8000) != 0;
}

}  // namespace platform
