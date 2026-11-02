#ifndef _WIN32
#	error "platform/windows/keyboard.cc must only be built on Windows"
#endif

#include "platform.h"

#include <conio.h>
#include <windows.h>

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
		case 0x48:
			return key::up;
		case 0x50:
			return key::down;
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

int read_edit_key()
{
	if (!_kbhit())
		return edit_key::none;
	const int value = _getch();
	if (value == 0 || value == 0xE0)
	{
		switch (_getch())
		{
			case 0x48:
				return edit_key::up;
			case 0x50:
				return edit_key::down;
			case 0x4B:
				return edit_key::left;
			case 0x4D:
				return edit_key::right;
			case 0x47:
				return edit_key::home;
			case 0x4F:
				return edit_key::end;
			case 0x53:
				return edit_key::del;
			case 0x49:
				return edit_key::page_up;
			case 0x51:
				return edit_key::page_down;
		}
		return edit_key::none;
	}
	if (value == 0x1B)
		return edit_key::escape;
	if (value == '\r' || value == '\n')
		return edit_key::enter;
	if (value == '\t')
		return edit_key::tab;
	if (value == 8 || value == 127)
		return edit_key::backspace;
	if (value >= 1 && value <= 26)
		return edit_key::ctrl(static_cast<char>('A' + value - 1));
	return value < 0x20 ? edit_key::none : value;
}

bool is_key_held(int key)
{
	return (::GetAsyncKeyState(key) & 0x8000) != 0;
}

}  // namespace platform
