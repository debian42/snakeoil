// all credits go to:
// https://www.c-plusplus.net/forum/topic/259410/konsolen-farbe-%C3%A4ndern/12

#ifndef CONSCOLOR_H
#include <iostream>
#ifdef WIN32
#include <Windows.h>
#endif
namespace ColorConsole
{
	static inline void SetForeground(int color);
	static inline void SetBackground(int color);

#ifdef WIN32

#define COLOR_MANIP_FB( NAME, FOREBACK, VALUE ) \
    template<typename C, typename T> inline std::basic_ostream<C, T>& \
        NAME( std::basic_ostream<C, T>& stream ) { \
        Set ## FOREBACK ( VALUE ); return stream; }

#define COLOR_MANIP( NAME, VALUE ) \
    COLOR_MANIP_FB( NAME, Foreground, VALUE ) \
    COLOR_MANIP_FB( NAME ## _bg, Background, VALUE )

	COLOR_MANIP(black, 0);
	COLOR_MANIP(blue, 1);
	COLOR_MANIP(green, 2);
	COLOR_MANIP(cyan, 3);
	COLOR_MANIP(red, 4);
	COLOR_MANIP(magenta, 5);
	COLOR_MANIP(brown, 6);
	COLOR_MANIP(lightGray, 7);
	COLOR_MANIP(darkGray, 8);
	COLOR_MANIP(lightBlue, 9);
	COLOR_MANIP(lightGreen, 10);
	COLOR_MANIP(lightCyan, 11);
	COLOR_MANIP(lightRed, 12);
	COLOR_MANIP(lightMagenta, 13);
	COLOR_MANIP(yellow, 14);
	COLOR_MANIP(white, 15);

#undef COLOR_MANIP_FB
#undef COLOR_MANIP

	namespace Private
	{
		static const unsigned MASK_BLUE = 1;
		static const unsigned MASK_GREEN = 2;
		static const unsigned MASK_RED = 4;
		static const unsigned MASK_INTENSITY = 8;

		static const unsigned FOREGROUND = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY;
		static const unsigned BACKGROUND = BACKGROUND_BLUE | BACKGROUND_GREEN | BACKGROUND_RED | BACKGROUND_INTENSITY;

		static inline void W32SetColor(int color, int mask)
		{
			CONSOLE_SCREEN_BUFFER_INFO s;
			const HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);

			if (h != INVALID_HANDLE_VALUE && h != NULL && GetConsoleScreenBufferInfo(h, &s) != 0) {
				SetConsoleTextAttribute(h, (WORD)(color | (s.wAttributes &  mask)));
			}
		}
	}

	static inline void SetForeground(int color)
	{
		using namespace Private;

		int value = 0;
		if (color & MASK_BLUE) value |= FOREGROUND_BLUE;
		if (color & MASK_GREEN) value |= FOREGROUND_GREEN;
		if (color & MASK_RED) value |= FOREGROUND_RED;
		if (color & MASK_INTENSITY) value |= FOREGROUND_INTENSITY;
		W32SetColor(value, BACKGROUND);
	}

	static inline void SetBackground(int color)
	{
		using namespace Private;

		int value = 0;
		if (color & MASK_BLUE) value |= BACKGROUND_BLUE;
		if (color & MASK_GREEN) value |= BACKGROUND_GREEN;
		if (color & MASK_RED) value |= BACKGROUND_RED;
		if (color & MASK_INTENSITY) value |= BACKGROUND_INTENSITY;
		W32SetColor(value, FOREGROUND);
	}
#endif
}
#endif