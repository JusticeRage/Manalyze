/*
    This file is part of Manalyze.

    Manalyze is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Manalyze is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Manalyze.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "color.h"

namespace utils
{

#ifdef BOOST_WINDOWS_API

void set_color(Color c)
{
	HANDLE h = ::GetStdHandle(STD_OUTPUT_HANDLE);
	if (h == INVALID_HANDLE_VALUE) {
		return;
	}

	switch(c)
	{
	case RED:
		::SetConsoleTextAttribute(h, 4);
		break;
	case GREEN:
		::SetConsoleTextAttribute(h, 2);
		break;
	case YELLOW:
		::SetConsoleTextAttribute(h, 14);
		break;
	case RESET:
		::SetConsoleTextAttribute(h, 7);
		break;
	}

	// The handle should not be closed, otherwise writing to stdout will become impossible.
}

#else // Unix implementation

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_RESET   "\x1b[0m"

void set_color(Color c)
{
	if (!isatty(fileno(stdout))) {
		return;
	}
	switch (c)
	{
	case RED:
		std::cout << ANSI_COLOR_RED;
		break;
	case YELLOW:
		std::cout << ANSI_COLOR_YELLOW;
		break;
	case GREEN:
		std::cout << ANSI_COLOR_GREEN;
		break;
	case RESET:
		std::cout << ANSI_COLOR_RESET;
		break;
	}
}

#endif

std::ostream& print_colored_text(const std::string& text,
								 Color c,
								 std::ostream& sink,
								 const std::string& prefix,
								 const std::string& suffix)
{
	sink << prefix;
	set_color(c);
	sink << text;
	set_color(RESET);
	return sink << suffix;
}

}
