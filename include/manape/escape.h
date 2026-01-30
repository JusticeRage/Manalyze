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

#pragma once

// Pretty printing functions from manacommons are only imported if available.
// This makes it easier to take the parser out of Manalyze and re-use it for other stuff.
#if defined WITH_MANACOMMONS
# include "manacommons/escape.h"
#else
# include <string>
# include <memory>


// Escape functions copied from manacommons/escape.h / manacommons/escape.cpp
// I know that's code duplication / generally not great design. The issue is that
// section names need to be escaped, and I have to provide a way to do this when
// manacommons is not provided, for people who just want to reuse the PE parser
// but are not interested in pulling the rest of Manalyze's code.
namespace io {

typedef std::shared_ptr<std::string> pString;

// ----------------------------------------------------------------------------

inline pString escape(const std::string& s) {
	std::string generated;
	generated.reserve(s.size());
	static const char hex_digits[] = "0123456789abcdef";

	for (unsigned char c : s)
	{
		if (c >= 0x20 && c <= 0x7e)
		{
			generated.push_back(static_cast<char>(c));
		}
		else
		{
			generated += "\\x";
			generated += hex_digits[(c >> 4) & 0x0F];
			generated += hex_digits[c & 0x0F];
		}
	}

	return std::make_shared<std::string>(generated);
}

} // !namespace io

#endif
