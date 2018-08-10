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

#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>
#include <boost/cstdint.hpp>

#include "manacommons/utf8/utf8.h"

// ----------------------------------------------------------------------------

void check_conversion(std::wstring input, const std::string& expected)
{
	std::vector<boost::uint8_t> utf8result;
	utf8::utf16to8(input.begin(), input.end(), std::back_inserter(utf8result));
	std::string result(utf8result.begin(), utf8result.end());
	BOOST_CHECK_EQUAL(result, expected);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_utf16_to_utf8)
{
	check_conversion(L"Simple ascii string", "Simple ascii string");
	check_conversion(L"é", "\xc3\xa9");
	check_conversion(L"©", "\xc2\xa9");
	check_conversion(L"© Microsoft Corporation. All rights reserved.", "\xc2\xa9 Microsoft Corporation. All rights reserved.");
	check_conversion(L"Ūnĭcōde̽", "\xc5\xaa\x6e\xc4\xad\x63\xc5\x8d\x64\x65\xcc\xbd");
	check_conversion(L"Юникод", "\xd0\xae\xd0\xbd\xd0\xb8\xd0\xba\xd0\xbe\xd0\xb4");
	check_conversion(L"უნიკოდი", "\xe1\x83\xa3\xe1\x83\x9c\xe1\x83\x98\xe1\x83\x99\xe1\x83\x9d\xe1\x83\x93\xe1\x83\x98");
	check_conversion(L"標準萬國碼", "\xe6\xa8\x99\xe6\xba\x96\xe8\x90\xac\xe5\x9c\x8b\xe7\xa2\xbc");
}

// ----------------------------------------------------------------------------
