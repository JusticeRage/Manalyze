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

#include "manacommons/base64.h"

// ----------------------------------------------------------------------------

void test_b64encode(const std::string& input, const std::string& expected)
{
    std::vector<boost::uint8_t> bytes(input.begin(), input.end());
    auto res = utils::b64encode(bytes);
    BOOST_ASSERT(res != nullptr);
    BOOST_CHECK_EQUAL(*res, expected);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(b64encode_tests)
{
    test_b64encode("", "");
    test_b64encode("f", "Zg==");
    test_b64encode("fo", "Zm8=");
    test_b64encode("foo", "Zm9v");
    test_b64encode("foob", "Zm9vYg==");
    test_b64encode("fooba", "Zm9vYmE=");
    test_b64encode("foobar", "Zm9vYmFy");
    test_b64encode("The quick brown fox\njumps over the lazy dog", "VGhlIHF1aWNrIGJyb3duIGZveApqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==");
}