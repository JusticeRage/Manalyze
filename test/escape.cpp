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

#include <boost/test/unit_test.hpp>
#include "manacommons/escape.h"

typedef boost::shared_ptr<std::string> pString;

// ----------------------------------------------------------------------------

/**
 *	@brief	Verifies that the io::escape function returns the expected result.
 *
 *	@param	const std::string& input The string to escape.
 *	@param	const std::string& expected The expected result.
 */
void check_string_escaping(const std::string& input, const std::string& expected)
{
	pString escaped = io::escape(input);
	BOOST_ASSERT(escaped != nullptr);
	BOOST_CHECK_EQUAL(*escaped, expected);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_string_escape)
{
	check_string_escaping("", "");
	check_string_escaping("All characters are printable.", "All characters are printable.");
	check_string_escaping("\"", "\"");
	check_string_escaping("\\", "\\");
	check_string_escaping("\\\\", "\\\\");
	check_string_escaping("é", "\\xe9");
	check_string_escaping("\x1", "\\x01");
	check_string_escaping("\x01", "\\x01");
	check_string_escaping("\r\n", "\\x0d\\x0a");
}

// ----------------------------------------------------------------------------

// Placeholder classes used to test the output of the escape function in the context
// of JSON formatting.
class io::OutputFormatter {};
class JsonFormatterPlaceholder : public io::OutputFormatter
{
public:
	typedef io::escaped_string_json<io::sink_type> escape_grammar;
};

// ----------------------------------------------------------------------------

/**
*	@brief	Verifies that the io::escape function returns the expected result for
*			JSON strings.
*
*	@param	const std::string& input The string to escape.
*	@param	const std::string& expected The expected result.
*/
void check_string_escaping_json(const std::string& input, const std::string& expected)
{
	pString escaped = io::escape<JsonFormatterPlaceholder>(input);
	BOOST_ASSERT(escaped != nullptr);
	BOOST_CHECK_EQUAL(*escaped, expected);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_string_escape_json)
{
	check_string_escaping_json("", "");
	check_string_escaping_json("All characters are printable.", "All characters are printable.");
	check_string_escaping_json("\"", "\\\"");
	check_string_escaping_json("\\", "\\\\");
	check_string_escaping_json("\\\\", "\\\\\\\\");
	check_string_escaping_json("\x01", "\x01");
	check_string_escaping_json("\r\n", "\\r\\n");
}