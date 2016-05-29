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

#include <string>
#include <boost/static_assert.hpp>
#include <boost/spirit/include/karma.hpp>
#include <boost/type_traits/is_base_of.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>

#include "manacommons/color.h"

namespace io
{

// ----------------------------------------------------------------------------
// Grammars used to escape stings
// ----------------------------------------------------------------------------

namespace karma = boost::spirit::karma;
typedef std::back_insert_iterator<std::string> sink_type;
typedef boost::shared_ptr<std::string> pString;

/**
*	@brief	This grammar is used to escape strings printed to the console.
*
*	Printable characters are returned as-is, while the others are displayed using the C
*	notation.
*/
template <typename OutputIterator>
struct escaped_string_raw
	: karma::grammar<OutputIterator, std::string()>
{
	escaped_string_raw()
		: escaped_string_raw::base_type(esc_str)
	{
		esc_str = *(boost::spirit::karma::iso8859_1::print | "\\x" << karma::right_align(2, 0)[karma::hex]);
	}

	karma::rule<OutputIterator, std::string()> esc_str;
	karma::symbols<char, char const*> esc_char;
};

// ----------------------------------------------------------------------------

/**
 *	@brief	This grammar is used to escape strings printed by the JSON formatter.
 *
 *	Paths contained in debug information insert unescaped backslashes which cause
 *	the resulting JSON to be invalid.
 *	Non-printable characters are not escaped in this grammar, because we expect
 *	UTF-8 strings.
 *
 *	WARNING: Single quotes are NOT escaped.
 */
// Source: http://svn.boost.org/svn/boost/trunk/libs/spirit/example/karma/escaped_string.cpp
template <typename OutputIterator>
struct escaped_string_json
	: karma::grammar<OutputIterator, std::string()>
{
	escaped_string_json()
		: escaped_string_json::base_type(esc_str)
	{
		// We allow "'" because it will be used in messages (i.e. [... don't ...]).
		// We don't care if those are not escaped because they will be printed between double quotes
		// in JSON strings.
		esc_char.add('\a', "\\a")('\b', "\\b")('\f', "\\f")('\n', "\\n")
			('\r', "\\r")('\t', "\\t")('\v', "\\v")('\\', "\\\\")
			('\"', "\\\"");

		esc_str = *(esc_char | boost::spirit::karma::char_);
	}

	karma::rule<OutputIterator, std::string()> esc_str;
	karma::symbols<char, char const*> esc_char;
};

// ----------------------------------------------------------------------------

/*
 *	Forward-declare the OutputFormatter class, so it can be used in a static
 *	assert in  template<typename T> std::string escape(const std::string&).
 */
class OutputFormatter;

// ----------------------------------------------------------------------------

/**
 *	@brief	Performs the actual string escaping based on the grammar given as
 *			template parameter.
 *
 *	@param	const std::string& s The string to escape.
 *
 *	@return	A pointer to the escaped string, or a null pointer if an error occurred.
 */
template<typename Grammar>
pString _do_escape(const std::string& s)
{
	BOOST_STATIC_ASSERT(boost::is_base_of<karma::grammar<sink_type, std::string()>, Grammar>::value);
	typedef std::back_insert_iterator<std::string> sink_type;

	std::string generated;
	sink_type sink(generated);

	Grammar g;
	if (!karma::generate(sink, g, s))
	{
		PRINT_WARNING << "Could not escape \"" << s << "!" << std::endl;
		return nullptr;
	}
	else {
		return boost::make_shared<std::string>(generated);
	}
}

// ----------------------------------------------------------------------------

/**
 *	@brief	Escapes problematic characters from a string.
 *
 *	The template parameter is the type of the formatter calling the function.
 *	Each output formatter has an escape_grammar type which describes how the
 *	string should be escaped.
 *
 *	@param const std::string& s The string to escape.
 *
 *	@returns The escaped string, or a null pointer if an error was encountered.
 */
template<typename T>
pString escape(const std::string& s)
{
	BOOST_STATIC_ASSERT(boost::is_base_of<OutputFormatter, T>::value);
	return _do_escape<typename T::escape_grammar>(s);
}

// ----------------------------------------------------------------------------

/*
 *	@brief	Escapes problematic characters from a string.
 *
 *	Non printable characters found in the input string will be escaped using
 *	the C notation (i.e. \x0D).
 *
 *	@param const std::string& s The string to escape.
 *
 *	@returns The escaped string, or a null pointer if an error was encountered.
 */
DECLSPEC_MANACOMMONS pString escape(const std::string& s);

}
