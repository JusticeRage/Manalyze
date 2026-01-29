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
#include <memory>
#include <type_traits>

#include "manacommons/color.h"

namespace io
{

// ----------------------------------------------------------------------------
// Grammars used to escape stings
// ----------------------------------------------------------------------------

typedef std::back_insert_iterator<std::string> sink_type;
typedef std::shared_ptr<std::string> pString;

/**
*	@brief	This grammar is used to escape strings printed to the console.
*
*	Printable characters are returned as-is, while the others are displayed using the C
*	notation.
*/
template <typename OutputIterator>
struct escaped_string_raw {};

// ----------------------------------------------------------------------------

/**
 *	@brief	This grammar is used to escape strings printed by the JSON formatter.
 *
 *	Paths contained in debug information insert unescaped backslashes which cause
 *	the resulting JSON to be invalid.
 *	Control characters are escaped to keep JSON output valid.
 *
 *	WARNING: Single quotes are NOT escaped.
 */
// Source: http://svn.boost.org/svn/boost/trunk/libs/spirit/example/karma/escaped_string.cpp
template <typename OutputIterator>
struct escaped_string_json {};

// ----------------------------------------------------------------------------

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
struct escape_impl;

template<typename OutputIterator>
struct escape_impl<escaped_string_raw<OutputIterator>>
{
	static pString run(const std::string& s)
	{
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
};

template<typename OutputIterator>
struct escape_impl<escaped_string_json<OutputIterator>>
{
	static pString run(const std::string& s)
	{
		std::string generated;
		generated.reserve(s.size());
		static const char hex_digits[] = "0123456789ABCDEF";

		for (unsigned char c : s)
		{
			switch (c)
			{
				case '\"': generated += "\\\""; break;
				case '\\': generated += "\\\\"; break;
				case '\b': generated += "\\b"; break;
				case '\f': generated += "\\f"; break;
				case '\n': generated += "\\n"; break;
				case '\r': generated += "\\r"; break;
				case '\t': generated += "\\t"; break;
				default:
					if (c < 0x20)
					{
						generated += "\\u00";
						generated += hex_digits[(c >> 4) & 0x0F];
						generated += hex_digits[c & 0x0F];
					}
					else {
						generated.push_back(static_cast<char>(c));
					}
			}
		}

		return std::make_shared<std::string>(generated);
	}
};

template<typename Grammar>
pString _do_escape(const std::string& s)
{
	return escape_impl<Grammar>::run(s);
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
	static_assert(std::is_base_of<OutputFormatter, T>::value, "Invalid formatter type.");
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
