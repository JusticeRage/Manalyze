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
# include <boost/static_assert.hpp>
# include <boost/spirit/include/karma.hpp>
# include <boost/type_traits/is_base_of.hpp>
# include <boost/shared_ptr.hpp>
# include <boost/make_shared.hpp>


// Escape functions copied from manacommons/escape.h / manacommons/escape.cpp
// I know that's code duplication / generally not great design. The issue is that
// section names need to be escaped, and I have to provide a way to do this when
// manacommons is not provided, for people who just want to reuse the PE parser
// but are not interested in pulling the rest of Manalyze's code.
namespace io {

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

inline pString escape(const std::string& s) {
    return _do_escape<escaped_string_raw<sink_type> >(s);
}

} // !namespace io

#endif
