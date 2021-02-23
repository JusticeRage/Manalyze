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

#include <map>
#include <sstream>
#include <string>

#include <boost/algorithm/string.hpp>
#include <boost/assign.hpp>
#include <boost/cstdint.hpp>
#include <boost/make_shared.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/system/api_config.hpp>

#if defined BOOST_WINDOWS_API && !defined DECLSPEC
	#ifdef MANAPE_EXPORT
		#define DECLSPEC    __declspec(dllexport)
	#else
		#define DECLSPEC    __declspec(dllimport)
	#endif
#elif !defined BOOST_WINDOWS_API && !defined DECLSPEC
	#define DECLSPEC
#endif

namespace nt {

/**
 *  @brief  A map which contains a list of function names corresponding to known DLL ordinals.
 * 
 * The map is in the form: { "first.dll":   { 1: "function 1", 2: "function 2", ... },
 *                           "second.dll":  { 3: "function 3", ... } }
 * 
 * Keys are lowercase DLL names. To generate a map, run manalyze with the -d export option on
 * target DLL and apply the following regular expression to the result:
 * Replace:     ([A-Za-z0-9_\-]+):\r\n\s+Ordinal:\s*(\d+) 
 * With:        \($2,\t\t"$1"\)
 */
extern const DECLSPEC std::map<std::string, std::map<boost::uint16_t, std::string> > ORDINAL_MAP;

/**
 *  @brief  Translates an ordinal into a function name, if possible.
 * 
 *  @param  ordinal The ordinal to translate.
 *  @param  dll The DLL into which the function is located.
 * 
 *  @return The name of the function corresponding to the ordinal, or a string containing "#[ordinal]"
 *          if it could not be translated.
 */
extern DECLSPEC boost::shared_ptr<std::string> translate_ordinal(boost::uint16_t ordinal, const std::string& dll);

} // !namespace nt
