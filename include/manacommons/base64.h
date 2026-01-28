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
#include <sstream>
#include <vector>

#include <cstdint>
#include <memory>
#if defined _WIN32 && !defined DECLSPEC_MANACOMMONS
	#ifdef MANACOMMONS_EXPORT
		#define DECLSPEC_MANACOMMONS    __declspec(dllexport)
	#else
		#define DECLSPEC_MANACOMMONS    __declspec(dllimport)
	#endif
#elif !defined _WIN32 && !defined DECLSPEC_MANACOMMONS
	#define DECLSPEC_MANACOMMONS
#endif

namespace utils {
typedef std::shared_ptr<std::string> pString;
    
// ----------------------------------------------------------------------------

/**
 *	@brief	Converts the input data into a Base64 encoded string.
 *
 *	Simple Base64 encoder.
 *
 *	@param	const std::vector<std::uint8_t>& bytes A vector of bytes to encode.
 *
 *	@return	A string containing the Base64 representation of the input.
 */
DECLSPEC_MANACOMMONS pString b64encode(const std::vector<std::uint8_t>& bytes);
    
} // !namespace 
