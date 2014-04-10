/*
    This file is part of Spike Guard.

    Spike Guard is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Spike Guard is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Spike Guard.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _SSDEEP_H_
#define _SSDEEP_H_

#include <iostream>
#include <vector>
#include <boost/shared_array.hpp>
#include <boost/cstdint.hpp>

#include "ssdeep/fuzzy.h"

namespace ssdeep {

/**
 *	@brief	Calculates the SSDeep hash of a file based on its name.
 *
 *	@param	const std::string& filename The path to the file to hash.
 *
 *	@return	A string containing the SSDeep hash. Empty if an error occurs.
 */
std::string hash_file(const std::string& filename);

/**
 *	@brief	Calculates the SSDeep hash of given bytes.
 *
 *	@param	const std::vector<boost::uint8_t>& bytes The bytes to hash.
 *
 *	@return	A string containing the SSDeep hash. Empty if an error occurs.
 */
std::string hash_buffer(const std::vector<boost::uint8_t>& bytes);

}

#endif // !_SSDEEP_H_