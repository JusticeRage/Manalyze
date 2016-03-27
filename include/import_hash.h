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

#include <boost/filesystem.hpp>

#include "hash-library/hashes.h"
#include "manape/pe.h"

namespace bfs = boost::filesystem;

namespace hash {

/**
 *	@brief	Computes the hash of a PE's imports.
 *	Per http://www.mandiant.com/blog/tracking-malware-import-hashing/
 *
 *	@return	A MD5 hash of the ordered import list.
 *
 *	Implementation is located in imports.cpp.
 */
std::string hash_imports(const mana::PE& pe);

} //namespace hash
