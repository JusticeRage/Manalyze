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

#include <stdio.h>
#include <algorithm>
#include <boost/shared_ptr.hpp>

#include "hash-library/hashes.h"
#include "manape/pe.h"

namespace plugin
{

/**
 * Calculates the authenticode digest of a PE.
 * @param pe The file to hash.
 * @param digest_oid The OID of the hashing algorithm to use.
 * @return The authenticode digest of the input file, or an empty string if an error occurred.
 */
std::string get_authenticode_hash(const mana::PE& pe, const std::string& digest_oid);


} // !namespace plugin