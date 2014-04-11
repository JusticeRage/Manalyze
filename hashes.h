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

#ifndef _HASHES_H_
#define _HASHES_H_

#include <string>
#include <vector>

#include <boost/shared_ptr.hpp>
#include <boost/assign.hpp>
#include <boost/cstdint.hpp>

#include "ssdeep.h"
#include "hash-library/digest.h"
#include "hash-library/md5.h"
#include "hash-library/sha1.h"
#include "hash-library/sha256.h"
#include "hash-library/keccak.h"

namespace hash {

typedef boost::shared_ptr<Digest> pDigest;

/**
 *	@brief	Computes the hash of a buffer.
 *
 *	@param	Digest& digest The digest to use.
 *	@param	const std::vector<boost::uint8_t>& bytes The buffer to hash.
 *
 *	@return	A string containing the hash value. May be empty if an error occurred.
 */
std::string hash_bytes(Digest& digest, const std::vector<boost::uint8_t>& bytes);

/**
 *	@brief	Computes the hash of a file.
 *
 *	@param	Digest& digest The digest to use.
 *	@param	const std::string& filename The path to the file to hash.
 *
 *	@return	A string containing the hash value. May be empty if an error occurred.
 */
std::string hash_file(Digest& digest, const std::string& filename);

/**
 *	@brief	Computes the hashes of a file.
 *
 *	This function is used to calculate multiple hashes of the same file in a single pass.
 *
 *	@param	std::vector<pDigest>& digests A list of digests to use.
 *			hash::ALL_DIGESTS is a suitable pre-initialized vector given for convenience.
 *
 *	@param	const std::string& filename The path to the file to hash.
 *
 *	@return	A vector containing all the computed hashes, in the same order as the input digests.
 *			If an error occurs for any digest, the return value's size is set to 0.
 */
std::vector<std::string> hash_file(std::vector<pDigest>& digests, const std::string& filename);

/**
 *	@brief	Computes the hashes of a buffer.
 *
 *	@param	std::vector<pDigest>& digests A list of digests to use.
 *			hash::ALL_DIGESTS is a suitable pre-initialized vector given for convenience.
 *
 *	@param	const std::vector<boost::uint8_t>& bytes The buffer to hash.
 *
 *	@return	A vector containing all the computed hashes, in the same order as the input digests.
 *			If an error occurs for any digest, the return value's size is set to 0.
 */
std::vector<std::string> hash_bytes(std::vector<pDigest>& digests, const std::vector<boost::uint8_t>& bytes);

// Convenience vector containing all available digests.
static std::vector<pDigest> ALL_DIGESTS = boost::assign::list_of(pDigest(new MD5))
																(pDigest(new SHA1))
																(pDigest(new SHA256))
																(pDigest(new Keccak));

// Simple map used to refer to ALL_DIGESTS consistently in case the list of algorithms evolves.
static std::map<std::string, int> ALL_DIGESTS_INDEX = 
	boost::assign::map_list_of	("MD5",		0)
								("SHA1",	1)
								("SHA256",	2)
								("SHA3",	3);

} // !namespace hash

#endif // !_HASHES_H_