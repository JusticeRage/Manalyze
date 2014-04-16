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

#include "hashes.h"

namespace hash {

std::string hash_bytes(Hash& digest, const std::vector<boost::uint8_t>& bytes)
{
	digest.reset();
	if (bytes.size() > 0) {
		digest.add(&bytes[0], bytes.size());
	}
	return digest.getHash();
}

// ----------------------------------------------------------------------------

std::vector<std::string> hash_bytes(std::vector<pHash>& digests, const std::vector<boost::uint8_t>& bytes)
{
	std::vector<std::string> res;
	for (std::vector<pHash>::iterator it = digests.begin() ; it != digests.end() ; ++it)
	{
		(*it)->reset();
		if (bytes.size() > 0) {
			(*it)->add(&bytes[0], bytes.size());
		}
		res.push_back((*it)->getHash());
	}
	return res;
}

// ----------------------------------------------------------------------------

std::string hash_file(Hash& digest, const std::string& filename)
{
	digest.reset();
	FILE* f = fopen(filename.c_str(), "rb");
	if (f == NULL) {
		return "";
	}
	boost::shared_array<boost::uint8_t> buffer = boost::shared_array<boost::uint8_t>(new boost::uint8_t[1024]);
	int read = 0;
	while (1024 == (read = fread(buffer.get(), 1, 1024, f))) {
		digest.add(buffer.get(), read);
	}

	// Append the bytes of the last read operation
	if (read != 0) {
		digest.add(buffer.get(), read);
	}

	fclose(f);
	return digest.getHash();
}

// ----------------------------------------------------------------------------

std::vector<std::string> hash_file(std::vector<pHash>& digests, const std::string& filename)
{
	std::vector<std::string> res = std::vector<std::string>();

	for (std::vector<pHash>::iterator it = digests.begin() ; it != digests.end() ; ++it) {
		(*it)->reset();
	}

	FILE* f = fopen(filename.c_str(), "rb");
	if (f == NULL) {
		return res;
	}
	boost::shared_array<boost::uint8_t> buffer = boost::shared_array<boost::uint8_t>(new boost::uint8_t[1024]);
	int read = 0;
	while (1024 == (read = fread(buffer.get(), 1, 1024, f))) 
	{
		for (std::vector<pHash>::iterator it = digests.begin() ; it != digests.end() ; ++it) {
			(*it)->add(buffer.get(), read);
		}
	}

	for (std::vector<pHash>::iterator it = digests.begin() ; it != digests.end() ; ++it) 
	{
		// Append the bytes of the last read operation
		if (read != 0) {
			(*it)->add(buffer.get(), read);
		}
		res.push_back((*it)->getHash());
	}

	fclose(f);
	return res;
}


} // !namespace hash