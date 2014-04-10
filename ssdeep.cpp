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

#include "ssdeep.h"

namespace ssdeep {

std::string hash_file(const std::string& filename)
{
	boost::shared_array<char> res = boost::shared_array<char>(new char[FUZZY_MAX_RESULT]);
	FILE* f = fopen(filename.c_str(), "rb");

	if (f == NULL || fuzzy_hash_file(f, res.get())) {
		return "";
	}
	return std::string(res.get());
}

std::string hash_buffer(const std::vector<boost::uint8_t>& bytes)
{
	boost::shared_array<char> res = boost::shared_array<char>(new char[FUZZY_MAX_RESULT]);
	if (fuzzy_hash_buf(&bytes[0], bytes.size(), res.get())) {
		return "";
	}
	return std::string(res.get());
}

}
