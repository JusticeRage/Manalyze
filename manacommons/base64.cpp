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

#include "manacommons/base64.h"

namespace utils {

pString b64encode(const std::vector<boost::uint8_t>& bytes)
{	
	if (bytes.size() == 0) {
		return boost::make_shared<std::string>("");
	}

	unsigned int padding = bytes.size() % 3;
	
	// Insert line breaks every 64 characters
	typedef	biter::insert_linebreaks<
		// Convert binary values to base64 characters
		biter::base64_from_binary<
			// Retrieve 6 bit integers from a sequence of 8 bit bytes
			biter::transform_width<const boost::uint8_t*, 6, 8> 
		> 
		,64
	> 
	base64_encode; // compose all the above operations in to a new iterator

	std::stringstream ss;
	std::copy(base64_encode(&bytes[0]), 
			  base64_encode(&bytes[0] + bytes.size()), 
			  std::ostream_iterator<char>(ss));

	if (padding != 0) {
		ss << std::string(3 - padding, '=');
	}
			  
	return boost::make_shared<std::string>(ss.str());
}

} // !namespace utils