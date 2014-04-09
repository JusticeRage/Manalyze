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

#include "nt_values.h"

namespace nt {



std::vector<std::string> translate_to_flags(int value, const flag_dict& dict)
{
	std::vector<std::string> res;
	for (flag_dict::const_iterator it = dict.begin() ; it != dict.end() ; ++it)
	{
		if ((value & it->second) != 0) { // The flag is present in the value
			res.push_back(it->first);
		}
	}
	return res;
}

std::string translate_to_flag(int value, const flag_dict& dict)
{
	for (flag_dict::const_iterator it = dict.begin() ; it != dict.end() ; ++it)
	{
		if (value == it->second) {
			return it->first;
		}
	}
	return "UNKNOWN";
}

}