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