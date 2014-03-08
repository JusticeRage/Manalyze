#include <stdio.h>

#include "utils.h"

namespace utils {

std::string read_ascii_string(FILE* f)
{
	std::string s = std::string();
	char c;
	while (1 == fread(&c, 1, 1, f))
	{
		if (c == '\0') {
			break;
		}
		s += c;
	}
	return s;
}

}