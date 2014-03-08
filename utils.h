#ifndef _UTILS_H_
#define _UTILS_H_

#include <string>

namespace utils 
{

/**
 *	@brief	Reads a null-terminated ASCII string in a file.
 */
std::string read_ascii_string(FILE* f);

}

#endif