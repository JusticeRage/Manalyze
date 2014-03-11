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

bool read_ascii_string_at_offset(FILE* f, unsigned int offset, std::string& out)
{
	unsigned int saved_offset = ftell(f);
	if (saved_offset == -1 || fseek(f, offset, SEEK_SET))
	{
		std::cerr << "[!] Error: Could not reach offset 0x" << std::hex << offset << "." << std::endl;
		return false;
	}
	out = read_ascii_string(f);
	return !fseek(f, saved_offset, SEEK_SET) && out != "";
}

bool is_address_in_section(unsigned int rva, sg::pimage_section_header section, bool check_raw_size)
{
	if (!check_raw_size) {
		return section->VirtualAddress <= rva && rva < section->VirtualAddress + section->VirtualSize;
	}
	else {
		return section->VirtualAddress <= rva && rva < section->VirtualAddress + section->SizeOfRawData;
	}
}

sg::pimage_section_header find_section(unsigned int rva, const std::vector<sg::pimage_section_header>& section_list)
{
	sg::pimage_section_header res = sg::pimage_section_header();
	std::vector<sg::pimage_section_header>::const_iterator it;
	for (it = section_list.begin() ; it != section_list.end() ; ++it)
	{
		if (is_address_in_section(rva, *it)) 
		{
			res = *it;
			break;
		}
	}

	if (!res) // VirtualSize may be erroneous. Check with RawSizeofData.
	{
		for (it = section_list.begin() ; it != section_list.end() ; ++it)
		{
			if (is_address_in_section(rva, *it, true)) 
			{
				res = *it;
				break;
			}
		}
	}

	return res;
}

}