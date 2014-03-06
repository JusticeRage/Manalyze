#include <iostream>
#include <iterator>
#include <string>
#include <vector>
#include <algorithm>

#include "pe.h"
#include "mandiant_modules.h"
#include "yara_modules.h"

int main(int argc, char** argv)
{
	if (argc < 2) {
		return 1;
	}
	std::cout << "*************************************** [ SGStatic ] ***" << std::endl;

	sg::PE pe(argv[1]);

	std::cout << "Input file: " << pe.get_path() << std::endl;
	//modules::peid_signature(pe);
	std::cout << "File size: " << pe.get_filesize() << std::endl << std::endl;

	pe.dump_dos_header();
	pe.dump_pe_header();
	pe.dump_image_optional_header();
	pe.dump_section_table();

	std::cin.get();
	return 0;
}
