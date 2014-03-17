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

#include <iostream>
#include <iterator>
#include <string>
#include <vector>
#include <algorithm>

#include "pe.h"
#include "resources.h"
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
	std::cout << "File size: " << pe.get_filesize() << std::endl << std::endl;

	pe.dump_dos_header();
	pe.dump_pe_header();
	pe.dump_image_optional_header();
	pe.dump_section_table();
	pe.dump_imports();
	pe.dump_exports();
	pe.dump_resources();
	pe.dump_version_info();

	//pe.extract_resources("extracted_resources");

	//modules::peid_signature(pe);

	return 0;
}
