#include <iostream>
#include <iterator>
#include <string>
#include <vector>
#include <algorithm>

#include "pe.h"
#include "mandiant_modules.h"
#include "yara_modules.h"

int check_sections(void                  *N,
                   VA                    secBase,
              	   std::string           &secName,
              	   image_section_header  s,
             	   bounded_buffer        *data)
{
	// Check the section names against a list of known names.
	std::string names[] = {".text", ".data", ".rdata", ".rsrc", ".idata", ".edata", ".pdata", ".reloc"};
	std::vector<std::string> common_names(names, names + 8);
	if (common_names.end() == std::find(common_names.begin(), common_names.end(), secName)) {
		std::cout << "Suspicious section name found: " << secName << std::endl;
	}
	return 0;
}



int main(int argc, char** argv)
{
	if (argc < 2) {
		return 1;
	}
	sg::PE pe(argv[1]);
	modules::check_sections(pe);
	modules::check_rsrc_size(pe);
	modules::peid_signature(pe);

	return 0;
}
