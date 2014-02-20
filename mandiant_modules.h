#ifndef _MANDIANT_MODULES_
#define _MANDIANT_MODULES_

#include <string>
#include <vector>
#include <iterator>
#include <algorithm>
#include <iostream>

#include "pe.h"


namespace modules {

/**
 Detects non-standard section names, which could indicate packer presence.
 */
int check_sections(sg::PE& pe)
{
	// Check the section names against a list of known names.
	std::string names[] = {".text", ".data", ".rdata", ".rsrc", ".idata", ".edata", ".pdata", ".reloc"};
	std::vector<std::string> common_names(names, names + 8);
	for (std::vector<sg::p_section>::iterator it = pe.get_sections().begin() ; it != pe.get_sections().end() ; ++it)
	{
		if (common_names.end() == std::find(common_names.begin(), common_names.end(), (*it)->name)) {
			std::cout << "Suspicious section name found: " << (*it)->name << std::endl;
		}
	}
	return 0;
}

int check_rsrc_size(sg::PE& pe)
{
	sg::p_section s = pe.get_section(".rsrc");
	if (s)
	{
		size_t filesize = pe.get_filesize();
		float ratio = (float) s->size / (float) filesize;
		if (ratio > .75) {
			std::cout << "Resources amount for " << ratio*100 << "% of the executable. This is potentially a dropper." << std::endl;
		}
	}
	return 0;
}

} // !namespace modules

#endif // !_MANDIANT_MODULES_
