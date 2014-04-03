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

	/*
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
}*/

} // !namespace modules

#endif // !_MANDIANT_MODULES_
