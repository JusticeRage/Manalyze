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

#include <sstream>
#include <algorithm>
#include <boost/assign/list_of.hpp>

#include "plugin_framework/plugin_interface.h"
#include "plugin_framework/auto_register.h"

namespace plugin {

class PackerDetectionPlugin : public IPlugin
{
public:
	int get_api_version() { return 1; }
	
	pString get_id() { 
		return pString(new std::string("packer"));
	}

	pString get_description() { 
		return pString(new std::string("Tries to structurally detect packer presence."));
	}

	pResult analyze(const sg::PE& pe) 
	{
		pResult res(new Result());
		// Check the section names against a list of known names.
		std::vector<std::string> common_names = boost::assign::list_of(".text")
																	  (".data")
																	  (".rdata")
																	  (".rsrc")
																	  (".idata")
																	  (".edata")
																	  (".pdata")
																	  (".reloc")
																	  (".bss");

		bool suspicious = false;

		std::vector<sg::pSection> sections = pe.get_sections();
		for (std::vector<sg::pSection>::iterator it = sections.begin() ; it != sections.end() ; ++it)
		{
			if (common_names.end() == std::find(common_names.begin(), common_names.end(), (*it)->get_name())) 
			{
				std::stringstream ss;
				ss << "Unusual section name found: " << (*it)->get_name();
				res->add_information(ss.str());
				suspicious = true;
			}
		}

		// TODO: Calculate entropy

		// A low number of imports indicates that the binary is packed.
		std::vector<std::string> imports = pe.find_imports(".*"); // Get all imports
		if (imports.size() < 10) // TODO: How much is too low?
		{
			std::stringstream ss;
			ss << "The PE only has " << imports.size() << " import(s).";
			res->add_information(ss.str());
			suspicious = true;
		}

		if (suspicious)
		{
			res->set_level(Result::SUSPICIOUS);
			res->set_summary("The PE is possibly packed.");
		}

		return res;
	}
};

AutoRegister<PackerDetectionPlugin> auto_register;

} // !namespace plugin