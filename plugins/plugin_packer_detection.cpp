/*
    This file is part of Manalyze.

    Manalyze is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Manalyze is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Manalyze.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <sstream>
#include <algorithm>
#include <map>
#include <string>
#include <boost/assign/list_of.hpp>
#include <boost/regex.hpp>

#include "plugin_framework/plugin_interface.h"
#include "plugin_framework/auto_register.h"

#include "nt_values.h"

namespace plugin {

// Check the section names against a list of known names.
const std::vector<std::string> common_names = boost::assign::list_of(".text")
																	(".data")
																	(".rdata")
																	(".rsrc")
																	(".idata")
																	(".edata")
																	(".pdata")
																	(".reloc")
																	(".bss")
																	(".tls")
																	(".sxdata"); // Apparently related to SafeSEH.

// Also check for known packer section names (i.e. UPX0, etc.)
const std::map<std::string, std::string> KNOWN_PACKER_SECTIONS =
	boost::assign::map_list_of ("\\.ndata",	 "The PE is an NSIS installer.")
							   ("upx[0-9]", "The PE is packed with UPX.");

class PackerDetectionPlugin : public IPlugin
{
public:
	int get_api_version() { return 1; }

	pString get_id() const {
		return pString(new std::string("packer"));
	}

	pString get_description() const {
		return pString(new std::string("Tries to structurally detect packer presence."));
	}

	pResult analyze(const sg::PE& pe)
	{
		pResult res = create_result();

		sg::shared_sections sections = pe.get_sections();
		for (sg::shared_sections::element_type::const_iterator it = sections->begin() ; it != sections->end() ; ++it)
		{
			if (common_names.end() == std::find(common_names.begin(), common_names.end(), *(*it)->get_name()))
			{
				// Check section name against known packer section names and set summary accordingly.
				for (std::map<std::string, std::string>::const_iterator it2 = KNOWN_PACKER_SECTIONS.begin() ;
					it2 != KNOWN_PACKER_SECTIONS.end() ; ++it2)
				{
					boost::regex e(it2->first, boost::regex::icase);
					if (boost::regex_match(*(*it)->get_name(), e)) {
						res->set_summary(it2->second);
					}
				}

				std::stringstream ss;
				ss << "Unusual section name found: " << *(*it)->get_name();
				res->add_information(ss.str());
				res->raise_level(SUSPICIOUS);
			}

			int characteristics = (*it)->get_characteristics();
			if (characteristics & nt::SECTION_CHARACTERISTICS.at("IMAGE_SCN_MEM_EXECUTE") &&
				characteristics & nt::SECTION_CHARACTERISTICS.at("IMAGE_SCN_MEM_WRITE"))
			{
				std::stringstream ss;
				ss << "Section " << *(*it)->get_name() << " is both writable and executable.";
				res->add_information(ss.str());
				res->raise_level(SUSPICIOUS);
			}

			if ((*it)->get_size_of_raw_data() == 0) { // TODO: Report this in a "structure" plugin?
				continue;
			}

			double entropy = (*it)->get_entropy();
			if (entropy > 7.)
			{
				std::stringstream ss;
				ss << "Section " << *(*it)->get_name() << " has an unusually high entropy (" << entropy << ").";
				res->raise_level(SUSPICIOUS);
			}
		}

		// A low number of imports indicates that the binary is packed.
		sg::const_shared_strings imports = pe.find_imports(".*"); // Get all imports

		// Read the minimum import number from the configuration
		unsigned int min_imports;
		if (!_config->count("min_imports")) {
			min_imports = 10;
		}
		else
        {
			try {
				min_imports = std::stoi(_config->at("min_imports"));
			}
			catch (std::invalid_argument)
            {
                PRINT_WARNING << "Could not parse packer.min_imports in the configuration file." << std::endl;
				min_imports = 10;
			}
		}

		if (imports->size() < min_imports)
		{
			std::stringstream ss;
			ss << "The PE only has " << imports->size() << " import(s).";
			res->add_information(ss.str());
			res->raise_level(SUSPICIOUS);
		}

		if (res->get_level() != NO_OPINION && res->get_summary() == NULL) {
			res->set_summary("The PE is possibly packed.");
		}

		return res;
	}
};

AutoRegister<PackerDetectionPlugin> auto_register_packer;

} // !namespace plugin
