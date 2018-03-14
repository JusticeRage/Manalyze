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

#include "plugin_framework/plugin_interface.h"
#include "yara/yara_wrapper.h"

namespace plugin {

/**
 *	@brief	Looks for well-known company names in the RT_VERSION resource of the PE.
 *
 *	The idea behind this check is that if the binary is unsigned but pretends to come from
 *	Microsoft, Adobe, etc. then it is very likely a malware.
 *
 *	@param	pe The PE to analyze.
 *	@param	res The result to update if something is found.
 */
void check_version_info(const mana::PE& pe, pResult res)
{
	// Find the VERSION_INFO resource
	auto resources = pe.get_resources();
	mana::pResource version_info;
	for (auto it = resources->begin() ; it != resources->end() ; ++it)
	{
		if (*(*it)->get_type() == "RT_VERSION")
		{
			version_info = *it;
			break;
		}
	}

	// No RT_VERSION resource, we're done.
	if (!version_info) {
		return;
	}

	yara::Yara y;
	if (!y.load_rules("yara_rules/company_names.yara"))
	{
		std::cerr << "Could not load company_names.yara!" << std::endl;
		return;
	}
	auto m = y.scan_bytes(*version_info->get_raw_data());
	if (m && m->size() > 0)
	{
		std::stringstream ss;
		auto found_strings = m->at(0)->get_found_strings();
		if (found_strings.size() > 0)
		{
			res->set_summary("The program tries to mislead users about its origins.");
			if ((m->at(0)->get_metadata()["type"] == "homograph")) {
				res->add_information("The PE uses homographs to impersonate a well known company!");
			}
			else
			{
				ss << "The PE pretends to be from " << *(m->at(0)->get_found_strings().begin())
				   << " but is not signed!";
				res->add_information(ss.str());
			}

			res->raise_level(MALICIOUS);
		}
	}
}

} // namespace plugin
