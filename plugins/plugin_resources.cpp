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

#include "yara/yara_wrapper.h"

// TODO: Remove when Yara doesn't mask get_object anymore
#undef get_object

#include "plugin_framework/plugin_interface.h"
#include "plugin_framework/auto_register.h"

namespace plugin {

class ResourcesPlugin : public IPlugin
{
public:
	int get_api_version() override { return 1; }

	pString get_id() const override {
		return boost::make_shared<std::string>("resources");
	}

	pString get_description() const override {
		return boost::make_shared<std::string>("Analyzes the program's resources.");
	}

	pResult analyze(const mana::PE& pe) override
	{
		pResult res = create_result();
		yara::Yara y;

		if (!y.load_rules("yara_rules/magic.yara")) {
			return res;
		}

		mana::shared_resources r = pe.get_resources();
		unsigned int size = 0;
		for (auto it = r->begin() ; it != r->end() ; ++it)
		{
			size += (*it)->get_size();
			yara::const_matches matches = y.scan_bytes(*(*it)->get_raw_data());
			if (matches->size() > 0)
			{
				for (int i = 0 ; i < matches->size() ; ++i)
				{
					std::string ext = matches->at(i)->operator[]("extension");
					if (ext == ".exe" || ext == ".sys" || ext == ".cab")
					{
						res->raise_level(MALICIOUS);
						std::stringstream ss;
						ss << "Resource " << *(*it)->get_name() << " detected as a " << matches->at(i)->operator[]("description") << ".";
						if (matches->size() > 1) {
							ss << " It is also possibly a polyglot file.";
						}
						res->add_information(ss.str());
					}
					else if (ext == ".pdf")
					{
						res->raise_level(SUSPICIOUS);
						std::stringstream ss;
						ss << "Resource " << *(*it)->get_name() << " detected as a PDF document.";
						res->add_information(ss.str());
					}
				}
			}
			else
			{
				if ((*it)->get_entropy() > 7.)
				{
					std::stringstream ss;
					ss << "Resource " << *(*it)->get_name() << " is possibly compressed or encrypted.";
					res->add_information(ss.str());
				}
			}
		}

		float ratio = (float) size / (float) pe.get_filesize();
		if (ratio > .75)
		{
			std::stringstream ss;
			ss << "Resources amount for "  << ratio*100 << "% of the executable.";
			res->raise_level(SUSPICIOUS);
			res->add_information(ss.str());
		}

		if (res->get_level() > NO_OPINION) {
			res->set_summary("The PE is possibly a dropper.");
		}
		else if (res->get_information()->size() > 0) {
			res->set_summary("The PE contains encrypted or compressed resources.");
		}

		return res;
	}
};

AutoRegister<ResourcesPlugin> auto_register_resources;

} // !namespace plugin
