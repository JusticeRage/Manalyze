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
#include "plugin_framework/auto_register.h"

namespace plugin {

class ExploitMitigationsPlugin : public IPlugin
{
    int get_api_version() const override { return 1; }

    pString get_id() const override {
        return boost::make_shared<std::string>("mitigation");
    }

    pString get_description() const override {
        return boost::make_shared<std::string>("Displays the enabled exploit mitigation techniques (DEP, ASLR, etc.).");
    }

    pResult analyze(const mana::PE& pe) override
    {
        pResult res = create_result();
        auto ioh = pe.get_image_optional_header();
        if (!ioh) {
            return res;
        }
        auto characteristics = *nt::translate_to_flags(ioh->DllCharacteristics, nt::DLL_CHARACTERISTICS);
        auto config = pe.get_config();

        if (config)
        {
            // /GS
            if (config->SecurityCookie != 0) {
                res->add_information("Stack Canary", "enabled");
            }
            else {
                res->add_information("Stack Canary", "disabled");
            }
        }
        else
        {
            // Actually, this may not be absolutely true. Some very old binaries may still have /GS enabled.
            // Add a Yara rule to detect the stack cookie's default value?
            res->add_information("Stack Canary", "disabled");
        }

        // SafeSEH
        if (std::find(characteristics.begin(), characteristics.end(), "IMAGE_DLLCHARACTERISTICS_NO_SEH") !=
            characteristics.end() || !config) {
            res->add_information("SafeSEH", "disabled");
        }
        else
        {
            std::stringstream ss;
			ss << "enabled (" << config->SEHandlerCount << " registered handler" << (config->SEHandlerCount == 1 ? "" : "s") << ")";
            res->add_information("SafeSEH", ss.str());
        }

        // ASLR
        if (std::find(characteristics.begin(), characteristics.end(), "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE") !=
            characteristics.end()) {
            res->add_information("ASLR", "enabled");
        }
        else {
            res->add_information("ASLR", "disabled");
        }

        // DEP
        if (std::find(characteristics.begin(), characteristics.end(), "IMAGE_DLLCHARACTERISTICS_NX_COMPAT") !=
            characteristics.end()) {
            res->add_information("DEP", "enabled");
        }
        else {
            res->add_information("DEP", "disabled");
        }

        if (res->get_information()->size() > 0) {
            res->set_summary("The following exploit mitigation techniques have been detected");
        }

		// CFG
		if (std::find(characteristics.begin(), characteristics.end(), "IMAGE_DLLCHARACTERISTICS_GUARD_CF") !=
			characteristics.end()) {
			res->add_information("CFG", "enabled");
		}
		else {
			res->add_information("CFG", "disabled");
		}

        return res;
    }
};

AutoRegister<ExploitMitigationsPlugin> auto_register_exploitmitigations;

} // !namespace plugin
