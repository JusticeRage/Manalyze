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
#include <set>

#include "yara/yara_wrapper.h"

// TODO: Remove when Yara doesn't mask get_object anymore
#undef get_object

#include "plugin_framework/plugin_interface.h"
#include "plugin_framework/auto_register.h"

namespace plugin {

class OverlayPlugin : public IPlugin
{
public:
	int get_api_version() const override { return 1; }

	pString get_id() const override {
		return boost::make_shared<std::string>("overlay");
	}

	pString get_description() const override {
		return boost::make_shared<std::string>("Analyzes data outside of the PE's boundaries.");
	}

	pResult analyze(const mana::PE& pe) override
	{
		pResult res = create_result();
        
        const auto overlay_bytes = pe.get_overlay_bytes();
        if (overlay_bytes == nullptr) {
            return res;
        }

        res->raise_level(SUSPICIOUS);
        res->set_summary("The file contains overlay data.");
        std::stringstream ss;
        ss << overlay_bytes->size() << " bytes of data starting at offset 0x" << std::hex << pe.get_filesize() - overlay_bytes->size() << ".";
        res->add_information(ss.str());

        // Try to detect the file type of the overlay data.
        yara::Yara y;
		if (!y.load_rules("yara_rules/magic.yara")) {
			return res;
		}
        yara::const_matches matches = y.scan_bytes(*overlay_bytes);
        if (matches && !matches->empty())
        {
            for (size_t i = 0; i < matches->size(); ++i)
            {
                res->raise_level(MALICIOUS);
                std::stringstream ss;
                ss << "The file contains a " << matches->at(i)->operator[]("description") << " after the PE data.";
                if (matches->size() > 1) {
                    ss << " It is also possibly a polyglot.";
                }
                res->add_information(ss.str());
            }
        }
        // No magic found: check the entropy to see if the data is encrypted.
        else 
        {
            const auto entropy = utils::shannon_entropy(*overlay_bytes);
            if (entropy > 7.) 
            {
                res->raise_level(SUSPICIOUS);
                std::stringstream ss;
                ss << "The overlay data has an entropy of " << entropy << " and is possibly compressed or encrypted.";
                res->add_information(ss.str());
            }
        }

        // Look at the ratio of overlay data.
        const double ratio = static_cast<double>(overlay_bytes->size()) / static_cast<double>(pe.get_filesize());
        if (ratio > .75)
        {
            std::stringstream ss;
            ss << "Overlay data amounts for " << ratio * 100 << "% of the executable.";
            res->raise_level(SUSPICIOUS);
            res->add_information(ss.str());
        }

		return res;
	}
};

AutoRegister<OverlayPlugin> auto_register_overlay;

} // !namespace plugin
