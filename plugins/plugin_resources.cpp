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

class ResourcesPlugin : public IPlugin
{
public:
	int get_api_version() const override { return 1; }

	pString get_id() const override {
		return boost::make_shared<std::string>("resources");
	}

    // ----------------------------------------------------------------------------

	pString get_description() const override {
		return boost::make_shared<std::string>("Analyzes the program's resources.");
	}

    // ----------------------------------------------------------------------------

    /**
     * @brief   This function inspects the timestamps of the resources.
     * 
     * It makes sure that the reported timestamps match the one contained in the PE header.
     * 
     * @param   pe  The PE file to analyze.
     * @param   res The result object to fill.
     */
    void check_resource_timestamps(const mana::PE& pe, pResult res)
	{
        const auto r = pe.get_resources();
        const auto pe_timestamp = boost::posix_time::from_time_t(pe.get_pe_header()->TimeDateStamp);
        auto timestamps = std::set<std::string>();
        auto timezones = std::set<int>();
        for (const auto& it : *r)
        {
            if (it->get_timestamp() == 0) { // Ignore empty timestamps.
                continue;
            }

            utils::pptime res_timestamp;
            // Some compilers seem to use posix times as timestamps. Determine which situation we are in.
            if (utils::is_actually_posix(it->get_timestamp(), pe.get_pe_header()->TimeDateStamp)) {
                res_timestamp = boost::make_shared<btime::ptime>(boost::posix_time::from_time_t(it->get_timestamp()));
            }
            else {
                res_timestamp = utils::dosdate_to_btime(it->get_timestamp());
            }
            if (!res_timestamp) { // Ignore un-convertable timestamps.
                continue;
            }

            // Create a set of timestamps which differ from the one reported in the PE header.
            auto delta = *res_timestamp - pe_timestamp;
            // There might be a slight delta between the PE timestamp and the one found in the resources.
            // Assume nobody will tamper them to fake the compilation date by less than 12 hours.
            if (delta > btime::hours(12) || delta < btime::hours(-12)) {
                timestamps.insert(*utils::dosdate_to_string(it->get_timestamp()));
            }

            // I have noticed that some timestamps differ from exactly [1-12] hours.
            // Could it be that something in the build chain uses local timestamps?
            // Report it if we have a delta of exactly 1-12h.

            auto hours = delta.hours();
            // There can be a delta of 1 second between the two timestamps, possibly due to delays during the compilation.
            // Account for it by rounding up to the next hour if needed.
            if (abs(delta.minutes()) == 59 && abs(delta.seconds()) > 50) 
            {
                if (hours < 0) {
                    hours -= 1;
                }
                else {
                    hours += 1;
                }
            }

            if (hours != 0 && abs(hours) <= 12 &&
                timezones.find(hours) == timezones.end())
            {
                if (abs(delta.minutes()) == 59 || abs(delta.minutes()) <= 1) {
                    std::stringstream ss;
                    ss << "The binary may have been compiled on a machine in the UTC" << std::showpos << hours << " timezone.";
                    res->add_information(ss.str());
                    timezones.insert(hours);
                }
            }
        }
        if (!timestamps.empty()) // New timestamps have been found.
        {
            res->raise_level(SUSPICIOUS);
            res->set_summary("The PE header may have been manually modified.");
            auto info = boost::make_shared<io::OutputTreeNode>("The resource timestamps differ from the PE header",
                io::OutputTreeNode::STRINGS,
                io::OutputTreeNode::NEW_LINE);
            for (const auto& timestamp : timestamps) {
                info->append(timestamp);
            }
            res->add_information(info);
        }
	}

    // ----------------------------------------------------------------------------

	pResult analyze(const mana::PE& pe) override
	{
		pResult res = create_result();
		yara::Yara y;

		if (!y.load_rules("yara_rules/magic.yara")) {
			return res;
		}

		const auto r = pe.get_resources();
		if (!r) {
			return res;
		}
		unsigned int size = 0;
		for (auto& it : *r)
		{
			// In some packed executables, resources still keep their original file size, which causes
			// them to become bigger than the file itself. Disregard those cases when they happen
			// because they make the resource to filesize ratio bigger than 1. 
			// These cases will be reported by the packer detection plugin.
			if (it->get_size() < pe.get_filesize()) {
				size += it->get_size();
			}
			yara::const_matches matches = y.scan_bytes(*it->get_raw_data());
			if (matches && !matches->empty())
			{
				for (size_t i = 0 ; i < matches->size() ; ++i)
				{
					const std::string ext = matches->at(i)->operator[]("extension");
					if (ext == ".exe" || ext == ".sys" || ext == ".cab")
					{
						res->raise_level(MALICIOUS);
						std::stringstream ss;
						ss << "Resource " << *it->get_name() << " detected as a " << matches->at(i)->operator[]("description") << ".";
						if (matches->size() > 1) {
							ss << " It is also possibly a polyglot file.";
						}
						res->add_information(ss.str());
					}
					else if (ext == ".pdf")
					{
						res->raise_level(SUSPICIOUS);
						std::stringstream ss;
						ss << "Resource " << *it->get_name() << " detected as a PDF document.";
						res->add_information(ss.str());
					}
				}
			}
			else
			{
				if (it->get_entropy() > 7.)
				{
					std::stringstream ss;
					ss << "Resource " << *it->get_name() << " is possibly compressed or encrypted.";
					res->add_information(ss.str());
				}
			}
		}

        // Check for anomalies in the resource timestamps.
        check_resource_timestamps(pe, res);

		const double ratio = static_cast<double>(size) / static_cast<double>(pe.get_filesize());
		if (ratio > .75)
		{
			std::stringstream ss;
			ss << "Resources amount for "  << ratio*100 << "% of the executable.";
			res->raise_level(SUSPICIOUS);
			res->add_information(ss.str());
		}

		if (res->get_level() > NO_OPINION && !res->get_summary()) {
			res->set_summary("The PE is possibly a dropper.");
		}
		else if (res->get_information()->size() > 0 && !res->get_summary()) {
			res->set_summary("The PE's resources present abnormal characteristics.");
		}

		return res;
	}
};

AutoRegister<ResourcesPlugin> auto_register_resources;

} // !namespace plugin
