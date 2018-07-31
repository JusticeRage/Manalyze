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

		const auto r = pe.get_resources();
		if (!r) {
			return res;
		}
		unsigned int size = 0;
		for (auto& it : *r)
		{
			// In some packed executables, resources still keep their original file size, which causes
			// them to become bigger than the file itself. Disregard those cases when they happen
			// because they make the resource to filesize rario bigger than 1. 
			// These cases will be reported by the packer detection plugin.
			if (it->get_size() < pe.get_filesize()) {
				size += it->get_size();
			}
			yara::const_matches matches = y.scan_bytes(*it->get_raw_data());
			if (!matches->empty())
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

		// Check for anomalies in resource timestamps. Compare them as strings as they are not in the same format.
		const auto pe_timestamp = utils::timestamp_to_string(pe.get_pe_header()->TimeDateStamp);
		auto timestamps = std::set<std::string>();
		for (const auto& it : *r)
		{
			if (it->get_timestamp() == 0) { // Ignore empty timestamps.
				continue;
			}

			// Create a set of timestamps which differ from the one reported in the PE header.
			const auto res_timestamp = utils::dosdate_to_string(it->get_timestamp());
			if (*res_timestamp != *pe_timestamp) {
				timestamps.insert(*res_timestamp);
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
			res->set_summary("The PE contains encrypted or compressed resources.");
		}

		return res;
	}
};

AutoRegister<ResourcesPlugin> auto_register_resources;

} // !namespace plugin
