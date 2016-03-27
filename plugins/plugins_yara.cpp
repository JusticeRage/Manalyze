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

#include "yara/yara_wrapper.h"
// The structure used to communicate with the yara ManaPE module.
#include "yara/modules/manape_data.h"

// TODO: Remove when Yara doesn't mask get_object anymore
#undef get_object

#include "plugin_framework/plugin_interface.h"
#include "plugin_framework/auto_register.h"

namespace plugin
{



// Provide a destructor for the structure sent to Yara.
void delete_manape_module_data(manape_data* data)
{
    if (data != nullptr && data->sections != nullptr) {
        free(data->sections);
    }
    if (data != nullptr) {
        delete data;
    }
}

// ----------------------------------------------------------------------------

class YaraPlugin : public IPlugin
{

public:
	YaraPlugin(const std::string& rule_file) : _rule_file(rule_file) {}

	/**
	 *	@brief	Helper function designed to generically prepare a result based on a Yara scan.
	 *
	 *	@param	const mana::PE& pe The PE to scan.
	 *	const std::string& summary The summary to set if there is a match.
	 *	Result::LEVEL level The threat level to set if there is a match.
	 *	const std::string& meta_field_name The meta field name (of the yara rule) to query to
	 *									   extract results.
	 *	bool show_strings Adds the matched strings/patterns to the result.
	 *
	 *	@return	A pResult detailing the findings of the scan.
	 */
	pResult scan(const mana::PE& pe, const std::string& summary, LEVEL level, const std::string& meta_field_name, bool show_strings = false)
	{
		pResult res = create_result();
		if (!_load_rules()) {
			return res;
		}

		yara::const_matches m = _engine.scan_file(*pe.get_path(), _create_manape_module_data(pe));
		if (m && m->size() > 0)
		{
			res->set_level(level);
			res->set_summary(summary);
			for (yara::match_vector::const_iterator it = m->begin() ; it != m->end() ; ++it)
			{
				if (!show_strings) {
					res->add_information((*it)->operator[](meta_field_name));
				}
				else
				{
					io::pNode output = boost::make_shared<io::OutputTreeNode>((*it)->operator[](meta_field_name),
						io::OutputTreeNode::STRINGS, io::OutputTreeNode::NEW_LINE);

					std::set<std::string> found = (*it)->get_found_strings();
					for (auto it2 = found.begin() ; it2 != found.end() ; ++it2) {
						output->append(*it2);
					}
					res->add_information(output);
				}
			}
		}

		return res;
	}

	int get_api_version() const override { return 1; }

protected:
	std::string _rule_file;
	yara::Yara _engine;

	virtual bool _load_rules()
	{
		if (!_engine.load_rules(_rule_file))
		{
			PRINT_ERROR << "Could not load " << _rule_file << "!" << std::endl;
			return false;
		}
		return true;
	}

private:
	/**
	 *	@brief	Creates the data used by the ManaPE Yara module.
	 *
	 *	This extracts a few of the PE's parsed elements and stores them inside a structure that the ManaPE Yara module
	 *	can use to do its work.
	 *	The manape_data object contains address information (entry point, sections, ...). Passing them to Yara prevents
	 *	me from using their built in PE parser (since manalyze has already done all the work).
	 */
	boost::shared_ptr<manape_data> _create_manape_module_data(const mana::PE& pe)
	{
        boost::shared_ptr<manape_data> res(new manape_data, delete_manape_module_data);
        auto ioh = pe.get_image_optional_header();
        auto sections = pe.get_sections();

        if (ioh) {
            res->entrypoint = ioh->AddressOfEntryPoint;
        }

        if (sections == nullptr)
        {
            res->number_of_sections = 0;
            res->sections = nullptr;
        }
        else
        {
            res->number_of_sections = sections->size();
            res->sections = (manape_file_portion*) malloc(res->number_of_sections * sizeof(manape_file_portion));
            if (res->sections != nullptr)
            {
                for (boost::uint32_t i = 0 ; i < res->number_of_sections ; ++i)
                {
                    res->sections[i].start = sections->at(i)->get_pointer_to_raw_data();
                    res->sections[i].size = sections->at(i)->get_size_of_raw_data();
                }
            }
            else
            {
                PRINT_WARNING << "Not enough memory to allocate data for the MANAPE module!"
                << DEBUG_INFO << std::endl;
                res->number_of_sections = 0;
            }
        }

        // Add VERSION_INFO location for some ClamAV signatures
        auto resources = pe.get_resources();
        for (auto it = resources->begin() ; it != resources->end() ; ++it)
        {
            if (*(*it)->get_type() == "RT_VERSION")
            {
                res->version_info.start = (*it)->get_offset();
                res->version_info.size = (*it)->get_size();
                break;
            }
        }
        return res;
	}

};

class ClamavPlugin : public YaraPlugin
{
public:
	ClamavPlugin() : YaraPlugin("yara_rules/clamav.yara") {}

	pResult analyze(const mana::PE& pe) override {
		return scan(pe, "Matching ClamAV signature(s):", MALICIOUS, "signature");
	}

	pString get_id() const override {
		return boost::make_shared<std::string>("clamav");
	}

	pString  get_description() const override {
		return boost::make_shared<std::string>("Scans the binary with ClamAV virus definitions.");
	}

private:
	/**
	 *	@brief	This function is overriden only to display an error message specific to ClamAV
	 *			rules, which need to be generated manually.
	 *
	 *	@return	Whether the rules were loaded successfully.
	 */
	virtual bool _load_rules() override
	{
		if (!_engine.load_rules(_rule_file))
		{
			PRINT_ERROR << "ClamAV rules haven't been generated yet!" << std::endl;
			PRINT_ERROR << "Please run yara_rules/update_clamav_signatures.py to create them, "
				"and refer to the documentation for additional information." << std::endl;
			return false;
		}
		return true;
	}
};

class CompilerDetectionPlugin : public YaraPlugin
{
public:
	CompilerDetectionPlugin() : YaraPlugin("yara_rules/compilers.yara") {}

	pResult analyze(const mana::PE& pe) override {
		return scan(pe, "Matching compiler(s):", NO_OPINION, "description");
	}

	pString get_id() const override {
		return boost::make_shared<std::string>("compilers");
	}

	boost::shared_ptr<std::string> get_description() const override {
		return boost::make_shared<std::string>("Tries to determine which compiler generated the binary.");
	}
};

class PEiDPlugin : public YaraPlugin
{
public:
	PEiDPlugin() : YaraPlugin("yara_rules/peid.yara") {}

	pResult analyze(const mana::PE& pe) override {
		return scan(pe, "PEiD Signature:", SUSPICIOUS, "packer_name");
	}

	boost::shared_ptr<std::string> get_id() const override {
		return boost::make_shared<std::string>("peid");
	}

	boost::shared_ptr<std::string> get_description() const override {
		return boost::make_shared<std::string>("Returns the PEiD signature of the binary.");
	}
};


class SuspiciousStringsPlugin : public YaraPlugin
{
public:
	SuspiciousStringsPlugin() : YaraPlugin("yara_rules/suspicious_strings.yara") {}

	pResult analyze(const mana::PE& pe) override {
		return scan(pe, "Strings found in the binary may indicate undesirable behavior:", SUSPICIOUS, "description", true);
	}

	boost::shared_ptr<std::string> get_id() const override {
		return boost::make_shared<std::string>("strings");
	}

	boost::shared_ptr<std::string> get_description() const override {
		return boost::make_shared<std::string>("Looks for suspicious strings (anti-VM, process names...).");
	}
};

class FindCryptPlugin : public YaraPlugin
{
public:
	FindCryptPlugin() : YaraPlugin("yara_rules/findcrypt.yara") {}

	pResult analyze(const mana::PE& pe) override
	{
		pResult res = scan(pe, "Cryptographic algorithms detected in the binary:", NO_OPINION, "description");

		// Look for common cryptography libraries
		if (pe.find_imports(".*", "libssl(32)?.dll|libcrypto.dll")->size() > 0) {
			res->add_information("Imports functions from OpenSSL.");
		}
		if (pe.find_imports(".*", "cryptopp.dll")->size() > 0) {
			res->add_information("Imports functions from Crypto++");
		}
		if (pe.find_imports(".*", "botan.dll")->size() > 0) {
			res->add_information("Imports functions from Botan");
		}
		if (pe.find_imports("Crypt(.*)")->size() > 0) {
			res->add_information("Uses Microsoft's Cryptographic API");
		}

		return res;
	}

	boost::shared_ptr<std::string> get_id() const override {
		return boost::make_shared<std::string>("findcrypt");
	}

	boost::shared_ptr<std::string> get_description() const override {
		return boost::make_shared<std::string>("Detects embedded cryptographic constants.");
	}
};

AutoRegister<ClamavPlugin> auto_register_clamav;
AutoRegister<CompilerDetectionPlugin> auto_register_compiler;
AutoRegister<PEiDPlugin> auto_register_peid;
AutoRegister<SuspiciousStringsPlugin> auto_register_strings;
AutoRegister<FindCryptPlugin> auto_register_findcrypt;

}
