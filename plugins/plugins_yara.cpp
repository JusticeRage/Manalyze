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

// TODO: Remove when Yara doesn't mask get_object anymore
#undef get_object

#include "plugin_framework/plugin_interface.h"
#include "plugin_framework/auto_register.h"

namespace plugin
{

class YaraPlugin : public IPlugin
{

public:
	YaraPlugin(const std::string& rule_file) : _rule_file(rule_file) {}

	/**
	 *	@brief	Helper function designed to generically prepare a result based on a Yara scan.
	 *
	 *	@param	const sg::PE& pe The PE to scan.
	 *	const std::string& summary The summary to set if there is a match.
	 *	Result::LEVEL level The threat level to set if there is a match.
	 *	const std::string& meta_field_name The meta field name (of the yara rule) to query to
	 *									   extract results.
	 *	bool show_strings Adds the matched strings/patterns to the result.
	 *
	 *	@return	A pResult detailing the findings of the scan.
	 */
	pResult scan(const sg::PE& pe, const std::string& summary, LEVEL level, const std::string& meta_field_name, bool show_strings = false)
	{
		pResult res = create_result();
		if (!_load_rules()) {
			return res;
		}

		yara::const_matches m = _engine.scan_file(*pe.get_path(), pe.create_manape_module_data());
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
					io::pNode output = io::pNode(new io::OutputTreeNode((*it)->operator[](meta_field_name),
						io::OutputTreeNode::STRINGS, io::OutputTreeNode::NEW_LINE));

					std::set<std::string> found = (*it)->get_found_strings();
					for (std::set<std::string>::iterator it2 = found.begin() ; it2 != found.end() ; ++it2) {
						output->append(*it2);
					}
					res->add_information(output);
				}
			}
		}

		return res;
	}

	int get_api_version() override { return 1; }

private:
	std::string _rule_file;
	yara::Yara _engine;

	bool _load_rules()
	{
		if (!_engine.load_rules(_rule_file))
		{
			PRINT_ERROR << "Could not load " << _rule_file << "!" << std::endl;
			return false;
		}
		return true;
	}

};

class ClamavPlugin : public YaraPlugin
{
public:
	ClamavPlugin() : YaraPlugin("yara_rules/clamav.yara") {}

	pResult analyze(const sg::PE& pe) override {
		return scan(pe, "Matching ClamAV signature(s):", MALICIOUS, "signature");
	}

	pString get_id() const override {
		return pString (new std::string("clamav"));
	}

	pString  get_description() const override {
		return pString (new std::string("Scans the binary with ClamAV virus definitions."));
	}
};

class CompilerDetectionPlugin : public YaraPlugin
{
public:
	CompilerDetectionPlugin() : YaraPlugin("yara_rules/compilers.yara") {}

	pResult analyze(const sg::PE& pe) override {
		return scan(pe, "Matching compiler(s):", NO_OPINION, "description");
	}

	boost::shared_ptr<std::string> get_id() const override {
		return boost::shared_ptr<std::string>(new std::string("compilers"));
	}

	boost::shared_ptr<std::string> get_description() const override {
		return boost::shared_ptr<std::string>(new std::string("Tries to determine which compiler generated the binary."));
	}
};

class PEiDPlugin : public YaraPlugin
{
public:
	PEiDPlugin() : YaraPlugin("yara_rules/peid.yara") {}

	pResult analyze(const sg::PE& pe) {
		return scan(pe, "PEiD Signature:", SUSPICIOUS, "packer_name");
	}

	boost::shared_ptr<std::string> get_id() const override {
		return boost::shared_ptr<std::string>(new std::string("peid"));
	}

	boost::shared_ptr<std::string> get_description() const override {
		return boost::shared_ptr<std::string>(new std::string("Returns the PEiD signature of the binary."));
	}
};


class SuspiciousStringsPlugin : public YaraPlugin
{
public:
	SuspiciousStringsPlugin() : YaraPlugin("yara_rules/suspicious_strings.yara") {}

	pResult analyze(const sg::PE& pe) override {
		return scan(pe, "Strings found in the binary may indicate undesirable behavior:", SUSPICIOUS, "description", true);
	}

	boost::shared_ptr<std::string> get_id() const override {
		return boost::shared_ptr<std::string>(new std::string("strings"));
	}

	boost::shared_ptr<std::string> get_description() const override {
		return boost::shared_ptr<std::string>(new std::string("Looks for suspicious strings (anti-VM, process names...)."));
	}
};

class FindCryptPlugin : public YaraPlugin
{
public:
	FindCryptPlugin() : YaraPlugin("yara_rules/findcrypt.yara") {}

	pResult analyze(const sg::PE& pe) override
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
		return boost::shared_ptr<std::string>(new std::string("findcrypt"));
	}

	boost::shared_ptr<std::string> get_description() const override {
		return boost::shared_ptr<std::string>(new std::string("Detects embedded cryptographic constants."));
	}
};

AutoRegister<ClamavPlugin> auto_register_clamav;
AutoRegister<CompilerDetectionPlugin> auto_register_compiler;
AutoRegister<PEiDPlugin> auto_register_peid;
AutoRegister<SuspiciousStringsPlugin> auto_register_strings;
AutoRegister<FindCryptPlugin> auto_register_findcrypt;

}
