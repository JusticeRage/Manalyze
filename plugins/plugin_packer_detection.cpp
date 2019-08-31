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

#include "manape/nt_values.h"

namespace plugin {

// Check the section names against a list of known names.
const std::vector<std::string> common_names = boost::assign::list_of(".text")
                                                                    (".textbss")
                                                                    (".data")
                                                                    (".DATA")
                                                                    ("DATA")
                                                                    ("_RDATA")
                                                                    (".eh_fram")
                                                                    (".rdata")
                                                                    (".rsrc")
                                                                    (".idata")
                                                                    (".edata")
                                                                    (".pdata")
                                                                    (".rodata")
                                                                    (".reloc")
                                                                    (".bss")
                                                                    (".BSS")
                                                                    ("BSS")
                                                                    (".tls")
                                                                    (".sxdata") // Apparently related to SafeSEH.
                                                                    (".gfids")
                                                                    (".00cfg")
                                                                    (".code")
                                                                    ("CODE")
                                                                    (".crt")
                                                                    (".CRT")
                                                                    ("INIT");

// Also check for known packer section names (i.e. UPX0, etc.)
// This list was updated with information from
// http://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/
const std::map<std::string, std::string> KNOWN_PACKER_SECTIONS =
    boost::assign::map_list_of ("\\.ndata",     "The PE is an NSIS installer")
                               ("\\.?(upx|UPX)[0-9!]", "The PE is packed with UPX")
                               ("\\.(mpress|MPRESS)[0-9]", "The PE is packed with mpress")
                               ("\\.[Aa][Ss][Pp]ack", "The PE is packed with Aspack")
                               ("\\.adata", "The PE is packed with Aspack or Armadillo")
                               ("\\.boom", "The PE is packed with Boomerang List Builder")
                               ("\\.ccg", "The PE is packed with CCG")
                               ("\\.charmve|\\.pinclie", "The program is instrumented with PIN")
                               ("BitArts", "The PE is packed with Crunch 2.0")
                               ("DAStub", "The PE is packed with Dragon Armor")
                               ("\\.enigma(1|2)", "The PE is packed with Enigma Protector")
                               ("!EPack", "The PE is packed with Epack")
                               ("\\.gentee", "The PE is a gentee installer")
                               ("kkrunchy", "The PE is packed with kkrunchy")
                               ("\\.mackt", "The PE was fixed by ImpREC")
                               ("\\.MaskPE", "The PE is packed with MaskPE")
                               ("MEW", "The PE is packed with MEW")
                               ("\\.neolite?", "The PE is packed with Neolite")
                               ("\\.?nsp[012]", "The PE is packed with NsPack")
                               ("\\.RLPack", "The PE is packed with RLPack")
                               ("(pe|PE)([Bb]undle|[cC][12]([TM]O)?|Compact2)", "The PE is packed with PEBundle")
                               ("PELOCKnt", "This PE is packed with PELock")
                               ("\\.perplex", "This PE is packed with Perplex")
                               ("PESHiELD", "This PE is packed with PEShield")
                               ("\\.petite", "This PE is packed with Petite")
                               ("ProCrypt", "This PE is packed with ProCrypt")
                               ("\\.rmnet", "This PE is packed with Ramnit")
                               ("\\.RPCrypt|RCryptor", "This PE is packed with RPCrypt")
                               ("\\.seau", "This PE is packed with SeauSFX")
                               ("\\.shrink[123]", "This PE is packed with Shrinker")
                               ("\\.spack", "This PE is packed with Simple Pack (by bagie)")
                               ("\\.svkp", "This PE is packed with SVKP")
                               ("\\.taz", "The PE is packed with PESpin")
                               ("(\\.?Themida)|(WinLicen)", "This PE is packed with Themida")
                               ("\\.tsu(arch|stub)", "This PE is packed with TSULoader")
                               ("PEPACK!!", "This PE is packed with PEPack")
                               ("\\.(Upack|ByDwing)", "This PE is packed with Upack")
                               ("\\.vmp[012]", "This PE is packed with VMProtect")
                               ("VProtect", "This PE is packed with VProtect")
                               ("\\.winapi", "This PE was modified with API Override")
                               ("_winzip_", "This PE is a WinZip self-extractor")
                               ("\\.WWPACK", "This PE is packed with WWPACK")
                               ("\\.y(P|0da)", "This PE is packed with Y0da");

class PackerDetectionPlugin : public IPlugin
{
public:
    int get_api_version() const override { return 1; }

    pString get_id() const override {
        return boost::make_shared<std::string>("packer");
    }

    pString get_description() const override {
        return boost::make_shared<std::string>("Tries to structurally detect packer presence.");
    }

    void rich_header_tests(const mana::PE& pe, pResult res) const
    {
        auto rich = pe.get_rich_header();
        if (!rich) {
            return;
        }

        // Validate the checksum in the RICH header
        boost::uint32_t checksum = rich->file_offset;
        auto bytes = pe.get_raw_bytes(rich->file_offset);
        // Checksum of the DOS header
        for (unsigned int i = 0; i < rich->file_offset; ++i)
        {
            // Ignore e_lfanew.
            if (0x3c <= i && i < 0x40) {
                continue;
            }
            checksum += utils::rol32(bytes->at(i), i);
        }
        // Checksum of the @comp.ids.
        for (unsigned int i = 0; i < rich->values.size(); ++i)
        {
            auto v = rich->values.at(i);
            checksum += utils::rol32((std::get<0>(v) << 16) | std::get<1>(v), std::get<2>(v));
        }

        if (checksum != rich->xor_key)
        {
            res->raise_level(MALICIOUS);
            if (res->get_summary() == nullptr) {
                res->set_summary("The file headers were tampered with.");
            }
            res->add_information("The RICH header checksum is invalid.");
        }

        // Verify that the number of imports is consistent with the one reported in the header
        for (auto it = rich->values.begin() ; it != rich->values.end() ; ++it)
        {
            // Look for the "Total imports" @comp.id.
            if (std::get<0>(*it) == 1)
            {
                auto imports = pe.find_imports(".*");
                // For some reason, the number of imports present here seems to be wrong in a lot of goodware.
                // It seems however that that number is never smaller than the actual number of imports.
                if (std::get<2>(*it) < imports->size())
                {
                    if (res->get_summary() == nullptr) {
                        res->set_summary("The PE is packed or was manually edited.");
                    }
                    res->add_information("The number of imports reported in the RICH header is inconsistent.");
                    res->raise_level(SUSPICIOUS);
                }
            }
        }
    }

    pResult analyze(const mana::PE& pe) override
    {
        pResult res = create_result();

        // Analyze sections
        mana::shared_sections sections = pe.get_sections();
        for (mana::shared_sections::element_type::const_iterator it = sections->begin() ; it != sections->end() ; ++it)
        {
            if (common_names.end() == std::find(common_names.begin(), common_names.end(), *(*it)->get_name()))
            {
                // Check section name against known packer section names and set the summary accordingly.
                for (auto it2 = KNOWN_PACKER_SECTIONS.begin() ; it2 != KNOWN_PACKER_SECTIONS.end() ; ++it2)
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

            // Look for WX sections
            unsigned int characteristics = (*it)->get_characteristics();
            if (characteristics & nt::SECTION_CHARACTERISTICS.at("IMAGE_SCN_MEM_EXECUTE") &&
                characteristics & nt::SECTION_CHARACTERISTICS.at("IMAGE_SCN_MEM_WRITE"))
            {
                std::stringstream ss;
                ss << "Section " << *(*it)->get_name() << " is both writable and executable.";
                res->add_information(ss.str());
                res->raise_level(SUSPICIOUS);
            }

            // Check the section's entropy
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
        mana::const_shared_strings imports = pe.find_imports(".*"); // Get all imports

        // A single import could indicate that the file is a .NET executable; don't warn about that.
        if (imports->size() == 1)
        {
            auto mscoree = pe.find_imported_dlls("mscoree.dll");
            if (!mscoree->empty())
            {

                auto corexemain = mscoree->at(0)->get_imports();
                if (!corexemain->empty() && corexemain->at(0)->Name == "_CorExeMain") {
                    return res;
                }
            }
        }

        // Read the minimum import number from the configuration
        unsigned int min_imports;
        if (_config == nullptr || !_config->count("min_imports")) {
            min_imports = 10;
        }
        else
        {
            try {
                min_imports = std::stoi(_config->at("min_imports"));
            }
            catch (std::invalid_argument&)
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

        // Look for resources bigger than the file itself
        auto resources = pe.get_resources();
        boost::uint64_t sum = 0;
        for (auto r = resources->begin() ; r != resources->end() ; ++r) {
            sum += (*r)->get_size();
        }
        if (sum > pe.get_filesize())
        {
            res->raise_level(SUSPICIOUS);
            res->add_information("The PE's resources are bigger than it is.");
        }

        // Perform tests on the RICH header.
        rich_header_tests(pe, res);

        // Put a default summary if none was set.
        if (res->get_level() != NO_OPINION && res->get_summary() == nullptr) {
            res->set_summary("The PE is possibly packed.");
        }

        return res;
    }
};

AutoRegister<PackerDetectionPlugin> auto_register_packer;

} // !namespace plugin
