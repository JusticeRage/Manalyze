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

#include "dump.h"

namespace mana {

// ----------------------------------------------------------------------------

void dump_dos_header(const mana::PE& pe, io::OutputFormatter& formatter)
{
	if (!pe.get_dos_header()) {
		return;
	}
	mana::dos_header header = *pe.get_dos_header();
	std::stringstream magic;
	magic << header.e_magic[0] << header.e_magic[1];

	io::pNode dos_header(new io::OutputTreeNode("DOS Header", io::OutputTreeNode::LIST));
	dos_header->append(boost::make_shared<io::OutputTreeNode>("e_magic", magic.str()));
	dos_header->append(boost::make_shared<io::OutputTreeNode>("e_cblp", header.e_cblp, io::OutputTreeNode::HEX));
	dos_header->append(boost::make_shared<io::OutputTreeNode>("e_cp", header.e_cp, io::OutputTreeNode::HEX));
	dos_header->append(boost::make_shared<io::OutputTreeNode>("e_crlc", header.e_crlc, io::OutputTreeNode::HEX));
	dos_header->append(boost::make_shared<io::OutputTreeNode>("e_cparhdr", header.e_cparhdr, io::OutputTreeNode::HEX));
	dos_header->append(boost::make_shared<io::OutputTreeNode>("e_minalloc", header.e_minalloc, io::OutputTreeNode::HEX));
	dos_header->append(boost::make_shared<io::OutputTreeNode>("e_maxalloc", header.e_maxalloc, io::OutputTreeNode::HEX));
	dos_header->append(boost::make_shared<io::OutputTreeNode>("e_ss", header.e_ss, io::OutputTreeNode::HEX));
	dos_header->append(boost::make_shared<io::OutputTreeNode>("e_sp", header.e_sp, io::OutputTreeNode::HEX));
	dos_header->append(boost::make_shared<io::OutputTreeNode>("e_csum", header.e_csum, io::OutputTreeNode::HEX));
	dos_header->append(boost::make_shared<io::OutputTreeNode>("e_ip", header.e_ip, io::OutputTreeNode::HEX));
	dos_header->append(boost::make_shared<io::OutputTreeNode>("e_cs", header.e_cs, io::OutputTreeNode::HEX));
	dos_header->append(boost::make_shared<io::OutputTreeNode>("e_ovno", header.e_ovno, io::OutputTreeNode::HEX));
	dos_header->append(boost::make_shared<io::OutputTreeNode>("e_oemid", header.e_oemid, io::OutputTreeNode::HEX));
	dos_header->append(boost::make_shared<io::OutputTreeNode>("e_oeminfo", header.e_oeminfo, io::OutputTreeNode::HEX));
	dos_header->append(boost::make_shared<io::OutputTreeNode>("e_lfanew", header.e_lfanew, io::OutputTreeNode::HEX));

	formatter.add_data(dos_header, *pe.get_path());
}

// ----------------------------------------------------------------------------

void dump_pe_header(const mana::PE& pe, io::OutputFormatter& formatter)
{
	if (!pe.get_pe_header()) {
		return;
	}
	mana::pe_header header = *pe.get_pe_header();
	io::pNode pe_header(new io::OutputTreeNode("PE Header", io::OutputTreeNode::LIST));
	std::stringstream ss;
	ss << header.Signature[0] << header.Signature[1];
	pe_header->append(boost::make_shared<io::OutputTreeNode>("Signature", ss.str()));
	pe_header->append(boost::make_shared<io::OutputTreeNode>("Machine", *nt::translate_to_flag(header.Machine, nt::MACHINE_TYPES)));
	pe_header->append(boost::make_shared<io::OutputTreeNode>("NumberofSections", header.NumberofSections));
	pe_header->append(boost::make_shared<io::OutputTreeNode>("TimeDateStamp", io::timestamp_to_string(header.TimeDateStamp)));
	pe_header->append(boost::make_shared<io::OutputTreeNode>("PointerToSymbolTable", header.PointerToSymbolTable, io::OutputTreeNode::HEX));
	pe_header->append(boost::make_shared<io::OutputTreeNode>("NumberOfSymbols", header.NumberOfSymbols));
	pe_header->append(boost::make_shared<io::OutputTreeNode>("SizeOfOptionalHeader", header.SizeOfOptionalHeader, io::OutputTreeNode::HEX));
	pe_header->append(boost::make_shared<io::OutputTreeNode>("Characteristics", *nt::translate_to_flags(header.Characteristics, nt::PE_CHARACTERISTICS)));

	formatter.add_data(pe_header, *pe.get_path());
}

// ----------------------------------------------------------------------------

void dump_image_optional_header(const mana::PE& pe, io::OutputFormatter& formatter)
{
	if (!pe.get_image_optional_header()) {
		return;
	}
	mana::image_optional_header ioh = *pe.get_image_optional_header();
	io::pNode ioh_header(new io::OutputTreeNode("Image Optional Header", io::OutputTreeNode::LIST));

	ioh_header->append(boost::make_shared<io::OutputTreeNode>("Magic", *nt::translate_to_flag(ioh.Magic, nt::IMAGE_OPTIONAL_HEADER_MAGIC)));
	std::stringstream ss;
	ss << static_cast<int>(ioh.MajorLinkerVersion) << "." << static_cast<int>(ioh.MinorImageVersion);
	ioh_header->append(boost::make_shared<io::OutputTreeNode>("LinkerVersion", ss.str()));
	ioh_header->append(boost::make_shared<io::OutputTreeNode>("SizeOfCode", ioh.SizeOfCode, io::OutputTreeNode::HEX));
	ioh_header->append(boost::make_shared<io::OutputTreeNode>("SizeOfInitializedData", ioh.SizeOfInitializedData, io::OutputTreeNode::HEX));
	ioh_header->append(boost::make_shared<io::OutputTreeNode>("SizeOfUninitializedData", ioh.SizeOfUninitializedData, io::OutputTreeNode::HEX));


	mana::pSection sec = mana::find_section(ioh.AddressOfEntryPoint, *pe.get_sections());
	ss.str(std::string());
	if (sec != nullptr) {
		ss << std::hex << "0x" << ioh.AddressOfEntryPoint << " (Section: " << *sec->get_name() << ")";
	}
	else {
		ss << std::hex << "0x" << ioh.AddressOfEntryPoint << " (Section: ?)";
	}
	ioh_header->append(boost::make_shared<io::OutputTreeNode>("AddressOfEntryPoint", ss.str()));
	ioh_header->append(boost::make_shared<io::OutputTreeNode>("BaseOfCode", ioh.BaseOfCode, io::OutputTreeNode::HEX));

	// Field absent from PE32+ headers.
	if (ioh.Magic == nt::IMAGE_OPTIONAL_HEADER_MAGIC.at("PE32")) {
		ioh_header->append(boost::make_shared<io::OutputTreeNode>("BaseOfData", ioh.BaseOfData, io::OutputTreeNode::HEX));
	}

	ioh_header->append(boost::make_shared<io::OutputTreeNode>("ImageBase", ioh.ImageBase, io::OutputTreeNode::HEX));
	ioh_header->append(boost::make_shared<io::OutputTreeNode>("SectionAlignment", ioh.SectionAlignment, io::OutputTreeNode::HEX));
	ioh_header->append(boost::make_shared<io::OutputTreeNode>("FileAlignment", ioh.FileAlignment, io::OutputTreeNode::HEX));

	ss.str(std::string());
	ss << static_cast<int>(ioh.MajorOperatingSystemVersion) << "." << static_cast<int>(ioh.MinorOperatingSystemVersion);
	ioh_header->append(boost::make_shared<io::OutputTreeNode>("OperatingSystemVersion", ss.str()));
	ss.str(std::string());
	ss << static_cast<int>(ioh.MajorImageVersion) << "." << static_cast<int>(ioh.MinorImageVersion);
	ioh_header->append(boost::make_shared<io::OutputTreeNode>("ImageVersion", ss.str()));
	ss.str(std::string());
	ss << static_cast<int>(ioh.MajorSubsystemVersion) << "." << static_cast<int>(ioh.MinorSubsystemVersion);
	ioh_header->append(boost::make_shared<io::OutputTreeNode>("SubsystemVersion", ss.str()));

	ioh_header->append(boost::make_shared<io::OutputTreeNode>("Win32VersionValue", ioh.Win32VersionValue));
	ioh_header->append(boost::make_shared<io::OutputTreeNode>("SizeOfImage", ioh.SizeOfImage, io::OutputTreeNode::HEX));
	ioh_header->append(boost::make_shared<io::OutputTreeNode>("SizeOfHeaders", ioh.SizeOfHeaders, io::OutputTreeNode::HEX));
	ioh_header->append(boost::make_shared<io::OutputTreeNode>("Checksum", ioh.Checksum, io::OutputTreeNode::HEX));
	ioh_header->append(boost::make_shared<io::OutputTreeNode>("Subsystem", *nt::translate_to_flag(ioh.Subsystem, nt::SUBSYSTEMS)));
	ioh_header->append(boost::make_shared<io::OutputTreeNode>("DllCharacteristics", *nt::translate_to_flags(ioh.DllCharacteristics, nt::DLL_CHARACTERISTICS)));
	ioh_header->append(boost::make_shared<io::OutputTreeNode>("SizeofStackReserve", ioh.SizeofStackReserve, io::OutputTreeNode::HEX));
	ioh_header->append(boost::make_shared<io::OutputTreeNode>("SizeofStackCommit", ioh.SizeofStackCommit, io::OutputTreeNode::HEX));
	ioh_header->append(boost::make_shared<io::OutputTreeNode>("SizeofHeapReserve", ioh.SizeofHeapReserve, io::OutputTreeNode::HEX));
	ioh_header->append(boost::make_shared<io::OutputTreeNode>("SizeofHeapCommit", ioh.SizeofHeapCommit, io::OutputTreeNode::HEX));
	ioh_header->append(boost::make_shared<io::OutputTreeNode>("LoaderFlags", ioh.LoaderFlags, io::OutputTreeNode::HEX));
	ioh_header->append(boost::make_shared<io::OutputTreeNode>("NumberOfRvaAndSizes", ioh.NumberOfRvaAndSizes));

	formatter.add_data(ioh_header, *pe.get_path());
}

// ----------------------------------------------------------------------------

void dump_section_table(const mana::PE& pe, io::OutputFormatter& formatter, bool compute_hashes)
{
	mana::shared_sections sections = pe.get_sections();
	if (sections->size() == 0) {
		return;
	}

	io::pNode section_list(new io::OutputTreeNode("Sections", io::OutputTreeNode::LIST));

	for (auto it = sections->begin(); it != sections->end(); ++it)
	{
		io::pNode section_node(new io::OutputTreeNode(*(*it)->get_name(), io::OutputTreeNode::LIST));
		if (compute_hashes)
		{
			const_shared_strings hashes = hash::hash_bytes(hash::ALL_DIGESTS, *(*it)->get_raw_data());
			section_node->append(boost::make_shared<io::OutputTreeNode>("MD5", hashes->at(ALL_DIGESTS_MD5)));
			section_node->append(boost::make_shared<io::OutputTreeNode>("SHA1", hashes->at(ALL_DIGESTS_SHA1)));
			section_node->append(boost::make_shared<io::OutputTreeNode>("SHA256", hashes->at(ALL_DIGESTS_SHA256)));
			section_node->append(boost::make_shared<io::OutputTreeNode>("SHA3", hashes->at(ALL_DIGESTS_SHA3)));
		}
		section_node->append(boost::make_shared<io::OutputTreeNode>("VirtualSize", (*it)->get_virtual_size(), io::OutputTreeNode::HEX));
		section_node->append(boost::make_shared<io::OutputTreeNode>("VirtualAddress", (*it)->get_virtual_address(), io::OutputTreeNode::HEX));
		section_node->append(boost::make_shared<io::OutputTreeNode>("SizeOfRawData", (*it)->get_size_of_raw_data(), io::OutputTreeNode::HEX));
		section_node->append(boost::make_shared<io::OutputTreeNode>("PointerToRawData", (*it)->get_pointer_to_raw_data(), io::OutputTreeNode::HEX));
		section_node->append(boost::make_shared<io::OutputTreeNode>("PointerToRelocations", (*it)->get_pointer_to_relocations(), io::OutputTreeNode::HEX));
		section_node->append(boost::make_shared<io::OutputTreeNode>("PointerToLineNumbers", (*it)->get_pointer_to_line_numbers(), io::OutputTreeNode::HEX));
		section_node->append(boost::make_shared<io::OutputTreeNode>("NumberOfLineNumbers", (*it)->get_number_of_line_numbers()));
		section_node->append(boost::make_shared<io::OutputTreeNode>("NumberOfRelocations", (*it)->get_number_of_relocations()));
		section_node->append(boost::make_shared<io::OutputTreeNode>("Characteristics", *nt::translate_to_flags((*it)->get_characteristics(), nt::SECTION_CHARACTERISTICS)));
		section_node->append(boost::make_shared<io::OutputTreeNode>("Entropy", (*it)->get_entropy()));

		section_list->append(section_node);
	}

	formatter.add_data(section_list, *pe.get_path());
}

// ----------------------------------------------------------------------------

void dump_imports(const mana::PE& pe, io::OutputFormatter& formatter)
{
	const_shared_strings dlls = pe.get_imported_dlls();
	if (dlls->size() == 0) {
		return;
	}

	io::pNode imports(new io::OutputTreeNode("Imports", io::OutputTreeNode::LIST));
	for (const_shared_strings::element_type::const_iterator it = dlls->begin() ; it != dlls->end() ; ++it)
	{
		const_shared_strings functions = pe.get_imported_functions(*it);
		io::pNode dll(new io::OutputTreeNode(*it, *functions));
		imports->append(dll);
	}
	formatter.add_data(imports, *pe.get_path());
}

// ----------------------------------------------------------------------------

void dump_exports(const mana::PE& pe, io::OutputFormatter& formatter)
{
	shared_exports exports = pe.get_exports();
	if (exports->size() == 0) {
		return;
	}

	io::pNode exports_list(new io::OutputTreeNode("Exports", io::OutputTreeNode::LIST));
	for (auto it = exports->begin() ; it != exports->end() ; ++it)
	{
		// TODO: Demangle C++ names here
		io::pNode ex(new io::OutputTreeNode((*it)->Name, io::OutputTreeNode::LIST));
		ex->append(boost::make_shared<io::OutputTreeNode>("Ordinal", (*it)->Ordinal));
		ex->append(boost::make_shared<io::OutputTreeNode>("Address", (*it)->Address, io::OutputTreeNode::HEX));
		if ((*it)->ForwardName != "") {
			ex->append(boost::make_shared<io::OutputTreeNode>("ForwardName", (*it)->ForwardName));
		}
		exports_list->append(ex);
	}

	formatter.add_data(exports_list, *pe.get_path());
}

// ----------------------------------------------------------------------------

void dump_resources(const mana::PE& pe, io::OutputFormatter& formatter, bool compute_hashes /* = false */)
{
	shared_resources resources = pe.get_resources();
	if (resources->size() == 0) {
		return;
	}

	io::pNode resource_list(new io::OutputTreeNode("Resources", io::OutputTreeNode::LIST));
	for (auto it = resources->begin() ; it != resources->end() ; ++it)
	{
		io::pNode res(new io::OutputTreeNode(*(*it)->get_name(), io::OutputTreeNode::LIST));
		res->append(boost::make_shared<io::OutputTreeNode>("Type", *(*it)->get_type()));
		res->append(boost::make_shared<io::OutputTreeNode>("Language", *(*it)->get_language()));
        res->append(boost::make_shared<io::OutputTreeNode>("Codepage", *nt::translate_to_flag((*it)->get_codepage(), nt::CODEPAGES)));
		res->append(boost::make_shared<io::OutputTreeNode>("Size", (*it)->get_size(), io::OutputTreeNode::HEX));
		res->append(boost::make_shared<io::OutputTreeNode>("Entropy", (*it)->get_entropy()));

		yara::const_matches m = detect_filetype(*it);
		if (m && m->size() > 0)
		{
			for (auto it2 = m->begin() ; it2 != m->end() ; ++it2) {
				res->append(boost::make_shared<io::OutputTreeNode>("Detected Filetype", (*it2)->operator[]("description")));
			}
		}

		if (compute_hashes)
		{
			const_shared_strings hashes = hash::hash_bytes(hash::ALL_DIGESTS, *(*it)->get_raw_data());
			res->append(boost::make_shared<io::OutputTreeNode>("MD5", hashes->at(ALL_DIGESTS_MD5)));
			res->append(boost::make_shared<io::OutputTreeNode>("SHA1", hashes->at(ALL_DIGESTS_SHA1)));
			res->append(boost::make_shared<io::OutputTreeNode>("SHA256", hashes->at(ALL_DIGESTS_SHA256)));
			res->append(boost::make_shared<io::OutputTreeNode>("SHA3", hashes->at(ALL_DIGESTS_SHA3)));
		}

		resource_list->append(res);
	}
	formatter.add_data(resource_list, *pe.get_path());
}

// ----------------------------------------------------------------------------

void dump_version_info(const mana::PE& pe, io::OutputFormatter& formatter)
{
	pversion_info vi;
	mana::shared_resources resources = pe.get_resources();
	for (auto it = resources->begin() ; it != resources->end() ; ++it)
	{
		if (*(*it)->get_type() == "RT_VERSION")
		{
			vi = (*it)->interpret_as<mana::pversion_info>();
			if (vi == nullptr)
			{
				PRINT_WARNING << "Could not parse a VERSION_INFO resource!" << std::endl;
				continue;
			}

			io::pNode existing_node = formatter.find_node("Version Info", *pe.get_path());
			io::pNode version_info_node;
			if (existing_node) {
				version_info_node = existing_node;
			}
			else {
				version_info_node = boost::make_shared<io::OutputTreeNode>("Version Info", io::OutputTreeNode::LIST);
			}

			version_info_node->append(boost::make_shared<io::OutputTreeNode>("Resource LangID", *(*it)->get_language()));
			io::pNode key_values = boost::make_shared<io::OutputTreeNode>(vi->Header.Key, io::OutputTreeNode::LIST);
			key_values->append(boost::make_shared<io::OutputTreeNode>("Signature", vi->Value->Signature, io::OutputTreeNode::HEX));
			key_values->append(boost::make_shared<io::OutputTreeNode>("StructVersion", vi->Value->StructVersion, io::OutputTreeNode::HEX));
			key_values->append(boost::make_shared<io::OutputTreeNode>("FileVersion", io::uint64_to_version_number(vi->Value->FileVersionMS, vi->Value->FileVersionLS)));
			key_values->append(boost::make_shared<io::OutputTreeNode>("ProductVersion", io::uint64_to_version_number(vi->Value->ProductVersionMS, vi->Value->ProductVersionLS)));
			key_values->append(boost::make_shared<io::OutputTreeNode>("FileFlags", *nt::translate_to_flags(vi->Value->FileFlags & vi->Value->FileFlagsMask, nt::FIXEDFILEINFO_FILEFLAGS)));
			key_values->append(boost::make_shared<io::OutputTreeNode>("FileOs", *nt::translate_to_flags(vi->Value->FileOs, nt::FIXEDFILEINFO_FILEOS)));
			key_values->append(boost::make_shared<io::OutputTreeNode>("FileType", *nt::translate_to_flag(vi->Value->FileType, nt::FIXEDFILEINFO_FILETYPE)));
			if (vi->Value->FileType == nt::FIXEDFILEINFO_FILETYPE.at("VFT_DRV")) {
				key_values->append(boost::make_shared<io::OutputTreeNode>("FileSubtype", *nt::translate_to_flag(vi->Value->FileSubtype, nt::FIXEDFILEINFO_FILESUBTYPE_DRV)));
			}
			else if (vi->Value->FileType == nt::FIXEDFILEINFO_FILETYPE.at("VFT_FONT")) {
				key_values->append(boost::make_shared<io::OutputTreeNode>("FileSubtype", *nt::translate_to_flag(vi->Value->FileSubtype, nt::FIXEDFILEINFO_FILESUBTYPE_FONT)));
			}

			key_values->append(boost::make_shared<io::OutputTreeNode>("Language", vi->Language));
			for (auto it2 = vi->StringTable.begin() ; it2 != vi->StringTable.end() ; ++it2) {
				key_values->append(boost::make_shared<io::OutputTreeNode>((*it2)->first, (*it2)->second));
			}

			version_info_node->append(key_values);
			formatter.add_data(version_info_node, *pe.get_path());
		}
	}
}

// ----------------------------------------------------------------------------

void dump_debug_info(const mana::PE& pe, io::OutputFormatter& formatter)
{
	mana::shared_debug_info di = pe.get_debug_info();
	if (di->size() == 0) {
		return;
	}
	io::pNode debug_info_list(new io::OutputTreeNode("Debug Info", io::OutputTreeNode::LIST));
	for (auto it = di->begin() ; it != di->end() ; ++it)
	{
		io::pNode debug_info_node(new io::OutputTreeNode(*nt::translate_to_flag((*it)->Type, nt::DEBUG_TYPES), io::OutputTreeNode::LIST));
		debug_info_node->append(boost::make_shared<io::OutputTreeNode>("Characteristics", (*it)->Characteristics));
		debug_info_node->append(boost::make_shared<io::OutputTreeNode>("TimeDateStamp", io::timestamp_to_string((*it)->TimeDateStamp)));
		std::stringstream ss;
		ss << (*it)->MajorVersion << "." << (*it)->MinorVersion;
		debug_info_node->append(boost::make_shared<io::OutputTreeNode>("Version", ss.str()));
		debug_info_node->append(boost::make_shared<io::OutputTreeNode>("SizeofData", (*it)->SizeofData));
		debug_info_node->append(boost::make_shared<io::OutputTreeNode>("AddressOfRawData", (*it)->AddressOfRawData, io::OutputTreeNode::HEX));
		debug_info_node->append(boost::make_shared<io::OutputTreeNode>("PointerToRawData", (*it)->PointerToRawData, io::OutputTreeNode::HEX));
		if ((*it)->Filename != "") {
			debug_info_node->append(boost::make_shared<io::OutputTreeNode>("Referenced File", (*it)->Filename));
		}
		debug_info_list->append(debug_info_node);
	}

	formatter.add_data(debug_info_list, *pe.get_path());
}

// ----------------------------------------------------------------------------

void dump_tls(const mana::PE& pe, io::OutputFormatter& formatter)
{
	mana::shared_tls tls = pe.get_tls();
	if (!tls) {
		return;
	}

	io::pNode tls_node(new io::OutputTreeNode("TLS Callbacks", io::OutputTreeNode::LIST));
	tls_node->append(boost::make_shared<io::OutputTreeNode>("StartAddressOfRawData", tls->StartAddressOfRawData, io::OutputTreeNode::HEX));
	tls_node->append(boost::make_shared<io::OutputTreeNode>("EndAddressOfRawData", tls->EndAddressOfRawData, io::OutputTreeNode::HEX));
	tls_node->append(boost::make_shared<io::OutputTreeNode>("AddressOfIndex", tls->AddressOfIndex, io::OutputTreeNode::HEX));
	tls_node->append(boost::make_shared<io::OutputTreeNode>("AddressOfCallbacks", tls->AddressOfCallbacks, io::OutputTreeNode::HEX));
	tls_node->append(boost::make_shared<io::OutputTreeNode>("SizeOfZeroFill", tls->SizeOfZeroFill, io::OutputTreeNode::HEX));
	tls_node->append(boost::make_shared<io::OutputTreeNode>("Characteristics", tls->Characteristics));

	std::vector<std::string> callbacks;
	for (auto it = tls->Callbacks.begin() ; it != tls->Callbacks.end() ; ++it)
	{
		std::stringstream ss;
		ss << std::hex << "0x" << *it;
		callbacks.push_back(ss.str());
	}
	tls_node->append(boost::make_shared<io::OutputTreeNode>("Callbacks", callbacks));
	formatter.add_data(tls_node, *pe.get_path());
}

// ----------------------------------------------------------------------------

void dump_summary(const mana::PE& pe, io::OutputFormatter& formatter)
{
	if (!pe.get_pe_header() || !pe.get_image_optional_header()) {
		return;
	}

	io::pNode summary(new io::OutputTreeNode("Summary", io::OutputTreeNode::LIST));

	// Grab all detected languages
	std::set<std::string> languages;
	mana::shared_resources res = pe.get_resources();
	pversion_info vi;
	for (auto it = res->begin() ; it != res->end() ; ++it)
	{
		if (*(*it)->get_type() == "RT_VERSION")
		{
			vi = (*it)->interpret_as<mana::pversion_info>();
			if (vi == nullptr) {
				continue;
			}
			if (!boost::starts_with(vi->Language, "UNKNOWN")) { // In debug builds, "UNKNOWN (0x1234ABCD)" is returned.
				languages.insert(vi->Language); // Some language info is also present in the VERSION_INFO resource.
			}
		}

		if (!boost::starts_with(*(*it)->get_language(), "UNKNOWN")) {
			languages.insert(*(*it)->get_language());
		}
	}

	// Get PDB location if it is present
	std::set<std::string> debug_files;
	mana::shared_debug_info di = pe.get_debug_info();
	for (auto it = di->begin() ; it != di->end() ; ++it)
	{
		if ((*it)->Filename != "") {
			debug_files.insert((*it)->Filename);
		}
	}

	// Inform the user if some COFF debug information is present
	mana::pe_header h = *pe.get_pe_header();
	if (h.NumberOfSymbols > 0 && h.PointerToSymbolTable != 0) {
		debug_files.insert("Embedded COFF debugging symbols");
	}

	summary->append(boost::make_shared<io::OutputTreeNode>("Architecture", *nt::translate_to_flag(h.Machine, nt::MACHINE_TYPES)));
	mana::image_optional_header ioh = *pe.get_image_optional_header();
	summary->append(boost::make_shared<io::OutputTreeNode>("Subsystem", *nt::translate_to_flag(ioh.Subsystem, nt::SUBSYSTEMS)));
	summary->append(boost::make_shared<io::OutputTreeNode>("Compilation Date", io::timestamp_to_string(h.TimeDateStamp)));

	// Exploit mitigation technologies
	std::vector<std::string> mitigation;
	auto characteristics = *nt::translate_to_flags(ioh.DllCharacteristics, nt::DLL_CHARACTERISTICS);
	if (std::find(characteristics.begin(), characteristics.end(), "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE") != characteristics.end()) {
		mitigation.push_back("ASLR");
	}
	if (std::find(characteristics.begin(), characteristics.end(), "IMAGE_DLLCHARACTERISTICS_NX_COMPAT") != characteristics.end()) {
		mitigation.push_back("DEP");
	}
	if (mitigation.size() > 0)	{
		summary->append(boost::make_shared<io::OutputTreeNode>("Exploit mitigation", mitigation));
	}

	if (languages.size() > 0) {
		summary->append(boost::make_shared<io::OutputTreeNode>("Detected languages", languages));
	}

	if (pe.get_tls() && pe.get_tls()->Callbacks.size() > 0)
	{
		std::stringstream ss;
		ss << pe.get_tls()->Callbacks.size() << " callback(s) detected.";
		summary->append(boost::make_shared<io::OutputTreeNode>("TLS Callbacks", ss.str()));
	}

	if (debug_files.size() > 0)	{
		summary->append(boost::make_shared<io::OutputTreeNode>("Debug artifacts", debug_files));
	}

	if (vi != nullptr)
	{
		for (auto it = vi->StringTable.begin() ; it != vi->StringTable.end() ; ++it)
        {
            if ((*it)->first != "" || (*it)->second != "") {
                summary->append(boost::make_shared<io::OutputTreeNode>((*it)->first, (*it)->second));
            }
		}
	}

	formatter.add_data(summary, *pe.get_path());
}

// ----------------------------------------------------------------------------

void dump_hashes(const mana::PE& pe, io::OutputFormatter& formatter)
{
	const_shared_strings hashes = hash::hash_file(hash::ALL_DIGESTS, *pe.get_path());
	io::pNode hashes_node(new io::OutputTreeNode("Hashes", io::OutputTreeNode::LIST));
	hashes_node->append(boost::make_shared<io::OutputTreeNode>("MD5", hashes->at(ALL_DIGESTS_MD5)));
	hashes_node->append(boost::make_shared<io::OutputTreeNode>("SHA1", hashes->at(ALL_DIGESTS_SHA1)));
	hashes_node->append(boost::make_shared<io::OutputTreeNode>("SHA256", hashes->at(ALL_DIGESTS_SHA256)));
	hashes_node->append(boost::make_shared<io::OutputTreeNode>("SHA3", hashes->at(ALL_DIGESTS_SHA3)));
	hashes_node->append(boost::make_shared<io::OutputTreeNode>("SSDeep", *ssdeep::hash_file(*pe.get_path())));
	hashes_node->append(boost::make_shared<io::OutputTreeNode>("Imports Hash", *hash::hash_imports(pe)));
	formatter.add_data(hashes_node, *pe.get_path());
}

// ----------------------------------------------------------------------------

yara::const_matches detect_filetype(mana::pResource r)
{
    static yara::pYara y = yara::Yara::create();
    if (y->load_rules("yara_rules/magic.yara"))
    {
        shared_bytes bytes = r->get_raw_data();
        if (bytes != nullptr) {
            return y->scan_bytes(*bytes);
        }
        else {
            return yara::matches();
        }
    }
    else {
        return yara::matches();
    }
}

// ----------------------------------------------------------------------------

bool extract_resources(const mana::PE& pe, const std::string& destination_folder)
{
    if (!bfs::exists(destination_folder) && !bfs::create_directory(destination_folder))
    {
        PRINT_ERROR << "Could not create directory " << destination_folder << "." << DEBUG_INFO << std::endl;
        return false;
    }

    bool res = true;
    auto base = bfs::basename(*pe.get_path());
    auto resources = pe.get_resources();
    if (resources == nullptr) {
        return true;
    }

    for (auto it = resources->begin() ; it != resources->end() ; ++it)
    {
        bfs::path destination_file;
        std::stringstream ss;
        if (*(*it)->get_type() == "RT_GROUP_ICON" || *(*it)->get_type() == "RT_GROUP_CURSOR")
        {
            ss << base << "_" << (*it)->get_id() << "_" << *(*it)->get_type() << ".ico";
            res &= (*it)->icon_extract(bfs::path(destination_folder) / bfs::path(ss.str()), *pe.get_resources());
        }
        else if (*(*it)->get_type() == "RT_MANIFEST")
        {
            ss << base << "_" << (*it)->get_id() << "_RT_MANIFEST.xml";
            res &= (*it)->extract(bfs::path(destination_folder) / bfs::path(ss.str()));
        }
        else if (*(*it)->get_type() == "RT_BITMAP")
        {
            ss << base << "_" << (*it)->get_id() << "_RT_BITMAP.bmp";
            res &= (*it)->extract(bfs::path(destination_folder) / bfs::path(ss.str()));
        }
        else if (*(*it)->get_type() == "RT_ICON" || *(*it)->get_type() == "RT_CURSOR" || *(*it)->get_type() == "RT_VERSION") {
            // Ignore the following resource types: we don't want to extract them.
            continue;
        }
        else if (*(*it)->get_type() == "RT_STRING")
        {
            // Append all the strings to the same file.
            destination_file = bfs::path(destination_folder) / bfs::path(base + "_RT_STRINGs.txt");
            res &= (*it)->extract(destination_file.string());
        }
        else // General case
        {
            ss << base << "_";
            if (*(*it)->get_name() != "") {
                ss << *(*it)->get_name();
            }
            else {
                ss << (*it)->get_id();
            }

            // Try to guess the file extension
            auto m = detect_filetype(*it);
            if (m && m->size() > 0) {
                ss << "_" << *(*it)->get_type() << m->at(0)->operator[]("extension");
            }
            else {
                ss << "_" << *(*it)->get_type() << ".raw";
            }

            res &= (*it)->extract(bfs::path(destination_folder) / bfs::path(ss.str()));
        }
    }
    return res;
}

} // !namespace mana
