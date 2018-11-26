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

#include <boost/system/api_config.hpp>

#define BOOST_TEST_MODULE ManalyzeTests
#if !defined BOOST_WINDOWS_API
#	define BOOST_TEST_DYN_LINK
#endif

#include <boost/test/unit_test.hpp>

#include "fixtures.h"
#include "manape/pe.h"

// ----------------------------------------------------------------------------

/**
 * Helper function which compares all the fields of an image_section_header with the given values.
 */
void check_section(mana::pSection section,
				   const std::string&  name, 
				   boost::uint32_t virtual_size,
				   boost::uint32_t virtual_address,
   				   boost::uint32_t size_raw_data,
	   			   boost::uint32_t pointer_raw_data,
				   boost::uint32_t pointer_reloc,
				   boost::uint32_t pointer_line,
				   boost::uint16_t number_reloc,
				   boost::uint16_t number_line,
				   boost::uint32_t characteristics)
{
	BOOST_CHECK(*section->get_name() == name);
	BOOST_CHECK(section->get_virtual_size() == virtual_size);
	BOOST_CHECK(section->get_virtual_address() == virtual_address);
	BOOST_CHECK(section->get_size_of_raw_data() == size_raw_data);
	BOOST_CHECK(section->get_pointer_to_raw_data() == pointer_raw_data);
	BOOST_CHECK(section->get_pointer_to_relocations() == pointer_reloc);
	BOOST_CHECK(section->get_pointer_to_line_numbers() == pointer_line);
	BOOST_CHECK(section->get_number_of_relocations() == number_reloc);
	BOOST_CHECK(section->get_number_of_line_numbers() == number_line);
	BOOST_CHECK(section->get_characteristics() == characteristics);
}

// ----------------------------------------------------------------------------
BOOST_FIXTURE_TEST_SUITE(resources, SetWorkingDirectory)
// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(parse_testfile)
{
    mana::PE pe("testfiles/manatest.exe");
	BOOST_CHECK_EQUAL(pe.get_filesize(), 16360);
	BOOST_ASSERT(pe.is_valid());
	BOOST_ASSERT(pe.get_path());
	BOOST_CHECK_EQUAL(*pe.get_path(), "testfiles/manatest.exe");
	mana::PE pe2("testfiles/manatest2.exe");
	BOOST_CHECK_EQUAL(pe2.get_filesize(), 72704);
	BOOST_ASSERT(pe2.is_valid());
	BOOST_ASSERT(pe2.get_path());
	BOOST_CHECK_EQUAL(*pe2.get_path(), "testfiles/manatest2.exe");
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(get_raw_bytes)
{
	mana::PE pe("testfiles/manatest.exe");
	auto bytes = pe.get_raw_bytes();
	BOOST_CHECK_EQUAL(bytes->size(), 16360);
	BOOST_CHECK_EQUAL(bytes->at(0), 'M');
	BOOST_CHECK_EQUAL(bytes->at(1), 'Z');
	BOOST_CHECK_EQUAL(bytes->at(16359), '\x00');
	BOOST_CHECK_EQUAL(bytes->at(16358), '\x00');
	BOOST_CHECK_EQUAL(bytes->at(16357), '\x00');
	BOOST_CHECK_EQUAL(bytes->at(16356), '\x00');
	BOOST_CHECK_EQUAL(bytes->at(16355), '\x0B');
	BOOST_CHECK_EQUAL(bytes->at(16354), '\x7C');

	bytes = pe.get_raw_bytes(0x80);
	BOOST_CHECK_EQUAL(bytes->size(), 0x80);
	std::string s(&(*bytes)[0x4E], &(*bytes)[0x75]);
	BOOST_CHECK_EQUAL(s, "This program cannot be run in DOS mode.");
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(parse_dos_header)
{
	mana::PE pe("testfiles/manatest.exe");

	boost::optional<mana::dos_header> pdos = pe.get_dos_header();
	BOOST_ASSERT(pdos);
	mana::dos_header dos = *pdos;
	BOOST_CHECK(dos.e_magic[0] == 'M' && dos.e_magic[1] == 'Z');
	BOOST_CHECK_EQUAL(dos.e_cblp, 0x90);
	BOOST_CHECK_EQUAL(dos.e_cp, 3);
	BOOST_CHECK_EQUAL(dos.e_crlc, 0);
	BOOST_CHECK_EQUAL(dos.e_cparhdr, 4);
	BOOST_CHECK_EQUAL(dos.e_minalloc, 0);
	BOOST_CHECK_EQUAL(dos.e_maxalloc, 0xFFFF);
	BOOST_CHECK_EQUAL(dos.e_ss, 0);
	BOOST_CHECK_EQUAL(dos.e_sp, 0xB8);
	BOOST_CHECK_EQUAL(dos.e_csum, 0);
	BOOST_CHECK_EQUAL(dos.e_ip, 0);
	BOOST_CHECK_EQUAL(dos.e_cs, 0);
	BOOST_CHECK_EQUAL(dos.e_lfarlc, 0x40);
	BOOST_CHECK_EQUAL(dos.e_ovno, 0);
	for (int i = 0 ; i < 4 ; ++i) {
		BOOST_CHECK_EQUAL(dos.e_res[i], 0);
	}
	BOOST_CHECK_EQUAL(dos.e_oemid, 0);
	BOOST_CHECK_EQUAL(dos.e_oeminfo, 0);
	for (int i = 0 ; i < 10 ; ++i) {
		BOOST_CHECK_EQUAL(dos.e_res2[i], 0);
	}
	BOOST_CHECK_EQUAL(dos.e_lfanew, 0xF0);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(parse_pe_header)
{
	mana::PE pe("testfiles/manatest.exe");

	auto ppe_header = pe.get_pe_header();
	BOOST_ASSERT(ppe_header);
	mana::pe_header peh = *ppe_header;
	BOOST_CHECK(peh.Signature[0] == 'P' && peh.Signature[1] == 'E' && peh.Signature[2] == 0 && peh.Signature[3] == 0);
	BOOST_CHECK(*nt::translate_to_flag(peh.Machine, nt::MACHINE_TYPES) == "IMAGE_FILE_MACHINE_I386");
	BOOST_CHECK(peh.NumberofSections == 6);
	BOOST_CHECK(peh.TimeDateStamp == 0x569a5cdb);
	BOOST_CHECK(peh.PointerToSymbolTable == 0);
	BOOST_CHECK(peh.NumberOfSymbols == 0);
	std::vector<std::string> characteristics;
	characteristics.push_back("IMAGE_FILE_32BIT_MACHINE");
	characteristics.push_back("IMAGE_FILE_EXECUTABLE_IMAGE");
	BOOST_CHECK(*nt::translate_to_flags(peh.Characteristics, nt::PE_CHARACTERISTICS) == characteristics);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(parse_opt_header)
{
	mana::PE pe("testfiles/manatest.exe");

	auto popt = pe.get_image_optional_header();
	BOOST_ASSERT(popt);
	mana::image_optional_header opt = *popt;
	BOOST_CHECK(opt.Magic == 0x10B && *nt::translate_to_flag(opt.Magic, nt::IMAGE_OPTIONAL_HEADER_MAGIC) == "PE32");
	BOOST_CHECK(opt.MajorLinkerVersion == 14 && opt.MinorLinkerVersion == 0);
	BOOST_CHECK(opt.SizeOfCode == 0x1200);
	BOOST_CHECK(opt.SizeOfInitializedData == 0x1a00);
	BOOST_CHECK(opt.SizeOfUninitializedData == 0);
	BOOST_CHECK(opt.AddressOfEntryPoint == 0x1617);
	BOOST_CHECK(opt.BaseOfCode == 0x1000);
	BOOST_CHECK(opt.BaseOfData == 0x3000);
	BOOST_CHECK(opt.ImageBase == 0x00400000);
	BOOST_CHECK(opt.SectionAlignment == 0x1000);
	BOOST_CHECK(opt.FileAlignment == 0x200);
	BOOST_CHECK(opt.MajorOperatingSystemVersion == 6 && opt.MinorOperatingSystemVersion == 0);
	BOOST_CHECK(opt.MajorImageVersion == 0 && opt.MinorImageVersion == 0);
	BOOST_CHECK(opt.MajorSubsystemVersion == 6 && opt.MinorSubsystemVersion == 0);
	BOOST_CHECK(opt.Win32VersionValue == 0);
	BOOST_CHECK(opt.SizeOfImage == 0x8000);
	BOOST_CHECK(opt.SizeOfHeaders == 0x400);
	BOOST_CHECK(opt.Checksum == 0x965E);
	BOOST_CHECK(*nt::translate_to_flag(opt.Subsystem, nt::SUBSYSTEMS) == "IMAGE_SUBSYSTEM_WINDOWS_CUI");
	std::vector<std::string> characteristics;
	characteristics.clear();
	characteristics.push_back("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE");
	characteristics.push_back("IMAGE_DLLCHARACTERISTICS_NX_COMPAT");
	characteristics.push_back("IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE");
	BOOST_CHECK(*nt::translate_to_flags(opt.DllCharacteristics, nt::DLL_CHARACTERISTICS) == characteristics);
	BOOST_CHECK(opt.SizeofStackReserve == 0x100000);
	BOOST_CHECK(opt.SizeofStackCommit == 0x1000);
	BOOST_CHECK(opt.SizeofHeapReserve == 0x100000);
	BOOST_CHECK(opt.SizeofHeapCommit == 0x1000);
	BOOST_CHECK(opt.LoaderFlags == 0);
	BOOST_CHECK(opt.NumberOfRvaAndSizes == 0x10);
	BOOST_CHECK(opt.directories[0].VirtualAddress == 0		 && opt.directories[0].Size == 0);
	BOOST_CHECK(opt.directories[1].VirtualAddress == 0x366C  && opt.directories[1].Size == 0xB4);
	BOOST_CHECK(opt.directories[2].VirtualAddress == 0x6000  && opt.directories[2].Size == 0x1E0);
	BOOST_CHECK(opt.directories[3].VirtualAddress == 0		 && opt.directories[3].Size == 0);
	BOOST_CHECK(opt.directories[4].VirtualAddress == 0x2E00  && opt.directories[4].Size == 0x11E8);
	BOOST_CHECK(opt.directories[5].VirtualAddress == 0x7000  && opt.directories[5].Size == 0x1AC);
	BOOST_CHECK(opt.directories[6].VirtualAddress == 0x31A0  && opt.directories[6].Size == 0x70);
	BOOST_CHECK(opt.directories[7].VirtualAddress == 0		 && opt.directories[7].Size == 0);
	BOOST_CHECK(opt.directories[8].VirtualAddress == 0		 && opt.directories[8].Size == 0);
	BOOST_CHECK(opt.directories[9].VirtualAddress == 0		 && opt.directories[9].Size == 0);
	BOOST_CHECK(opt.directories[10].VirtualAddress == 0x3210 && opt.directories[10].Size == 0x40);
	BOOST_CHECK(opt.directories[11].VirtualAddress == 0		 && opt.directories[11].Size == 0);
	BOOST_CHECK(opt.directories[12].VirtualAddress == 0x3000 && opt.directories[12].Size == 0x100);
	BOOST_CHECK(opt.directories[13].VirtualAddress == 0		 && opt.directories[13].Size == 0);
	BOOST_CHECK(opt.directories[14].VirtualAddress == 0		 && opt.directories[14].Size == 0);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(parse_sections)
{
	mana::PE pe("testfiles/manatest.exe");

	auto psections = pe.get_sections();
	BOOST_ASSERT(psections);
	auto sec = *psections;
	BOOST_ASSERT(sec.size() == 6);
	check_section(sec[0], ".text",  0x104b, 0x1000, 0x1200, 0x400,  0, 0, 0, 0, 0x60000020);
	check_section(sec[1], ".rdata", 0xf62,  0x3000, 0x1000, 0x1600, 0, 0, 0, 0, 0x40000040);
	check_section(sec[2], ".data",  0x384,  0x4000, 0x200,  0x2600, 0, 0, 0, 0, 0xC0000040);
	check_section(sec[3], ".gfids", 0x20,   0x5000, 0x200,  0x2800, 0, 0, 0, 0, 0x40000040);
	check_section(sec[4], ".rsrc",  0x1e0,  0x6000, 0x200,  0x2a00, 0, 0, 0, 0, 0x40000040);
	check_section(sec[5], ".reloc", 0x1ac,  0x7000, 0x200,  0x2c00, 0, 0, 0, 0, 0x42000040);
}

// ----------------------------------------------------------------------------

/**
 *	@brief	Helper function which checks that a section contains the expected data.
 */
void check_debug_directory_entry(mana::debug_directory_entry d,
								 const std::string& type,
								 boost::uint32_t size,
								 boost::uint32_t address_raw_data,
								 boost::uint32_t pointer_raw_data)
{
	BOOST_CHECK(*nt::translate_to_flag(d.Type, nt::DEBUG_TYPES) == type);
	BOOST_CHECK(d.SizeofData == size);
	BOOST_CHECK(d.AddressOfRawData == address_raw_data);
	BOOST_CHECK(d.PointerToRawData == pointer_raw_data);
	BOOST_CHECK(d.Characteristics == 0);
	BOOST_CHECK(d.MajorVersion == 0);
	BOOST_CHECK(d.MinorVersion == 0);
	BOOST_CHECK(d.TimeDateStamp == 0x569a5cdb);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(parse_exports)
{
	mana::PE pe("testfiles/manatest2.exe");
	auto pexports = pe.get_exports();
	BOOST_ASSERT(pexports);
	BOOST_ASSERT(pexports->size() == 1);
	auto exported = pexports->at(0);
	BOOST_CHECK_EQUAL(exported->Address, 0x1000);
	BOOST_CHECK_EQUAL(exported->ForwardName, "");
	BOOST_CHECK_EQUAL(exported->Name, "exported");
	BOOST_CHECK_EQUAL(exported->Ordinal, 1);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(parse_debug_info)
{
	mana::PE pe("testfiles/manatest.exe");
	
	auto pdebug = pe.get_debug_info();
	BOOST_ASSERT(pdebug);
	auto debug = *pdebug;
	BOOST_ASSERT(debug.size() == 4);
	for (int i = 0 ; i < 4 ; i++) {
		BOOST_ASSERT(debug[i]);
	}

	check_debug_directory_entry(*debug[0], "IMAGE_DEBUG_TYPE_CODEVIEW", 71, 0x3280, 0x1880);
	check_debug_directory_entry(*debug[1], "IMAGE_DEBUG_TYPE_VC_FEATURE", 20, 0x32c8, 0x18c8);
	check_debug_directory_entry(*debug[2], "IMAGE_DEBUG_TYPE_POGO", 632, 0x32dc, 0x18dc);
	check_debug_directory_entry(*debug[3], "IMAGE_DEBUG_TYPE_ILTCG", 0, 0, 0);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(parse_config)
{
	mana::PE pe("testfiles/manatest.exe");

	auto pconfig = pe.get_config();
	BOOST_ASSERT(pconfig);
	auto config = *pconfig;
	
	BOOST_CHECK_EQUAL(config.Size, 0x5c);
	BOOST_CHECK_EQUAL(config.TimeDateStamp, 0);
	BOOST_CHECK_EQUAL(config.MajorVersion, 0);
	BOOST_CHECK_EQUAL(config.MinorVersion, 0);
	BOOST_CHECK_EQUAL(config.GlobalFlagsClear, 0);
	BOOST_CHECK_EQUAL(config.GlobalFlagsSet, 0);
	BOOST_CHECK_EQUAL(config.CriticalSectionDefaultTimeout, 0);
	BOOST_CHECK_EQUAL(config.DeCommitFreeBlockThreshold, 0);
	BOOST_CHECK_EQUAL(config.DeCommitTotalFreeThreshold, 0);
	BOOST_CHECK_EQUAL(config.LockPrefixTable, 0);
	BOOST_CHECK_EQUAL(config.MaximumAllocationSize, 0);
	BOOST_CHECK_EQUAL(config.VirtualMemoryThreshold, 0);
	BOOST_CHECK_EQUAL(config.ProcessAffinityMask, 0);
	BOOST_CHECK_EQUAL(config.ProcessHeapFlags, 0);
	BOOST_CHECK_EQUAL(config.CSDVersion, 0);
	BOOST_CHECK_EQUAL(config.Reserved1, 0);
	BOOST_CHECK_EQUAL(config.EditList, 0);
	BOOST_CHECK_EQUAL(config.SecurityCookie, 0x404004);
	BOOST_CHECK_EQUAL(config.SEHandlerTable, 0x403270);
	BOOST_CHECK_EQUAL(config.SEHandlerCount, 4);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(detect_architecture)
{
	mana::PE pe86("testfiles/manatest.exe");
	BOOST_CHECK(pe86.get_architecture() == mana::PE::x86);
	mana::PE pe64("testfiles/manatest3.exe");
	BOOST_CHECK(pe64.get_architecture() == mana::PE::x64);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(parse_tls)
{
	mana::PE pe("testfiles/manatest3.exe");
	auto tls = pe.get_tls();
	BOOST_ASSERT(tls != nullptr);

	BOOST_CHECK_EQUAL(tls->StartAddressOfRawData,					0x140007000);
	BOOST_CHECK_EQUAL(tls->EndAddressOfRawData,						0x140007001);
	BOOST_CHECK_EQUAL(tls->AddressOfIndex,							0x140005098);
	BOOST_CHECK_EQUAL(tls->AddressOfCallbacks,						0x140003228);
	BOOST_CHECK_EQUAL(tls->SizeOfZeroFill,							0);
	BOOST_CHECK_EQUAL(*nt::translate_to_flag(tls->Characteristics,	nt::SECTION_CHARACTERISTICS), "IMAGE_SCN_ALIGN_1BYTES");
	BOOST_ASSERT(tls->Callbacks.size() == 1);
	BOOST_CHECK_EQUAL(tls->Callbacks[0],							0x140001070);

	mana::PE control("testfiles/manatest.exe");
	tls = control.get_tls();
	BOOST_CHECK(tls == nullptr);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(parse_delayed_imports)
{
	mana::PE pe("testfiles/manatest3.exe");
	auto dldt = pe.get_delay_load_table();
	BOOST_ASSERT(dldt != nullptr);

	BOOST_CHECK_EQUAL(dldt->Attributes,					1);
	BOOST_CHECK_EQUAL(dldt->NameStr,					"ADVAPI32.dll");
	BOOST_CHECK_EQUAL(dldt->ModuleHandle,				0x5050);
	BOOST_CHECK_EQUAL(dldt->DelayImportAddressTable,	0x5038);
	BOOST_CHECK_EQUAL(dldt->DelayImportNameTable,		0x3ab0);
	BOOST_CHECK_EQUAL(dldt->BoundDelayImportTable,		0x3ad8);
	BOOST_CHECK_EQUAL(dldt->UnloadDelayImportTable,		0);
	BOOST_CHECK_EQUAL(dldt->TimeStamp,					0);

	auto delay_loaded_import = pe.find_imports("CryptAcquireContextW");
	BOOST_ASSERT(delay_loaded_import->size() == 1);
	BOOST_CHECK_EQUAL(delay_loaded_import->at(0), "CryptAcquireContextW");

	// Also check the underlying structure. First find the corresponding ImportedLibrary object.
	auto imports = pe.get_imports();
	BOOST_ASSERT(imports != nullptr);
	mana::pImportedLibrary lib;
	for (auto it = imports->begin() ; it != imports->end() ; ++it)
	{
		pString s = (*it)->get_name();
		if (s != nullptr && *s == "ADVAPI32.dll")
		{
			lib = *it;
			break;
		}
	}

	BOOST_ASSERT(lib != nullptr);
	BOOST_CHECK_EQUAL(lib->get_type(), mana::ImportedLibrary::DELAY_LOADED);
	BOOST_CHECK(lib->get_image_import_descriptor() == nullptr); // No image import descriptor for delay-loaded DLLs.
	BOOST_CHECK_EQUAL(lib->get_imports()->size(), 1);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(parse_overlay)
{
    mana::PE pe("testfiles/manatest3.exe");
    auto overlay = pe.get_overlay_bytes();
    BOOST_ASSERT(overlay);
    std::string s(overlay->begin(), overlay->end());
    BOOST_CHECK_EQUAL(s, "Overlay Bytes :)");

    overlay = pe.get_overlay_bytes(8);
    BOOST_ASSERT(overlay);
    std::string s2(overlay->begin(), overlay->end());
    BOOST_CHECK_EQUAL(s2, "Overlay ");

    overlay = pe.get_overlay_bytes(0);
    BOOST_ASSERT(!overlay);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(parse_rich_header)
{
	mana::PE pe("testfiles/manatest.exe");
	auto rich = pe.get_rich_header();
	BOOST_ASSERT(rich != nullptr);
	BOOST_CHECK_EQUAL(rich->xor_key, 0x374baddd);
	BOOST_CHECK_EQUAL(rich->file_offset, 0x80);
	BOOST_CHECK_EQUAL(rich->values.size(), 11);

	BOOST_CHECK_EQUAL(std::get<0>(rich->values.at(0)),  0);
	BOOST_CHECK_EQUAL(std::get<1>(rich->values.at(0)),  0);
	BOOST_CHECK_EQUAL(std::get<2>(rich->values.at(0)),  0);
	BOOST_CHECK_EQUAL(std::get<0>(rich->values.at(1)),  0x0093);
	BOOST_CHECK_EQUAL(std::get<1>(rich->values.at(1)),  0x7809);
	BOOST_CHECK_EQUAL(std::get<2>(rich->values.at(1)),  0xa);
	BOOST_CHECK_EQUAL(std::get<0>(rich->values.at(2)),  0x0103);
	BOOST_CHECK_EQUAL(std::get<1>(rich->values.at(2)),  0x5b6e);
	BOOST_CHECK_EQUAL(std::get<2>(rich->values.at(2)),  1);
	BOOST_CHECK_EQUAL(std::get<0>(rich->values.at(3)),  0x105);
	BOOST_CHECK_EQUAL(std::get<1>(rich->values.at(3)),  0x5b6e);
	BOOST_CHECK_EQUAL(std::get<2>(rich->values.at(3)),  17);
	BOOST_CHECK_EQUAL(std::get<0>(rich->values.at(10)), 0x0102);
	BOOST_CHECK_EQUAL(std::get<1>(rich->values.at(10)), 0x5bd2);
	BOOST_CHECK_EQUAL(std::get<2>(rich->values.at(10)), 1);
}

// ----------------------------------------------------------------------------
BOOST_AUTO_TEST_SUITE_END()
// ----------------------------------------------------------------------------
