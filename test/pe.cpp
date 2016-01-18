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

#include <boost/test/unit_test.hpp>
#include <boost/filesystem.hpp>

#include "manape/pe.h"
#include "manape/imports.h" // Contains the hash::hash_imports function.

namespace unit = boost::unit_test::framework;
namespace fs = boost::filesystem;

// ----------------------------------------------------------------------------

/**
 * Fixture setting the current directory to "[project_dir]/test/".
 * The initial working directory is restored after the test.
 */
class SetWorkingDirectory
{
public:
    SetWorkingDirectory()
    {
        // Save the current working directory
        _original_directory = fs::current_path().string();

        // Go to the test directory
        fs::path working_dir(unit::master_test_suite().argv[0]);
        working_dir = working_dir.parent_path();
        fs::current_path(working_dir / ".." / "test");
    }

    ~SetWorkingDirectory() {
        fs::current_path(_original_directory);
    }

private:
    std::string _original_directory;
};

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


BOOST_FIXTURE_TEST_CASE(parse_testfile, SetWorkingDirectory)
{
    mana::PE pe("testfiles/manatest.exe");
	BOOST_CHECK_EQUAL(pe.get_filesize(), 16360);
	BOOST_ASSERT(pe.is_valid());
}

// ----------------------------------------------------------------------------

BOOST_FIXTURE_TEST_CASE(parse_dos_header, SetWorkingDirectory)
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

BOOST_FIXTURE_TEST_CASE(parse_pe_header, SetWorkingDirectory)
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

BOOST_FIXTURE_TEST_CASE(parse_opt_header, SetWorkingDirectory)
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

BOOST_FIXTURE_TEST_CASE(parse_sections, SetWorkingDirectory)
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

BOOST_FIXTURE_TEST_CASE(parse_resources, SetWorkingDirectory)
{
	mana::PE pe("testfiles/manatest.exe");
	auto resources = pe.get_resources();
	BOOST_ASSERT(resources);
	BOOST_ASSERT(resources->size() == 1);
	mana::pResource r = resources->at(0);
	BOOST_CHECK(*r->get_type() == "RT_MANIFEST");
	BOOST_CHECK(r->get_id() == 1);
	BOOST_CHECK(r->get_size() == 381);
	BOOST_CHECK(r->get_codepage() == 0);
	BOOST_CHECK(r->get_offset() == 0x2a60);
	BOOST_CHECK(*r->get_language() == "English - United States");
	auto bytes = r->get_raw_data();
	std::string rt_manifest(bytes->begin(), bytes->end());
	std::string expected = "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>\r\n"
		"<assembly xmlns='urn:schemas-microsoft-com:asm.v1' manifestVersion='1.0'>\r\n"
		"  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">\r\n"
		"    <security>\r\n"
		"      <requestedPrivileges>\r\n"
		"        <requestedExecutionLevel level='asInvoker' uiAccess='false' />\r\n"
		"      </requestedPrivileges>\r\n"
		"    </security>\r\n"
		"  </trustInfo>\r\n"
		"</assembly>\r\n";
	BOOST_CHECK(rt_manifest == expected);
}

// ----------------------------------------------------------------------------

BOOST_FIXTURE_TEST_CASE(parse_imports, SetWorkingDirectory)
{
	mana::PE pe("testfiles/manatest.exe");
	BOOST_ASSERT(pe.get_imported_dlls());
	auto dlls = *pe.get_imported_dlls();
	BOOST_ASSERT(dlls.size() == 8);
	std::vector<std::string> expected_dlls;
	expected_dlls.push_back("KERNEL32.dll");
	expected_dlls.push_back("MSVCP140.dll");
	expected_dlls.push_back("VCRUNTIME140.dll");
	expected_dlls.push_back("api-ms-win-crt-runtime-l1-1-0.dll");
	expected_dlls.push_back("api-ms-win-crt-math-l1-1-0.dll");
	expected_dlls.push_back("api-ms-win-crt-stdio-l1-1-0.dll");
	expected_dlls.push_back("api-ms-win-crt-locale-l1-1-0.dll");
	expected_dlls.push_back("api-ms-win-crt-heap-l1-1-0.dll");
	BOOST_ASSERT(dlls == expected_dlls);

	BOOST_ASSERT(pe.get_imported_functions("KERNEL32.dll"));
	auto functions = *pe.get_imported_functions("KERNEL32.dll");
	BOOST_ASSERT(functions.size() == 15);
	std::vector<std::string> expected_functions;
	expected_functions.push_back("WriteProcessMemory");
	expected_functions.push_back("OpenProcess");
	expected_functions.push_back("CreateRemoteThread");
	expected_functions.push_back("SetUnhandledExceptionFilter");
	expected_functions.push_back("GetCurrentProcess");
	expected_functions.push_back("TerminateProcess");
	expected_functions.push_back("IsProcessorFeaturePresent");
	expected_functions.push_back("QueryPerformanceCounter");
	expected_functions.push_back("GetCurrentProcessId");
	expected_functions.push_back("GetCurrentThreadId");
	expected_functions.push_back("GetSystemTimeAsFileTime");
	expected_functions.push_back("InitializeSListHead");
	expected_functions.push_back("IsDebuggerPresent");
	expected_functions.push_back("GetModuleHandleW");
	expected_functions.push_back("UnhandledExceptionFilter");
	BOOST_CHECK(functions == expected_functions);

	auto imphash = hash::hash_imports(pe);
	BOOST_ASSERT(imphash);
	BOOST_CHECK(*imphash == "924ac5aa343a9f838d5c16a5d77de2ec");
}

// ----------------------------------------------------------------------------

BOOST_FIXTURE_TEST_CASE(find_imports, SetWorkingDirectory)
{
	// Find functions by regular expression
	mana::PE pe("testfiles/manatest.exe");
	auto pfunctions = pe.find_imports(".*basic_ostream.*", "MSVCP\\d{3}.dll|KERNEL32.dll");
	BOOST_ASSERT(pfunctions);
	BOOST_ASSERT(pfunctions->size() == 6);
	std::vector<std::string> expected_functions;
	expected_functions.push_back("??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QAEAAV01@P6AAAVios_base@1@AAV21@@Z@Z");
	expected_functions.push_back("??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QAEAAV01@P6AAAV01@AAV01@@Z@Z");
	expected_functions.push_back("?cout@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A");
	expected_functions.push_back("?_Osfx@?$basic_ostream@DU?$char_traits@D@std@@@std@@QAEXXZ");
	expected_functions.push_back("?flush@?$basic_ostream@DU?$char_traits@D@std@@@std@@QAEAAV12@XZ");
	expected_functions.push_back("?put@?$basic_ostream@DU?$char_traits@D@std@@@std@@QAEAAV12@D@Z");
	BOOST_CHECK(*pfunctions == expected_functions);

	// Verify that the same search on all DLLs returns the same results
	pfunctions = pe.find_imports(".*basic_ostream.*");
	BOOST_ASSERT(pfunctions);
	BOOST_CHECK(*pfunctions == expected_functions);
}

// ----------------------------------------------------------------------------

BOOST_FIXTURE_TEST_CASE(find_imports_no_match, SetWorkingDirectory)
{
	mana::PE pe("testfiles/manatest.exe");
	auto pfunctions = pe.find_imports("I DON'T EXIST");
	BOOST_ASSERT(pfunctions);
	BOOST_CHECK(pfunctions->size() == 0);
}
