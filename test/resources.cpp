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

#include <vector>
#include <boost/assign.hpp>

#include "fixtures.h"
#include "manape/pe.h"
#include "manape/resources.h"
#include "hash-library/hashes.h"

// ----------------------------------------------------------------------------
BOOST_FIXTURE_TEST_SUITE(resources, SetWorkingDirectory)
// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(parse_resources)
{
	mana::PE pe("testfiles/manatest.exe");
	auto resources = pe.get_resources();
	BOOST_ASSERT(resources);
	BOOST_ASSERT(resources->size() == 1);
	mana::pResource r = resources->at(0);
	BOOST_CHECK(*r->get_type() == "RT_MANIFEST");
	BOOST_CHECK(r->get_id() == 1);
	BOOST_CHECK(*r->get_name() == "1");
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

BOOST_AUTO_TEST_CASE(interpret_manifest)
{
	mana::PE pe("testfiles/manatest.exe");
	auto resources = pe.get_resources();
	BOOST_ASSERT(resources);
	BOOST_ASSERT(resources->size() == 1);
	mana::pResource r = resources->at(0);
	BOOST_ASSERT(*r->get_type() == "RT_MANIFEST");
	pString rt_manifest = r->interpret_as<pString>();
	BOOST_ASSERT(rt_manifest);
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
	BOOST_CHECK(*rt_manifest == expected);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(extract_manifest)
{
	// TODO: Rewrite unit tests for the extract function.
	// A test is needed for RT_BITMAPs and RT_STRINGs in particular.

	mana::PE pe("testfiles/manatest.exe");
	auto resources = pe.get_resources();
    for (auto it = resources->begin() ; it != resources->end() ; ++it)
    {
        if (*(*it)->get_type() == "RT_MANIFEST")
        {
            (*it)->extract("manifest.xml");
            break;
        }
    }
	auto h = hash::hash_file(*hash::ALL_DIGESTS.at(ALL_DIGESTS_SHA256), "manifest.xml");
	fs::remove("manifest.xml");
	BOOST_ASSERT(h);
	BOOST_CHECK_EQUAL(*h, "4bb79dcea0a901f7d9eac5aa05728ae92acb42e0cb22e5dd14134f4421a3d8df");
}

// ----------------------------------------------------------------------------

/**
 *	@brief	Helper function which checks all of a Resource's fields against
 *			given values.
 */
void check_resource(mana::pResource r,
					boost::uint32_t id,
					const std::string& type,
					const std::string& language,
					boost::uint32_t size,
					double entropy)
{
	BOOST_ASSERT(r);
	BOOST_CHECK_EQUAL(r->get_id(), id);
	BOOST_ASSERT(r->get_type());
	BOOST_CHECK_EQUAL(*r->get_type(), type);
	BOOST_CHECK_EQUAL(r->get_codepage(), 0);
	BOOST_ASSERT(r->get_language());
	BOOST_CHECK_EQUAL(*r->get_language(), language);
	BOOST_CHECK_EQUAL(r->get_size(), size);
	double res_entropy = r->get_entropy();
	BOOST_CHECK(entropy - 0.01 < res_entropy &&
				res_entropy < entropy + 0.01);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(parse_resources_2)
{
	mana::PE pe("testfiles/manatest2.exe");
	auto resources = pe.get_resources();
	BOOST_ASSERT(resources->size() == 14);
	check_resource(resources->at(0),  102, "RC_DATA",       "French - France",         16360,  6.18);
	check_resource(resources->at(1),  1,   "RT_ICON",       "English - United States", 0xb13,  7.44);
	check_resource(resources->at(2),  2,   "RT_ICON",       "English - United States", 0xea8,  2.14);
	check_resource(resources->at(3),  3,   "RT_ICON",       "English - United States", 0x8a8,  1.94);
	check_resource(resources->at(4),  4,   "RT_ICON",       "English - United States", 0x568,  1.24);
	check_resource(resources->at(5),  5,   "RT_ICON",       "English - United States", 0xc4a,  7.48);
	check_resource(resources->at(6),  6,   "RT_ICON",       "English - United States", 0x4228, 2.58);
	check_resource(resources->at(7),  7,   "RT_ICON",       "English - United States", 0x25a8, 2.68);
	check_resource(resources->at(8),  8,   "RT_ICON",       "English - United States", 0x10a8, 2.69);
	check_resource(resources->at(9),  9,   "RT_ICON",       "English - United States", 0x468,  2.87);
	check_resource(resources->at(10), 7,   "RT_STRING",     "German - Germany",        0x76,   4.34);
	check_resource(resources->at(11), 101, "RT_GROUP_ICON", "English - United States", 0x84,   3.00);
	check_resource(resources->at(12), 1,   "RT_VERSION",    "English - United States", 0x2d4,  3.31);
	check_resource(resources->at(13), 1,   "RT_MANIFEST",   "English - United States", 0x17d,  4.91);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(interpret_stringtable)
{
	mana::PE pe("testfiles/manatest2.exe");
	auto resources = pe.get_resources();
	BOOST_ASSERT(resources->size() == 14);
	auto string_table = resources->at(10)->interpret_as<mana::const_shared_strings>();
	BOOST_ASSERT(string_table && string_table->size() == 16);
	for (int i = 0 ; i < 7 ; ++i) {
		BOOST_CHECK(string_table->at(i) == "");
	}
	BOOST_CHECK_EQUAL(string_table->at(7), "Test 1");
	BOOST_CHECK_EQUAL(string_table->at(8), "Test 2");

	// Unicode representation of "无法对 %1 进行写操作，因为它是只读文件或已经被其他人打开。"
	std::string utf8_string = string_table->at(9);
	boost::uint8_t bytes[] = 
					  { 0xE6, 0x97, 0xA0, 0xE6, 0xB3, 0x95, 0xE5, 0xAF, 0xB9, 0x20, 0x25, 0x31, 0x20, 
						0xE8, 0xBF, 0x9B, 0xE8, 0xA1, 0x8C, 0xE5, 0x86, 0x99, 0xE6, 0x93, 0x8D, 0xE4, 
						0xBD, 0x9C, 0xEF, 0xBC, 0x8C, 0xE5, 0x9B, 0xA0, 0xE4, 0xB8, 0xBA, 0xE5, 0xAE, 
						0x83, 0xE6, 0x98, 0xAF, 0xE5, 0x8F, 0xAA, 0xE8, 0xAF, 0xBB, 0xE6, 0x96, 0x87, 
						0xE4, 0xBB, 0xB6, 0xE6, 0x88, 0x96, 0xE5, 0xB7, 0xB2, 0xE7, 0xBB, 0x8F, 0xE8, 
						0xA2, 0xAB, 0xE5, 0x85, 0xB6, 0xE4, 0xBB, 0x96, 0xE4, 0xBA, 0xBA, 0xE6, 0x89, 
						0x93, 0xE5, 0xBC, 0x80, 0xE3, 0x80, 0x82 };
	std::vector<boost::uint8_t> expected(bytes, bytes + sizeof(bytes));
	std::vector<boost::uint8_t> found(utf8_string.begin(), utf8_string.end());
	BOOST_CHECK(expected == found);

	for (int i = 10 ; i < 16 ; ++i) {
		BOOST_CHECK(string_table->at(i) == "");
	}
}

// ----------------------------------------------------------------------------

template<class T>
void check_pair(boost::shared_ptr<std::pair<T, T> > pair, const T& first, const T& second )
{
	BOOST_CHECK_EQUAL(pair->first, first);
	BOOST_CHECK_EQUAL(pair->second, second);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(interpret_versioninfo)
{
	mana::PE pe("testfiles/manatest2.exe");
	auto resources = pe.get_resources();
	BOOST_ASSERT(resources->size() == 14);
	auto vi = resources->at(12)->interpret_as<mana::pversion_info>();
	BOOST_ASSERT(vi);
	BOOST_CHECK_EQUAL(vi->Header.Key, "VS_VERSION_INFO");
	BOOST_CHECK_EQUAL(vi->Value->Signature, 0xfeef04bd);
	BOOST_CHECK_EQUAL(vi->Value->FileFlags, 0);
	BOOST_CHECK_EQUAL(*nt::translate_to_flag(vi->Value->FileType, nt::FIXEDFILEINFO_FILETYPE), "VFT_APP");
	std::vector<std::string> fileos_expected =
		boost::assign::list_of("VOS_DOS_WINDOWS32")("VOS_NT")("VOS_NT_WINDOWS32")("VOS_WINCE")("VOS__WINDOWS32");
	auto fileos = *nt::translate_to_flags(vi->Value->FileOs, nt::FIXEDFILEINFO_FILEOS);
	BOOST_ASSERT(fileos.size() == fileos_expected.size());
	BOOST_CHECK_EQUAL_COLLECTIONS(fileos.begin(), fileos.end(), fileos_expected.begin(), fileos_expected.end());

	// VersionInfo string table
	std::vector<mana::ppair> string_table = vi->StringTable;
	check_pair<std::string>(string_table[0], "CompanyName", "manalyzer.org");
	check_pair<std::string>(string_table[1], "FileDescription", "Manalyze test file.");
	check_pair<std::string>(string_table[2], "FileVersion", "1.0.0.0");
	check_pair<std::string>(string_table[3], "InternalName", "manatest2.exe");
	check_pair<std::string>(string_table[4], "LegalCopyright", "Copyright (C) 2016");
	check_pair<std::string>(string_table[5], "OriginalFilename", "manatest2.exe");
	check_pair<std::string>(string_table[6], "ProductName", "manatest2.exe");
	check_pair<std::string>(string_table[7], "ProductVersion", "1.0.0.0");
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(interpret_icon)
{
	mana::PE pe("testfiles/manatest2.exe");
	auto resources = pe.get_resources();
	for (auto it = resources->begin(); it != resources->end(); ++it)
	{
		if (*(*it)->get_type() == "RT_GROUP_ICON")
		{
			auto res = (*it)->icon_extract("testfiles/icon.ico", *pe.get_resources());
			break;
		}
	}

	auto h = hash::hash_file(*hash::ALL_DIGESTS.at(ALL_DIGESTS_SHA1), "testfiles/icon.ico");
	BOOST_ASSERT(fs::exists("testfiles/icon.ico"));
	fs::remove("testfiles/icon.ico");
	BOOST_ASSERT(h);
	BOOST_CHECK_EQUAL(*h, "ef6952d242906001e0d3269e5df0d8e22f3c56d1");
	
}

// ----------------------------------------------------------------------------
BOOST_AUTO_TEST_SUITE_END()
// ----------------------------------------------------------------------------
