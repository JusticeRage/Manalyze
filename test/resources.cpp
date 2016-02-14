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
	mana::PE pe("testfiles/manatest.exe");
	pe.extract_resources(".");
	auto h = hash::hash_file(*hash::ALL_DIGESTS.at(ALL_DIGESTS_SHA256), "manatest_1_RT_MANIFEST.xml");
	fs::remove("manatest_1_RT_MANIFEST.xml");
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
	check_resource(resources->at(10), 7,   "RT_STRING",     "German - Germany",        0x38,   1.54);
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
	auto string_table = resources->at(10)->interpret_as<const_shared_strings>();
	BOOST_ASSERT(string_table && string_table->size() == 16);
	BOOST_CHECK_EQUAL(string_table->at(7), "Test 1");
	BOOST_CHECK_EQUAL(string_table->at(8), "Test 2");
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
BOOST_AUTO_TEST_SUITE_END()
// ----------------------------------------------------------------------------