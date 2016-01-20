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
	BOOST_CHECK(*h == "4bb79dcea0a901f7d9eac5aa05728ae92acb42e0cb22e5dd14134f4421a3d8df");
}

// ----------------------------------------------------------------------------
BOOST_AUTO_TEST_SUITE_END()
// ----------------------------------------------------------------------------