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
#include "fixtures.h"
#include "manape/section.h"
#include "manape/pe.h"
#include "hash-library/hashes.h"

BOOST_AUTO_TEST_CASE(section_invalid_args)
{
	mana::image_section_header h = {0};
	mana::Section s(h, nullptr, 0);

	auto res = s.get_raw_data();
	BOOST_CHECK(res->size() == 0);
	BOOST_CHECK(s.get_entropy() == 0);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(check_address_inside_section)
{
	mana::image_section_header h;
	h.VirtualAddress = 100;
	h.SizeOfRawData = 40;
	h.VirtualSize = 50;
	mana::pSection s = boost::make_shared<mana::Section>(h, nullptr, 200);

	// Check with VirtualSize
	BOOST_CHECK(mana::is_address_in_section(-1, s) == false);
	BOOST_CHECK(mana::is_address_in_section(99, s) == false);
	BOOST_CHECK(mana::is_address_in_section(100, s) == true);
	BOOST_CHECK(mana::is_address_in_section(125, s) == true);
	BOOST_CHECK(mana::is_address_in_section(149, s) == true);
	BOOST_CHECK(mana::is_address_in_section(150, s) == false);
	BOOST_CHECK(mana::is_address_in_section(200, s) == false);

	// Check with SizeOfRawData
	BOOST_CHECK(mana::is_address_in_section(-1, s, true) == false);
	BOOST_CHECK(mana::is_address_in_section(99, s, true) == false);
	BOOST_CHECK(mana::is_address_in_section(100, s, true) == true);
	BOOST_CHECK(mana::is_address_in_section(125, s, true) == true);
	BOOST_CHECK(mana::is_address_in_section(139, s, true) == true);
	BOOST_CHECK(mana::is_address_in_section(140, s, true) == false);
	BOOST_CHECK(mana::is_address_in_section(200, s, true) == false);

	// Section with a null size
	h.VirtualSize = 0;
	h.SizeOfRawData = 0;
	s = boost::make_shared<mana::Section>(h, nullptr, 200);
	BOOST_CHECK(mana::is_address_in_section(100, s) == false);
	BOOST_CHECK(mana::is_address_in_section(100, s, true) == false);
}

// ----------------------------------------------------------------------------

void check_section_hash(mana::shared_bytes data, const std::string& md5)
{
	BOOST_ASSERT(data);
	pString h = hash::hash_bytes(*hash::ALL_DIGESTS.at(ALL_DIGESTS_MD5), *data);
	BOOST_ASSERT(h);
	BOOST_CHECK(*h == md5);
}

// ----------------------------------------------------------------------------

void check_section_entropy(mana::pSection section, double entropy)
{
	BOOST_ASSERT(section);
	double section_entropy = section->get_entropy();
	BOOST_CHECK(entropy - 0.01 < section_entropy &&
			    section_entropy < entropy + 0.01);
}

// ----------------------------------------------------------------------------
BOOST_FIXTURE_TEST_SUITE(sections, SetWorkingDirectory)
// ----------------------------------------------------------------------------

// Values in this test suite checked against
// https://www.virustotal.com/en/file/f1f6992fe20fae686dc9d810554371ed4ef42db3f35f2b2c2cf4b5ad4c708a4b/analysis/

BOOST_AUTO_TEST_CASE(section_get_raw_data)
{
	mana::PE pe("testfiles/manatest.exe");
	auto sections = pe.get_sections();
	BOOST_ASSERT(sections->size() == 6);
	check_section_hash(sections->at(0)->get_raw_data(), "53dae03e5d3f8c7eb2de7d70031b54e7");
	check_section_hash(sections->at(1)->get_raw_data(), "7fad1397bb3f659039aa3882ccf8c654");
	check_section_hash(sections->at(2)->get_raw_data(), "550b6d19eefd3a6f89a89a9be78fdbaf");
	check_section_hash(sections->at(3)->get_raw_data(), "b65f8c4251948181c105796e168065b2");
	check_section_hash(sections->at(4)->get_raw_data(), "d223c232889289f7388583adeff234e1");
	check_section_hash(sections->at(5)->get_raw_data(), "3f22bbba6970dcddf452b25b7b38f9ad");
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(section_entropy)
{
	mana::PE pe("testfiles/manatest.exe");
	auto sections = pe.get_sections();
	BOOST_ASSERT(sections->size() == 6);
	check_section_entropy(sections->at(0), 5.93);
	check_section_entropy(sections->at(1), 4.96);
	check_section_entropy(sections->at(2), 0.28);
	check_section_entropy(sections->at(3), 0.16);
	check_section_entropy(sections->at(4), 4.70);
	check_section_entropy(sections->at(5), 5.71);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(find_section)
{
	mana::PE pe("testfiles/manatest.exe");
	auto sections = pe.get_sections();
	BOOST_ASSERT(sections);
	BOOST_CHECK(mana::find_section(0, *sections) == nullptr);
	BOOST_CHECK(mana::find_section(4095, *sections) == nullptr);
	BOOST_CHECK(mana::find_section(0xFFFFFFFF, *sections) == nullptr);

	mana::pSection s = mana::find_section(4096, *sections);
	BOOST_CHECK(s && s->get_name() && *s->get_name() == ".text");

	// Just at the start of .data and the end of .rdata, comparison has to be made with SizeOfRawData
	s = mana::find_section(16384, *sections);
	BOOST_CHECK(s && s->get_name() && *s->get_name() == ".data");

	// Call find_section with an empty vector of sections.
	s = mana::find_section(0, std::vector<mana::pSection>());
	BOOST_CHECK(s == nullptr);
}

// ----------------------------------------------------------------------------
BOOST_AUTO_TEST_SUITE_END()
// ----------------------------------------------------------------------------
