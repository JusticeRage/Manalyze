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
#include "manape/pe.h"
#include "plugin_framework/plugin_interface.h"

namespace plugin {
extern "C" IPlugin* create();
extern "C" void destroy(IPlugin* plugin);
}

BOOST_FIXTURE_TEST_SUITE(authenticode_openssl, SetWorkingDirectory)

BOOST_AUTO_TEST_CASE(reject_empty_certificate_before_bio_creation)
{
	auto bytes = read_binary_file("testfiles/manatest.exe");
	constexpr size_t optional_header = 0x108;
	constexpr size_t security_directory = optional_header + 96 + IMAGE_DIRECTORY_ENTRY_SECURITY * 8;
	constexpr std::uint32_t certificate_offset = 0x2e00;
	write_u32(bytes, security_directory, certificate_offset);
	write_u32(bytes, security_directory + 4, 8);
	write_u32(bytes, certificate_offset, 8);
	write_u16(bytes, certificate_offset + 4, 0x0200);
	write_u16(bytes, certificate_offset + 6, WIN_CERT_TYPE_PKCS_SIGNED_DATA);

	auto pe = mana::PE::create_from_bytes(bytes.data(), bytes.size(), "empty-certificate.exe");
	BOOST_REQUIRE(pe && pe->is_valid());
	auto certificates = pe->get_certificates();
	BOOST_REQUIRE_EQUAL(certificates->size(), 1);
	BOOST_REQUIRE(certificates->front()->Certificate.empty());

	std::unique_ptr<plugin::IPlugin, void (*)(plugin::IPlugin*)> authenticode(
		plugin::create(), plugin::destroy);
	BOOST_REQUIRE(authenticode);
	BOOST_CHECK(authenticode->analyze(*pe));
}

BOOST_AUTO_TEST_SUITE_END()
