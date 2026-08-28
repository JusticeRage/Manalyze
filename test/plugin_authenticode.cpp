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

#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <openssl/asn1.h>

#include "../plugins/plugin_authenticode/asn1.h"
#include "fixtures.h"
#include "manacommons/color.h"
#include "manape/pe.h"
#include "plugin_framework/plugin_interface.h"

namespace plugin {
extern "C" IPlugin* create();
extern "C" void destroy(IPlugin* plugin);
}

namespace {
using Asn1StringPtr = std::unique_ptr<ASN1_STRING, decltype(&ASN1_STRING_free)>;

std::vector<std::uint8_t> from_hex(const std::string& hex)
{
	std::vector<std::uint8_t> bytes;
	BOOST_REQUIRE_EQUAL(hex.size() % 2, 0);
	for (size_t i = 0; i < hex.size(); i += 2) {
		bytes.push_back(static_cast<std::uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
	}
	return bytes;
}

Asn1StringPtr make_asn1_string(const std::vector<std::uint8_t>& bytes)
{
	Asn1StringPtr value(ASN1_STRING_new(), ASN1_STRING_free);
	BOOST_REQUIRE(value);
	BOOST_REQUIRE_EQUAL(ASN1_STRING_set(value.get(), bytes.data(), bytes.size()), 1);
	return value;
}

class ErrorCapture
{
public:
	ErrorCapture()
		: previous_level(utils::get_log_level()),
		  previous_buffer(std::cerr.rdbuf(captured.rdbuf()))
	{ utils::set_log_level(utils::LogLevel::ERROR); }

	~ErrorCapture()
	{
		std::cerr.rdbuf(previous_buffer);
		utils::set_log_level(previous_level);
	}

	std::string str() const { return captured.str(); }

private:
	utils::LogLevel previous_level;
	std::ostringstream captured;
	std::streambuf* previous_buffer;
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(authenticode_openssl, SetWorkingDirectory)

BOOST_AUTO_TEST_CASE(parse_valid_spc_indirect_data_digest)
{
	const auto encoded = from_hex(
		"304c3017060a2b06010401823702010f3009030100a004a2028000"
		"3031300d060960864801650304020105000420"
		"000102030405060708090a0b0c0d0e0f"
		"101112131415161718191a1b1c1d1e1f");
	auto asn1 = make_asn1_string(encoded);
	AuthenticodeDigest digest;
	BOOST_REQUIRE(plugin::parse_spc_asn1(asn1.get(), digest));
	BOOST_CHECK_EQUAL(digest.algorithm, "2.16.840.1.101.3.4.2.1");
	BOOST_REQUIRE_EQUAL(digest.digest.size(), 32);
	for (size_t i = 0; i < digest.digest.size(); ++i)
		BOOST_CHECK_EQUAL(digest.digest[i], i);
}

BOOST_AUTO_TEST_CASE(reject_truncated_nested_tlv)
{
	const auto encoded = from_hex(
		"301c3017060a2b06010401823702010f3009030100a004a2028000300130");
	auto asn1 = make_asn1_string(encoded);
	AuthenticodeDigest digest;
	digest.algorithm = "unchanged";
	digest.digest = {0xaa};
	ErrorCapture errors;
	BOOST_CHECK(!plugin::parse_spc_asn1(asn1.get(), digest));
	BOOST_CHECK_NE(errors.str().find("AlgorithmIdentifier"), std::string::npos);
	BOOST_CHECK_EQUAL(digest.algorithm, "unchanged");
	BOOST_REQUIRE_EQUAL(digest.digest.size(), 1);
	BOOST_CHECK_EQUAL(digest.digest.front(), 0xaa);
}

BOOST_AUTO_TEST_CASE(reject_overdeclared_nested_tlv)
{
	const auto encoded = from_hex(
		"304c3017060a2b06010401823702010f3009030100a004a2028000"
		"3031300d067f60864801650304020105000420"
		"000102030405060708090a0b0c0d0e0f"
		"101112131415161718191a1b1c1d1e1f");
	auto asn1 = make_asn1_string(encoded);
	AuthenticodeDigest digest;
	digest.algorithm = "unchanged";
	digest.digest = {0xaa};
	ErrorCapture errors;
	BOOST_CHECK(!plugin::parse_spc_asn1(asn1.get(), digest));
	BOOST_CHECK_NE(errors.str().find("algorithm"), std::string::npos);
	BOOST_CHECK_EQUAL(digest.algorithm, "unchanged");
	BOOST_REQUIRE_EQUAL(digest.digest.size(), 1);
	BOOST_CHECK_EQUAL(digest.digest.front(), 0xaa);
}

BOOST_AUTO_TEST_CASE(reject_empty_required_attribute_with_diagnostic)
{
	const auto encoded = from_hex("3000");
	auto asn1 = make_asn1_string(encoded);
	AuthenticodeDigest digest;
	digest.algorithm = "unchanged";
	digest.digest = {0xaa};
	ErrorCapture errors;
	BOOST_CHECK(!plugin::parse_spc_asn1(asn1.get(), digest));
	BOOST_CHECK_NE(errors.str().find("SpcAttributeTypeAndOptionalValue"), std::string::npos);
	BOOST_CHECK_EQUAL(digest.algorithm, "unchanged");
	BOOST_REQUIRE_EQUAL(digest.digest.size(), 1);
	BOOST_CHECK_EQUAL(digest.digest.front(), 0xaa);
}

BOOST_AUTO_TEST_CASE(reject_null_spc_data_with_diagnostic)
{
	AuthenticodeDigest digest;
	digest.algorithm = "unchanged";
	digest.digest = {0xaa};
	ErrorCapture errors;
	BOOST_CHECK(!plugin::parse_spc_asn1(nullptr, digest));
	BOOST_CHECK_NE(errors.str().find("SpcIndirectDataContent"), std::string::npos);
	BOOST_CHECK_EQUAL(digest.algorithm, "unchanged");
	BOOST_REQUIRE_EQUAL(digest.digest.size(), 1);
	BOOST_CHECK_EQUAL(digest.digest.front(), 0xaa);
}

BOOST_AUTO_TEST_CASE(reject_empty_spc_data_with_diagnostic)
{
	Asn1StringPtr asn1(ASN1_STRING_new(), ASN1_STRING_free);
	BOOST_REQUIRE(asn1);
	AuthenticodeDigest digest;
	digest.algorithm = "unchanged";
	digest.digest = {0xaa};
	ErrorCapture errors;
	BOOST_CHECK(!plugin::parse_spc_asn1(asn1.get(), digest));
	BOOST_CHECK_NE(errors.str().find("SpcIndirectDataContent"), std::string::npos);
	BOOST_CHECK_EQUAL(digest.algorithm, "unchanged");
	BOOST_REQUIRE_EQUAL(digest.digest.size(), 1);
	BOOST_CHECK_EQUAL(digest.digest.front(), 0xaa);
}

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
