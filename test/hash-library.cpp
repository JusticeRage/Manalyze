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

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>

#include "hash-library/hashes.h"
#include "hash-library/ssdeep.h"
#include "hash-library/cryptocurrency.h"
#include "fixtures.h"

BOOST_AUTO_TEST_CASE(hash_phrase)
{
	std::string input("The quick brown fox jumps over the lazy dog");
	std::vector<boost::uint8_t> bytes(input.begin(), input.end());
	hash::const_shared_strings hashes = hash::hash_bytes(hash::ALL_DIGESTS, bytes);

	BOOST_CHECK_EQUAL("9e107d9d372bb6826bd81d3542a419d6", hashes->at(ALL_DIGESTS_MD5));
	BOOST_CHECK_EQUAL("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", hashes->at(ALL_DIGESTS_SHA1));
	BOOST_CHECK_EQUAL("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", hashes->at(ALL_DIGESTS_SHA256));
	BOOST_CHECK_EQUAL("07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6", hashes->at(ALL_DIGESTS_SHA512));
	BOOST_CHECK_EQUAL("69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04", hashes->at(ALL_DIGESTS_SHA3));
	BOOST_CHECK_EQUAL("4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15", hashes->at(ALL_DIGESTS_KECCAK));
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(null_hash)
{
	std::vector<boost::uint8_t> bytes(0);
	hash::const_shared_strings hashes = hash::hash_bytes(hash::ALL_DIGESTS, bytes);

	BOOST_CHECK_EQUAL("d41d8cd98f00b204e9800998ecf8427e", hashes->at(ALL_DIGESTS_MD5));
	BOOST_CHECK_EQUAL("da39a3ee5e6b4b0d3255bfef95601890afd80709", hashes->at(ALL_DIGESTS_SHA1));
	BOOST_CHECK_EQUAL("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hashes->at(ALL_DIGESTS_SHA256));
	BOOST_CHECK_EQUAL("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", hashes->at(ALL_DIGESTS_SHA512));
	BOOST_CHECK_EQUAL("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", hashes->at(ALL_DIGESTS_SHA3));
    BOOST_CHECK_EQUAL("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", hashes->at(ALL_DIGESTS_KECCAK));
}

BOOST_AUTO_TEST_CASE(SHA512TEST)
{
    std::string input("lalalalalalalalalalalalalalalala");
    std::vector<boost::uint8_t> bytes(input.begin(), input.end());
    hash::const_shared_strings hashes = hash::hash_bytes(hash::ALL_DIGESTS, bytes);

    BOOST_CHECK_EQUAL("93161156c77aa89f9666b77fa0be19274df3220fb6f5463279de5dd405386258039e33274d8395cbca60060afe16dc02cdc2a354b77981ad97192deb270a84fe", hashes->at(ALL_DIGESTS_SHA512));
}

// ----------------------------------------------------------------------------

// Make sure that null pointers are returned when asked to hash missing files.
BOOST_AUTO_TEST_CASE(hash_missing_file)
{
	hash::const_shared_strings hashes = hash::hash_file(hash::ALL_DIGESTS, "I_DON'T_EXIST.txt");
	BOOST_ASSERT(!hashes);
	pString h = hash::hash_file(*hash::ALL_DIGESTS.at(ALL_DIGESTS_MD5), "I_DON'T_EXIST.txt");
	BOOST_CHECK(!h);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(ssdeep_hash_buffer)
{
	std::vector<boost::uint8_t> buffer(65536);
	memset(&buffer[0], 0x41, 65536);
	pString s = ssdeep::hash_buffer(buffer);
	BOOST_ASSERT(s);
	BOOST_CHECK(*s == "3:Wttkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkw:Yu");
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(btc_test_address)
{
	BOOST_CHECK(hash::test_btc_address("19wFVDUWhrjRe3rPCsokhcf1w9Stj3Sr6K"));
	BOOST_CHECK(!hash::test_btc_address("19wFVDUWhrjRe3rPCsokhcf1w9Stj3Sr6A"));
	BOOST_CHECK(hash::test_btc_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"));
	BOOST_CHECK(hash::test_btc_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"));
	BOOST_CHECK(!hash::test_btc_address(""));
	BOOST_CHECK(!hash::test_btc_address("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(xmr_test_address)
{
    BOOST_CHECK(hash::test_xmr_address("475NqVg9G3a5TC1NQvj5etELipZXP9r9T9JsvxK6LV39Xs3ZbqbmaXPbtK8bQxkWhPGd2m1Ab89XVETQVe3g9KYpJg3KPrL"));
	BOOST_CHECK(!hash::test_xmr_address("475NqVg9G3a5TC1NQvj5etELipZXP9r9T9JsvxK6LV39Xs3ZbqbmaXPbtK8bQxkWhPGd2m1Ab89XVETQVe3g9KYpJg3KPrM"));
	BOOST_CHECK(!hash::test_xmr_address("375NqVg9G3a5TC1NQvj5etELipZXP9r9T9JsvxK6LV39Xs3ZbqbmaXPbtK8bQxkWhPGd2m1Ab89XVETQVe3g9KYpJg3KPrL"));
	BOOST_CHECK(hash::test_xmr_address("49RE83FnhxQdDdqK2Ac6REU5qNe9hZBuFKydsg9cH86353MjB4bhqAuNB4Wj8gubEfAcus349NnGkWuwoAv7gXMQNqGP1G6"));
	BOOST_CHECK(hash::test_xmr_address("42xi8beBHWbARKEL29RJVTCJVfuqHPb7MR44b2Vf9tteRX3qSKyiaeKE2aSiNR5Adi2dtrZQfXQ1y2Mjd9hDVXB4Fzg5TU8"));
	BOOST_CHECK(!hash::test_xmr_address(""));
	BOOST_CHECK(!hash::test_xmr_address("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
}

// ----------------------------------------------------------------------------

BOOST_FIXTURE_TEST_CASE(ssdeep_hash_file, SetWorkingDirectory)
{
	pString s = ssdeep::hash_file("testfiles/manatest.exe");
	BOOST_ASSERT(s);
	BOOST_CHECK(*s == "384:l3a7DCXuMusPxN7gP/zP0JXZO708ijc3pVVPjqUeI7XQ62r:9U8v5N7YYtc708cc5VVPjze966");

	// Verify that we obtain the same value by reading the file into a buffer and hashing it.
	FILE* f = fopen("testfiles/manatest.exe", "rb");
	BOOST_ASSERT(f != nullptr);
	std::vector<boost::uint8_t> bytes(static_cast<unsigned int>(fs::file_size("testfiles/manatest.exe")));
	size_t copied = fread(&bytes[0], 1, bytes.size(), f);
	if (copied != bytes.size())
	{
		fclose(f);
		BOOST_FAIL("[ssdeep_hash_file] Unable to copy the input file into a buffer.");
	}
	fclose(f);
	s = ssdeep::hash_buffer(bytes);
	BOOST_ASSERT(s);
	BOOST_CHECK(*s == "384:l3a7DCXuMusPxN7gP/zP0JXZO708ijc3pVVPjqUeI7XQ62r:9U8v5N7YYtc708cc5VVPjze966");
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(ssdeep_hash_empty_input)
{
	pString s = ssdeep::hash_file("I_DON'T_EXIST.txt");
	BOOST_CHECK(!s);
	s = ssdeep::hash_buffer(std::vector<boost::uint8_t>());
	BOOST_CHECK(!s);
}

// ----------------------------------------------------------------------------
BOOST_FIXTURE_TEST_SUITE(hash_files, SetupFiles)
// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(hash_phrase_file)
{
    hash::const_shared_strings hashes = hash::hash_file(hash::ALL_DIGESTS, "fox");
    BOOST_CHECK_EQUAL("9e107d9d372bb6826bd81d3542a419d6", hashes->at(ALL_DIGESTS_MD5));
    BOOST_CHECK_EQUAL("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", hashes->at(ALL_DIGESTS_SHA1));
    BOOST_CHECK_EQUAL("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", hashes->at(ALL_DIGESTS_SHA256));
	BOOST_CHECK_EQUAL("07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6", hashes->at(ALL_DIGESTS_SHA512));
    BOOST_CHECK_EQUAL("69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04", hashes->at(ALL_DIGESTS_SHA3));
    BOOST_CHECK_EQUAL("4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15", hashes->at(ALL_DIGESTS_KECCAK));
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(null_hash_file)
{
    hash::const_shared_strings hashes = hash::hash_file(hash::ALL_DIGESTS, "empty");
    BOOST_CHECK_EQUAL("d41d8cd98f00b204e9800998ecf8427e", hashes->at(ALL_DIGESTS_MD5));
    BOOST_CHECK_EQUAL("da39a3ee5e6b4b0d3255bfef95601890afd80709", hashes->at(ALL_DIGESTS_SHA1));
    BOOST_CHECK_EQUAL("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hashes->at(ALL_DIGESTS_SHA256));
    BOOST_CHECK_EQUAL("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", hashes->at(ALL_DIGESTS_SHA512));
    BOOST_CHECK_EQUAL("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", hashes->at(ALL_DIGESTS_SHA3));
    BOOST_CHECK_EQUAL("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", hashes->at(ALL_DIGESTS_KECCAK));
}

// ----------------------------------------------------------------------------
BOOST_AUTO_TEST_SUITE_END()
// ----------------------------------------------------------------------------
