#define BOOST_TEST_MODULE ManalyzeTests
#define BOOST_TEST_DYN_LINK

#include "hash-library/hashes.h"
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_CASE(hash_phrase)
{
	std::string input("The quick brown fox jumps over the lazy dog");
	std::vector<boost::uint8_t> bytes(input.begin(), input.end());
	hash::const_shared_strings hashes = hash::hash_bytes(hash::ALL_DIGESTS, bytes);

	BOOST_CHECK_EQUAL("9e107d9d372bb6826bd81d3542a419d6", hashes->at(ALL_DIGESTS_MD5));
	BOOST_CHECK_EQUAL("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", hashes->at(ALL_DIGESTS_SHA1));
	BOOST_CHECK_EQUAL("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", hashes->at(ALL_DIGESTS_SHA256));
	BOOST_CHECK_EQUAL("4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15", hashes->at(ALL_DIGESTS_SHA3));
}

BOOST_AUTO_TEST_CASE(null_hash)
{
	std::vector<boost::uint8_t> bytes(0);
	hash::const_shared_strings hashes = hash::hash_bytes(hash::ALL_DIGESTS, bytes);

	BOOST_CHECK_EQUAL("d41d8cd98f00b204e9800998ecf8427e", hashes->at(ALL_DIGESTS_MD5));
	BOOST_CHECK_EQUAL("da39a3ee5e6b4b0d3255bfef95601890afd80709", hashes->at(ALL_DIGESTS_SHA1));
	BOOST_CHECK_EQUAL("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hashes->at(ALL_DIGESTS_SHA256));
	BOOST_CHECK_EQUAL("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", hashes->at(ALL_DIGESTS_SHA3));
}
