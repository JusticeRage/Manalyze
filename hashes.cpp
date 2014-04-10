#include "hashes.h"

namespace hash {

std::string hash_bytes(Digest& digest, const std::vector<boost::uint8_t>& bytes)
{
	digest.reset();
	if (bytes.size() > 0) {
		digest.add(&bytes[0], bytes.size());
	}
	return digest.getHash();
}

// ----------------------------------------------------------------------------

std::vector<std::string> hash_bytes(std::vector<pDigest>& digests, const std::vector<boost::uint8_t>& bytes)
{
	std::vector<std::string> res;
	for (std::vector<pDigest>::iterator it = digests.begin() ; it != digests.end() ; ++it)
	{
		(*it)->reset();
		if (bytes.size() > 0) {
			(*it)->add(&bytes[0], bytes.size());
		}
		res.push_back((*it)->getHash());
	}
	return res;
}

// ----------------------------------------------------------------------------

std::string hash_file(Digest& digest, const std::string& filename)
{
	digest.reset();
	FILE* f = fopen(filename.c_str(), "rb");
	if (f == NULL) {
		return "";
	}
	boost::shared_array<boost::uint8_t> buffer = boost::shared_array<boost::uint8_t>(new boost::uint8_t[1024]);
	int read = 0;
	while (1024 == (read = fread(buffer.get(), 1, 1024, f))) {
		digest.add(buffer.get(), read);
	}

	// Append the bytes of the last read operation
	if (read != 0) {
		digest.add(buffer.get(), read);
	}

	return digest.getHash();
}

// ----------------------------------------------------------------------------

std::vector<std::string> hash_file(std::vector<pDigest>& digests, const std::string& filename)
{
	std::vector<std::string> res = std::vector<std::string>();

	for (std::vector<pDigest>::iterator it = digests.begin() ; it != digests.end() ; ++it) {
		(*it)->reset();
	}

	FILE* f = fopen(filename.c_str(), "rb");
	if (f == NULL) {
		return res;
	}
	boost::shared_array<boost::uint8_t> buffer = boost::shared_array<boost::uint8_t>(new boost::uint8_t[1024]);
	int read = 0;
	while (1024 == (read = fread(buffer.get(), 1, 1024, f))) 
	{
		for (std::vector<pDigest>::iterator it = digests.begin() ; it != digests.end() ; ++it) {
			(*it)->add(buffer.get(), read);
		}
	}

	for (std::vector<pDigest>::iterator it = digests.begin() ; it != digests.end() ; ++it) 
	{
		// Append the bytes of the last read operation
		if (read != 0) {
			(*it)->add(buffer.get(), read);
		}
		res.push_back((*it)->getHash());
	}

	return res;
}


} // !namespace hash