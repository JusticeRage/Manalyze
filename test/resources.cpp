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

#include <atomic>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <limits>
#include <sstream>
#include <thread>
#include <type_traits>
#include <vector>

#include "fixtures.h"
#include "manacommons/color.h"
#include "manape/pe.h"
#include "manape/resources.h"
#include "hash-library/hashes.h"

namespace {

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

std::vector<std::uint8_t> make_repeated_resource_tree(std::uint16_t root_count,
	std::uint16_t type_count, std::uint16_t name_count)
{
	auto bytes = read_binary_file("testfiles/manatest2.exe");
	constexpr size_t resource_raw = 0x2000;
	constexpr std::uint32_t resource_rva = 0x5000;
	const size_t root_entries = resource_raw + 16;
	const size_t type_dir = root_entries + 8 * root_count;
	const size_t type_entries = type_dir + 16;
	const size_t name_dir = type_entries + 8 * type_count;
	const size_t name_entries = name_dir + 16;
	const size_t leaf = name_entries + 8 * name_count;
	const size_t payload = leaf + 16;
	if (payload >= bytes.size()) {
		throw std::out_of_range("generated resource tree exceeds fixture");
	}

	std::fill(bytes.begin() + resource_raw, bytes.end(), 0);
	write_u16(bytes, resource_raw + 14, root_count);
	for (size_t i = 0; i < root_count; ++i) {
		write_u32(bytes, root_entries + 8 * i, 10);
		write_u32(bytes, root_entries + 8 * i + 4,
			0x80000000u | static_cast<std::uint32_t>(type_dir - resource_raw));
	}
	write_u16(bytes, type_dir + 14, type_count);
	for (size_t i = 0; i < type_count; ++i) {
		write_u32(bytes, type_entries + 8 * i, 1);
		write_u32(bytes, type_entries + 8 * i + 4,
			0x80000000u | static_cast<std::uint32_t>(name_dir - resource_raw));
	}
	write_u16(bytes, name_dir + 14, name_count);
	for (size_t i = 0; i < name_count; ++i) {
		write_u32(bytes, name_entries + 8 * i, 0x409);
		write_u32(bytes, name_entries + 8 * i + 4,
			static_cast<std::uint32_t>(leaf - resource_raw));
	}
	write_u32(bytes, leaf, resource_rva + static_cast<std::uint32_t>(payload - resource_raw));
	write_u32(bytes, leaf + 4, 1);
	bytes[payload] = 0x41;
	return bytes;
}

mana::pResource make_bitmap_resource(std::uint16_t bit_count, std::uint32_t colors_used)
{
	FILE* raw = tmpfile();
	BOOST_REQUIRE(raw != nullptr);
	mana::pFile file(raw, fclose);
	std::vector<std::uint8_t> dib(40, 0);
	write_u32(dib, 0, 40);
	write_u16(dib, 14, bit_count);
	write_u32(dib, 32, colors_used);
	BOOST_REQUIRE_EQUAL(fputc(0, raw), 0);
	BOOST_REQUIRE_EQUAL(fwrite(dib.data(), 1, dib.size(), raw), dib.size());
	return std::make_shared<mana::Resource>("RT_BITMAP", 1, "", 0,
		static_cast<std::uint32_t>(dib.size()), 0, 1, "bitmap", file, dib.size() + 1);
}

std::vector<std::uint8_t> read_version_blob()
{
	auto bytes = read_binary_file("testfiles/manatest2.exe");
	return std::vector<std::uint8_t>(bytes.begin() + 0x2350,
		bytes.begin() + 0x2350 + 0x2d4);
}

mana::pResource make_version_resource(const std::vector<std::uint8_t>& blob,
	std::uint32_t declared_size)
{
	FILE* file = tmpfile();
	BOOST_REQUIRE(file != nullptr);
	const std::uint8_t prefix[4] = {0, 0, 0, 0};
	BOOST_REQUIRE_EQUAL(fwrite(prefix, 1, sizeof(prefix), file), sizeof(prefix));
	BOOST_REQUIRE_EQUAL(fwrite(blob.data(), 1, blob.size(), file), blob.size());
	BOOST_REQUIRE_EQUAL(fseek(file, 0, SEEK_SET), 0);
	mana::pFile handle(file, fclose);
	return std::make_shared<mana::Resource>("RT_VERSION", "VERSION", "", 0,
		declared_size, 0, 4, "version-resource", handle, blob.size() + 4,
		std::make_shared<std::mutex>());
}

} // namespace

// ----------------------------------------------------------------------------
BOOST_FIXTURE_TEST_SUITE(resources, SetWorkingDirectory)
// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(bitmap_layout_is_aligned)
{
	BOOST_CHECK_EQUAL(sizeof(mana::bitmap_header), 14);
	BOOST_CHECK(std::is_trivially_copyable<mana::bitmap_header>::value);
	BOOST_CHECK_GE(alignof(mana::bitmap), alignof(std::vector<std::uint8_t>));
	mana::bitmap value{};
	const auto data_address = reinterpret_cast<std::uintptr_t>(&value.data);
	BOOST_CHECK_EQUAL(data_address % alignof(std::vector<std::uint8_t>), 0);
}

BOOST_AUTO_TEST_CASE(bitmap_palette_depths)
{
	for (std::uint16_t depth = 1; depth <= 8; ++depth) {
		auto indexed = make_bitmap_resource(depth, 0)->interpret_as<mana::pbitmap>();
		BOOST_REQUIRE(indexed);
		const std::uint32_t indexed_offset = indexed->OffsetToData;
		BOOST_CHECK_EQUAL(indexed_offset, 14 + 40 + 4 * (std::uint32_t{1} << depth));
	}

	for (std::uint16_t depth : {24, 32}) {
		auto bitmap = make_bitmap_resource(depth, 0)->interpret_as<mana::pbitmap>();
		BOOST_REQUIRE(bitmap);
		const std::uint32_t direct_color_offset = bitmap->OffsetToData;
		BOOST_CHECK_EQUAL(direct_color_offset, 14 + 40);
	}
}

BOOST_AUTO_TEST_CASE(reject_unsupported_bitmap_depths)
{
	for (std::uint16_t depth : {0, 9, 33, 40, 65535}) {
		BOOST_CHECK(!make_bitmap_resource(depth, 0)->interpret_as<mana::pbitmap>());
		BOOST_CHECK(!make_bitmap_resource(depth, 1)->interpret_as<mana::pbitmap>());
	}
}

BOOST_AUTO_TEST_CASE(reject_overflowing_bitmap_palette_offset)
{
	BOOST_CHECK(!make_bitmap_resource(8, std::numeric_limits<std::uint32_t>::max())
		->interpret_as<mana::pbitmap>());
}

BOOST_AUTO_TEST_CASE(reject_resource_directory_over_entry_limit)
{
	auto bytes = make_repeated_resource_tree(257, 1, 1);
	auto pe = mana::PE::create_from_bytes(bytes.data(), bytes.size(), "resource-entry-limit.exe");
	BOOST_REQUIRE(pe && pe->is_valid());
	auto resources = pe->get_resources();
	BOOST_REQUIRE(resources);
	BOOST_CHECK(resources->empty());
}

BOOST_AUTO_TEST_CASE(reject_resource_tree_over_total_budget)
{
	auto bytes = make_repeated_resource_tree(40, 256, 1);
	auto pe = mana::PE::create_from_bytes(bytes.data(), bytes.size(), "resource-budget.exe");
	BOOST_REQUIRE(pe && pe->is_valid());
	auto resources = pe->get_resources();
	BOOST_REQUIRE(resources);
	BOOST_CHECK(resources->empty());
}

BOOST_AUTO_TEST_CASE(reject_unmapped_resource_root_with_named_error)
{
	auto bytes = make_repeated_resource_tree(1, 1, 1);
	constexpr size_t optional_header = 0x128;
	constexpr size_t resource_directory =
		optional_header + 96 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8;
	write_u32(bytes, resource_directory, 0xffff0000);

	ErrorCapture errors;
	auto pe = mana::PE::create_from_bytes(bytes.data(), bytes.size(), "unmapped-resource-root.exe");
	BOOST_REQUIRE(pe && pe->is_valid());
	BOOST_CHECK(pe->get_resources()->empty());
	BOOST_CHECK_NE(errors.str().find("IMAGE_RESOURCE_DIRECTORY"), std::string::npos);
}

BOOST_AUTO_TEST_CASE(reject_overflowing_resource_relative_rva)
{
	auto bytes = make_repeated_resource_tree(1, 1, 1);
	constexpr size_t optional_header = 0x128;
	constexpr size_t resource_directory =
		optional_header + 96 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8;
	constexpr size_t section_table = optional_header + 0xe0;
	constexpr size_t resource_section = section_table + 4 * 40;

	write_u32(bytes, resource_directory, 0xfffffff0);
	write_u32(bytes, resource_section + 8, 1);
	write_u32(bytes, resource_section + 12, 0xfffffff0);
	constexpr size_t first_language_entry = 0x2040;
	write_u32(bytes, first_language_entry + 4, 0x1010);
	write_u32(bytes, 0x400, 0x1010);
	write_u32(bytes, 0x404, 1);
	write_u32(bytes, 0x408, 0);
	write_u32(bytes, 0x40c, 0);
	bytes[0x410] = 0x41;

	ErrorCapture errors;
	auto pe = mana::PE::create_from_bytes(bytes.data(), bytes.size(), "wrapped-resource-rva.exe");
	BOOST_REQUIRE(pe && pe->is_valid());
	BOOST_CHECK(pe->get_resources()->empty());
	BOOST_CHECK_NE(errors.str().find("IMAGE_RESOURCE_DATA_ENTRY"), std::string::npos);
}

BOOST_AUTO_TEST_CASE(keep_valid_resource_after_invalid_data_entry_offset)
{
	auto bytes = make_repeated_resource_tree(1, 1, 2);
	constexpr size_t first_language_entry = 0x2040;
	constexpr size_t second_language_entry = 0x2048;
	write_u32(bytes, first_language_entry, 0x409);
	write_u32(bytes, first_language_entry + 4, 0x7ffffff0);
	write_u32(bytes, second_language_entry, 0x40c);

	ErrorCapture errors;
	auto pe = mana::PE::create_from_bytes(bytes.data(), bytes.size(), "recover-resource-leaf.exe");
	BOOST_REQUIRE(pe && pe->is_valid());
	const auto resources = pe->get_resources();
	BOOST_REQUIRE_EQUAL(resources->size(), 1);
	BOOST_CHECK_EQUAL(*resources->front()->get_language(), "French - France");
	BOOST_CHECK_NE(errors.str().find("IMAGE_RESOURCE_DATA_ENTRY"), std::string::npos);
}

BOOST_AUTO_TEST_CASE(keep_valid_resource_after_malformed_named_directory_entry)
{
	auto bytes = make_repeated_resource_tree(2, 1, 1);
	constexpr size_t resource_raw = 0x2000;
	constexpr size_t root_entries = resource_raw + 16;
	write_u16(bytes, resource_raw + 12, 1);
	write_u16(bytes, resource_raw + 14, 1);
	write_u32(bytes, root_entries, 0xfffffff0);

	ErrorCapture errors;
	auto pe = mana::PE::create_from_bytes(bytes.data(), bytes.size(),
		"recover-named-resource-entry.exe");
	BOOST_REQUIRE(pe && pe->is_valid());
	const auto resources = pe->get_resources();
	BOOST_REQUIRE_EQUAL(resources->size(), 1);
	BOOST_CHECK_EQUAL(*resources->front()->get_type(), "RT_RCDATA");
	const auto payload = resources->front()->get_raw_data();
	BOOST_REQUIRE_EQUAL(payload->size(), 1);
	BOOST_CHECK_EQUAL(payload->front(), 0x41);
	BOOST_CHECK_NE(errors.str().find("IMAGE_RESOURCE_DIRECTORY_ENTRY"), std::string::npos);
}

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

BOOST_AUTO_TEST_CASE(parse_resources_from_bytes)
{
	std::ifstream input("testfiles/manatest.exe", std::ios::binary);
	BOOST_ASSERT(input);
	std::vector<std::uint8_t> bytes{
		std::istreambuf_iterator<char>(input),
		std::istreambuf_iterator<char>()};
	BOOST_ASSERT(!bytes.empty());

	auto pe = mana::PE::create_from_bytes(bytes.data(), bytes.size(), "manatest.exe");
	BOOST_ASSERT(pe);
	auto resources = pe->get_resources();
	BOOST_ASSERT(resources);
	BOOST_ASSERT(resources->size() == 1);
	auto r = resources->at(0);
	BOOST_ASSERT(r);
	BOOST_CHECK(*r->get_type() == "RT_MANIFEST");
	BOOST_CHECK(r->get_id() == 1);
	BOOST_CHECK(*r->get_name() == "1");
	BOOST_CHECK(r->get_size() == 381);
	BOOST_CHECK(r->get_codepage() == 0);
	BOOST_CHECK(r->get_offset() == 0x2a60);
	BOOST_CHECK(*r->get_language() == "English - United States");
	auto res = r->get_raw_data();
	std::string rt_manifest(res->begin(), res->end());
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

BOOST_AUTO_TEST_CASE(concurrent_resource_and_section_reads)
{
	std::ifstream input("testfiles/manatest.exe", std::ios::binary);
	BOOST_ASSERT(input);
	std::vector<std::uint8_t> bytes{
		std::istreambuf_iterator<char>(input),
		std::istreambuf_iterator<char>()};
	BOOST_ASSERT(!bytes.empty());

	auto pe = mana::PE::create_from_bytes(bytes.data(), bytes.size(), "manatest.exe");
	BOOST_ASSERT(pe);

	auto sections = pe->get_sections();
	auto resources = pe->get_resources();
	BOOST_ASSERT(sections && !sections->empty());
	BOOST_ASSERT(resources && !resources->empty());
	auto section = sections->at(0);
	auto resource = resources->at(0);
	BOOST_ASSERT(section);
	BOOST_ASSERT(resource);

	auto base_file = pe->get_bytes_at_offset(0, 2);
	auto base_section = section->get_raw_data();
	auto base_resource = resource->get_raw_data();
	BOOST_ASSERT(base_file && base_file->size() == 2);
	BOOST_ASSERT(base_section && !base_section->empty());
	BOOST_ASSERT(base_resource && !base_resource->empty());

	auto sample_matches = [](const std::vector<std::uint8_t>& data,
							 const std::vector<std::uint8_t>& base) -> bool {
		if (data.size() != base.size() || data.empty()) {
			return false;
		}
		const size_t size = data.size();
		const size_t mid = size / 2;
		const size_t idxs[] = {
			0,
			size > 1 ? 1u : 0u,
			mid,
			size > 2 ? size - 2 : 0u,
			size - 1,
		};
		for (size_t idx : idxs) {
			if (idx >= size || data[idx] != base[idx]) {
				return false;
			}
		}
		return true;
	};

	std::atomic<bool> ok(true);
	auto worker = [&]() {
		for (int i = 0; i < 200 && ok.load(); ++i) {
			auto file_bytes = pe->get_bytes_at_offset(0, 2);
			if (!file_bytes || file_bytes->size() != base_file->size() ||
				file_bytes->at(0) != base_file->at(0) || file_bytes->at(1) != base_file->at(1)) {
				ok.store(false);
				return;
			}

			auto sec_bytes = section->get_raw_data();
			if (!sec_bytes || !sample_matches(*sec_bytes, *base_section)) {
				ok.store(false);
				return;
			}

			auto res_bytes = resource->get_raw_data();
			if (!res_bytes || !sample_matches(*res_bytes, *base_resource)) {
				ok.store(false);
				return;
			}
		}
	};

	std::vector<std::thread> threads;
	for (int i = 0; i < 8; ++i) {
		threads.emplace_back(worker);
	}
	for (auto& t : threads) {
		t.join();
	}

	BOOST_CHECK(ok.load());
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(resource_unknown_filesize)
{
	mana::pResource r = std::make_shared<mana::Resource>(
		"RT_MANIFEST",
		"1",
		"English - United States",
		0,
		16,
		0,
		4,
		"unknown",
		mana::pFile(),
		0);
	auto bytes = r->get_raw_data();
	BOOST_ASSERT(bytes);
	BOOST_CHECK(bytes->empty());
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
					std::uint32_t id,
					const std::string& type,
					const std::string& language,
					std::uint32_t size,
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
	std::uint8_t bytes[] = 
					  { 0xE6, 0x97, 0xA0, 0xE6, 0xB3, 0x95, 0xE5, 0xAF, 0xB9, 0x20, 0x25, 0x31, 0x20, 
						0xE8, 0xBF, 0x9B, 0xE8, 0xA1, 0x8C, 0xE5, 0x86, 0x99, 0xE6, 0x93, 0x8D, 0xE4, 
						0xBD, 0x9C, 0xEF, 0xBC, 0x8C, 0xE5, 0x9B, 0xA0, 0xE4, 0xB8, 0xBA, 0xE5, 0xAE, 
						0x83, 0xE6, 0x98, 0xAF, 0xE5, 0x8F, 0xAA, 0xE8, 0xAF, 0xBB, 0xE6, 0x96, 0x87, 
						0xE4, 0xBB, 0xB6, 0xE6, 0x88, 0x96, 0xE5, 0xB7, 0xB2, 0xE7, 0xBB, 0x8F, 0xE8, 
						0xA2, 0xAB, 0xE5, 0x85, 0xB6, 0xE4, 0xBB, 0x96, 0xE4, 0xBA, 0xBA, 0xE6, 0x89, 
						0x93, 0xE5, 0xBC, 0x80, 0xE3, 0x80, 0x82 };
	std::vector<std::uint8_t> expected(bytes, bytes + sizeof(bytes));
	std::vector<std::uint8_t> found(utf8_string.begin(), utf8_string.end());
	BOOST_CHECK(expected == found);

	for (int i = 10 ; i < 16 ; ++i) {
		BOOST_CHECK(string_table->at(i) == "");
	}
}

// ----------------------------------------------------------------------------

template<class T>
void check_pair(std::shared_ptr<std::pair<T, T> > pair, const T& first, const T& second )
{
	BOOST_CHECK_EQUAL(pair->first, first);
	BOOST_CHECK_EQUAL(pair->second, second);
}

void check_version_strings(const mana::pversion_info& version)
{
	BOOST_REQUIRE(version);
	BOOST_REQUIRE_EQUAL(version->StringTable.size(), 8);
	check_pair<std::string>(version->StringTable[0], "CompanyName", "manalyzer.org");
	check_pair<std::string>(version->StringTable[1], "FileDescription", "Manalyze test file.");
	check_pair<std::string>(version->StringTable[2], "FileVersion", "1.0.0.0");
	check_pair<std::string>(version->StringTable[3], "InternalName", "manatest2.exe");
	check_pair<std::string>(version->StringTable[4], "LegalCopyright", "Copyright (C) 2016");
	check_pair<std::string>(version->StringTable[5], "OriginalFilename", "manatest2.exe");
	check_pair<std::string>(version->StringTable[6], "ProductName", "manatest2.exe");
	check_pair<std::string>(version->StringTable[7], "ProductVersion", "1.0.0.0");
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(parse_version_info_without_varfileinfo)
{
	auto blob = read_version_blob();
	blob.resize(0x290);
	write_u16(blob, 0, 0x290);
	check_version_strings(make_version_resource(blob, 0x290)
		->interpret_as<mana::pversion_info>());
}

BOOST_AUTO_TEST_CASE(parse_version_info_with_leading_varfileinfo)
{
	const auto original = read_version_blob();
	std::vector<std::uint8_t> blob;
	blob.insert(blob.end(), original.begin(), original.begin() + 0x5c);
	blob.insert(blob.end(), original.begin() + 0x290, original.end());
	blob.insert(blob.end(), original.begin() + 0x5c, original.begin() + 0x290);
	check_version_strings(make_version_resource(blob, 0x2d4)
		->interpret_as<mana::pversion_info>());
}

BOOST_AUTO_TEST_CASE(reject_version_header_without_bounded_key)
{
	auto blob = read_version_blob();
	write_u16(blob, 0, 8);
	auto resource = make_version_resource(blob, 8);
	ErrorCapture errors;
	BOOST_CHECK(!resource->interpret_as<mana::pversion_info>());
	BOOST_REQUIRE_EQUAL(resource->get_raw_data()->size(), 8);
	BOOST_CHECK_NE(errors.str().find("RT_VERSION"), std::string::npos);
}

BOOST_AUTO_TEST_CASE(reject_version_key_outside_declared_root_length)
{
	std::vector<std::uint8_t> blob(1024 * 1024, 0x41);
	write_u16(blob, 0, 8);
	write_u16(blob, 2, 0);
	write_u16(blob, 4, 0);
	write_u16(blob, blob.size() - sizeof(std::uint16_t), 0);
	auto resource = make_version_resource(blob, static_cast<std::uint32_t>(blob.size()));
	ErrorCapture errors;
	BOOST_CHECK(!resource->interpret_as<mana::pversion_info>());
	BOOST_CHECK_NE(errors.str().find("Could not read the RT_VERSION root header"),
		std::string::npos);
}

BOOST_AUTO_TEST_CASE(reject_varfileinfo_length_smaller_than_header)
{
	auto original = read_version_blob();
	std::vector<std::uint8_t> blob;
	blob.insert(blob.end(), original.begin(), original.begin() + 0x5c);
	blob.insert(blob.end(), original.begin() + 0x290, original.end());
	blob.insert(blob.end(), original.begin() + 0x5c, original.begin() + 0x290);
	write_u16(blob, 0x5c, 0x1f);
	auto resource = make_version_resource(blob, static_cast<std::uint32_t>(blob.size()));
	ErrorCapture errors;
	BOOST_CHECK(!resource->interpret_as<mana::pversion_info>());
	BOOST_REQUIRE(resource->get_raw_data());
	BOOST_CHECK_NE(errors.str().find("RT_VERSION"), std::string::npos);
}

BOOST_AUTO_TEST_CASE(reject_varfileinfo_skip_past_resource_extent)
{
	auto original = read_version_blob();
	std::vector<std::uint8_t> blob;
	blob.insert(blob.end(), original.begin(), original.begin() + 0x5c);
	blob.insert(blob.end(), original.begin() + 0x290, original.end());
	blob.insert(blob.end(), original.begin() + 0x5c, original.begin() + 0x290);
	write_u16(blob, 0, 0x9f);
	auto resource = make_version_resource(blob, 0x9f);
	ErrorCapture errors;
	BOOST_CHECK(!resource->interpret_as<mana::pversion_info>());
	BOOST_REQUIRE_EQUAL(resource->get_raw_data()->size(), 0x9f);
	BOOST_CHECK_NE(errors.str().find("RT_VERSION"), std::string::npos);
}

BOOST_AUTO_TEST_CASE(reject_version_string_past_resource_extent)
{
	auto blob = read_version_blob();
	blob.resize(0x290);
	write_u16(blob, 0, 0xbc);
	write_u16(blob, 0x5c, 0x60);
	write_u16(blob, 0x80, 0x3c);
	auto resource = make_version_resource(blob, 0xbc);
	ErrorCapture errors;
	BOOST_CHECK(!resource->interpret_as<mana::pversion_info>());
	BOOST_REQUIRE_EQUAL(resource->get_raw_data()->size(), 0xbc);
	BOOST_CHECK_NE(errors.str().find("RT_VERSION"), std::string::npos);
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
		{"VOS_DOS_WINDOWS32", "VOS_NT", "VOS_NT_WINDOWS32", "VOS_WINCE", "VOS__WINDOWS32"};
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

BOOST_AUTO_TEST_CASE(reject_short_cursor_during_reconstruction)
{
	FILE* raw = tmpfile();
	BOOST_REQUIRE(raw != nullptr);
	mana::pFile file(raw, fclose);
	const std::uint8_t cursor_bytes[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
	BOOST_REQUIRE_EQUAL(fwrite(cursor_bytes, 1, sizeof(cursor_bytes), raw), sizeof(cursor_bytes));

	auto first = std::make_shared<mana::Resource>("RT_CURSOR", 1, "", 0, 3, 0, 1,
		"cursor", file, sizeof(cursor_bytes));
	auto second = std::make_shared<mana::Resource>("RT_CURSOR", 2, "", 0, 8, 0, 4,
		"cursor", file, sizeof(cursor_bytes));
	auto directory = std::make_shared<mana::group_icon_directory>();
	directory->Reserved = 0;
	directory->Type = 2;
	directory->Count = 2;
	for (std::uint32_t id : {1u, 2u}) {
		auto entry = std::make_shared<mana::group_icon_directory_entry>();
		std::memset(entry.get(), 0, sizeof(*entry));
		entry->Id = id;
		directory->Entries.push_back(entry);
	}

	auto result = mana::reconstruct_icon(directory, {first, second});
	BOOST_CHECK(!result);
}

// ----------------------------------------------------------------------------
BOOST_AUTO_TEST_SUITE_END()
// ----------------------------------------------------------------------------
