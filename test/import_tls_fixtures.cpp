#include "import_tls_fixtures.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <stdexcept>

#include "fixtures.h"
#include "manape/nt_values.h"

namespace {

void require_range(std::size_t size, std::size_t offset, std::size_t count)
{
	if (offset > size || count > size - offset) {
		throw std::out_of_range("fixture patch exceeds input");
	}
}

void write_binary_file(const std::filesystem::path& path,
	const std::vector<std::uint8_t>& bytes)
{
	std::ofstream output(path, std::ios::binary);
	if (!output) throw std::runtime_error("could not create fixture output");
	output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
	if (!output) throw std::runtime_error("could not write fixture output");
}

} // namespace

CompactImageBuilder::CompactImageBuilder(std::size_t file_size)
	: _bytes(std::make_shared<std::vector<std::uint8_t>>(file_size)),
	  _view{file_size, 0, 0, 0, 0x200, {}, {}}
{
	const auto bytes = _bytes;
	_view.read_at = [bytes](std::uint64_t offset, void* destination,
		std::size_t size) {
		if (offset > bytes->size() || size > bytes->size() - offset) {
			return false;
		}
		if (size != 0) {
			std::memcpy(destination, bytes->data() + offset, size);
		}
		return true;
	};
}

CompactImageBuilder& CompactImageBuilder::headers(std::uint64_t size_of_headers)
{
	_view.size_of_headers = size_of_headers;
	return *this;
}

CompactImageBuilder& CompactImageBuilder::image(std::uint64_t image_base,
	std::uint64_t size_of_image, std::uint32_t file_alignment)
{
	_view.image_base = image_base;
	_view.size_of_image = size_of_image;
	_view.file_alignment = file_alignment;
	return *this;
}

CompactImageBuilder& CompactImageBuilder::section(
	const mana::detail::SectionMapping& mapping)
{
	_view.sections.push_back(mapping);
	return *this;
}

void CompactImageBuilder::put16(std::size_t offset, std::uint16_t value)
{
	require_range(_bytes->size(), offset, sizeof(value));
	for (std::size_t i = 0; i < sizeof(value); ++i) {
		(*_bytes)[offset + i] = static_cast<std::uint8_t>(value >> (8 * i));
	}
}

void CompactImageBuilder::put32(std::size_t offset, std::uint32_t value)
{
	require_range(_bytes->size(), offset, sizeof(value));
	for (std::size_t i = 0; i < sizeof(value); ++i) {
		(*_bytes)[offset + i] = static_cast<std::uint8_t>(value >> (8 * i));
	}
}

void CompactImageBuilder::put64(std::size_t offset, std::uint64_t value)
{
	require_range(_bytes->size(), offset, sizeof(value));
	for (std::size_t i = 0; i < sizeof(value); ++i) {
		(*_bytes)[offset + i] = static_cast<std::uint8_t>(value >> (8 * i));
	}
}

void CompactImageBuilder::put_ascii(std::size_t offset, const std::string& value,
	bool terminate)
{
	const std::size_t size = value.size() + (terminate ? 1 : 0);
	require_range(_bytes->size(), offset, size);
	std::copy(value.begin(), value.end(), _bytes->begin() + offset);
	if (terminate) (*_bytes)[offset + value.size()] = 0;
}

mana::detail::ImageView CompactImageBuilder::view() const
{
	return _view;
}

std::vector<std::uint8_t> make_import_extent_pe(std::uint32_t rva,
	std::uint32_t declared_size, bool root_in_headers)
{
	auto bytes = read_binary_file("testfiles/manatest.exe");
	constexpr std::size_t optional_header = 0x108;
	constexpr std::size_t import_directory = optional_header + 96 +
		IMAGE_DIRECTORY_ENTRY_IMPORT * 8;
	constexpr std::size_t original_descriptor = 0x1c6c;
	constexpr std::uint32_t rdata_rva = 0x3000;
	constexpr std::size_t rdata_offset = 0x1600;

	if (!root_in_headers && rva < rdata_rva) {
		throw std::out_of_range("import root is outside the fixture section");
	}
	const std::size_t root_offset = root_in_headers ? rva :
		rdata_offset + static_cast<std::size_t>(rva - rdata_rva);
	require_range(bytes.size(), original_descriptor, 20);
	require_range(bytes.size(), root_offset, 40);
	std::copy_n(bytes.begin() + original_descriptor, 20,
		bytes.begin() + root_offset);
	std::fill_n(bytes.begin() + root_offset + 20, 20, 0);
	write_u32(bytes, root_offset + 24, 0x11111111);
	write_u32(bytes, root_offset + 28, 0x22222222);
	write_u32(bytes, root_offset + 32, 0xffffffff);
	write_u32(bytes, import_directory, rva);
	write_u32(bytes, import_directory + 4, declared_size);
	return bytes;
}

std::vector<std::uint8_t> make_tls_callbacks_pe(bool pe32_plus,
	const std::vector<std::uint64_t>&, bool, bool)
{
	return read_binary_file(pe32_plus ? "testfiles/manatest3.exe" :
		"testfiles/manatest.exe");
}

void write_import_tls_corpus(const std::filesystem::path& fixture_root,
	const std::filesystem::path& output_dir)
{
	std::filesystem::create_directories(output_dir);
	const auto old_path = std::filesystem::current_path();
	std::filesystem::current_path(fixture_root);
	try {
		write_binary_file(output_dir / "import-declared-boundary.exe",
			make_import_extent_pe(0x366c, 40, false));
	} catch (...) {
		std::filesystem::current_path(old_path);
		throw;
	}
	std::filesystem::current_path(old_path);
}
