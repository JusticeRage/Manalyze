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

std::vector<std::uint8_t> make_delay_import_pe(std::uint32_t attributes,
	bool add_second_descriptor)
{
	auto bytes = read_binary_file("testfiles/manatest3.exe");
	constexpr std::size_t delay_descriptor = 0x2670;
	require_range(bytes.size(), delay_descriptor, 64);
	write_u32(bytes, delay_descriptor, attributes);
	if (add_second_descriptor) {
		std::copy_n(bytes.begin() + delay_descriptor, 32,
			bytes.begin() + delay_descriptor + 32);
	}
	return bytes;
}

std::vector<std::uint8_t> make_delay_import_standard_exhaustion_pe()
{
	auto bytes = make_delay_import_pe(1, false);
	constexpr std::size_t optional_header = 0x108;
	constexpr std::size_t section_table = 0x1f8;
	constexpr std::size_t new_section = section_table + 8 * 40;
	constexpr std::size_t original_descriptor = 0x26e8;
	constexpr std::uint32_t raw_offset = 0x4000;
	constexpr std::uint32_t section_rva = 0xb000;
	constexpr std::uint32_t descriptor_count = 65537;
	constexpr std::uint32_t descriptor_bytes = descriptor_count * 20;
	constexpr std::uint32_t raw_size =
		(descriptor_bytes + 0x1ff) & ~std::uint32_t{0x1ff};
	constexpr std::uint32_t image_size =
		(section_rva + descriptor_bytes + 0xfff) & ~std::uint32_t{0xfff};
	constexpr std::size_t import_directory = optional_header + 112 +
		IMAGE_DIRECTORY_ENTRY_IMPORT * 8;

	require_range(bytes.size(), original_descriptor, 20);
	std::vector<std::uint8_t> descriptor(
		bytes.begin() + original_descriptor,
		bytes.begin() + original_descriptor + 20);
	bytes.resize(raw_offset + raw_size, 0);
	write_u16(bytes, 0xf6, 9);
	write_u32(bytes, optional_header + 56, image_size);
	std::fill_n(bytes.begin() + new_section, 40, 0);
	const char name[] = ".imps";
	std::copy(name, name + sizeof(name) - 1, bytes.begin() + new_section);
	write_u32(bytes, new_section + 8, descriptor_bytes);
	write_u32(bytes, new_section + 12, section_rva);
	write_u32(bytes, new_section + 16, raw_size);
	write_u32(bytes, new_section + 20, raw_offset);
	write_u32(bytes, new_section + 36, 0x40000040);
	for (std::uint32_t i = 0; i < descriptor_count; ++i) {
		std::copy(descriptor.begin(), descriptor.end(),
			bytes.begin() + raw_offset + static_cast<std::size_t>(i) * 20);
	}
	write_u32(bytes, import_directory, section_rva);
	write_u32(bytes, import_directory + 4, descriptor_bytes);
	return bytes;
}

std::vector<std::uint8_t> make_tls_callbacks_pe(bool pe32_plus,
	const std::vector<std::uint64_t>& callbacks, bool terminate,
	bool terminate_in_zero_fill)
{
	auto bytes = read_binary_file(pe32_plus ? "testfiles/manatest3.exe" :
		"testfiles/manatest.exe");
	const std::size_t pointer_size = pe32_plus ? 8 : 4;
	const std::size_t optional_header = 0x108;
	const std::size_t data_directories = optional_header +
		(pe32_plus ? 112 : 96);
	const std::size_t tls_directory = data_directories +
		IMAGE_DIRECTORY_ENTRY_TLS * 8;
	const std::uint64_t image_base = pe32_plus ? 0x140000000ULL : 0x400000ULL;
	const std::uint32_t root_rva = pe32_plus ? 0x42c0 : 0x3f80;
	const std::size_t root_offset = pe32_plus ? 0x2ec0 : 0x2580;
	const std::uint32_t callbacks_rva = pe32_plus ? 0x4300 : 0x3fc0;
	const std::size_t callbacks_offset = pe32_plus ? 0x2f00 : 0x25c0;
	const std::size_t root_size = pe32_plus ? 40 : 24;
	const std::size_t table_size = callbacks.size() * pointer_size +
		(terminate && !terminate_in_zero_fill ? pointer_size : 0);
	require_range(bytes.size(), root_offset, root_size);
	require_range(bytes.size(), callbacks_offset, table_size);

	std::fill_n(bytes.begin() + root_offset, root_size, 0);
	if (pe32_plus) {
		write_u64(bytes, root_offset + 24, image_base + callbacks_rva);
	} else {
		write_u32(bytes, root_offset + 12,
			static_cast<std::uint32_t>(image_base + callbacks_rva));
	}
	for (std::size_t i = 0; i < callbacks.size(); ++i) {
		if (pe32_plus) {
			write_u64(bytes, callbacks_offset + i * pointer_size, callbacks[i]);
		} else {
			write_u32(bytes, callbacks_offset + i * pointer_size,
				static_cast<std::uint32_t>(callbacks[i]));
		}
	}
	if (terminate && !terminate_in_zero_fill) {
		if (pe32_plus) {
			write_u64(bytes, callbacks_offset + callbacks.size() * pointer_size, 0);
		} else {
			write_u32(bytes, callbacks_offset + callbacks.size() * pointer_size, 0);
		}
	}
	if (!terminate || terminate_in_zero_fill) {
		const std::size_t section_table = pe32_plus ? 0x1f8 : 0x1e8;
		const std::size_t rdata_section = section_table + 40;
		const std::uint32_t initialized_size = static_cast<std::uint32_t>(
			callbacks_offset - (pe32_plus ? 0x1c00 : 0x1600) +
			callbacks.size() * pointer_size);
		write_u32(bytes, rdata_section + 8,
			initialized_size + (terminate_in_zero_fill ? pointer_size : 0));
		write_u32(bytes, rdata_section + 16, initialized_size);
	}
	write_u32(bytes, tls_directory, root_rva);
	write_u32(bytes, tls_directory + 4, static_cast<std::uint32_t>(root_size));
	return bytes;
}

std::vector<std::uint8_t> make_tls_budget_exhaustion_pe()
{
	constexpr std::size_t callback_limit = 1048576;
	constexpr std::size_t optional_header = 0x108;
	constexpr std::size_t section_table = 0x1e8;
	constexpr std::size_t new_section = section_table + 6 * 40;
	constexpr std::uint32_t section_rva = 0x8000;
	constexpr std::uint32_t raw_offset = 0x4000;
	constexpr std::uint32_t callback_bytes =
		static_cast<std::uint32_t>((callback_limit + 2) * 4);
	constexpr std::uint32_t raw_size =
		(callback_bytes + 0x1ff) & ~std::uint32_t{0x1ff};
	constexpr std::uint32_t image_size =
		(section_rva + callback_bytes + 0xfff) & ~std::uint32_t{0xfff};

	auto bytes = make_tls_callbacks_pe(false, {}, true);
	bytes.resize(raw_offset + raw_size, 0);
	write_u16(bytes, 0xf6, 7);
	write_u32(bytes, optional_header + 56, image_size);
	std::fill_n(bytes.begin() + new_section, 40, 0);
	const char name[] = ".tlscb";
	std::copy(name, name + sizeof(name) - 1, bytes.begin() + new_section);
	write_u32(bytes, new_section + 8, callback_bytes);
	write_u32(bytes, new_section + 12, section_rva);
	write_u32(bytes, new_section + 16, raw_size);
	write_u32(bytes, new_section + 20, raw_offset);
	write_u32(bytes, new_section + 36, 0x40000040);
	std::fill_n(bytes.begin() + raw_offset, (callback_limit + 1) * 4, 0x41);
	write_u32(bytes, 0x2580 + 12, 0x400000 + section_rva);
	return bytes;
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
