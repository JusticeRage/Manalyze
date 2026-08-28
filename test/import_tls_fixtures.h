#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "manape/parser_internal.h"

class CompactImageBuilder
{
public:
	explicit CompactImageBuilder(std::size_t file_size);
	CompactImageBuilder& headers(std::uint64_t size_of_headers);
	CompactImageBuilder& image(std::uint64_t image_base,
		std::uint64_t size_of_image, std::uint32_t file_alignment);
	CompactImageBuilder& section(const mana::detail::SectionMapping& mapping);
	void put16(std::size_t offset, std::uint16_t value);
	void put32(std::size_t offset, std::uint32_t value);
	void put64(std::size_t offset, std::uint64_t value);
	void put_ascii(std::size_t offset, const std::string& value,
		bool terminate = true);
	mana::detail::ImageView view() const;

private:
	std::shared_ptr<std::vector<std::uint8_t>> _bytes;
	mana::detail::ImageView _view;
};

std::vector<std::uint8_t> make_import_extent_pe(std::uint32_t rva,
	std::uint32_t declared_size, bool root_in_headers);
std::vector<std::uint8_t> make_tls_callbacks_pe(bool pe32_plus,
	const std::vector<std::uint64_t>& callbacks, bool terminate,
	bool terminate_in_zero_fill = false);
void write_import_tls_corpus(const std::filesystem::path& fixture_root,
	const std::filesystem::path& output_dir);
