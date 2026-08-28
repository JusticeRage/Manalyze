#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

#include "manape/work_budget.h"

namespace mana::detail {

struct SectionMapping
{
	std::uint64_t virtual_address;
	std::uint64_t virtual_size;
	std::uint64_t raw_offset;
	std::uint64_t raw_size;
};

using ReadAt = std::function<bool(std::uint64_t, void*, std::size_t)>;

struct ImageView
{
	std::uint64_t file_size;
	std::uint64_t size_of_headers;
	std::uint64_t size_of_image;
	std::uint64_t image_base;
	std::uint32_t file_alignment;
	std::vector<SectionMapping> sections;
	ReadAt read_at;
};

enum class SpanBacking { initialized, zero_fill };

struct MappedSpan
{
	SpanBacking backing;
	std::uint64_t rva;
	std::uint64_t size;
	std::uint64_t file_offset;
	std::size_t region;
};

std::optional<MappedSpan> resolve_mapped_span(const ImageView& image,
	std::uint64_t rva);

} // namespace mana::detail
