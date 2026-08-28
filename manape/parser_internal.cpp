#include "manape/parser_internal.h"

#include <algorithm>
#include <limits>

namespace mana::detail {

std::optional<MappedSpan> resolve_mapped_span(const ImageView& image,
	std::uint64_t rva)
{
	if (image.file_alignment == 0) return std::nullopt;

	if (rva < image.size_of_headers) {
		const std::uint64_t end = std::min(image.size_of_headers, image.file_size);
		if (rva >= end) return std::nullopt;
		return MappedSpan{SpanBacking::initialized, rva, end - rva, rva, 0};
	}

	const SectionMapping* selected = nullptr;
	std::size_t region = 0;
	std::uint64_t delta = 0;
	bool virtual_match = false;
	for (std::size_t i = 0; i < image.sections.size(); ++i) {
		const auto& section = image.sections[i];
		if (rva < section.virtual_address) continue;
		const std::uint64_t candidate_delta = rva - section.virtual_address;
		if (candidate_delta >= section.virtual_size) continue;
		selected = &section;
		region = i + 1;
		delta = candidate_delta;
		virtual_match = true;
		break;
	}

	if (selected == nullptr) {
		for (std::size_t i = 0; i < image.sections.size(); ++i) {
			const auto& section = image.sections[i];
			if (rva < section.virtual_address) continue;
			const std::uint64_t candidate_delta = rva - section.virtual_address;
			if (candidate_delta >= section.raw_size) continue;
			selected = &section;
			region = i + 1;
			delta = candidate_delta;
			break;
		}
	}
	if (selected == nullptr) return std::nullopt;

	const std::uint64_t aligned_raw =
		(selected->raw_offset / image.file_alignment) * image.file_alignment;
	std::uint64_t initialized_bytes = 0;
	if (aligned_raw < image.file_size) {
		initialized_bytes = std::min(selected->raw_size,
			image.file_size - aligned_raw);
	}

	const std::uint64_t selected_size =
		virtual_match ? selected->virtual_size : selected->raw_size;
	std::uint64_t remaining = selected_size - delta;
	remaining = std::min(remaining,
		std::numeric_limits<std::uint64_t>::max() - rva);
	if (remaining == 0) return std::nullopt;

	if (delta < initialized_bytes) {
		return MappedSpan{SpanBacking::initialized, rva,
			std::min(remaining, initialized_bytes - delta),
			aligned_raw + delta, region};
	}
	if (virtual_match) {
		return MappedSpan{SpanBacking::zero_fill, rva, remaining, 0, region};
	}
	return std::nullopt;
}

} // namespace mana::detail
