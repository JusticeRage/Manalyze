#include "manape/parser_internal.h"

#include <algorithm>
#include <limits>
#include <unordered_map>

namespace mana::detail {

namespace {

struct ImportParseContext
{
	explicit ImportParseContext(const ImportLimits& limits)
		: descriptors(limits.descriptors), functions(limits.functions),
		  physical_string_bytes(limits.physical_string_bytes),
		  materialized_dll_name_bytes(limits.materialized_dll_name_bytes),
		  materialized_function_name_bytes(
			  limits.materialized_function_name_bytes)
	{}

	WorkBudget descriptors;
	WorkBudget functions;
	WorkBudget physical_string_bytes;
	WorkBudget materialized_dll_name_bytes;
	WorkBudget materialized_function_name_bytes;
	std::unordered_map<std::uint64_t, std::string> successful_strings;
	std::unordered_map<std::uint64_t, std::vector<import_lookup_table>>
		successful_thunks;
	bool exhausted = false;
	bool budget_diagnostic_attempted = false;
};

void emit_diagnostic(const DiagnosticSink& sink, ParserDiagnostic diagnostic)
{
	if (sink) sink(diagnostic);
}

} // namespace

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

ImportParseResult parse_imports(const ImageView& image,
	const image_data_directory& standard_directory,
	const image_data_directory&,
	bool,
	const ImportLimits& limits,
	const DiagnosticSink& diagnostics,
	ImportMetrics*)
{
	ImportParseResult result;
	if (standard_directory.VirtualAddress == 0) return result;

	constexpr std::uint64_t descriptor_size = 5 * sizeof(std::uint32_t);
	if (standard_directory.Size != 0 &&
		standard_directory.Size < descriptor_size) {
		emit_diagnostic(diagnostics, ParserDiagnostic::import_extent_too_small);
		return result;
	}

	const auto root = resolve_mapped_span(image,
		standard_directory.VirtualAddress);
	if (!root || root->backing != SpanBacking::initialized) {
		emit_diagnostic(diagnostics, ParserDiagnostic::import_malformed);
		return result;
	}

	std::uint64_t remaining = standard_directory.Size != 0 ?
		standard_directory.Size : root->size;
	std::uint64_t cursor = standard_directory.VirtualAddress;
	ImportParseContext context(limits);
	bool terminated = false;

	while (remaining >= descriptor_size) {
		const auto span = resolve_mapped_span(image, cursor);
		if (!span || span->backing != SpanBacking::initialized ||
			span->size < descriptor_size || !image.read_at) {
			break;
		}

		image_import_descriptor descriptor{};
		if (!image.read_at(span->file_offset, &descriptor, descriptor_size)) {
			emit_diagnostic(diagnostics, ParserDiagnostic::import_malformed);
			return result;
		}
		if (descriptor.OriginalFirstThunk == 0 && descriptor.FirstThunk == 0) {
			terminated = true;
			break;
		}
		if (!context.descriptors.charge(1)) {
			context.exhausted = true;
			if (!context.budget_diagnostic_attempted) {
				context.budget_diagnostic_attempted = true;
				emit_diagnostic(diagnostics,
					ParserDiagnostic::import_budget_exhausted);
			}
			result.exhausted = true;
			return result;
		}

		result.libraries.push_back(
			ParsedImportLibrary{false, descriptor, {}, {}});
		cursor += descriptor_size;
		remaining -= descriptor_size;
	}

	if (!terminated) {
		emit_diagnostic(diagnostics,
			ParserDiagnostic::import_descriptor_unterminated);
	}
	return result;
}

} // namespace mana::detail
