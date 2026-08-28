#include "manape/parser_internal.h"

#include <algorithm>
#include <array>
#include <limits>
#include <unordered_map>
#include <unordered_set>

namespace mana::detail {

namespace {

constexpr std::size_t string_read_chunk = 4096;

enum class DecodeStatus { success, malformed, exhausted };

struct StringSource
{
	StringCacheKey key;
};

template<typename Value>
struct PendingDecode
{
	Value value;
	StringCacheKey key;
	bool cache_hit;
};

struct ImportParseContext
{
	explicit ImportParseContext(const ImportLimits& limits,
		ImportMetrics* parse_metrics)
		: descriptors(limits.descriptors), functions(limits.functions),
		  physical_string_bytes(limits.physical_string_bytes),
		  materialized_dll_name_bytes(limits.materialized_dll_name_bytes),
		  materialized_function_name_bytes(
			  limits.materialized_function_name_bytes), metrics(parse_metrics)
	{}

	WorkBudget descriptors;
	WorkBudget functions;
	WorkBudget physical_string_bytes;
	WorkBudget materialized_dll_name_bytes;
	WorkBudget materialized_function_name_bytes;
	std::unordered_map<StringCacheKey, std::string, StringCacheKeyHash>
		successful_dll_strings;
	std::unordered_map<StringCacheKey, DecodedImportName, StringCacheKeyHash>
		successful_function_names;
	std::unordered_map<ThunkCacheKey, std::vector<std::uint64_t>,
		ThunkCacheKeyHash>
		successful_thunks;
	ImportMetrics* metrics;
	bool exhausted = false;
	bool budget_diagnostic_attempted = false;
};

void emit_diagnostic(const DiagnosticSink& sink, ParserDiagnostic diagnostic)
{
	if (sink) sink(diagnostic);
}

void exhaust_imports(ImportParseContext& context,
	const DiagnosticSink& diagnostics)
{
	context.exhausted = true;
	if (context.budget_diagnostic_attempted) return;
	context.budget_diagnostic_attempted = true;
	emit_diagnostic(diagnostics, ParserDiagnostic::import_budget_exhausted);
}

std::optional<StringSource> resolve_string_source(const ImageView& image,
	std::uint64_t source, bool allow_direct_fallback)
{
	const auto span = resolve_mapped_span(image, source);
	if (span) {
		if (span->backing != SpanBacking::initialized) return std::nullopt;
		return StringSource{{StringSourceKind::mapped_rva,
			span->file_offset, span->size}};
	}
	if (!allow_direct_fallback || source == 0 || source >= image.file_size) {
		return std::nullopt;
	}
	return StringSource{{StringSourceKind::direct_file_offset,
		source, image.file_size - source}};
}

DecodeStatus read_string_bytes(const ImageView& image,
	const StringCacheKey& key, std::size_t prefix_size,
	ImportParseContext& context, std::array<std::uint8_t, 2>& prefix,
	std::string& value)
{
	if (!image.read_at) return DecodeStatus::malformed;
	std::uint64_t consumed = 0;
	std::size_t prefix_written = 0;
	std::array<std::uint8_t, string_read_chunk> buffer{};
	while (consumed < key.extent) {
		const std::size_t request = static_cast<std::size_t>(
			std::min<std::uint64_t>(string_read_chunk, key.extent - consumed));
		if (!context.physical_string_bytes.charge(request)) {
			return DecodeStatus::exhausted;
		}
		if (context.metrics) {
			++context.metrics->string_read_calls;
			context.metrics->string_bytes_read += request;
		}
		if (!image.read_at(key.source + consumed, buffer.data(), request)) {
			return DecodeStatus::malformed;
		}

		for (std::size_t i = 0; i < request; ++i) {
			if (prefix_written < prefix_size) {
				prefix[prefix_written++] = buffer[i];
				continue;
			}
			if (buffer[i] == 0) return DecodeStatus::success;
			value.push_back(static_cast<char>(buffer[i]));
		}
		consumed += request;
	}
	return DecodeStatus::malformed;
}

DecodeStatus decode_dll_name(const ImageView& image, std::uint64_t source,
	bool allow_direct_fallback, ImportParseContext& context,
	PendingDecode<std::string>& decoded)
{
	const auto location = resolve_string_source(image, source,
		allow_direct_fallback);
	if (!location) return DecodeStatus::malformed;
	decoded.key = location->key;
	const auto cached = context.successful_dll_strings.find(decoded.key);
	if (cached != context.successful_dll_strings.end()) {
		decoded.value = cached->second;
		decoded.cache_hit = true;
		if (context.metrics) ++context.metrics->string_cache_hits;
		return DecodeStatus::success;
	}

	std::array<std::uint8_t, 2> unused{};
	decoded.cache_hit = false;
	return read_string_bytes(image, decoded.key, 0, context, unused,
		decoded.value);
}

DecodeStatus decode_function_name(const ImageView& image,
	std::uint64_t source, ImportParseContext& context,
	PendingDecode<DecodedImportName>& decoded)
{
	const auto location = resolve_string_source(image, source, false);
	if (!location) return DecodeStatus::malformed;
	decoded.key = location->key;
	const auto cached = context.successful_function_names.find(decoded.key);
	if (cached != context.successful_function_names.end()) {
		decoded.value = cached->second;
		decoded.cache_hit = true;
		if (context.metrics) ++context.metrics->string_cache_hits;
		return DecodeStatus::success;
	}

	std::array<std::uint8_t, 2> hint{};
	decoded.cache_hit = false;
	const auto status = read_string_bytes(image, decoded.key, hint.size(),
		context, hint, decoded.value.name);
	if (status != DecodeStatus::success) return status;
	decoded.value.hint = static_cast<std::uint16_t>(hint[0]) |
		(static_cast<std::uint16_t>(hint[1]) << 8);
	return DecodeStatus::success;
}

bool read_mapped_value(const ImageView& image, std::uint64_t rva,
	void* destination, std::size_t size)
{
	const auto span = resolve_mapped_span(image, rva);
	return span && span->backing == SpanBacking::initialized &&
		span->size >= size && image.read_at &&
		image.read_at(span->file_offset, destination, size);
}

bool materialize_import(std::uint64_t raw, std::uint64_t ordinal_mask,
	const ImageView& image, ParsedImportLibrary& library,
	std::unordered_set<ImportIdentity, ImportIdentityHash>& identities,
	ImportParseContext& context, const DiagnosticSink& diagnostics)
{
	if (library.functions.size() >= 10000) {
		emit_diagnostic(diagnostics, ParserDiagnostic::import_malformed);
		return false;
	}
	if (!context.functions.charge(1)) {
		exhaust_imports(context, diagnostics);
		return false;
	}

	import_lookup_table function{};
	function.AddressOfData = raw;
	PendingDecode<DecodedImportName> decoded{};
	bool has_pending_name = false;
	if ((raw & ordinal_mask) == 0) {
		const auto status = decode_function_name(image,
			raw & 0x7fffffffULL, context, decoded);
		if (status == DecodeStatus::exhausted) {
			exhaust_imports(context, diagnostics);
			return false;
		}
		if (status != DecodeStatus::success) {
			emit_diagnostic(diagnostics, ParserDiagnostic::import_malformed);
			return false;
		}
		if (!context.materialized_function_name_bytes.charge(
			decoded.value.name.size())) {
			exhaust_imports(context, diagnostics);
			return false;
		}
		function.Hint = decoded.value.hint;
		function.Name = decoded.value.name;
		has_pending_name = !decoded.cache_hit;
	}

	if (context.metrics) ++context.metrics->duplicate_checks;
	const auto inserted = identities.insert({function.AddressOfData,
		function.Hint, function.Name});
	if (!inserted.second) {
		emit_diagnostic(diagnostics, ParserDiagnostic::import_malformed);
		return false;
	}
	if (has_pending_name) {
		context.successful_function_names.emplace(decoded.key,
			std::move(decoded.value));
		if (context.metrics) {
			context.metrics->function_name_cache_entries =
				context.successful_function_names.size();
		}
	}
	library.functions.push_back(std::move(function));
	return true;
}

bool traverse_import_table(const ImageView& image, std::uint64_t table_rva,
	bool pe32_plus, ParsedImportLibrary& library, ImportParseContext& context,
	const DiagnosticSink& diagnostics)
{
	const std::size_t slot_size = pe32_plus ? sizeof(std::uint64_t) :
		sizeof(std::uint32_t);
	const std::uint64_t ordinal_mask = pe32_plus ? 0x8000000000000000ULL :
		0x80000000ULL;
	const auto root = resolve_mapped_span(image, table_rva);
	if (!root || root->backing != SpanBacking::initialized) {
		emit_diagnostic(diagnostics, ParserDiagnostic::import_malformed);
		return false;
	}

	const ThunkCacheKey key{table_rva, slot_size};
	std::unordered_set<ImportIdentity, ImportIdentityHash> identities;
	const auto cached = context.successful_thunks.find(key);
	if (cached != context.successful_thunks.end()) {
		if (context.metrics) ++context.metrics->thunk_cache_hits;
		for (const auto raw : cached->second) {
			if (!materialize_import(raw, ordinal_mask, image, library,
				identities, context, diagnostics)) {
				return false;
			}
		}
		return true;
	}

	std::vector<std::uint64_t> pending;
	std::uint64_t cursor = table_rva;
	while (true) {
		const auto span = resolve_mapped_span(image, cursor);
		if (!span || span->region != root->region) {
			emit_diagnostic(diagnostics, ParserDiagnostic::import_malformed);
			return false;
		}
		if (span->backing == SpanBacking::zero_fill) {
			context.successful_thunks.emplace(key, std::move(pending));
			if (context.metrics) {
				context.metrics->thunk_cache_entries =
					context.successful_thunks.size();
			}
			return true;
		}
		if (span->size < slot_size || !image.read_at) {
			emit_diagnostic(diagnostics, ParserDiagnostic::import_malformed);
			return false;
		}

		std::uint64_t raw = 0;
		if (context.metrics) ++context.metrics->thunk_slot_reads;
		if (!image.read_at(span->file_offset, &raw, slot_size)) {
			emit_diagnostic(diagnostics, ParserDiagnostic::import_malformed);
			return false;
		}
		if (raw == 0) {
			context.successful_thunks.emplace(key, std::move(pending));
			if (context.metrics) {
				context.metrics->thunk_cache_entries =
					context.successful_thunks.size();
			}
			return true;
		}
		if (!materialize_import(raw, ordinal_mask, image, library, identities,
			context, diagnostics)) {
			return false;
		}
		pending.push_back(raw);
		if (cursor > std::numeric_limits<std::uint64_t>::max() - slot_size) {
			emit_diagnostic(diagnostics, ParserDiagnostic::import_malformed);
			return false;
		}
		cursor += slot_size;
	}
}

bool materialize_library_name(const ImageView& image,
	std::uint64_t source, bool allow_direct_fallback, bool delay_loaded,
	const std::optional<image_import_descriptor>& descriptor,
	ImportParseResult& result, ImportParseContext& context,
	const DiagnosticSink& diagnostics)
{
	PendingDecode<std::string> decoded{};
	const auto status = decode_dll_name(image, source, allow_direct_fallback,
		context, decoded);
	if (status == DecodeStatus::exhausted) {
		exhaust_imports(context, diagnostics);
		return false;
	}
	if (status != DecodeStatus::success) {
		emit_diagnostic(diagnostics, ParserDiagnostic::import_malformed);
		return false;
	}
	if (!context.materialized_dll_name_bytes.charge(decoded.value.size())) {
		exhaust_imports(context, diagnostics);
		return false;
	}
	result.libraries.push_back({delay_loaded, descriptor,
		decoded.value, {}, true});
	if (!decoded.cache_hit) {
		context.successful_dll_strings.emplace(decoded.key,
			std::move(decoded.value));
	}
	return true;
}

} // namespace

std::size_t StringCacheKeyHash::operator()(const StringCacheKey& key) const noexcept
{
	std::size_t value = std::hash<std::uint64_t>{}(key.source);
	value ^= std::hash<std::uint64_t>{}(key.extent) + 0x9e3779b9 +
		(value << 6) + (value >> 2);
	value ^= std::hash<unsigned int>{}(static_cast<unsigned int>(key.kind)) +
		0x9e3779b9 + (value << 6) + (value >> 2);
	return value;
}

std::size_t ThunkCacheKeyHash::operator()(const ThunkCacheKey& key) const noexcept
{
	std::size_t value = std::hash<std::uint64_t>{}(key.table_rva);
	value ^= std::hash<std::size_t>{}(key.slot_width) + 0x9e3779b9 +
		(value << 6) + (value >> 2);
	return value;
}

std::size_t ImportIdentityHash::operator()(
	const ImportIdentity& identity) const noexcept
{
	std::size_t value = std::hash<std::uint64_t>{}(identity.address_of_data);
	value ^= std::hash<std::uint16_t>{}(identity.hint) + 0x9e3779b9 +
		(value << 6) + (value >> 2);
	value ^= std::hash<std::string>{}(identity.name) + 0x9e3779b9 +
		(value << 6) + (value >> 2);
	return value;
}

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
	const image_data_directory& delay_directory,
	bool pe32_plus,
	const ImportLimits& limits,
	const DiagnosticSink& diagnostics,
	ImportMetrics* metrics)
{
	ImportParseResult result;
	ImportParseContext context(limits, metrics);
	std::vector<image_import_descriptor> descriptors;

	constexpr std::uint64_t descriptor_size = 5 * sizeof(std::uint32_t);
	bool standard_can_continue = standard_directory.VirtualAddress != 0;
	if (standard_can_continue && standard_directory.Size != 0 &&
		standard_directory.Size < descriptor_size) {
		emit_diagnostic(diagnostics, ParserDiagnostic::import_extent_too_small);
		standard_can_continue = false;
	}

	std::optional<MappedSpan> root;
	if (standard_can_continue) {
		root = resolve_mapped_span(image, standard_directory.VirtualAddress);
		if (!root || root->backing != SpanBacking::initialized) {
			emit_diagnostic(diagnostics, ParserDiagnostic::import_malformed);
			standard_can_continue = false;
		}
	}

	std::uint64_t remaining = !standard_can_continue ? 0 :
		(standard_directory.Size != 0 ? standard_directory.Size : root->size);
	std::uint64_t cursor = standard_directory.VirtualAddress;
	bool terminated = false;

	while (standard_can_continue && remaining >= descriptor_size) {
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
			exhaust_imports(context, diagnostics);
			break;
		}

		descriptors.push_back(descriptor);
		cursor += descriptor_size;
		remaining -= descriptor_size;
	}

	if (standard_can_continue && !terminated && !context.exhausted) {
		emit_diagnostic(diagnostics,
			ParserDiagnostic::import_descriptor_unterminated);
	}
	if (context.exhausted) {
		result.libraries.reserve(descriptors.size());
		for (const auto& descriptor : descriptors) {
			result.libraries.push_back({false, descriptor, {}, {}, false});
		}
	}

	bool standard_names_valid = true;
	if (!context.exhausted) {
		for (const auto& descriptor : descriptors) {
			if (!materialize_library_name(image, descriptor.Name, true, false,
				descriptor, result, context, diagnostics)) {
				standard_names_valid = false;
				break;
			}
		}
	}

	if (!context.exhausted && standard_names_valid) {
		for (auto& library : result.libraries) {
			const auto& descriptor = *library.descriptor;
			const std::uint64_t table_rva = descriptor.OriginalFirstThunk != 0 ?
				descriptor.OriginalFirstThunk : descriptor.FirstThunk;
			if (!traverse_import_table(image, table_rva, pe32_plus, library,
				context, diagnostics)) {
				break;
			}
		}
	}

	if (!context.exhausted && delay_directory.VirtualAddress != 0) {
		delay_load_directory_table delay{};
		if (read_mapped_value(image, delay_directory.VirtualAddress, &delay,
			8 * sizeof(std::uint32_t)) &&
			materialize_library_name(image, delay.Name, false, true,
				std::nullopt, result, context, diagnostics)) {
			delay.NameStr = result.libraries.back().name;
			result.delay_directory = delay;
			traverse_import_table(image, delay.DelayImportNameTable, pe32_plus,
				result.libraries.back(), context, diagnostics);
		}
	}

	result.exhausted = context.exhausted;
	return result;
}

} // namespace mana::detail
