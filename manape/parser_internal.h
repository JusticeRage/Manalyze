#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "manape/pe_structs.h"
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

struct ImportLimits
{
	std::uint64_t descriptors;
	std::uint64_t functions;
	std::uint64_t physical_string_bytes;
	std::uint64_t materialized_dll_name_bytes;
	std::uint64_t materialized_function_name_bytes;
};

struct ImportMetrics
{
	std::uint64_t string_read_calls = 0;
	std::uint64_t string_bytes_read = 0;
	std::uint64_t string_cache_hits = 0;
	std::uint64_t thunk_slot_reads = 0;
	std::uint64_t thunk_cache_hits = 0;
	std::uint64_t thunk_cache_entries = 0;
	std::uint64_t duplicate_checks = 0;
	std::uint64_t function_name_cache_entries = 0;
};

enum class StringSourceKind { mapped_rva, direct_file_offset };

struct StringCacheKey
{
	StringSourceKind kind;
	std::uint64_t source;
	std::uint64_t extent;

	bool operator==(const StringCacheKey& other) const
	{
		return kind == other.kind && source == other.source &&
			extent == other.extent;
	}
};

struct StringCacheKeyHash
{
	std::size_t operator()(const StringCacheKey& key) const noexcept;
};

struct DecodedImportName
{
	std::uint16_t hint;
	std::string name;
};

struct ThunkCacheKey
{
	std::uint64_t table_rva;
	std::size_t slot_width;

	bool operator==(const ThunkCacheKey& other) const
	{
		return table_rva == other.table_rva && slot_width == other.slot_width;
	}
};

struct ThunkCacheKeyHash
{
	std::size_t operator()(const ThunkCacheKey& key) const noexcept;
};

struct ImportIdentity
{
	std::uint64_t address_of_data;
	std::uint16_t hint;
	std::string name;

	bool operator==(const ImportIdentity& other) const
	{
		return address_of_data == other.address_of_data &&
			hint == other.hint && name == other.name;
	}
};

struct ImportIdentityHash
{
	std::size_t operator()(const ImportIdentity& identity) const noexcept;
};

enum class ParserDiagnostic
{
	import_extent_too_small,
	import_descriptor_unterminated,
	import_malformed,
	import_budget_exhausted,
	tls_callback_va_invalid,
	tls_callback_unterminated,
	tls_budget_exhausted,
};

using DiagnosticSink = std::function<void(ParserDiagnostic)>;

struct ParsedImportLibrary
{
	bool delay_loaded;
	std::optional<image_import_descriptor> descriptor;
	std::string name;
	std::vector<import_lookup_table> functions;
	bool name_materialized = false;
};

struct ImportParseResult
{
	std::vector<ParsedImportLibrary> libraries;
	std::optional<delay_load_directory_table> delay_directory;
	bool exhausted = false;
};

std::optional<MappedSpan> resolve_mapped_span(const ImageView& image,
	std::uint64_t rva);

ImportParseResult parse_imports(const ImageView& image,
	const image_data_directory& standard_directory,
	const image_data_directory& delay_directory,
	bool pe32_plus,
	const ImportLimits& limits,
	const DiagnosticSink& diagnostics,
	ImportMetrics* metrics = nullptr);

} // namespace mana::detail
