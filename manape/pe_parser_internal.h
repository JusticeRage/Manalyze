#pragma once

#include <cstdint>

#include "manape/work_budget.h"

namespace mana::detail {

struct PEParserWorkLimits
{
	std::uint64_t rich_entries;
	std::uint64_t coff_symbol_records;
	std::uint64_t coff_string_table_bytes;
};

struct PEParserWorkStats
{
	std::uint64_t rich_records_read = 0;
	std::uint64_t rich_entries_appended = 0;
	std::uint64_t rich_reverse_passes = 0;
	std::uint64_t coff_symbol_records_read = 0;
	std::uint64_t coff_string_bytes_read = 0;
	std::uint64_t coff_string_read_calls = 0;
	std::uint64_t coff_max_buffer_bytes = 0;
};

constexpr PEParserWorkLimits production_pe_parser_work_limits() noexcept
{
	return {1048576, 1048576, 256ULL * 1024 * 1024};
}

} // namespace mana::detail
