#if !defined(MANALYZE_PARSER_TESTING)
#error "manape/pe_test_hooks.h is only available to parser tests"
#endif

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "manape/pe.h"
#include "manape/pe_parser_internal.h"

namespace mana::detail {

struct PEParserTestAccess
{
	static std::shared_ptr<PE> create_from_bytes(
		const std::uint8_t* data, std::size_t size, const std::string& name,
		const PEParserWorkLimits& limits, PEParserWorkStats& stats);
	static std::size_t retained_coff_symbols(const PE& pe);
	static std::size_t retained_coff_strings(const PE& pe);
};

} // namespace mana::detail
