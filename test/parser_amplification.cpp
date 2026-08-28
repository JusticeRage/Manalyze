/*
    This file is part of Manalyze.

    Manalyze is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
*/

#include <boost/system/api_config.hpp>

#define BOOST_TEST_MODULE ManalyzeParserAmplificationTests
#if !defined BOOST_WINDOWS_API
#	define BOOST_TEST_DYN_LINK
#endif

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <sstream>
#include <tuple>
#include <vector>

#if defined(_WIN32)
#	include <windows.h>
#elif defined(__APPLE__)
#	include <mach-o/dyld.h>
#	include <sys/wait.h>
#	include <unistd.h>
#elif defined(__FreeBSD__)
#	include <sys/types.h>
#	include <sys/sysctl.h>
#	include <sys/wait.h>
#	include <unistd.h>
#else
#	include <sys/wait.h>
#	include <unistd.h>
#endif

#include "fixtures.h"
#include "manacommons/color.h"
#include "manape/pe.h"
#include "manape/pe_test_hooks.h"

namespace {

struct SilenceLogsFixture
{
	SilenceLogsFixture() { utils::set_log_level(utils::LogLevel::OFF); }
};

class ErrorCapture
{
public:
	explicit ErrorCapture(utils::LogLevel level = utils::LogLevel::ERROR)
		: previous_level(utils::get_log_level()),
		  previous_buffer(std::cerr.rdbuf(captured.rdbuf()))
	{
		utils::set_log_level(level);
	}
	~ErrorCapture()
	{
		std::cerr.rdbuf(previous_buffer);
		utils::set_log_level(previous_level);
	}
	std::string str() const { return captured.str(); }
private:
	utils::LogLevel previous_level;
	std::ostringstream captured;
	std::streambuf* previous_buffer;
};

const char* const PARSER_CAP_TEST_CHILD = "MANALYZE_PARSER_CAP_TEST_CHILD";
const char* const PARSER_CAP_TEST_NAME =
	"parser_amplification/cap_malformed_coff_symbol_diagnostics_without_stopping_scan";

std::string current_test_executable()
{
#if defined(_WIN32)
	std::vector<char> path(MAX_PATH);
	for (;;) {
		const DWORD length = ::GetModuleFileNameA(nullptr, path.data(),
			static_cast<DWORD>(path.size()));
		if (length == 0) return {};
		if (length < path.size()) return std::string(path.data(), length);
		path.resize(path.size() * 2);
	}
#elif defined(__APPLE__)
	std::uint32_t size = 0;
	_NSGetExecutablePath(nullptr, &size);
	std::vector<char> path(size);
	if (_NSGetExecutablePath(path.data(), &size) == 0) return path.data();
	return {};
#elif defined(__FreeBSD__)
	const int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1 };
	size_t size = 0;
	if (::sysctl(mib, 4, nullptr, &size, nullptr, 0) != 0 || size == 0) return {};
	std::vector<char> path(size);
	if (::sysctl(mib, 4, path.data(), &size, nullptr, 0) == 0 && size != 0) {
		return path.data();
	}
	return {};
#elif defined(__linux__)
	std::vector<char> path(1024);
	for (;;) {
		const ssize_t length = ::readlink("/proc/self/exe", path.data(), path.size());
		if (length < 0) return {};
		if (static_cast<size_t>(length) < path.size()) {
			return std::string(path.data(), static_cast<size_t>(length));
		}
		path.resize(path.size() * 2);
	}
#else
	return {};
#endif
}

std::string fixture_compatible_argv0()
{
	const fs::path original(unit::master_test_suite().argv[0]);
	if (original.is_absolute()) return original.string();
	return (fs::current_path().parent_path() / "bin" / original.filename()).string();
}

int run_cap_test_child()
{
	const std::string executable = current_test_executable();
	if (executable.empty()) return EXIT_FAILURE;
	const std::string argv0 = fixture_compatible_argv0();
	const std::string run_test = std::string("--run_test=") + PARSER_CAP_TEST_NAME;

#if defined(_WIN32)
	std::string command_line = "\"" + argv0 + "\" " + run_test + " --log_level=error";
	STARTUPINFOA startup_info = {};
	startup_info.cb = sizeof(startup_info);
	PROCESS_INFORMATION process_info = {};
	if (!::SetEnvironmentVariableA(PARSER_CAP_TEST_CHILD, PARSER_CAP_TEST_NAME)) {
		return EXIT_FAILURE;
	}
	const BOOL created = ::CreateProcessA(executable.c_str(), command_line.data(), nullptr,
		nullptr, FALSE, 0, nullptr, nullptr, &startup_info, &process_info);
	::SetEnvironmentVariableA(PARSER_CAP_TEST_CHILD, nullptr);
	if (!created) return EXIT_FAILURE;
	bool succeeded = false;
	const DWORD wait_result = ::WaitForSingleObject(process_info.hProcess, INFINITE);
	if (wait_result == WAIT_OBJECT_0) {
		DWORD exit_code = EXIT_FAILURE;
		succeeded = ::GetExitCodeProcess(process_info.hProcess, &exit_code) && exit_code == 0;
	} else {
		constexpr DWORD reap_timeout_ms = 5000;
		const BOOL terminated = ::TerminateProcess(process_info.hProcess, EXIT_FAILURE);
		const DWORD reap_result = ::WaitForSingleObject(process_info.hProcess, reap_timeout_ms);
		if (!terminated || reap_result != WAIT_OBJECT_0) succeeded = false;
	}
	::CloseHandle(process_info.hThread);
	::CloseHandle(process_info.hProcess);
	return succeeded ? EXIT_SUCCESS : EXIT_FAILURE;
#else
	const pid_t pid = ::fork();
	if (pid == 0) {
		if (::setenv(PARSER_CAP_TEST_CHILD, PARSER_CAP_TEST_NAME, 1) != 0) {
			::_exit(EXIT_FAILURE);
		}
		char* const child_argv[] = {
			const_cast<char*>(argv0.c_str()),
			const_cast<char*>(run_test.c_str()),
			const_cast<char*>("--log_level=error"),
			nullptr
		};
		::execv(executable.c_str(), child_argv);
		::_exit(EXIT_FAILURE);
	}
	if (pid < 0) return EXIT_FAILURE;

	int status = 0;
	while (::waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR) return EXIT_FAILURE;
	}
	return WIFEXITED(status) ? WEXITSTATUS(status) : EXIT_FAILURE;
#endif
}

bool is_cap_test_child()
{
	const char* marker = std::getenv(PARSER_CAP_TEST_CHILD);
	return marker != nullptr && std::string(marker) == PARSER_CAP_TEST_NAME;
}

void write_u64(std::vector<std::uint8_t>& bytes, size_t offset, std::uint64_t value)
{
	if (offset > bytes.size() || bytes.size() - offset < sizeof(value)) {
		throw std::out_of_range("64-bit fixture patch exceeds input");
	}
	for (size_t i = 0; i < sizeof(value); ++i) {
		bytes[offset + i] = static_cast<std::uint8_t>(value >> (8 * i));
	}
}

std::vector<std::uint8_t> make_rich_pe(std::size_t entry_count, bool include_dans = true)
{
	auto bytes = read_binary_file("testfiles/manatest.exe");
	const std::uint32_t original_pe_offset =
		static_cast<std::uint32_t>(bytes[0x3c]) |
		(static_cast<std::uint32_t>(bytes[0x3d]) << 8) |
		(static_cast<std::uint32_t>(bytes[0x3e]) << 16) |
		(static_cast<std::uint32_t>(bytes[0x3f]) << 24);
	constexpr std::size_t rich_offset = 0x80;
	constexpr std::uint32_t key = 0x12345678;
	const std::size_t rich_size = (entry_count + 2) * sizeof(std::uint64_t);
	const std::size_t rich_end = (rich_offset + rich_size + 3) & ~std::size_t(3);
	const std::size_t new_pe_offset = std::max<std::size_t>(
		original_pe_offset + 4, rich_end);
	const std::size_t shift = new_pe_offset - original_pe_offset;
	bytes.resize(bytes.size() + shift);
	std::copy_backward(bytes.begin() + original_pe_offset, bytes.end() - shift, bytes.end());
	std::fill(bytes.begin() + 0x40, bytes.begin() + new_pe_offset, 0);
	write_u32(bytes, 0x3c, static_cast<std::uint32_t>(new_pe_offset));

	const std::uint32_t marker = include_dans ? 0x536e6144 : 0x11111111;
	write_u64(bytes, rich_offset,
		(static_cast<std::uint64_t>(key) << 32) | (marker ^ key));
	for (std::size_t i = 0; i < entry_count; ++i) {
		const std::uint32_t build = static_cast<std::uint32_t>(i & 0xffff);
		const std::uint32_t product = static_cast<std::uint32_t>((i * 3) & 0xffff);
		const std::uint32_t id = (build << 16) | product;
		const std::uint32_t count = static_cast<std::uint32_t>(i + 1);
		write_u64(bytes, rich_offset + (i + 1) * sizeof(std::uint64_t),
			(static_cast<std::uint64_t>(count ^ key) << 32) | (id ^ key));
	}
	write_u32(bytes, rich_offset + (entry_count + 1) * sizeof(std::uint64_t), 0x68636952);
	write_u32(bytes, rich_offset + (entry_count + 1) * sizeof(std::uint64_t) + 4, key);
	return bytes;
}

std::vector<std::uint8_t> make_coff_pe(
	std::uint32_t declared_symbol_count,
	std::uint32_t physical_symbol_count,
	const std::vector<std::uint8_t>& string_payload)
{
	auto bytes = read_binary_file("testfiles/manatest.exe");
	const std::uint32_t symbol_offset = static_cast<std::uint32_t>(bytes.size());
	bytes.resize(bytes.size() + static_cast<std::size_t>(physical_symbol_count) * 18, 0);
	write_u32(bytes, 0xfc, symbol_offset);
	write_u32(bytes, 0x100, declared_symbol_count);
	const std::uint32_t string_table_size =
		static_cast<std::uint32_t>(sizeof(std::uint32_t) + string_payload.size());
	const std::size_t table_offset = bytes.size();
	bytes.resize(bytes.size() + sizeof(std::uint32_t));
	write_u32(bytes, table_offset, string_table_size);
	bytes.insert(bytes.end(), string_payload.begin(), string_payload.end());
	return bytes;
}

std::shared_ptr<mana::PE> parse_with_rich_limit(const std::vector<std::uint8_t>& bytes,
	std::uint64_t rich_limit, mana::detail::PEParserWorkStats& stats)
{
	auto limits = mana::detail::production_pe_parser_work_limits();
	limits.rich_entries = rich_limit;
	return mana::detail::PEParserTestAccess::create_from_bytes(
		bytes.data(), bytes.size(), "generated-rich.exe", limits, stats);
}

std::shared_ptr<mana::PE> parse_with_coff_limits(const std::vector<std::uint8_t>& bytes,
	std::uint64_t symbol_limit, std::uint64_t string_limit,
	mana::detail::PEParserWorkStats& stats)
{
	auto limits = mana::detail::production_pe_parser_work_limits();
	limits.coff_symbol_records = symbol_limit;
	limits.coff_string_table_bytes = string_limit;
	return mana::detail::PEParserTestAccess::create_from_bytes(
		bytes.data(), bytes.size(), "generated-coff.exe", limits, stats);
}

void check_generated_tuple(const mana::rich_header& rich, std::size_t index)
{
	BOOST_CHECK_EQUAL(std::get<0>(rich.values.at(index)), index & 0xffff);
	BOOST_CHECK_EQUAL(std::get<1>(rich.values.at(index)), (index * 3) & 0xffff);
	BOOST_CHECK_EQUAL(std::get<2>(rich.values.at(index)), index + 1);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(parser_amplification, SetWorkingDirectory)

BOOST_AUTO_TEST_CASE(parse_4096_rich_entries_in_encoded_order)
{
	SilenceLogsFixture silence_logs;
	const auto bytes = make_rich_pe(4096);
	mana::detail::PEParserWorkStats stats;
	auto pe = parse_with_rich_limit(bytes, 4096, stats);
	BOOST_REQUIRE(pe && pe->is_valid());
	auto rich = pe->get_rich_header();
	BOOST_REQUIRE(rich);
	BOOST_CHECK_EQUAL(rich->file_offset, 0x80);
	BOOST_REQUIRE_EQUAL(rich->values.size(), 4096);
	check_generated_tuple(*rich, 0);
	check_generated_tuple(*rich, 2048);
	check_generated_tuple(*rich, 4095);
}

BOOST_AUTO_TEST_CASE(rich_parser_reports_one_linear_reverse_pass)
{
	SilenceLogsFixture silence_logs;
	constexpr std::size_t entry_count = 4096;
	const auto bytes = make_rich_pe(entry_count);
	mana::detail::PEParserWorkStats stats;
	auto pe = parse_with_rich_limit(bytes, entry_count, stats);
	BOOST_REQUIRE(pe && pe->get_rich_header());
	BOOST_CHECK_EQUAL(stats.rich_records_read, entry_count + 1);
	BOOST_CHECK_EQUAL(stats.rich_entries_appended, entry_count);
	BOOST_CHECK_EQUAL(stats.rich_reverse_passes, 1);
}

BOOST_AUTO_TEST_CASE(rich_candidate_without_dans_is_discarded)
{
	SilenceLogsFixture silence_logs;
	constexpr std::size_t entry_count = 4096;
	const auto bytes = make_rich_pe(entry_count, false);
	mana::detail::PEParserWorkStats stats;
	auto pe = parse_with_rich_limit(bytes, 8192, stats);
	BOOST_REQUIRE(pe && pe->is_valid());
	BOOST_CHECK(!pe->get_rich_header());
	const std::size_t rich_offset = 0x80 + (entry_count + 1) * sizeof(std::uint64_t);
	BOOST_CHECK_LE(stats.rich_records_read, rich_offset / sizeof(std::uint64_t));
}

BOOST_AUTO_TEST_CASE(rich_limit_accepts_below_limit_entries)
{
	SilenceLogsFixture silence_logs;
	const auto bytes = make_rich_pe(2);
	mana::detail::PEParserWorkStats stats;
	auto pe = parse_with_rich_limit(bytes, 3, stats);
	BOOST_REQUIRE(pe && pe->is_valid());
	BOOST_REQUIRE(pe->get_rich_header());
	BOOST_CHECK_EQUAL(pe->get_rich_header()->values.size(), 2);
}

BOOST_AUTO_TEST_CASE(rich_limit_accepts_exact_limit_entries)
{
	SilenceLogsFixture silence_logs;
	const auto bytes = make_rich_pe(3);
	mana::detail::PEParserWorkStats stats;
	auto pe = parse_with_rich_limit(bytes, 3, stats);
	BOOST_REQUIRE(pe && pe->is_valid());
	BOOST_REQUIRE(pe->get_rich_header());
	BOOST_CHECK_EQUAL(pe->get_rich_header()->values.size(), 3);
}

BOOST_AUTO_TEST_CASE(rich_limit_discards_above_limit_candidate)
{
	const auto bytes = make_rich_pe(4);
	mana::detail::PEParserWorkStats stats;
	ErrorCapture warnings(utils::LogLevel::WARNING);
	auto pe = parse_with_rich_limit(bytes, 3, stats);
	BOOST_REQUIRE(pe && pe->is_valid());
	BOOST_CHECK(!pe->get_rich_header());
	BOOST_CHECK_EQUAL(stats.rich_entries_appended, 3);
	BOOST_CHECK_EQUAL(stats.rich_reverse_passes, 0);
	const std::string diagnostic = "Rich header entry budget exhausted";
	const std::string output = warnings.str();
	const size_t first = output.find(diagnostic);
	BOOST_REQUIRE_NE(first, std::string::npos);
	BOOST_CHECK_EQUAL(output.find(diagnostic, first + diagnostic.size()), std::string::npos);
}

BOOST_AUTO_TEST_CASE(rich_limit_preserves_later_metadata)
{
	SilenceLogsFixture silence_logs;
	const auto bytes = read_binary_file("testfiles/manatest.exe");
	auto control = mana::PE::create_from_bytes(
		bytes.data(), bytes.size(), "control-manatest.exe");
	BOOST_REQUIRE(control && control->is_valid());
	mana::detail::PEParserWorkStats stats;
	auto pe = parse_with_rich_limit(bytes, 10, stats);
	BOOST_REQUIRE(pe && pe->is_valid());
	BOOST_CHECK(!pe->get_rich_header());
	BOOST_CHECK_EQUAL(pe->get_sections()->size(), control->get_sections()->size());
	BOOST_REQUIRE_EQUAL(pe->get_debug_info()->size(), control->get_debug_info()->size());
	BOOST_REQUIRE(!pe->get_debug_info()->empty());
	BOOST_CHECK_EQUAL(pe->get_debug_info()->front()->Filename,
		control->get_debug_info()->front()->Filename);
}

BOOST_AUTO_TEST_CASE(existing_rich_values_are_unchanged)
{
	SilenceLogsFixture silence_logs;
	const auto bytes = read_binary_file("testfiles/manatest.exe");
	mana::detail::PEParserWorkStats stats;
	auto pe = parse_with_rich_limit(bytes, 11, stats);
	BOOST_REQUIRE(pe && pe->is_valid());
	auto rich = pe->get_rich_header();
	BOOST_REQUIRE(rich);
	BOOST_CHECK_EQUAL(rich->xor_key, 0x374baddd);
	BOOST_CHECK_EQUAL(rich->file_offset, 0x80);
	BOOST_REQUIRE_EQUAL(rich->values.size(), 11);
	BOOST_CHECK_EQUAL(std::get<0>(rich->values.at(0)), 0);
	BOOST_CHECK_EQUAL(std::get<1>(rich->values.at(1)), 0x7809);
	BOOST_CHECK_EQUAL(std::get<2>(rich->values.at(10)), 1);
}

BOOST_AUTO_TEST_CASE(production_rich_limit_is_stable)
{
	BOOST_CHECK_EQUAL(mana::detail::production_pe_parser_work_limits().rich_entries, 1048576);
}

BOOST_AUTO_TEST_CASE(coff_symbol_exact_physical_extent_is_validated_without_retention)
{
	SilenceLogsFixture silence_logs;
	const auto bytes = make_coff_pe(1, 1, {});
	mana::detail::PEParserWorkStats stats;
	auto pe = parse_with_coff_limits(bytes, 1, 4, stats);
	BOOST_REQUIRE(pe && pe->is_valid());
	BOOST_CHECK_EQUAL(stats.coff_symbol_records_read, 1);
	BOOST_CHECK_EQUAL(mana::detail::PEParserTestAccess::retained_coff_symbols(*pe), 0);
	BOOST_CHECK_EQUAL(mana::detail::PEParserTestAccess::retained_coff_strings(*pe), 0);
}

BOOST_AUTO_TEST_CASE(coff_symbol_extent_failure_precedes_budget_and_preserves_metadata)
{
	const auto bytes = make_coff_pe(2, 1, {});
	const auto control_bytes = read_binary_file("testfiles/manatest.exe");
	auto control = mana::PE::create_from_bytes(
		control_bytes.data(), control_bytes.size(), "control-manatest.exe");
	BOOST_REQUIRE(control && control->is_valid());
	mana::detail::PEParserWorkStats stats;
	ErrorCapture errors(utils::LogLevel::WARNING);
	auto pe = parse_with_coff_limits(bytes, 1, 4, stats);
	BOOST_REQUIRE(pe && pe->is_valid());
	BOOST_CHECK_EQUAL(stats.coff_symbol_records_read, 0);
	BOOST_CHECK_EQUAL(mana::detail::PEParserTestAccess::retained_coff_symbols(*pe), 0);
	BOOST_CHECK_EQUAL(mana::detail::PEParserTestAccess::retained_coff_strings(*pe), 0);
	BOOST_REQUIRE(pe->get_sections());
	BOOST_CHECK_EQUAL(pe->get_sections()->size(), control->get_sections()->size());
	BOOST_REQUIRE_EQUAL(pe->get_debug_info()->size(), control->get_debug_info()->size());
	BOOST_REQUIRE(!pe->get_debug_info()->empty());
	BOOST_CHECK_EQUAL(pe->get_debug_info()->front()->Filename,
		control->get_debug_info()->front()->Filename);
	const std::string output = errors.str();
	BOOST_CHECK_NE(output.find("COFF symbol table extends beyond the end of the file"),
		std::string::npos);
	BOOST_CHECK_EQUAL(output.find("COFF symbol-record budget exhausted"), std::string::npos);
}

BOOST_AUTO_TEST_CASE(coff_symbol_limit_accepts_below_limit_records_without_retention)
{
	SilenceLogsFixture silence_logs;
	const auto bytes = make_coff_pe(2, 2, {});
	mana::detail::PEParserWorkStats stats;
	auto pe = parse_with_coff_limits(bytes, 3, 4, stats);
	BOOST_REQUIRE(pe && pe->is_valid());
	BOOST_CHECK_EQUAL(stats.coff_symbol_records_read, 2);
	BOOST_CHECK_EQUAL(mana::detail::PEParserTestAccess::retained_coff_symbols(*pe), 0);
}

BOOST_AUTO_TEST_CASE(coff_symbol_limit_accepts_exact_limit_records_without_retention)
{
	SilenceLogsFixture silence_logs;
	const auto bytes = make_coff_pe(3, 3, {});
	mana::detail::PEParserWorkStats stats;
	auto pe = parse_with_coff_limits(bytes, 3, 4, stats);
	BOOST_REQUIRE(pe && pe->is_valid());
	BOOST_CHECK_EQUAL(stats.coff_symbol_records_read, 3);
	BOOST_CHECK_EQUAL(mana::detail::PEParserTestAccess::retained_coff_symbols(*pe), 0);
}

BOOST_AUTO_TEST_CASE(coff_symbol_limit_rejects_complete_table_before_iteration)
{
	const auto bytes = make_coff_pe(4, 4, {});
	mana::detail::PEParserWorkStats stats;
	ErrorCapture warnings(utils::LogLevel::WARNING);
	auto pe = parse_with_coff_limits(bytes, 3, 4, stats);
	BOOST_REQUIRE(pe && pe->is_valid());
	BOOST_CHECK_EQUAL(stats.coff_symbol_records_read, 0);
	BOOST_CHECK_EQUAL(mana::detail::PEParserTestAccess::retained_coff_symbols(*pe), 0);
	BOOST_CHECK_EQUAL(mana::detail::PEParserTestAccess::retained_coff_strings(*pe), 0);
	const std::string diagnostic = "COFF symbol-record budget exhausted";
	const std::string output = warnings.str();
	const std::size_t first = output.find(diagnostic);
	BOOST_REQUIRE_NE(first, std::string::npos);
	BOOST_CHECK_EQUAL(output.find(diagnostic, first + diagnostic.size()), std::string::npos);
}

BOOST_AUTO_TEST_CASE(production_coff_symbol_limit_is_stable)
{
	BOOST_CHECK_EQUAL(
		mana::detail::production_pe_parser_work_limits().coff_symbol_records, 1048576);
}

BOOST_AUTO_TEST_CASE(coff_string_payload_uses_fixed_memory_without_retention)
{
	constexpr std::size_t payload_size = 1024 * 1024;
	const auto bytes = make_coff_pe(1, 1, std::vector<std::uint8_t>(payload_size, 0));
	mana::detail::PEParserWorkStats stats;
	ErrorCapture errors;
	auto pe = parse_with_coff_limits(bytes, 1, payload_size, stats);
	BOOST_REQUIRE(pe && pe->is_valid());
	BOOST_CHECK_EQUAL(stats.coff_string_bytes_read, payload_size);
	BOOST_CHECK_EQUAL(stats.coff_string_read_calls, 256);
	BOOST_CHECK_EQUAL(stats.coff_max_buffer_bytes, 4096);
	BOOST_CHECK_EQUAL(mana::detail::PEParserTestAccess::retained_coff_strings(*pe), 0);
	BOOST_CHECK_EQUAL(errors.str().find("COFF String Table"), std::string::npos);
}

BOOST_AUTO_TEST_CASE(coff_string_multiple_values_are_validated_without_retention)
{
	const auto bytes = make_coff_pe(1, 1, {'A', 0, 'B', 0});
	mana::detail::PEParserWorkStats stats;
	ErrorCapture errors;
	auto pe = parse_with_coff_limits(bytes, 1, 4, stats);
	BOOST_REQUIRE(pe && pe->is_valid());
	BOOST_CHECK_EQUAL(stats.coff_string_bytes_read, 4);
	BOOST_CHECK_EQUAL(mana::detail::PEParserTestAccess::retained_coff_strings(*pe), 0);
	BOOST_CHECK_EQUAL(errors.str().find("COFF String Table"), std::string::npos);
}

BOOST_AUTO_TEST_CASE(coff_string_below_byte_limit_scans_complete_payload)
{
	const auto bytes = make_coff_pe(1, 1, {'A', 'B', 0});
	mana::detail::PEParserWorkStats stats;
	ErrorCapture errors;
	auto pe = parse_with_coff_limits(bytes, 1, 4, stats);
	BOOST_REQUIRE(pe && pe->is_valid());
	BOOST_CHECK_EQUAL(stats.coff_string_bytes_read, 3);
	BOOST_CHECK_EQUAL(stats.coff_string_read_calls, 1);
	BOOST_CHECK_EQUAL(stats.coff_max_buffer_bytes, 3);
	BOOST_CHECK_EQUAL(mana::detail::PEParserTestAccess::retained_coff_strings(*pe), 0);
	BOOST_CHECK_EQUAL(errors.str().find("COFF String Table"), std::string::npos);
}

BOOST_AUTO_TEST_CASE(coff_string_exact_byte_limit_scans_complete_payload)
{
	const auto bytes = make_coff_pe(1, 1, {'A', 'B', 'C', 0});
	mana::detail::PEParserWorkStats stats;
	ErrorCapture errors;
	auto pe = parse_with_coff_limits(bytes, 1, 4, stats);
	BOOST_REQUIRE(pe && pe->is_valid());
	BOOST_CHECK_EQUAL(stats.coff_string_bytes_read, 4);
	BOOST_CHECK_EQUAL(stats.coff_string_read_calls, 1);
	BOOST_CHECK_EQUAL(stats.coff_max_buffer_bytes, 4);
	BOOST_CHECK_EQUAL(mana::detail::PEParserTestAccess::retained_coff_strings(*pe), 0);
	BOOST_CHECK_EQUAL(errors.str().find("COFF String Table"), std::string::npos);
}

BOOST_AUTO_TEST_CASE(coff_string_over_byte_limit_stops_before_scan_and_preserves_metadata)
{
	const auto bytes = make_coff_pe(1, 1, {'A', 'B', 'C', 'D', 0});
	const auto control_bytes = read_binary_file("testfiles/manatest.exe");
	auto control = mana::PE::create_from_bytes(
		control_bytes.data(), control_bytes.size(), "control-manatest.exe");
	BOOST_REQUIRE(control && control->is_valid());
	mana::detail::PEParserWorkStats stats;
	ErrorCapture warnings(utils::LogLevel::WARNING);
	auto pe = parse_with_coff_limits(bytes, 1, 4, stats);
	BOOST_REQUIRE(pe && pe->is_valid());
	BOOST_CHECK_EQUAL(stats.coff_string_bytes_read, 0);
	BOOST_CHECK_EQUAL(stats.coff_string_read_calls, 0);
	BOOST_CHECK_EQUAL(stats.coff_max_buffer_bytes, 0);
	BOOST_CHECK_EQUAL(mana::detail::PEParserTestAccess::retained_coff_strings(*pe), 0);
	BOOST_REQUIRE(pe->get_sections());
	BOOST_CHECK_EQUAL(pe->get_sections()->size(), control->get_sections()->size());
	BOOST_REQUIRE_EQUAL(pe->get_debug_info()->size(), control->get_debug_info()->size());
	BOOST_REQUIRE(!pe->get_debug_info()->empty());
	BOOST_CHECK_EQUAL(pe->get_debug_info()->front()->Filename,
		control->get_debug_info()->front()->Filename);
	const std::string diagnostic = "COFF string-table byte budget exhausted";
	const std::string output = warnings.str();
	const std::size_t first = output.find(diagnostic);
	BOOST_REQUIRE_NE(first, std::string::npos);
	BOOST_CHECK_EQUAL(output.find(diagnostic, first + diagnostic.size()), std::string::npos);
}

BOOST_AUTO_TEST_CASE(coff_string_empty_payload_requires_no_reads)
{
	const auto bytes = make_coff_pe(1, 1, {});
	mana::detail::PEParserWorkStats stats;
	ErrorCapture errors;
	auto pe = parse_with_coff_limits(bytes, 1, 0, stats);
	BOOST_REQUIRE(pe && pe->is_valid());
	BOOST_CHECK_EQUAL(stats.coff_string_bytes_read, 0);
	BOOST_CHECK_EQUAL(stats.coff_string_read_calls, 0);
	BOOST_CHECK_EQUAL(stats.coff_max_buffer_bytes, 0);
	BOOST_CHECK_EQUAL(mana::detail::PEParserTestAccess::retained_coff_strings(*pe), 0);
	BOOST_CHECK_EQUAL(errors.str().find("COFF String Table"), std::string::npos);
}

BOOST_AUTO_TEST_CASE(production_coff_string_byte_limit_is_stable)
{
	BOOST_CHECK_EQUAL(
		mana::detail::production_pe_parser_work_limits().coff_string_table_bytes,
		268435456);
}

BOOST_AUTO_TEST_CASE(cap_malformed_coff_symbol_diagnostics_without_stopping_scan)
{
	if (!is_cap_test_child()) {
		BOOST_CHECK_EQUAL(run_cap_test_child(), EXIT_SUCCESS);
		return;
	}

	const std::uint32_t symbol_count = LOG_CAP + 5;
	const std::size_t symbol_offset = read_binary_file("testfiles/manatest.exe").size();
	auto bytes = make_coff_pe(symbol_count, symbol_count, {});
	for (std::uint32_t i = 0; i < symbol_count; ++i) {
		write_u16(bytes, symbol_offset + static_cast<std::size_t>(i) * 18 + 12, 0xffff);
	}
	mana::detail::PEParserWorkStats stats;
	ErrorCapture warnings(utils::LogLevel::WARNING);
	auto pe = parse_with_coff_limits(bytes, symbol_count, 4, stats);
	BOOST_REQUIRE(pe && pe->is_valid());
	BOOST_CHECK_EQUAL(stats.coff_symbol_records_read, symbol_count);
	BOOST_CHECK_EQUAL(mana::detail::PEParserTestAccess::retained_coff_symbols(*pe), 0);

	const std::string diagnostic = "COFF symbol's section number";
	const std::string output = warnings.str();
	std::size_t count = 0;
	for (std::size_t position = output.find(diagnostic); position != std::string::npos;
		position = output.find(diagnostic, position + diagnostic.size())) {
		++count;
	}
	BOOST_CHECK_GT(count, 0);
	BOOST_CHECK_LT(count, symbol_count);
}

BOOST_AUTO_TEST_SUITE_END()
