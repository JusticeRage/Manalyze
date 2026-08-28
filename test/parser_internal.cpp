#include <cstdint>
#include <limits>
#include <optional>
#include <vector>

#include <boost/test/unit_test.hpp>

#include "manape/parser_internal.h"
#include "import_tls_fixtures.h"

namespace {

mana::detail::ImageView make_image(std::uint64_t file_size,
	std::uint64_t size_of_headers = 0)
{
	return {file_size, size_of_headers, 0, 0, 0x200, {}, {}};
}

void check_span(const std::optional<mana::detail::MappedSpan>& span,
	mana::detail::SpanBacking backing, std::uint64_t rva, std::uint64_t size,
	std::uint64_t file_offset, std::size_t region)
{
	BOOST_REQUIRE(span.has_value());
	BOOST_CHECK(span->backing == backing);
	BOOST_CHECK_EQUAL(span->rva, rva);
	BOOST_CHECK_EQUAL(span->size, size);
	BOOST_CHECK_EQUAL(span->file_offset, file_offset);
	BOOST_CHECK_EQUAL(span->region, region);
}

constexpr mana::detail::ImportLimits import_limits(std::uint64_t descriptors = 16,
	std::uint64_t functions = 128)
{
	return {descriptors, functions, 4096, 4096, 4096};
}

void put_descriptor(CompactImageBuilder& image, std::size_t offset,
	std::uint32_t original_first_thunk, std::uint32_t name,
	std::uint32_t first_thunk)
{
	image.put32(offset, original_first_thunk);
	image.put32(offset + 4, 0);
	image.put32(offset + 8, 0);
	image.put32(offset + 12, name);
	image.put32(offset + 16, first_thunk);
}

void put_delay_descriptor(CompactImageBuilder& image, std::size_t offset,
	std::uint32_t attributes, std::uint32_t name, std::uint32_t name_table)
{
	image.put32(offset, attributes);
	image.put32(offset + 4, name);
	image.put32(offset + 8, 0x11111111);
	image.put32(offset + 12, 0x22222222);
	image.put32(offset + 16, name_table);
	image.put32(offset + 20, 0x33333333);
	image.put32(offset + 24, 0x44444444);
	image.put32(offset + 28, 0x55555555);
}

CompactImageBuilder make_standard_delay_image(std::uint32_t attributes = 1,
	bool add_second_delay = false, bool share_sources = false)
{
	CompactImageBuilder image(0x500);
	image.headers(0xc0).image(0, 0x8000, 1);
	image.section({0x1000, 6, 0x100, 6});
	image.section({0x2000, 8, 0x200, 8});
	image.section({0x3000, 6, 0x300, 6});
	if (!share_sources) {
		image.section({0x1100, 6, 0x110, 6});
		image.section({0x2100, 12, 0x210, 12});
		image.section({0x3100, 6, 0x310, 6});
		image.section({0x3200, 6, 0x320, 6});
	}

	put_descriptor(image, 0x20, 0x2000, 0x1000, 0x2000);
	put_descriptor(image, 0x34, 0, 0, 0);
	const std::uint32_t delay_name = share_sources ? 0x1000 : 0x1100;
	const std::uint32_t delay_table = share_sources ? 0x2000 : 0x2100;
	put_delay_descriptor(image, 0x60, attributes, delay_name, delay_table);
	if (add_second_delay) {
		put_delay_descriptor(image, 0x80, attributes, delay_name, delay_table);
	}

	image.put_ascii(0x100, "A.dll");
	image.put32(0x200, 0x3000);
	image.put32(0x204, 0);
	image.put16(0x300, 1);
	image.put_ascii(0x302, "One");
	if (!share_sources) {
		image.put_ascii(0x110, "B.dll");
		image.put32(0x210, 0x3100);
		image.put32(0x214, 0x3200);
		image.put32(0x218, 0);
		image.put16(0x310, 2);
		image.put_ascii(0x312, "Two");
		image.put16(0x320, 3);
		image.put_ascii(0x322, "Tri");
	}
	return image;
}

mana::detail::ImportParseResult parse_standard_and_delay(
	const mana::detail::ImageView& image,
	const mana::detail::ImportLimits& limits,
	std::vector<mana::detail::ParserDiagnostic>& diagnostics,
	mana::detail::ImportMetrics* metrics = nullptr)
{
	return mana::detail::parse_imports(image, {0x20, 40}, {0x60, 64}, false,
		limits, [&](mana::detail::ParserDiagnostic diagnostic) {
			diagnostics.push_back(diagnostic);
		}, metrics);
}

mana::detail::ImportParseResult parse_standard_imports(
	const mana::detail::ImageView& image, std::uint32_t rva, std::uint32_t size,
	const mana::detail::ImportLimits& limits,
	std::vector<mana::detail::ParserDiagnostic>& diagnostics,
	mana::detail::ImportMetrics* metrics = nullptr)
{
	return mana::detail::parse_imports(image, {rva, size}, {0, 0}, false,
		limits, [&](mana::detail::ParserDiagnostic diagnostic) {
			diagnostics.push_back(diagnostic);
		}, metrics);
}

CompactImageBuilder make_named_import_image(const std::string& dll_name,
	bool terminate_dll, const std::optional<std::string>& function_name,
	bool terminate_function = true)
{
	CompactImageBuilder image(0x400);
	image.headers(0x80).image(0, 0x4000, 1);
	const std::uint64_t dll_extent = dll_name.size() + (terminate_dll ? 1 : 0);
	image.section({0x1000, dll_extent, 0x100, dll_extent});
	image.section({0x2000, 8, 0x180, 8});
	if (function_name) {
		const std::uint64_t function_extent = 2 + function_name->size() +
			(terminate_function ? 1 : 0);
		image.section({0x3000, function_extent, 0x200, function_extent});
		image.put16(0x200, 7);
		image.put_ascii(0x202, *function_name, terminate_function);
	}
	put_descriptor(image, 0x20, 0x2000, 0x1000, 0x2000);
	put_descriptor(image, 0x34, 0, 0, 0);
	image.put_ascii(0x100, dll_name, terminate_dll);
	image.put32(0x180, function_name ? 0x3000 : 0x80000001);
	image.put32(0x184, 0);
	return image;
}

CompactImageBuilder make_repeated_dll_image(std::uint32_t first_name,
	std::uint32_t second_name)
{
	CompactImageBuilder image(0x400);
	image.headers(0x80).image(0, 0x4000, 1);
	image.section({0x2000, 16, 0x180, 16});
	put_descriptor(image, 0x20, 0x2000, first_name, 0x2000);
	put_descriptor(image, 0x34, 0x2008, second_name, 0x2008);
	put_descriptor(image, 0x48, 0, 0, 0);
	image.put32(0x180, 0x80000001);
	image.put32(0x184, 0);
	image.put32(0x188, 0x80000002);
	image.put32(0x18c, 0);
	return image;
}

std::uint64_t ordinal_value(bool pe32_plus, std::uint16_t ordinal)
{
	return (pe32_plus ? 0x8000000000000000ULL : 0x80000000ULL) | ordinal;
}

CompactImageBuilder make_ordinal_thunk_image(bool pe32_plus,
	const std::vector<std::uint64_t>& values, bool terminate,
	std::size_t partial_tail = 0, std::size_t zero_fill_tail = 0,
	bool repeated_descriptor = false)
{
	const std::size_t slot_size = pe32_plus ? 8 : 4;
	const std::size_t initialized_size =
		(values.size() + (terminate ? 1 : 0)) * slot_size + partial_tail;
	CompactImageBuilder image(std::max<std::size_t>(0x400,
		0x200 + initialized_size));
	image.headers(0x80).image(0, 0x8000, 1);
	image.section({0x1000, 6, 0x100, 6});
	image.section({0x2000, initialized_size + zero_fill_tail,
		0x200, initialized_size});
	put_descriptor(image, 0x20, 0x2000, 0x1000, 0x2000);
	if (repeated_descriptor) {
		put_descriptor(image, 0x34, 0x2000, 0x1000, 0x2000);
		put_descriptor(image, 0x48, 0, 0, 0);
	} else {
		put_descriptor(image, 0x34, 0, 0, 0);
	}
	image.put_ascii(0x100, "A.dll");
	for (std::size_t i = 0; i < values.size(); ++i) {
		if (pe32_plus) image.put64(0x200 + i * slot_size, values[i]);
		else image.put32(0x200 + i * slot_size,
			static_cast<std::uint32_t>(values[i]));
	}
	return image;
}

mana::detail::ImportParseResult parse_standard_imports_for_architecture(
	const mana::detail::ImageView& image, bool pe32_plus,
	const mana::detail::ImportLimits& limits,
	std::vector<mana::detail::ParserDiagnostic>& diagnostics,
	mana::detail::ImportMetrics* metrics = nullptr)
{
	return mana::detail::parse_imports(image, {0x20, 0x3c}, {0, 0},
		pe32_plus, limits,
		[&](mana::detail::ParserDiagnostic diagnostic) {
			diagnostics.push_back(diagnostic);
		}, metrics);
}

CompactImageBuilder make_tls_image(bool pe32_plus,
	const std::vector<std::uint64_t>& callbacks, bool terminate,
	std::size_t partial_tail = 0, std::size_t zero_fill_tail = 0,
	std::optional<std::uint64_t> callback_va = std::nullopt)
{
	const std::size_t slot_size = pe32_plus ? 8 : 4;
	const std::size_t initialized_size = callbacks.size() * slot_size +
		(terminate ? slot_size : 0) + partial_tail;
	const std::uint64_t image_base = pe32_plus ? 0x140000000ULL : 0x400000ULL;
	CompactImageBuilder image(std::max<std::size_t>(0x200,
		0x100 + initialized_size));
	image.headers(0x80).image(image_base, 0x4000, 1);
	image.section({0x1000, initialized_size + zero_fill_tail,
		0x100, initialized_size});
	if (pe32_plus) {
		image.put64(0x20, 0x1111222233334444ULL);
		image.put64(0x28, 0x5555666677778888ULL);
		image.put64(0x30, 0x9999aaaabbbbccccULL);
		image.put64(0x38, callback_va.value_or(image_base + 0x1000));
		image.put32(0x40, 0x12345678);
		image.put32(0x44, 0x9abcdef0);
	} else {
		image.put32(0x20, 0x401111);
		image.put32(0x24, 0x402222);
		image.put32(0x28, 0x403333);
		image.put32(0x2c, static_cast<std::uint32_t>(
			callback_va.value_or(image_base + 0x1000)));
		image.put32(0x30, 0x12345678);
		image.put32(0x34, 0x9abcdef0);
	}
	for (std::size_t i = 0; i < callbacks.size(); ++i) {
		if (pe32_plus) image.put64(0x100 + i * slot_size, callbacks[i]);
		else image.put32(0x100 + i * slot_size,
			static_cast<std::uint32_t>(callbacks[i]));
	}
	return image;
}

mana::detail::TlsParseResult parse_tls_image(
	const mana::detail::ImageView& image, bool pe32_plus,
	std::uint32_t declared_size, mana::detail::WorkBudget& budget,
	std::vector<mana::detail::ParserDiagnostic>& diagnostics)
{
	return mana::detail::parse_tls(image, {0x20, declared_size}, pe32_plus,
		budget, [&](mana::detail::ParserDiagnostic diagnostic) {
			diagnostics.push_back(diagnostic);
		});
}

} // namespace

BOOST_AUTO_TEST_SUITE(parser_internal)

BOOST_AUTO_TEST_CASE(mapped_span_headers_stop_at_physical_eof)
{
	auto image = make_image(0x180, 0x200);

	check_span(mana::detail::resolve_mapped_span(image, 0x20),
		mana::detail::SpanBacking::initialized, 0x20, 0x160, 0x20, 0);
	check_span(mana::detail::resolve_mapped_span(image, 0x17f),
		mana::detail::SpanBacking::initialized, 0x17f, 1, 0x17f, 0);
	BOOST_CHECK(!mana::detail::resolve_mapped_span(image, 0x180));
	BOOST_CHECK(!mana::detail::resolve_mapped_span(image, 0x200));
}

BOOST_AUTO_TEST_CASE(mapped_span_section_separates_initialized_and_zero_fill)
{
	auto image = make_image(0x1000);
	image.sections = {{0x1000, 0x300, 0x400, 0x200}};

	check_span(mana::detail::resolve_mapped_span(image, 0x1080),
		mana::detail::SpanBacking::initialized, 0x1080, 0x180, 0x480, 1);
	check_span(mana::detail::resolve_mapped_span(image, 0x1200),
		mana::detail::SpanBacking::zero_fill, 0x1200, 0x100, 0, 1);
	check_span(mana::detail::resolve_mapped_span(image, 0x12ff),
		mana::detail::SpanBacking::zero_fill, 0x12ff, 1, 0, 1);
	BOOST_CHECK(!mana::detail::resolve_mapped_span(image, 0x1300));
}

BOOST_AUTO_TEST_CASE(mapped_span_first_virtual_section_wins_overlap)
{
	auto image = make_image(0x1000);
	image.sections = {
		{0x1000, 0x300, 0x400, 0x100},
		{0x1080, 0x300, 0x800, 0x300},
	};

	check_span(mana::detail::resolve_mapped_span(image, 0x1100),
		mana::detail::SpanBacking::zero_fill, 0x1100, 0x200, 0, 1);
}

BOOST_AUTO_TEST_CASE(mapped_span_raw_size_fallback_uses_first_table_entry)
{
	auto image = make_image(0x1000);
	image.sections = {
		{0x1000, 0x10, 0x400, 0x200},
		{0x1040, 0x10, 0x800, 0x200},
	};

	check_span(mana::detail::resolve_mapped_span(image, 0x1080),
		mana::detail::SpanBacking::initialized, 0x1080, 0x180, 0x480, 1);
	BOOST_CHECK(!mana::detail::resolve_mapped_span(image, 0x1240));
}

BOOST_AUTO_TEST_CASE(mapped_span_aligns_raw_pointer_like_public_mapping)
{
	auto image = make_image(0x1000);
	image.sections = {{0x1000, 0x300, 0x450, 0x200}};

	check_span(mana::detail::resolve_mapped_span(image, 0x1080),
		mana::detail::SpanBacking::initialized, 0x1080, 0x180, 0x480, 1);
}

BOOST_AUTO_TEST_CASE(mapped_span_truncated_raw_extent_transitions_at_eof)
{
	auto image = make_image(0x500);
	image.sections = {{0x1000, 0x300, 0x400, 0x200}};

	check_span(mana::detail::resolve_mapped_span(image, 0x1080),
		mana::detail::SpanBacking::initialized, 0x1080, 0x80, 0x480, 1);
	check_span(mana::detail::resolve_mapped_span(image, 0x1100),
		mana::detail::SpanBacking::zero_fill, 0x1100, 0x200, 0, 1);
	BOOST_CHECK(!mana::detail::resolve_mapped_span(image, 0x1300));
}

BOOST_AUTO_TEST_CASE(mapped_span_rejects_zero_alignment_and_wrapped_ranges)
{
	auto image = make_image(0x1000, 0x200);
	image.file_alignment = 0;
	image.sections = {{0x1000, 0x100, 0x400, 0x100}};
	BOOST_CHECK(!mana::detail::resolve_mapped_span(image, 0x20));
	BOOST_CHECK(!mana::detail::resolve_mapped_span(image, 0x1000));

	const auto max = std::numeric_limits<std::uint64_t>::max();
	auto near_limit = make_image(max);
	near_limit.file_alignment = 0x10;
	near_limit.sections = {{max - 0x10, 0x20, max - 8, 0x20}};
	BOOST_CHECK(!mana::detail::resolve_mapped_span(near_limit, 8));

	near_limit.sections = {{max - 0x10, 0x10, max - 8, 0x10}};
	check_span(mana::detail::resolve_mapped_span(near_limit, max - 8),
		mana::detail::SpanBacking::initialized, max - 8, 7, max - 7, 1);
	check_span(mana::detail::resolve_mapped_span(near_limit, max - 1),
		mana::detail::SpanBacking::zero_fill, max - 1, 1, 0, 1);
	BOOST_CHECK(!mana::detail::resolve_mapped_span(near_limit, max));
}

BOOST_AUTO_TEST_CASE(import_descriptor_uses_exact_oft_ft_terminator)
{
	CompactImageBuilder image(0x200);
	image.headers(0x200);
	put_descriptor(image, 0x40, 0x100, 0x120, 0x140);
	image.put32(0x40 + 24, 1);
	image.put32(0x40 + 28, 2);
	image.put32(0x40 + 32, 3);
	std::vector<mana::detail::ParserDiagnostic> diagnostics;

	const auto result = parse_standard_imports(image.view(), 0x40, 40,
		import_limits(), diagnostics);

	BOOST_REQUIRE_EQUAL(result.libraries.size(), 1);
	BOOST_REQUIRE(result.libraries[0].descriptor.has_value());
	BOOST_CHECK_EQUAL(result.libraries[0].descriptor->OriginalFirstThunk, 0x100);
	BOOST_CHECK(diagnostics.empty());
}

BOOST_AUTO_TEST_CASE(import_descriptor_stops_at_declared_extent)
{
	CompactImageBuilder image(0x200);
	image.headers(0x200);
	put_descriptor(image, 0x40, 0x100, 0x120, 0x140);
	put_descriptor(image, 0x54, 0x150, 0x160, 0x170);
	std::vector<mana::detail::ParserDiagnostic> diagnostics;

	const auto result = parse_standard_imports(image.view(), 0x40, 20,
		import_limits(), diagnostics);

	BOOST_CHECK_EQUAL(result.libraries.size(), 1);
	BOOST_REQUIRE_EQUAL(diagnostics.size(), 1);
	BOOST_CHECK(diagnostics[0] ==
		mana::detail::ParserDiagnostic::import_descriptor_unterminated);
}

BOOST_AUTO_TEST_CASE(import_descriptor_rejects_too_small_declared_extent)
{
	for (const std::uint32_t size : {1U, 19U}) {
		CompactImageBuilder image(0x100);
		image.headers(0x100);
		put_descriptor(image, 0x40, 1, 2, 3);
		std::size_t reads = 0;
		auto view = image.view();
		const auto read_at = view.read_at;
		view.read_at = [&](std::uint64_t offset, void* destination,
			std::size_t count) {
			++reads;
			return read_at(offset, destination, count);
		};
		std::vector<mana::detail::ParserDiagnostic> diagnostics;

		const auto result = parse_standard_imports(view, 0x40, size,
			import_limits(), diagnostics);

		BOOST_CHECK(result.libraries.empty());
		BOOST_CHECK_EQUAL(reads, 0);
		BOOST_REQUIRE_EQUAL(diagnostics.size(), 1);
		BOOST_CHECK(diagnostics[0] ==
			mana::detail::ParserDiagnostic::import_extent_too_small);
	}
}

BOOST_AUTO_TEST_CASE(import_descriptor_ignores_partial_declared_tail)
{
	CompactImageBuilder image(0x100);
	image.headers(0x100);
	put_descriptor(image, 0x40, 1, 2, 3);
	std::size_t descriptor_reads = 0;
	auto view = image.view();
	const auto read_at = view.read_at;
	view.read_at = [&](std::uint64_t offset, void* destination,
		std::size_t count) {
		if (count == 20) ++descriptor_reads;
		return read_at(offset, destination, count);
	};
	std::vector<mana::detail::ParserDiagnostic> diagnostics;

	const auto result = parse_standard_imports(view, 0x40, 39,
		import_limits(), diagnostics);

	BOOST_CHECK_EQUAL(result.libraries.size(), 1);
	BOOST_CHECK_EQUAL(descriptor_reads, 1);
	BOOST_REQUIRE_EQUAL(diagnostics.size(), 1);
	BOOST_CHECK(diagnostics[0] ==
		mana::detail::ParserDiagnostic::import_descriptor_unterminated);
}

BOOST_AUTO_TEST_CASE(import_descriptor_zero_size_stops_at_header_extent)
{
	CompactImageBuilder image(0x140);
	image.headers(0x100);
	put_descriptor(image, 0xec, 1, 2, 3);
	put_descriptor(image, 0x100, 4, 5, 6);
	std::vector<mana::detail::ParserDiagnostic> diagnostics;

	const auto result = parse_standard_imports(image.view(), 0xec, 0,
		import_limits(), diagnostics);

	BOOST_CHECK_EQUAL(result.libraries.size(), 1);
	BOOST_REQUIRE_EQUAL(diagnostics.size(), 1);
	BOOST_CHECK(diagnostics[0] ==
		mana::detail::ParserDiagnostic::import_descriptor_unterminated);
}

BOOST_AUTO_TEST_CASE(import_descriptor_zero_size_stops_at_section_extent)
{
	CompactImageBuilder image(0x300);
	image.image(0, 0x2000, 0x100);
	image.section({0x1000, 0x100, 0x100, 0x100});
	put_descriptor(image, 0x1ec, 0x1000, 2, 0x1000);
	put_descriptor(image, 0x200, 4, 5, 6);
	std::vector<mana::detail::ParserDiagnostic> diagnostics;

	const auto result = parse_standard_imports(image.view(), 0x10ec, 0,
		import_limits(), diagnostics);

	BOOST_CHECK_EQUAL(result.libraries.size(), 1);
	BOOST_REQUIRE_EQUAL(diagnostics.size(), 1);
	BOOST_CHECK(diagnostics[0] ==
		mana::detail::ParserDiagnostic::import_descriptor_unterminated);
}

BOOST_AUTO_TEST_CASE(import_descriptor_budget_preserves_completed_output)
{
	CompactImageBuilder image(0x200);
	image.headers(0x200);
	put_descriptor(image, 0x40, 1, 2, 3);
	put_descriptor(image, 0x54, 4, 5, 6);
	std::size_t descriptor_reads = 0;
	auto view = image.view();
	const auto read_at = view.read_at;
	view.read_at = [&](std::uint64_t offset, void* destination,
		std::size_t count) {
		if (count == 20) ++descriptor_reads;
		return read_at(offset, destination, count);
	};
	std::vector<mana::detail::ParserDiagnostic> diagnostics;
	mana::detail::ImportMetrics metrics;

	const auto result = parse_standard_imports(view, 0x40, 60,
		import_limits(1), diagnostics, &metrics);

	BOOST_CHECK(result.exhausted);
	BOOST_REQUIRE_EQUAL(result.libraries.size(), 1);
	BOOST_REQUIRE(result.libraries[0].descriptor.has_value());
	BOOST_CHECK_EQUAL(result.libraries[0].descriptor->OriginalFirstThunk, 1);
	BOOST_CHECK(!result.libraries[0].name_materialized);
	BOOST_CHECK_EQUAL(descriptor_reads, 2);
	BOOST_CHECK_EQUAL(metrics.string_read_calls, 0);
	BOOST_REQUIRE_EQUAL(diagnostics.size(), 1);
	BOOST_CHECK(diagnostics[0] ==
		mana::detail::ParserDiagnostic::import_budget_exhausted);
}

BOOST_AUTO_TEST_CASE(import_descriptor_terminator_is_read_but_not_charged)
{
	CompactImageBuilder image(0x100);
	image.headers(0x100);
	put_descriptor(image, 0x40, 1, 2, 3);
	std::size_t descriptor_reads = 0;
	auto view = image.view();
	const auto read_at = view.read_at;
	view.read_at = [&](std::uint64_t offset, void* destination,
		std::size_t count) {
		if (count == 20) ++descriptor_reads;
		return read_at(offset, destination, count);
	};
	std::vector<mana::detail::ParserDiagnostic> diagnostics;

	const auto result = parse_standard_imports(view, 0x40, 40,
		import_limits(1), diagnostics);

	BOOST_CHECK(!result.exhausted);
	BOOST_CHECK_EQUAL(result.libraries.size(), 1);
	BOOST_CHECK_EQUAL(descriptor_reads, 2);
	BOOST_CHECK(diagnostics.empty());
}

BOOST_AUTO_TEST_CASE(import_string_accepts_nul_at_mapped_boundaries)
{
	auto image = make_named_import_image("BOUND.dll", true, "ExactFunction");
	std::vector<mana::detail::ParserDiagnostic> diagnostics;
	mana::detail::ImportMetrics metrics;

	const auto result = parse_standard_imports(image.view(), 0x20, 40,
		import_limits(), diagnostics, &metrics);

	BOOST_REQUIRE_EQUAL(result.libraries.size(), 1);
	BOOST_CHECK_EQUAL(result.libraries[0].name, "BOUND.dll");
	BOOST_REQUIRE_EQUAL(result.libraries[0].functions.size(), 1);
	BOOST_CHECK_EQUAL(result.libraries[0].functions[0].Hint, 7);
	BOOST_CHECK_EQUAL(result.libraries[0].functions[0].Name, "ExactFunction");
	BOOST_CHECK(!result.exhausted);
}

BOOST_AUTO_TEST_CASE(import_string_rejects_dll_nul_beyond_mapped_extent)
{
	auto image = make_named_import_image("BAD", false, std::nullopt);
	image.put_ascii(0x103, "", true);
	std::vector<mana::detail::ParserDiagnostic> diagnostics;
	mana::detail::ImportMetrics metrics;

	const auto result = parse_standard_imports(image.view(), 0x20, 40,
		import_limits(), diagnostics, &metrics);

	BOOST_CHECK(result.libraries.empty());
	BOOST_CHECK_EQUAL(metrics.string_read_calls, 1);
	BOOST_CHECK_EQUAL(metrics.string_bytes_read, 3);
}

BOOST_AUTO_TEST_CASE(import_string_rejects_function_nul_beyond_mapped_extent)
{
	auto image = make_named_import_image("OK.dll", true, "BAD", false);
	image.put_ascii(0x205, "", true);
	std::vector<mana::detail::ParserDiagnostic> diagnostics;

	const auto result = parse_standard_imports(image.view(), 0x20, 40,
		import_limits(), diagnostics);

	BOOST_REQUIRE_EQUAL(result.libraries.size(), 1);
	BOOST_CHECK_EQUAL(result.libraries[0].name, "OK.dll");
	BOOST_CHECK(result.libraries[0].functions.empty());
}

BOOST_AUTO_TEST_CASE(import_string_direct_fallback_is_dll_only)
{
	CompactImageBuilder direct_dll(0x300);
	direct_dll.headers(0x80).image(0, 0x4000, 1);
	direct_dll.section({0x2000, 8, 0x180, 8});
	put_descriptor(direct_dll, 0x20, 0x2000, 0x250, 0x2000);
	put_descriptor(direct_dll, 0x34, 0, 0, 0);
	direct_dll.put32(0x180, 0x80000001);
	direct_dll.put32(0x184, 0);
	direct_dll.put_ascii(0x250, "RAW.dll");
	std::vector<mana::detail::ParserDiagnostic> diagnostics;
	mana::detail::ImportMetrics metrics;
	const auto direct_result = parse_standard_imports(direct_dll.view(),
		0x20, 40, import_limits(), diagnostics, &metrics);
	BOOST_REQUIRE_EQUAL(direct_result.libraries.size(), 1);
	BOOST_CHECK_EQUAL(direct_result.libraries[0].name, "RAW.dll");
	BOOST_CHECK_EQUAL(metrics.string_bytes_read, 0xb0);

	CompactImageBuilder direct_thunk(0x300);
	direct_thunk.headers(0x80).image(0, 0x4000, 1);
	direct_thunk.section({0x1000, 7, 0x100, 7});
	put_descriptor(direct_thunk, 0x20, 0x250, 0x1000, 0x250);
	put_descriptor(direct_thunk, 0x34, 0, 0, 0);
	direct_thunk.put_ascii(0x100, "OK.dll");
	direct_thunk.put32(0x250, 0);
	std::size_t direct_thunk_reads = 0;
	auto thunk_view = direct_thunk.view();
	const auto thunk_read_at = thunk_view.read_at;
	thunk_view.read_at = [&](std::uint64_t offset, void* destination,
		std::size_t count) {
		if (offset == 0x250) ++direct_thunk_reads;
		return thunk_read_at(offset, destination, count);
	};
	diagnostics.clear();
	const auto thunk_result = parse_standard_imports(thunk_view, 0x20, 40,
		import_limits(), diagnostics);
	BOOST_REQUIRE_EQUAL(thunk_result.libraries.size(), 1);
	BOOST_CHECK(thunk_result.libraries[0].functions.empty());
	BOOST_CHECK_EQUAL(direct_thunk_reads, 0);

	CompactImageBuilder direct_hint(0x300);
	direct_hint.headers(0x80).image(0, 0x4000, 1);
	direct_hint.section({0x1000, 7, 0x100, 7});
	direct_hint.section({0x2000, 8, 0x180, 8});
	put_descriptor(direct_hint, 0x20, 0x2000, 0x1000, 0x2000);
	put_descriptor(direct_hint, 0x34, 0, 0, 0);
	direct_hint.put_ascii(0x100, "OK.dll");
	direct_hint.put32(0x180, 0x250);
	direct_hint.put32(0x184, 0);
	direct_hint.put16(0x250, 3);
	direct_hint.put_ascii(0x252, "DirectFunction");
	std::size_t direct_hint_reads = 0;
	auto hint_view = direct_hint.view();
	const auto hint_read_at = hint_view.read_at;
	hint_view.read_at = [&](std::uint64_t offset, void* destination,
		std::size_t count) {
		if (offset == 0x250) ++direct_hint_reads;
		return hint_read_at(offset, destination, count);
	};
	diagnostics.clear();
	const auto hint_result = parse_standard_imports(hint_view, 0x20, 40,
		import_limits(), diagnostics);
	BOOST_REQUIRE_EQUAL(hint_result.libraries.size(), 1);
	BOOST_CHECK(hint_result.libraries[0].functions.empty());
	BOOST_CHECK_EQUAL(direct_hint_reads, 0);
}

BOOST_AUTO_TEST_CASE(import_string_mapped_source_wins_over_direct_fallback)
{
	CompactImageBuilder image(0x400);
	image.headers(0x80).image(0, 0x4000, 1);
	image.section({0x300, 3, 0x100, 3});
	image.section({0x2000, 8, 0x180, 8});
	put_descriptor(image, 0x20, 0x2000, 0x300, 0x2000);
	put_descriptor(image, 0x34, 0, 0, 0);
	image.put_ascii(0x100, "BAD", false);
	image.put32(0x180, 0x80000001);
	image.put32(0x184, 0);
	image.put_ascii(0x300, "DIRECT.dll");
	std::vector<mana::detail::ParserDiagnostic> diagnostics;
	mana::detail::ImportMetrics metrics;

	const auto result = parse_standard_imports(image.view(), 0x20, 40,
		import_limits(), diagnostics, &metrics);

	BOOST_CHECK(result.libraries.empty());
	BOOST_CHECK_EQUAL(metrics.string_read_calls, 1);
	BOOST_CHECK_EQUAL(metrics.string_bytes_read, 3);
}

BOOST_AUTO_TEST_CASE(import_name_budget_charges_complete_4096_byte_chunks)
{
	CompactImageBuilder image(0x2100);
	image.headers(0x2100).image(0, 0x4000, 1);
	put_descriptor(image, 0x20, 0x80, 0x100, 0x80);
	put_descriptor(image, 0x34, 0, 0, 0);
	image.put32(0x80, 0x1100);
	image.put32(0x84, 0);
	image.put_ascii(0x100, "D");
	image.put16(0x1100, 4);
	image.put_ascii(0x1102, "Function");

	for (const std::uint64_t physical_limit : {4095ULL, 4096ULL, 8192ULL}) {
		auto limits = import_limits();
		limits.physical_string_bytes = physical_limit;
		std::vector<mana::detail::ParserDiagnostic> diagnostics;
		mana::detail::ImportMetrics metrics;
		const auto result = parse_standard_imports(image.view(), 0x20, 40,
			limits, diagnostics, &metrics);

		BOOST_CHECK(result.exhausted == (physical_limit != 8192));
		BOOST_CHECK_EQUAL(result.libraries.size(), physical_limit < 4096 ? 0 : 1);
		if (!result.libraries.empty()) {
			BOOST_CHECK_EQUAL(result.libraries[0].functions.size(),
				physical_limit == 8192 ? 1 : 0);
		}
		BOOST_CHECK_EQUAL(metrics.string_read_calls, physical_limit / 4096);
		BOOST_CHECK_EQUAL(metrics.string_bytes_read,
			(physical_limit / 4096) * 4096);
	}
}

BOOST_AUTO_TEST_CASE(import_name_budget_dll_materialization_boundaries)
{
	for (const std::uint64_t logical_limit : {4ULL, 5ULL, 6ULL}) {
		auto image = make_named_import_image("A.dll", true, std::nullopt);
		auto limits = import_limits();
		limits.materialized_dll_name_bytes = logical_limit;
		std::vector<mana::detail::ParserDiagnostic> diagnostics;
		const auto result = parse_standard_imports(image.view(), 0x20, 40,
			limits, diagnostics);

		BOOST_CHECK_EQUAL(result.libraries.size(), logical_limit < 5 ? 0 : 1);
		BOOST_CHECK(result.exhausted == (logical_limit < 5));
	}
}

BOOST_AUTO_TEST_CASE(import_name_budget_function_materialization_boundaries)
{
	for (const std::uint64_t logical_limit : {3ULL, 4ULL, 5ULL}) {
		auto image = make_named_import_image("A.dll", true, "Func");
		auto limits = import_limits();
		limits.materialized_function_name_bytes = logical_limit;
		std::vector<mana::detail::ParserDiagnostic> diagnostics;
		const auto result = parse_standard_imports(image.view(), 0x20, 40,
			limits, diagnostics);

		BOOST_REQUIRE_EQUAL(result.libraries.size(), 1);
		BOOST_CHECK_EQUAL(result.libraries[0].functions.size(),
			logical_limit < 4 ? 0 : 1);
		BOOST_CHECK(result.exhausted == (logical_limit < 4));
	}
}

BOOST_AUTO_TEST_CASE(import_name_budget_failed_function_use_is_not_cached)
{
	auto image = make_named_import_image("A.dll", true, "Func");
	auto limits = import_limits();
	limits.physical_string_bytes = 13;
	limits.materialized_function_name_bytes = 3;
	std::vector<mana::detail::ParserDiagnostic> diagnostics;
	mana::detail::ImportMetrics metrics;

	const auto result = parse_standard_imports(image.view(), 0x20, 40,
		limits, diagnostics, &metrics);

	BOOST_CHECK(result.exhausted);
	BOOST_REQUIRE_EQUAL(result.libraries.size(), 1);
	BOOST_CHECK(result.libraries[0].functions.empty());
	BOOST_CHECK_EQUAL(metrics.string_read_calls, 2);
	BOOST_CHECK_EQUAL(metrics.string_bytes_read, 13);
	BOOST_CHECK_EQUAL(metrics.string_cache_hits, 0);
	BOOST_CHECK_EQUAL(metrics.function_name_cache_entries, 0);
}

BOOST_AUTO_TEST_CASE(import_name_budget_existing_function_cache_survives_failure)
{
	auto image = make_repeated_dll_image(0x1000, 0x1000);
	image.section({0x1000, 6, 0x100, 6});
	image.section({0x3000, 7, 0x200, 7});
	image.put_ascii(0x100, "A.dll");
	image.put32(0x180, 0x3000);
	image.put32(0x188, 0x3000);
	image.put16(0x200, 9);
	image.put_ascii(0x202, "Func");
	auto limits = import_limits();
	limits.physical_string_bytes = 13;
	limits.materialized_dll_name_bytes = 10;
	limits.materialized_function_name_bytes = 4;
	std::vector<mana::detail::ParserDiagnostic> diagnostics;
	mana::detail::ImportMetrics metrics;

	const auto result = parse_standard_imports(image.view(), 0x20, 60,
		limits, diagnostics, &metrics);

	BOOST_CHECK(result.exhausted);
	BOOST_REQUIRE_EQUAL(result.libraries.size(), 2);
	BOOST_REQUIRE_EQUAL(result.libraries[0].functions.size(), 1);
	BOOST_CHECK(result.libraries[1].functions.empty());
	BOOST_CHECK_EQUAL(metrics.string_read_calls, 2);
	BOOST_CHECK_EQUAL(metrics.string_bytes_read, 13);
	BOOST_CHECK_EQUAL(metrics.string_cache_hits, 2);
	BOOST_CHECK_EQUAL(metrics.function_name_cache_entries, 1);
}

BOOST_AUTO_TEST_CASE(import_string_failed_decode_is_charged_and_not_retried)
{
	CompactImageBuilder image(0x400);
	image.headers(0x80).image(0, 0x4000, 1);
	image.section({0x300, 3, 0x100, 3});
	image.section({0x2000, 32, 0x180, 32});
	put_descriptor(image, 0x20, 1, 0x300, 1);
	put_descriptor(image, 0x34, 0, 0, 0);
	image.put_ascii(0x100, "BAD", false);
	image.put32(0x184, 0x300);
	auto limits = import_limits();
	limits.physical_string_bytes = 3;
	std::vector<mana::detail::ParserDiagnostic> diagnostics;
	mana::detail::ImportMetrics metrics;

	const auto result = mana::detail::parse_imports(image.view(), {0x20, 40},
		{0x2000, 32}, false, limits,
		[&](mana::detail::ParserDiagnostic diagnostic) {
			diagnostics.push_back(diagnostic);
		}, &metrics);

	BOOST_CHECK(result.exhausted);
	BOOST_CHECK(result.libraries.empty());
	BOOST_CHECK_EQUAL(metrics.string_read_calls, 1);
	BOOST_CHECK_EQUAL(metrics.string_bytes_read, 3);
	BOOST_CHECK_EQUAL(metrics.string_cache_hits, 0);
}

BOOST_AUTO_TEST_CASE(import_string_cache_hit_avoids_physical_recharge)
{
	auto image = make_repeated_dll_image(0x1000, 0x1000);
	image.section({0x1000, 6, 0x100, 6});
	image.put_ascii(0x100, "A.dll");
	auto limits = import_limits();
	limits.physical_string_bytes = 6;
	limits.materialized_dll_name_bytes = 10;
	std::vector<mana::detail::ParserDiagnostic> diagnostics;
	mana::detail::ImportMetrics metrics;

	const auto result = parse_standard_imports(image.view(), 0x20, 60,
		limits, diagnostics, &metrics);

	BOOST_REQUIRE_EQUAL(result.libraries.size(), 2);
	BOOST_CHECK_EQUAL(result.libraries[0].name, "A.dll");
	BOOST_CHECK_EQUAL(result.libraries[1].name, "A.dll");
	BOOST_CHECK_EQUAL(metrics.string_read_calls, 1);
	BOOST_CHECK_EQUAL(metrics.string_bytes_read, 6);
	BOOST_CHECK_EQUAL(metrics.string_cache_hits, 1);
}

BOOST_AUTO_TEST_CASE(import_string_function_cache_hit_avoids_physical_recharge)
{
	auto image = make_repeated_dll_image(0x1000, 0x1000);
	image.section({0x1000, 6, 0x100, 6});
	image.section({0x3000, 7, 0x200, 7});
	image.put_ascii(0x100, "A.dll");
	image.put32(0x180, 0x3000);
	image.put32(0x188, 0x3000);
	image.put16(0x200, 9);
	image.put_ascii(0x202, "Func");
	auto limits = import_limits();
	limits.physical_string_bytes = 13;
	limits.materialized_dll_name_bytes = 10;
	limits.materialized_function_name_bytes = 8;
	std::vector<mana::detail::ParserDiagnostic> diagnostics;
	mana::detail::ImportMetrics metrics;

	const auto result = parse_standard_imports(image.view(), 0x20, 60,
		limits, diagnostics, &metrics);

	BOOST_REQUIRE_EQUAL(result.libraries.size(), 2);
	BOOST_REQUIRE_EQUAL(result.libraries[0].functions.size(), 1);
	BOOST_REQUIRE_EQUAL(result.libraries[1].functions.size(), 1);
	BOOST_CHECK_EQUAL(result.libraries[1].functions[0].Name, "Func");
	BOOST_CHECK_EQUAL(metrics.string_read_calls, 2);
	BOOST_CHECK_EQUAL(metrics.string_bytes_read, 13);
	BOOST_CHECK_EQUAL(metrics.string_cache_hits, 2);
}

BOOST_AUTO_TEST_CASE(import_string_cache_key_includes_mapped_extent)
{
	auto image = make_repeated_dll_image(0x1000, 0x1100);
	image.section({0x1000, 2, 0x100, 2});
	image.section({0x1100, 3, 0x100, 3});
	image.put_ascii(0x100, "A");
	auto limits = import_limits();
	limits.physical_string_bytes = 5;
	limits.materialized_dll_name_bytes = 2;
	std::vector<mana::detail::ParserDiagnostic> diagnostics;
	mana::detail::ImportMetrics metrics;

	const auto result = parse_standard_imports(image.view(), 0x20, 60,
		limits, diagnostics, &metrics);

	BOOST_REQUIRE_EQUAL(result.libraries.size(), 2);
	BOOST_CHECK_EQUAL(metrics.string_read_calls, 2);
	BOOST_CHECK_EQUAL(metrics.string_bytes_read, 5);
	BOOST_CHECK_EQUAL(metrics.string_cache_hits, 0);
}

BOOST_AUTO_TEST_CASE(import_string_cache_key_includes_source_kind)
{
	auto image = make_repeated_dll_image(0x1000, 0x300);
	image.section({0x1000, 0x100, 0x300, 0x100});
	image.put_ascii(0x300, "A");
	auto limits = import_limits();
	limits.physical_string_bytes = 0x200;
	limits.materialized_dll_name_bytes = 2;
	std::vector<mana::detail::ParserDiagnostic> diagnostics;
	mana::detail::ImportMetrics metrics;

	const auto result = parse_standard_imports(image.view(), 0x20, 60,
		limits, diagnostics, &metrics);

	BOOST_REQUIRE_EQUAL(result.libraries.size(), 2);
	BOOST_CHECK_EQUAL(metrics.string_read_calls, 2);
	BOOST_CHECK_EQUAL(metrics.string_bytes_read, 0x200);
	BOOST_CHECK_EQUAL(metrics.string_cache_hits, 0);
}

BOOST_AUTO_TEST_CASE(import_name_budget_failed_new_logical_use_is_not_a_hit)
{
	auto image = make_repeated_dll_image(0x1000, 0x1100);
	image.section({0x1000, 2, 0x100, 2});
	image.section({0x1100, 4, 0x110, 4});
	image.put_ascii(0x100, "A");
	image.put_ascii(0x110, "BBB");
	auto limits = import_limits();
	limits.physical_string_bytes = 6;
	limits.materialized_dll_name_bytes = 1;
	std::vector<mana::detail::ParserDiagnostic> diagnostics;
	mana::detail::ImportMetrics metrics;

	const auto result = parse_standard_imports(image.view(), 0x20, 60,
		limits, diagnostics, &metrics);

	BOOST_CHECK(result.exhausted);
	BOOST_REQUIRE_EQUAL(result.libraries.size(), 1);
	BOOST_CHECK_EQUAL(metrics.string_read_calls, 2);
	BOOST_CHECK_EQUAL(metrics.string_bytes_read, 6);
	BOOST_CHECK_EQUAL(metrics.string_cache_hits, 0);
}

BOOST_AUTO_TEST_CASE(import_name_budget_existing_cache_survives_logical_failure)
{
	auto image = make_repeated_dll_image(0x1000, 0x1000);
	image.section({0x1000, 2, 0x100, 2});
	image.put_ascii(0x100, "A");
	auto limits = import_limits();
	limits.physical_string_bytes = 2;
	limits.materialized_dll_name_bytes = 1;
	std::vector<mana::detail::ParserDiagnostic> diagnostics;
	mana::detail::ImportMetrics metrics;

	const auto result = parse_standard_imports(image.view(), 0x20, 60,
		limits, diagnostics, &metrics);

	BOOST_CHECK(result.exhausted);
	BOOST_REQUIRE_EQUAL(result.libraries.size(), 1);
	BOOST_CHECK_EQUAL(metrics.string_read_calls, 1);
	BOOST_CHECK_EQUAL(metrics.string_bytes_read, 2);
	BOOST_CHECK_EQUAL(metrics.string_cache_hits, 1);
}

BOOST_AUTO_TEST_CASE(import_thunk_exact_initialized_boundary_accepts_terminator)
{
	for (const bool pe32_plus : {false, true}) {
		BOOST_TEST_CONTEXT("slot width " << (pe32_plus ? 8 : 4)) {
			auto image = make_ordinal_thunk_image(pe32_plus,
				{ordinal_value(pe32_plus, 1)}, true);
			std::vector<mana::detail::ParserDiagnostic> diagnostics;
			mana::detail::ImportMetrics metrics;

			const auto result = parse_standard_imports_for_architecture(
				image.view(), pe32_plus, import_limits(), diagnostics, &metrics);

			BOOST_REQUIRE_EQUAL(result.libraries.size(), 1);
			BOOST_REQUIRE_EQUAL(result.libraries[0].functions.size(), 1);
			BOOST_CHECK_EQUAL(result.libraries[0].functions[0].AddressOfData,
				ordinal_value(pe32_plus, 1));
			BOOST_CHECK_EQUAL(metrics.thunk_slot_reads, 2);
			BOOST_CHECK(diagnostics.empty());
		}
	}
}

BOOST_AUTO_TEST_CASE(import_thunk_unterminated_complete_slot_preserves_function)
{
	for (const bool pe32_plus : {false, true}) {
		auto image = make_ordinal_thunk_image(pe32_plus,
			{ordinal_value(pe32_plus, 2)}, false);
		std::vector<mana::detail::ParserDiagnostic> diagnostics;
		mana::detail::ImportMetrics metrics;

		const auto result = parse_standard_imports_for_architecture(image.view(),
			pe32_plus, import_limits(), diagnostics, &metrics);

		BOOST_REQUIRE_EQUAL(result.libraries.size(), 1);
		BOOST_CHECK_EQUAL(result.libraries[0].functions.size(), 1);
		BOOST_CHECK_EQUAL(metrics.thunk_slot_reads, 1);
		BOOST_REQUIRE_EQUAL(diagnostics.size(), 1);
		BOOST_CHECK(diagnostics[0] ==
			mana::detail::ParserDiagnostic::import_malformed);
	}
}

BOOST_AUTO_TEST_CASE(import_thunk_partial_final_slot_is_not_read)
{
	for (const bool pe32_plus : {false, true}) {
		const std::size_t slot_size = pe32_plus ? 8 : 4;
		auto image = make_ordinal_thunk_image(pe32_plus,
			{ordinal_value(pe32_plus, 3)}, false, slot_size - 1);
		std::size_t partial_reads = 0;
		auto view = image.view();
		const auto read_at = view.read_at;
		view.read_at = [&](std::uint64_t offset, void* destination,
			std::size_t count) {
			if (offset == 0x200 + slot_size) ++partial_reads;
			return read_at(offset, destination, count);
		};
		std::vector<mana::detail::ParserDiagnostic> diagnostics;

		const auto result = parse_standard_imports_for_architecture(view,
			pe32_plus, import_limits(), diagnostics);

		BOOST_REQUIRE_EQUAL(result.libraries.size(), 1);
		BOOST_CHECK_EQUAL(result.libraries[0].functions.size(), 1);
		BOOST_CHECK_EQUAL(partial_reads, 0);
		BOOST_REQUIRE_EQUAL(diagnostics.size(), 1);
		BOOST_CHECK(diagnostics[0] ==
			mana::detail::ParserDiagnostic::import_malformed);
	}
}

BOOST_AUTO_TEST_CASE(import_thunk_same_region_zero_fill_is_terminator)
{
	for (const bool pe32_plus : {false, true}) {
		const std::size_t slot_size = pe32_plus ? 8 : 4;
		auto image = make_ordinal_thunk_image(pe32_plus,
			{ordinal_value(pe32_plus, 4)}, false, 0, slot_size);
		std::vector<mana::detail::ParserDiagnostic> diagnostics;
		mana::detail::ImportMetrics metrics;

		const auto result = parse_standard_imports_for_architecture(image.view(),
			pe32_plus, import_limits(), diagnostics, &metrics);

		BOOST_REQUIRE_EQUAL(result.libraries.size(), 1);
		BOOST_CHECK_EQUAL(result.libraries[0].functions.size(), 1);
		BOOST_CHECK_EQUAL(metrics.thunk_slot_reads, 1);
		BOOST_CHECK(diagnostics.empty());
	}
}

BOOST_AUTO_TEST_CASE(import_thunk_does_not_cross_into_another_region)
{
	for (const bool pe32_plus : {false, true}) {
		const std::size_t slot_size = pe32_plus ? 8 : 4;
		auto image = make_ordinal_thunk_image(pe32_plus,
			{ordinal_value(pe32_plus, 5)}, false);
		image.section({0x2000 + slot_size, slot_size,
			0x300, slot_size});
		std::vector<mana::detail::ParserDiagnostic> diagnostics;
		mana::detail::ImportMetrics metrics;

		const auto result = parse_standard_imports_for_architecture(image.view(),
			pe32_plus, import_limits(), diagnostics, &metrics);

		BOOST_REQUIRE_EQUAL(result.libraries.size(), 1);
		BOOST_CHECK_EQUAL(result.libraries[0].functions.size(), 1);
		BOOST_CHECK_EQUAL(metrics.thunk_slot_reads, 1);
		BOOST_REQUIRE_EQUAL(diagnostics.size(), 1);
		BOOST_CHECK(diagnostics[0] ==
			mana::detail::ParserDiagnostic::import_malformed);
	}
}

BOOST_AUTO_TEST_CASE(import_thunk_shared_table_is_physically_decoded_once)
{
	for (const bool pe32_plus : {false, true}) {
		const auto raw = ordinal_value(pe32_plus, 7);
		auto image = make_ordinal_thunk_image(pe32_plus,
			{raw}, true, 0, 0, true);
		std::vector<mana::detail::ParserDiagnostic> diagnostics;
		mana::detail::ImportMetrics metrics;

		const auto result = parse_standard_imports_for_architecture(image.view(),
			pe32_plus, import_limits(), diagnostics, &metrics);

		BOOST_REQUIRE_EQUAL(result.libraries.size(), 2);
		BOOST_REQUIRE_EQUAL(result.libraries[0].functions.size(), 1);
		BOOST_REQUIRE_EQUAL(result.libraries[1].functions.size(), 1);
		BOOST_CHECK_EQUAL(result.libraries[0].functions[0].AddressOfData, raw);
		BOOST_CHECK_EQUAL(result.libraries[1].functions[0].AddressOfData, raw);
		BOOST_CHECK_EQUAL(metrics.thunk_slot_reads, 2);
		BOOST_CHECK_EQUAL(metrics.thunk_cache_hits, 1);
		BOOST_CHECK_EQUAL(metrics.thunk_cache_entries, 1);
		BOOST_CHECK_EQUAL(metrics.duplicate_checks, 2);
		BOOST_CHECK(diagnostics.empty());
	}
}

BOOST_AUTO_TEST_CASE(import_thunk_cache_distinguishes_same_physical_source_rvas)
{
	for (const bool pe32_plus : {false, true}) {
		const std::size_t slot_size = pe32_plus ? 8 : 4;
		CompactImageBuilder image(0x400);
		image.headers(0x80).image(0, 0x8000, 1);
		image.section({0x1000, 6, 0x100, 6});
		image.section({0x2000, 2 * slot_size, 0x200, 2 * slot_size});
		image.section({0x3000, 2 * slot_size, 0x200, 2 * slot_size});
		put_descriptor(image, 0x20, 0x2000, 0x1000, 0x2000);
		put_descriptor(image, 0x34, 0x3000, 0x1000, 0x3000);
		put_descriptor(image, 0x48, 0, 0, 0);
		image.put_ascii(0x100, "A.dll");
		const auto raw = ordinal_value(pe32_plus, 8);
		if (pe32_plus) image.put64(0x200, raw);
		else image.put32(0x200, static_cast<std::uint32_t>(raw));
		std::vector<mana::detail::ParserDiagnostic> diagnostics;
		mana::detail::ImportMetrics metrics;

		const auto result = parse_standard_imports_for_architecture(image.view(),
			pe32_plus, import_limits(), diagnostics, &metrics);

		BOOST_REQUIRE_EQUAL(result.libraries.size(), 2);
		BOOST_REQUIRE_EQUAL(result.libraries[0].functions.size(), 1);
		BOOST_REQUIRE_EQUAL(result.libraries[1].functions.size(), 1);
		BOOST_CHECK_EQUAL(result.libraries[0].functions[0].AddressOfData, raw);
		BOOST_CHECK_EQUAL(result.libraries[1].functions[0].AddressOfData, raw);
		BOOST_CHECK_EQUAL(metrics.thunk_slot_reads, 4);
		BOOST_CHECK_EQUAL(metrics.thunk_cache_hits, 0);
		BOOST_CHECK_EQUAL(metrics.thunk_cache_entries, 2);
		BOOST_CHECK_EQUAL(metrics.duplicate_checks, 2);
		BOOST_CHECK(diagnostics.empty());
	}
}

BOOST_AUTO_TEST_CASE(import_thunk_cache_distinguishes_different_extent_rvas)
{
	for (const bool pe32_plus : {false, true}) {
		const std::size_t slot_size = pe32_plus ? 8 : 4;
		CompactImageBuilder image(0x400);
		image.headers(0x80).image(0, 0x8000, 1);
		image.section({0x1000, 6, 0x100, 6});
		image.section({0x2000, 2 * slot_size, 0x200, 2 * slot_size});
		image.section({0x3000, 3 * slot_size, 0x200, 3 * slot_size});
		put_descriptor(image, 0x20, 0x2000, 0x1000, 0x2000);
		put_descriptor(image, 0x34, 0x3000, 0x1000, 0x3000);
		put_descriptor(image, 0x48, 0, 0, 0);
		image.put_ascii(0x100, "A.dll");
		const auto raw = ordinal_value(pe32_plus, 9);
		if (pe32_plus) image.put64(0x200, raw);
		else image.put32(0x200, static_cast<std::uint32_t>(raw));
		std::vector<mana::detail::ParserDiagnostic> diagnostics;
		mana::detail::ImportMetrics metrics;

		const auto result = parse_standard_imports_for_architecture(image.view(),
			pe32_plus, import_limits(), diagnostics, &metrics);

		BOOST_REQUIRE_EQUAL(result.libraries.size(), 2);
		BOOST_CHECK_EQUAL(metrics.thunk_slot_reads, 4);
		BOOST_CHECK_EQUAL(metrics.thunk_cache_hits, 0);
		BOOST_CHECK_EQUAL(metrics.thunk_cache_entries, 2);
		BOOST_CHECK_EQUAL(metrics.duplicate_checks, 2);
		BOOST_CHECK(diagnostics.empty());
	}
}

BOOST_AUTO_TEST_CASE(import_thunk_cache_distinguishes_backing_layout_rvas)
{
	for (const bool pe32_plus : {false, true}) {
		const std::size_t slot_size = pe32_plus ? 8 : 4;
		CompactImageBuilder image(0x400);
		image.headers(0x80).image(0, 0x8000, 1);
		image.section({0x1000, 6, 0x100, 6});
		image.section({0x2000, 3 * slot_size, 0x200, 2 * slot_size});
		image.section({0x3000, 3 * slot_size, 0x200, 3 * slot_size});
		put_descriptor(image, 0x20, 0x2000, 0x1000, 0x2000);
		put_descriptor(image, 0x34, 0x3000, 0x1000, 0x3000);
		put_descriptor(image, 0x48, 0, 0, 0);
		image.put_ascii(0x100, "A.dll");
		for (std::size_t i = 0; i < 3; ++i) {
			const auto raw = ordinal_value(pe32_plus,
				static_cast<std::uint16_t>(20 + i));
			if (pe32_plus) image.put64(0x200 + i * slot_size, raw);
			else image.put32(0x200 + i * slot_size,
				static_cast<std::uint32_t>(raw));
		}
		std::vector<mana::detail::ParserDiagnostic> diagnostics;
		mana::detail::ImportMetrics metrics;

		const auto result = parse_standard_imports_for_architecture(image.view(),
			pe32_plus, import_limits(), diagnostics, &metrics);

		BOOST_REQUIRE_EQUAL(result.libraries.size(), 2);
		BOOST_CHECK_EQUAL(result.libraries[0].functions.size(), 2);
		BOOST_CHECK_EQUAL(result.libraries[1].functions.size(), 3);
		BOOST_CHECK_EQUAL(metrics.thunk_slot_reads, 5);
		BOOST_CHECK_EQUAL(metrics.thunk_cache_hits, 0);
		BOOST_CHECK_EQUAL(metrics.thunk_cache_entries, 1);
		BOOST_CHECK_EQUAL(metrics.duplicate_checks, 5);
		BOOST_CHECK_EQUAL(diagnostics.size(), 1);
		if (!diagnostics.empty()) {
			BOOST_CHECK(diagnostics[0] ==
				mana::detail::ParserDiagnostic::import_malformed);
		}
	}
}

BOOST_AUTO_TEST_CASE(import_thunk_cache_distinguishes_raw_fallback_tail_aliases)
{
	for (const bool pe32_plus : {false, true}) {
		const std::size_t slot_size = pe32_plus ? 8 : 4;
		CompactImageBuilder image(0x400);
		image.headers(0x80).image(0, 0x8000, 1);
		image.section({0x1000, 6, 0x100, 6});
		image.section({0x2000, slot_size, 0x200, 2 * slot_size});
		image.section({0x3000, slot_size, 0x200, slot_size});
		put_descriptor(image, 0x20, 0x2000, 0x1000, 0x2000);
		put_descriptor(image, 0x34, 0x3000, 0x1000, 0x3000);
		put_descriptor(image, 0x48, 0, 0, 0);
		image.put_ascii(0x100, "A.dll");
		const auto raw = ordinal_value(pe32_plus, 29);
		if (pe32_plus) image.put64(0x200, raw);
		else image.put32(0x200, static_cast<std::uint32_t>(raw));
		std::vector<mana::detail::ParserDiagnostic> diagnostics;
		mana::detail::ImportMetrics metrics;

		const auto result = parse_standard_imports_for_architecture(image.view(),
			pe32_plus, import_limits(), diagnostics, &metrics);

		BOOST_REQUIRE_EQUAL(result.libraries.size(), 2);
		BOOST_CHECK_EQUAL(result.libraries[0].functions.size(), 1);
		BOOST_CHECK_EQUAL(result.libraries[1].functions.size(), 1);
		BOOST_CHECK_EQUAL(metrics.thunk_slot_reads, 3);
		BOOST_CHECK_EQUAL(metrics.thunk_cache_hits, 0);
		BOOST_CHECK_EQUAL(metrics.thunk_cache_entries, 1);
		BOOST_CHECK_EQUAL(metrics.duplicate_checks, 2);
		BOOST_CHECK_EQUAL(diagnostics.size(), 1);
		if (!diagnostics.empty()) {
			BOOST_CHECK(diagnostics[0] ==
				mana::detail::ParserDiagnostic::import_malformed);
		}
	}
}

BOOST_AUTO_TEST_CASE(import_thunk_cache_distinguishes_overlap_precedence_rvas)
{
	for (const bool pe32_plus : {false, true}) {
		const std::size_t slot_size = pe32_plus ? 8 : 4;
		CompactImageBuilder image(0x400);
		image.headers(0x80).image(0, 0x8000, 1);
		image.section({0x1000, 6, 0x100, 6});
		image.section({0x2000, 2 * slot_size, 0x200, 2 * slot_size});
		image.section({0x3000 + slot_size, slot_size, 0x300, slot_size});
		image.section({0x3000, 2 * slot_size, 0x200, 2 * slot_size});
		put_descriptor(image, 0x20, 0x2000, 0x1000, 0x2000);
		put_descriptor(image, 0x34, 0x3000, 0x1000, 0x3000);
		put_descriptor(image, 0x48, 0, 0, 0);
		image.put_ascii(0x100, "A.dll");
		const auto raw = ordinal_value(pe32_plus, 30);
		if (pe32_plus) image.put64(0x200, raw);
		else image.put32(0x200, static_cast<std::uint32_t>(raw));
		std::vector<mana::detail::ParserDiagnostic> diagnostics;
		mana::detail::ImportMetrics metrics;

		const auto result = parse_standard_imports_for_architecture(image.view(),
			pe32_plus, import_limits(), diagnostics, &metrics);

		BOOST_REQUIRE_EQUAL(result.libraries.size(), 2);
		BOOST_CHECK_EQUAL(result.libraries[0].functions.size(), 1);
		BOOST_CHECK_EQUAL(result.libraries[1].functions.size(), 1);
		BOOST_CHECK_EQUAL(metrics.thunk_slot_reads, 3);
		BOOST_CHECK_EQUAL(metrics.thunk_cache_hits, 0);
		BOOST_CHECK_EQUAL(metrics.thunk_cache_entries, 1);
		BOOST_CHECK_EQUAL(metrics.duplicate_checks, 2);
		BOOST_CHECK_EQUAL(diagnostics.size(), 1);
		if (!diagnostics.empty()) {
			BOOST_CHECK(diagnostics[0] ==
				mana::detail::ParserDiagnostic::import_malformed);
		}
	}
}

BOOST_AUTO_TEST_CASE(import_thunk_cache_distinguishes_raw_fallback_precedence_rvas)
{
	for (const bool pe32_plus : {false, true}) {
		for (const bool virtual_precedence : {false, true}) {
			const std::size_t slot_size = pe32_plus ? 8 : 4;
			CompactImageBuilder image(0x400);
			image.headers(0x80).image(0, 0x8000, 1);
			image.section({0x1000, 6, 0x100, 6});
			image.section({0x2000, 0, 0x200, 2 * slot_size});
			if (virtual_precedence) {
				image.section({0x3000, 0, 0x200, 2 * slot_size});
				image.section({0x3000 + slot_size, slot_size,
					0x300, slot_size});
			} else {
				image.section({0x3000 + slot_size, 0, 0x300, slot_size});
				image.section({0x3000, 0, 0x200, 2 * slot_size});
			}
			put_descriptor(image, 0x20, 0x2000, 0x1000, 0x2000);
			put_descriptor(image, 0x34, 0x3000, 0x1000, 0x3000);
			put_descriptor(image, 0x48, 0, 0, 0);
			image.put_ascii(0x100, "A.dll");
			const auto raw = ordinal_value(pe32_plus, 31);
			if (pe32_plus) image.put64(0x200, raw);
			else image.put32(0x200, static_cast<std::uint32_t>(raw));
			std::vector<mana::detail::ParserDiagnostic> diagnostics;
			mana::detail::ImportMetrics metrics;

			const auto result = parse_standard_imports_for_architecture(
				image.view(), pe32_plus, import_limits(), diagnostics, &metrics);

			BOOST_REQUIRE_EQUAL(result.libraries.size(), 2);
			BOOST_CHECK_EQUAL(result.libraries[0].functions.size(), 1);
			BOOST_CHECK_EQUAL(result.libraries[1].functions.size(), 1);
			BOOST_CHECK_EQUAL(metrics.thunk_slot_reads, 3);
			BOOST_CHECK_EQUAL(metrics.thunk_cache_hits, 0);
			BOOST_CHECK_EQUAL(metrics.thunk_cache_entries, 1);
			BOOST_CHECK_EQUAL(metrics.duplicate_checks, 2);
			BOOST_CHECK_EQUAL(diagnostics.size(), 1);
			if (!diagnostics.empty()) {
				BOOST_CHECK(diagnostics[0] ==
					mana::detail::ParserDiagnostic::import_malformed);
			}
		}
	}
}

BOOST_AUTO_TEST_CASE(import_thunk_cache_key_separates_slot_widths)
{
	const mana::detail::ThunkCacheKey pe32{0x2000, 4};
	const mana::detail::ThunkCacheKey pe32_plus{0x2000, 8};

	BOOST_CHECK(!(pe32 == pe32_plus));
}

BOOST_AUTO_TEST_CASE(import_thunk_malformed_table_is_not_cached)
{
	auto image = make_ordinal_thunk_image(false,
		{ordinal_value(false, 10)}, false);
	image.section({0x3000, 32, 0x280, 32});
	image.put32(0x284, 0x1000);
	image.put32(0x290, 0x2000);
	std::vector<mana::detail::ParserDiagnostic> diagnostics;
	mana::detail::ImportMetrics metrics;

	const auto result = mana::detail::parse_imports(image.view(), {0x20, 40},
		{0x3000, 32}, false, import_limits(),
		[&](mana::detail::ParserDiagnostic diagnostic) {
			diagnostics.push_back(diagnostic);
		}, &metrics);

	BOOST_REQUIRE_EQUAL(result.libraries.size(), 2);
	BOOST_CHECK_EQUAL(result.libraries[0].functions.size(), 1);
	BOOST_CHECK_EQUAL(result.libraries[1].functions.size(), 1);
	BOOST_CHECK_EQUAL(metrics.thunk_slot_reads, 2);
	BOOST_CHECK_EQUAL(metrics.thunk_cache_hits, 0);
	BOOST_CHECK_EQUAL(metrics.thunk_cache_entries, 0);
}

BOOST_AUTO_TEST_CASE(import_thunk_read_failure_is_not_cached)
{
	auto image = make_ordinal_thunk_image(false,
		{ordinal_value(false, 10)}, true);
	image.section({0x3000, 32, 0x280, 32});
	image.put32(0x284, 0x1000);
	image.put32(0x290, 0x2000);
	auto view = image.view();
	const auto read_at = view.read_at;
	bool failed_once = false;
	view.read_at = [&](std::uint64_t offset, void* destination,
		std::size_t count) {
		if (!failed_once && offset == 0x200 && count == 4) {
			failed_once = true;
			return false;
		}
		return read_at(offset, destination, count);
	};
	std::vector<mana::detail::ParserDiagnostic> diagnostics;
	mana::detail::ImportMetrics metrics;

	const auto result = mana::detail::parse_imports(view, {0x20, 40},
		{0x3000, 32}, false, import_limits(),
		[&](mana::detail::ParserDiagnostic diagnostic) {
			diagnostics.push_back(diagnostic);
		}, &metrics);

	BOOST_REQUIRE_EQUAL(result.libraries.size(), 2);
	BOOST_CHECK(result.libraries[0].functions.empty());
	BOOST_REQUIRE_EQUAL(result.libraries[1].functions.size(), 1);
	BOOST_CHECK_EQUAL(metrics.thunk_slot_reads, 3);
	BOOST_CHECK_EQUAL(metrics.thunk_cache_hits, 0);
	BOOST_CHECK_EQUAL(metrics.thunk_cache_entries, 1);
}

BOOST_AUTO_TEST_CASE(import_thunk_cache_hit_avoids_thunk_and_name_reads)
{
	for (const bool pe32_plus : {false, true}) {
		auto image = make_repeated_dll_image(0x1000, 0x1000);
		image.section({0x1000, 6, 0x100, 6});
		image.section({0x3000, 7, 0x200, 7});
		image.put_ascii(0x100, "A.dll");
		if (pe32_plus) {
			image.put64(0x180, 0x3000);
			image.put64(0x188, 0);
		} else {
			image.put32(0x180, 0x3000);
			image.put32(0x184, 0);
		}
		put_descriptor(image, 0x34, 0x2000, 0x1000, 0x2000);
		image.put16(0x200, 9);
		image.put_ascii(0x202, "Func");
		auto limits = import_limits();
		limits.physical_string_bytes = 13;
		limits.materialized_dll_name_bytes = 10;
		limits.materialized_function_name_bytes = 8;
		std::vector<mana::detail::ParserDiagnostic> diagnostics;
		mana::detail::ImportMetrics metrics;

		const auto result = mana::detail::parse_imports(image.view(), {0x20, 60},
			{0, 0}, pe32_plus, limits,
			[&](mana::detail::ParserDiagnostic diagnostic) {
				diagnostics.push_back(diagnostic);
			}, &metrics);

		BOOST_REQUIRE_EQUAL(result.libraries.size(), 2);
		BOOST_REQUIRE_EQUAL(result.libraries[0].functions.size(), 1);
		BOOST_REQUIRE_EQUAL(result.libraries[1].functions.size(), 1);
		BOOST_CHECK_EQUAL(result.libraries[0].functions[0].Name, "Func");
		BOOST_CHECK_EQUAL(result.libraries[1].functions[0].Name, "Func");
		BOOST_CHECK_EQUAL(metrics.thunk_slot_reads, 2);
		BOOST_CHECK_EQUAL(metrics.thunk_cache_hits, 1);
		BOOST_CHECK_EQUAL(metrics.thunk_cache_entries, 1);
		BOOST_CHECK_EQUAL(metrics.duplicate_checks, 2);
		BOOST_CHECK_EQUAL(metrics.string_read_calls, 2);
		BOOST_CHECK_EQUAL(metrics.string_cache_hits, 2);
		BOOST_CHECK(diagnostics.empty());
	}
}

BOOST_AUTO_TEST_CASE(import_thunk_unique_functions_use_one_duplicate_probe_each)
{
	std::vector<std::uint64_t> values;
	for (std::uint16_t ordinal = 1; ordinal <= 64; ++ordinal) {
		values.push_back(ordinal_value(false, ordinal));
	}
	auto image = make_ordinal_thunk_image(false, values, true);
	std::vector<mana::detail::ParserDiagnostic> diagnostics;
	mana::detail::ImportMetrics metrics;

	const auto result = parse_standard_imports_for_architecture(image.view(),
		false, import_limits(), diagnostics, &metrics);

	BOOST_REQUIRE_EQUAL(result.libraries.size(), 1);
	BOOST_REQUIRE_EQUAL(result.libraries[0].functions.size(), values.size());
	BOOST_CHECK_EQUAL(metrics.duplicate_checks, values.size());
	for (std::size_t i = 0; i < values.size(); ++i) {
		BOOST_CHECK_EQUAL(result.libraries[0].functions[i].AddressOfData,
			values[i]);
	}
}

BOOST_AUTO_TEST_CASE(import_thunk_duplicate_identity_stops_with_partial_output)
{
	const auto repeated = ordinal_value(false, 11);
	auto image = make_ordinal_thunk_image(false, {repeated, repeated}, true);
	std::vector<mana::detail::ParserDiagnostic> diagnostics;
	mana::detail::ImportMetrics metrics;

	const auto result = parse_standard_imports_for_architecture(image.view(),
		false, import_limits(), diagnostics, &metrics);

	BOOST_REQUIRE_EQUAL(result.libraries.size(), 1);
	BOOST_REQUIRE_EQUAL(result.libraries[0].functions.size(), 1);
	BOOST_CHECK_EQUAL(result.libraries[0].functions[0].AddressOfData, repeated);
	BOOST_CHECK_EQUAL(metrics.duplicate_checks, 2);
	BOOST_REQUIRE_EQUAL(diagnostics.size(), 1);
	BOOST_CHECK(diagnostics[0] ==
		mana::detail::ParserDiagnostic::import_malformed);
}

BOOST_AUTO_TEST_CASE(import_function_limit_accepts_exactly_ten_thousand)
{
	for (const std::size_t count : {9999U, 10000U, 10001U}) {
		std::vector<std::uint64_t> values;
		values.reserve(count);
		for (std::size_t i = 0; i < count; ++i) {
			values.push_back(ordinal_value(false,
				static_cast<std::uint16_t>(i + 1)));
		}
		auto image = make_ordinal_thunk_image(false, values, true);
		std::vector<mana::detail::ParserDiagnostic> diagnostics;
		mana::detail::ImportMetrics metrics;

		const auto result = parse_standard_imports_for_architecture(image.view(),
			false, import_limits(16, std::min<std::size_t>(count, 10000)),
			diagnostics, &metrics);

		BOOST_REQUIRE_EQUAL(result.libraries.size(), 1);
		BOOST_CHECK_EQUAL(result.libraries[0].functions.size(),
			std::min<std::size_t>(count, 10000));
		BOOST_CHECK_EQUAL(metrics.duplicate_checks,
			std::min<std::size_t>(count, 10000));
		BOOST_CHECK_EQUAL(metrics.thunk_slot_reads,
			count <= 10000 ? count + 1 : count);
		BOOST_CHECK(result.exhausted == false);
		BOOST_CHECK(diagnostics.empty() == (count <= 10000));
	}
}

BOOST_AUTO_TEST_CASE(import_function_limit_charges_each_logical_cache_hit)
{
	for (const bool pe32_plus : {false, true}) {
		const std::vector<std::uint64_t> values{
			ordinal_value(pe32_plus, 12), ordinal_value(pe32_plus, 13)};
		for (const std::uint64_t limit : {3ULL, 4ULL, 5ULL}) {
			auto image = make_ordinal_thunk_image(pe32_plus, values,
				true, 0, 0, true);
			std::vector<mana::detail::ParserDiagnostic> diagnostics;
			mana::detail::ImportMetrics metrics;

			const auto result = parse_standard_imports_for_architecture(image.view(),
				pe32_plus, import_limits(16, limit), diagnostics, &metrics);

			BOOST_CHECK(result.exhausted == (limit < 4));
			BOOST_REQUIRE_EQUAL(result.libraries.size(), 2);
			BOOST_REQUIRE_EQUAL(result.libraries[0].functions.size(), 2);
			const auto replayed = std::min<std::uint64_t>(limit - 2, 2);
			BOOST_REQUIRE_EQUAL(result.libraries[1].functions.size(), replayed);
			for (std::size_t i = 0; i < values.size(); ++i) {
				BOOST_CHECK_EQUAL(
					result.libraries[0].functions[i].AddressOfData, values[i]);
			}
			for (std::size_t i = 0; i < replayed; ++i) {
				BOOST_CHECK_EQUAL(
					result.libraries[1].functions[i].AddressOfData, values[i]);
			}
			BOOST_CHECK_EQUAL(metrics.thunk_slot_reads, 3);
			BOOST_CHECK_EQUAL(metrics.thunk_cache_hits, 1);
			BOOST_CHECK_EQUAL(metrics.thunk_cache_entries, 1);
			BOOST_CHECK_EQUAL(metrics.duplicate_checks,
				std::min<std::uint64_t>(limit, 4));
			BOOST_CHECK(diagnostics.empty() == (limit >= 4));
		}
	}
}

BOOST_AUTO_TEST_CASE(import_function_limit_failure_does_not_cache_table)
{
	auto image = make_ordinal_thunk_image(false,
		{ordinal_value(false, 16), ordinal_value(false, 17)}, true);
	std::vector<mana::detail::ParserDiagnostic> diagnostics;
	mana::detail::ImportMetrics metrics;

	const auto result = parse_standard_imports_for_architecture(image.view(),
		false, import_limits(16, 1), diagnostics, &metrics);

	BOOST_CHECK(result.exhausted);
	BOOST_REQUIRE_EQUAL(result.libraries.size(), 1);
	BOOST_CHECK_EQUAL(result.libraries[0].functions.size(), 1);
	BOOST_CHECK_EQUAL(metrics.thunk_cache_entries, 0);
}

BOOST_AUTO_TEST_CASE(import_function_limit_compact_boundaries)
{
	for (const std::uint64_t limit : {1ULL, 2ULL, 3ULL}) {
		auto image = make_ordinal_thunk_image(false,
			{ordinal_value(false, 14), ordinal_value(false, 15)}, true);
		std::vector<mana::detail::ParserDiagnostic> diagnostics;
		mana::detail::ImportMetrics metrics;

		const auto result = parse_standard_imports_for_architecture(image.view(),
			false, import_limits(16, limit), diagnostics, &metrics);

		BOOST_REQUIRE_EQUAL(result.libraries.size(), 1);
		BOOST_CHECK_EQUAL(result.libraries[0].functions.size(),
			std::min<std::uint64_t>(limit, 2));
		BOOST_CHECK(result.exhausted == (limit < 2));
		BOOST_CHECK_EQUAL(metrics.duplicate_checks,
			std::min<std::uint64_t>(limit, 2));
	}
}

BOOST_AUTO_TEST_CASE(delay_import_reads_only_first_rva_record)
{
	for (const std::uint32_t attributes : {0U, 1U}) {
		auto image = make_standard_delay_image(attributes, true);
		std::vector<mana::detail::ParserDiagnostic> diagnostics;

		const auto result = parse_standard_and_delay(image.view(),
			{1, 3, 30, 10, 9}, diagnostics);

		BOOST_REQUIRE_EQUAL(result.libraries.size(), 2);
		BOOST_CHECK_EQUAL(result.libraries[0].name, "A.dll");
		BOOST_CHECK_EQUAL(result.libraries[1].name, "B.dll");
		BOOST_REQUIRE(result.delay_directory);
		BOOST_CHECK_EQUAL(result.delay_directory->Attributes, attributes);
		BOOST_CHECK_EQUAL(result.delay_directory->Name, 0x1100);
		BOOST_CHECK_EQUAL(result.delay_directory->DelayImportNameTable, 0x2100);
		BOOST_CHECK_EQUAL(result.delay_directory->NameStr, "B.dll");
		BOOST_REQUIRE_EQUAL(result.libraries[1].functions.size(), 2);
		BOOST_CHECK_EQUAL(result.libraries[1].functions[0].Name, "Two");
		BOOST_CHECK_EQUAL(result.libraries[1].functions[1].Name, "Tri");
		BOOST_CHECK(diagnostics.empty());
	}
}

BOOST_AUTO_TEST_CASE(delay_import_uses_shared_budgets_but_not_descriptors)
{
	auto image = make_standard_delay_image();
	std::vector<mana::detail::ParserDiagnostic> diagnostics;
	const auto exact = parse_standard_and_delay(image.view(),
		{1, 3, 30, 10, 9}, diagnostics);

	BOOST_CHECK(!exact.exhausted);
	BOOST_REQUIRE_EQUAL(exact.libraries.size(), 2);
	BOOST_REQUIRE(exact.delay_directory);
	BOOST_CHECK_EQUAL(exact.libraries[0].functions.size(), 1);
	BOOST_CHECK_EQUAL(exact.libraries[1].functions.size(), 2);
	BOOST_CHECK(diagnostics.empty());

	diagnostics.clear();
	const auto short_dll = parse_standard_and_delay(image.view(),
		{1, 3, 30, 9, 9}, diagnostics);
	BOOST_CHECK(short_dll.exhausted);
	BOOST_REQUIRE_EQUAL(short_dll.libraries.size(), 1);
	BOOST_CHECK(!short_dll.delay_directory);
	BOOST_REQUIRE_EQUAL(diagnostics.size(), 1);
	BOOST_CHECK(diagnostics[0] ==
		mana::detail::ParserDiagnostic::import_budget_exhausted);
}

BOOST_AUTO_TEST_CASE(delay_import_reuses_exact_standard_name_and_thunk_rvas)
{
	auto image = make_standard_delay_image(1, false, true);
	std::vector<mana::detail::ParserDiagnostic> diagnostics;
	mana::detail::ImportMetrics metrics;

	const auto result = parse_standard_and_delay(image.view(),
		{1, 2, 12, 10, 6}, diagnostics, &metrics);

	BOOST_REQUIRE_EQUAL(result.libraries.size(), 2);
	BOOST_REQUIRE_EQUAL(result.libraries[0].functions.size(), 1);
	BOOST_REQUIRE_EQUAL(result.libraries[1].functions.size(), 1);
	BOOST_CHECK_EQUAL(result.libraries[0].name, "A.dll");
	BOOST_CHECK_EQUAL(result.libraries[1].name, "A.dll");
	BOOST_CHECK_EQUAL(result.libraries[0].functions[0].Name, "One");
	BOOST_CHECK_EQUAL(result.libraries[1].functions[0].Name, "One");
	BOOST_CHECK_EQUAL(metrics.string_read_calls, 2);
	BOOST_CHECK_EQUAL(metrics.string_bytes_read, 12);
	BOOST_CHECK_EQUAL(metrics.string_cache_hits, 2);
	BOOST_CHECK_EQUAL(metrics.thunk_slot_reads, 2);
	BOOST_CHECK_EQUAL(metrics.thunk_cache_hits, 1);
	BOOST_CHECK(diagnostics.empty());
}

BOOST_AUTO_TEST_CASE(delay_import_exhaustion_preserves_library_and_functions)
{
	const std::vector<mana::detail::ImportLimits> limits{
		{1, 2, 30, 10, 9},
		{1, 3, 24, 10, 9},
		{1, 3, 30, 10, 6},
	};
	for (const auto& limit : limits) {
		auto image = make_standard_delay_image();
		std::vector<mana::detail::ParserDiagnostic> diagnostics;

		const auto result = parse_standard_and_delay(image.view(), limit,
			diagnostics);

		BOOST_CHECK(result.exhausted);
		BOOST_REQUIRE_EQUAL(result.libraries.size(), 2);
		BOOST_REQUIRE(result.delay_directory);
		BOOST_CHECK_EQUAL(result.delay_directory->NameStr, "B.dll");
		BOOST_REQUIRE_EQUAL(result.libraries[1].functions.size(), 1);
		BOOST_CHECK_EQUAL(result.libraries[1].functions[0].Name, "Two");
		BOOST_REQUIRE_EQUAL(diagnostics.size(), 1);
		BOOST_CHECK(diagnostics[0] ==
			mana::detail::ParserDiagnostic::import_budget_exhausted);
	}
}

BOOST_AUTO_TEST_CASE(delay_import_is_suppressed_after_standard_exhaustion)
{
	auto image = make_standard_delay_image();
	std::vector<mana::detail::ParserDiagnostic> diagnostics;

	const auto result = parse_standard_and_delay(image.view(),
		{0, 3, 30, 10, 9}, diagnostics);

	BOOST_CHECK(result.exhausted);
	BOOST_CHECK(!result.delay_directory);
	BOOST_CHECK(std::none_of(result.libraries.begin(), result.libraries.end(),
		[](const mana::detail::ParsedImportLibrary& library) {
			return library.delay_loaded;
		}));
	BOOST_REQUIRE_EQUAL(diagnostics.size(), 1);
	BOOST_CHECK(diagnostics[0] ==
		mana::detail::ParserDiagnostic::import_budget_exhausted);
}

BOOST_AUTO_TEST_CASE(tls_pe32_decodes_fixed_root_and_four_byte_slots)
{
	auto image = make_tls_image(false, {0x11223344, 0xaabbccdd}, true);
	mana::detail::WorkBudget budget(2);
	std::vector<mana::detail::ParserDiagnostic> diagnostics;

	const auto result = parse_tls_image(image.view(), false, 24, budget,
		diagnostics);

	BOOST_REQUIRE(result.directory);
	BOOST_CHECK_EQUAL(result.directory->StartAddressOfRawData, 0x401111);
	BOOST_CHECK_EQUAL(result.directory->EndAddressOfRawData, 0x402222);
	BOOST_CHECK_EQUAL(result.directory->AddressOfIndex, 0x403333);
	BOOST_CHECK_EQUAL(result.directory->AddressOfCallbacks, 0x401000);
	BOOST_CHECK_EQUAL(result.directory->SizeOfZeroFill, 0x12345678);
	BOOST_CHECK_EQUAL(result.directory->Characteristics, 0x9abcdef0);
	BOOST_REQUIRE_EQUAL(result.directory->Callbacks.size(), 2);
	BOOST_CHECK_EQUAL(result.directory->Callbacks[0], 0x11223344);
	BOOST_CHECK_EQUAL(result.directory->Callbacks[1], 0xaabbccdd);
	BOOST_CHECK_EQUAL(budget.remaining(), 0);
	BOOST_CHECK(diagnostics.empty());
}

BOOST_AUTO_TEST_CASE(tls_pe32_plus_decodes_fixed_root_and_eight_byte_slots)
{
	auto image = make_tls_image(true, {0x1122334455667788ULL}, true);
	mana::detail::WorkBudget budget(1);
	std::vector<mana::detail::ParserDiagnostic> diagnostics;

	const auto result = parse_tls_image(image.view(), true, 40, budget,
		diagnostics);

	BOOST_REQUIRE(result.directory);
	BOOST_CHECK_EQUAL(result.directory->StartAddressOfRawData,
		0x1111222233334444ULL);
	BOOST_CHECK_EQUAL(result.directory->EndAddressOfRawData,
		0x5555666677778888ULL);
	BOOST_CHECK_EQUAL(result.directory->AddressOfIndex,
		0x9999aaaabbbbccccULL);
	BOOST_REQUIRE_EQUAL(result.directory->Callbacks.size(), 1);
	BOOST_CHECK_EQUAL(result.directory->Callbacks[0], 0x1122334455667788ULL);
	BOOST_CHECK(diagnostics.empty());
}

BOOST_AUTO_TEST_CASE(tls_root_sizes_are_minimums_and_callbacks_are_external)
{
	for (const bool pe32_plus : {false, true}) {
		const std::uint32_t minimum = pe32_plus ? 40 : 24;
		for (const std::uint32_t declared : {minimum, minimum + 8}) {
			auto image = make_tls_image(pe32_plus, {0xabcdef01}, true);
			mana::detail::WorkBudget budget(1);
			std::vector<mana::detail::ParserDiagnostic> diagnostics;

			const auto result = parse_tls_image(image.view(), pe32_plus, declared,
				budget, diagnostics);

			BOOST_REQUIRE(result.directory);
			BOOST_REQUIRE_EQUAL(result.directory->Callbacks.size(), 1);
			BOOST_CHECK_EQUAL(result.directory->Callbacks[0], 0xabcdef01);
			BOOST_CHECK_EQUAL(result.directory->SizeOfZeroFill, 0x12345678);
			BOOST_CHECK_EQUAL(result.directory->Characteristics, 0x9abcdef0);
			BOOST_CHECK(diagnostics.empty());
		}
	}
}

BOOST_AUTO_TEST_CASE(tls_rejects_undersized_and_truncated_fixed_roots)
{
	for (const bool pe32_plus : {false, true}) {
		const std::uint32_t minimum = pe32_plus ? 40 : 24;
		auto image = make_tls_image(pe32_plus, {}, true);
		mana::detail::WorkBudget budget(4);
		std::vector<mana::detail::ParserDiagnostic> diagnostics;
		auto result = parse_tls_image(image.view(), pe32_plus, minimum - 1,
			budget, diagnostics);
		BOOST_CHECK(!result.directory);
		BOOST_CHECK_EQUAL(budget.remaining(), 4);

		diagnostics.clear();
		auto truncated = image.view();
		truncated.size_of_headers = 0x20 + minimum - 1;
		result = parse_tls_image(truncated, pe32_plus, minimum, budget,
			diagnostics);
		BOOST_CHECK(!result.directory);
		BOOST_CHECK_EQUAL(budget.remaining(), 4);
	}
}

BOOST_AUTO_TEST_CASE(tls_zero_callback_va_is_unretained_and_does_no_slot_read)
{
	auto image = make_tls_image(true, {0x1122334455667788ULL}, true, 0, 0, 0);
	auto view = image.view();
	const auto read_at = view.read_at;
	std::size_t callback_reads = 0;
	view.read_at = [&](std::uint64_t offset, void* destination,
		std::size_t size) {
		if (offset >= 0x100) ++callback_reads;
		return read_at(offset, destination, size);
	};
	mana::detail::WorkBudget budget(7);
	std::vector<mana::detail::ParserDiagnostic> diagnostics;

	const auto result = parse_tls_image(view, true, 40, budget, diagnostics);

	BOOST_CHECK(!result.directory);
	BOOST_CHECK(!result.exhausted);
	BOOST_CHECK_EQUAL(budget.remaining(), 7);
	BOOST_CHECK_EQUAL(callback_reads, 0);
	BOOST_REQUIRE_EQUAL(diagnostics.size(), 1);
	BOOST_CHECK(diagnostics[0] ==
		mana::detail::ParserDiagnostic::tls_callback_va_invalid);
}

BOOST_AUTO_TEST_CASE(tls_rejects_invalid_callback_va_without_direct_fallback)
{
	for (const bool pe32_plus : {false, true}) {
		const std::uint64_t image_base = pe32_plus ? 0x140000000ULL : 0x400000;
		const std::vector<std::uint64_t> addresses{
			image_base - 1,
			image_base + 0x4000,
			image_base + 0x4001,
			std::numeric_limits<std::uint64_t>::max(),
		};
		for (const auto address : addresses) {
			auto image = make_tls_image(pe32_plus, {0x12345678}, true, 0, 0,
				address);
			mana::detail::WorkBudget budget(1);
			std::vector<mana::detail::ParserDiagnostic> diagnostics;

			const auto result = parse_tls_image(image.view(), pe32_plus,
				pe32_plus ? 40 : 24, budget, diagnostics);

			BOOST_CHECK(!result.directory);
			BOOST_CHECK_EQUAL(budget.remaining(), 1);
			BOOST_REQUIRE_EQUAL(diagnostics.size(), 1);
			BOOST_CHECK(diagnostics[0] ==
				mana::detail::ParserDiagnostic::tls_callback_va_invalid);
		}
	}
}

BOOST_AUTO_TEST_CASE(tls_callback_targets_need_not_map_inside_image)
{
	auto image = make_tls_image(true, {0xffffffffffffffffULL}, true);
	mana::detail::WorkBudget budget(1);
	std::vector<mana::detail::ParserDiagnostic> diagnostics;

	const auto result = parse_tls_image(image.view(), true, 40, budget,
		diagnostics);

	BOOST_REQUIRE(result.directory);
	BOOST_REQUIRE_EQUAL(result.directory->Callbacks.size(), 1);
	BOOST_CHECK_EQUAL(result.directory->Callbacks[0],
		0xffffffffffffffffULL);
	BOOST_CHECK(diagnostics.empty());
}

BOOST_AUTO_TEST_CASE(tls_physical_null_at_initialized_boundary_terminates)
{
	for (const bool pe32_plus : {false, true}) {
		auto image = make_tls_image(pe32_plus, {0x1234}, true);
		mana::detail::WorkBudget budget(1);
		std::vector<mana::detail::ParserDiagnostic> diagnostics;

		const auto result = parse_tls_image(image.view(), pe32_plus,
			pe32_plus ? 40 : 24, budget, diagnostics);

		BOOST_REQUIRE(result.directory);
		BOOST_REQUIRE_EQUAL(result.directory->Callbacks.size(), 1);
		BOOST_CHECK(diagnostics.empty());
	}
}

BOOST_AUTO_TEST_CASE(tls_same_region_zero_fill_is_a_terminator)
{
	for (const bool pe32_plus : {false, true}) {
		const std::size_t slot_size = pe32_plus ? 8 : 4;
		auto image = make_tls_image(pe32_plus, {0x1234}, false, 0,
			slot_size);
		auto view = image.view();
		const auto read_at = view.read_at;
		std::size_t slot_reads = 0;
		view.read_at = [&](std::uint64_t offset, void* destination,
			std::size_t size) {
			if (offset >= 0x100) ++slot_reads;
			return read_at(offset, destination, size);
		};
		mana::detail::WorkBudget budget(1);
		std::vector<mana::detail::ParserDiagnostic> diagnostics;

		const auto result = parse_tls_image(view, pe32_plus,
			pe32_plus ? 40 : 24, budget, diagnostics);

		BOOST_REQUIRE(result.directory);
		BOOST_REQUIRE_EQUAL(result.directory->Callbacks.size(), 1);
		BOOST_CHECK_EQUAL(slot_reads, 1);
		BOOST_CHECK(diagnostics.empty());
	}
}

BOOST_AUTO_TEST_CASE(tls_region_boundary_and_partial_slot_are_unterminated)
{
	for (const bool pe32_plus : {false, true}) {
		for (const std::size_t partial : {std::size_t{0}, std::size_t{1}}) {
			auto image = make_tls_image(pe32_plus, {0x1234}, false, partial);
			auto view = image.view();
			const auto read_at = view.read_at;
			std::size_t slot_reads = 0;
			view.read_at = [&](std::uint64_t offset, void* destination,
				std::size_t size) {
				if (offset >= 0x100) ++slot_reads;
				return read_at(offset, destination, size);
			};
			mana::detail::WorkBudget budget(2);
			std::vector<mana::detail::ParserDiagnostic> diagnostics;

			const auto result = parse_tls_image(view, pe32_plus,
				pe32_plus ? 40 : 24, budget, diagnostics);

			BOOST_REQUIRE(result.directory);
			BOOST_REQUIRE_EQUAL(result.directory->Callbacks.size(), 1);
			BOOST_CHECK_EQUAL(slot_reads, 1);
			BOOST_REQUIRE_EQUAL(diagnostics.size(), 1);
			BOOST_CHECK(diagnostics[0] ==
				mana::detail::ParserDiagnostic::tls_callback_unterminated);
		}
	}
}

BOOST_AUTO_TEST_CASE(tls_callback_table_does_not_cross_into_adjacent_region)
{
	for (const bool pe32_plus : {false, true}) {
		const std::size_t slot_size = pe32_plus ? 8 : 4;
		auto image = make_tls_image(pe32_plus, {0x1234}, false);
		image.section({0x1000 + slot_size, slot_size, 0x180, slot_size});
		mana::detail::WorkBudget budget(2);
		std::vector<mana::detail::ParserDiagnostic> diagnostics;

		const auto result = parse_tls_image(image.view(), pe32_plus,
			pe32_plus ? 40 : 24, budget, diagnostics);

		BOOST_REQUIRE(result.directory);
		BOOST_REQUIRE_EQUAL(result.directory->Callbacks.size(), 1);
		BOOST_REQUIRE_EQUAL(diagnostics.size(), 1);
		BOOST_CHECK(diagnostics[0] ==
			mana::detail::ParserDiagnostic::tls_callback_unterminated);
	}
}

BOOST_AUTO_TEST_CASE(tls_unmapped_or_unreadable_table_retains_fixed_root)
{
	auto image = make_tls_image(false, {}, false, 0, 0, 0x402000);
	for (const bool fail_read : {false, true}) {
		auto view = image.view();
		if (fail_read) {
			view.sections = {{0x2000, 4, 0x100, 4}};
			const auto read_at = view.read_at;
			view.read_at = [read_at](std::uint64_t offset, void* destination,
				std::size_t size) {
				return offset < 0x100 && read_at(offset, destination, size);
			};
		}
		mana::detail::WorkBudget budget(1);
		std::vector<mana::detail::ParserDiagnostic> diagnostics;

		const auto result = parse_tls_image(view, false, 24, budget,
			diagnostics);

		BOOST_REQUIRE(result.directory);
		BOOST_CHECK(result.directory->Callbacks.empty());
		BOOST_REQUIRE_EQUAL(diagnostics.size(), 1);
		BOOST_CHECK(diagnostics[0] ==
			mana::detail::ParserDiagnostic::tls_callback_unterminated);
	}
}

BOOST_AUTO_TEST_CASE(tls_callback_budget_reads_then_charges_nonzero_only)
{
	for (const bool pe32_plus : {false, true}) {
		for (const std::uint64_t limit : {0ULL, 1ULL, 2ULL, 3ULL}) {
			auto image = make_tls_image(pe32_plus,
				{0x11111111, 0x22222222}, true);
			auto view = image.view();
			const auto read_at = view.read_at;
			std::size_t slot_reads = 0;
			view.read_at = [&](std::uint64_t offset, void* destination,
				std::size_t size) {
				if (offset >= 0x100) ++slot_reads;
				return read_at(offset, destination, size);
			};
			mana::detail::WorkBudget budget(limit);
			std::vector<mana::detail::ParserDiagnostic> diagnostics;

			const auto result = parse_tls_image(view, pe32_plus,
				pe32_plus ? 40 : 24, budget, diagnostics);

			BOOST_REQUIRE(result.directory);
			const auto retained = std::min<std::uint64_t>(limit, 2);
			BOOST_CHECK_EQUAL(result.directory->Callbacks.size(), retained);
			BOOST_CHECK(result.exhausted == (limit < 2));
			BOOST_CHECK_EQUAL(slot_reads, limit < 2 ? retained + 1 : 3);
			BOOST_CHECK_EQUAL(budget.remaining(), limit > 2 ? limit - 2 : 0);
			BOOST_CHECK_EQUAL(diagnostics.size(), limit < 2 ? 1 : 0);
			if (limit < 2) {
				BOOST_CHECK(diagnostics[0] ==
					mana::detail::ParserDiagnostic::tls_budget_exhausted);
			}
		}
	}
}

BOOST_AUTO_TEST_SUITE_END()
