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

constexpr mana::detail::ImportLimits import_limits(std::uint64_t descriptors = 16)
{
	return {descriptors, 128, 4096, 4096, 4096};
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

mana::detail::ImportParseResult parse_standard_imports(
	const mana::detail::ImageView& image, std::uint32_t rva, std::uint32_t size,
	const mana::detail::ImportLimits& limits,
	std::vector<mana::detail::ParserDiagnostic>& diagnostics)
{
	return mana::detail::parse_imports(image, {rva, size}, {0, 0}, false,
		limits, [&](mana::detail::ParserDiagnostic diagnostic) {
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
	std::size_t bytes_read = 0;
	auto view = image.view();
	const auto read_at = view.read_at;
	view.read_at = [&](std::uint64_t offset, void* destination,
		std::size_t count) {
		bytes_read += count;
		return read_at(offset, destination, count);
	};
	std::vector<mana::detail::ParserDiagnostic> diagnostics;

	const auto result = parse_standard_imports(view, 0x40, 39,
		import_limits(), diagnostics);

	BOOST_CHECK_EQUAL(result.libraries.size(), 1);
	BOOST_CHECK_EQUAL(bytes_read, 20);
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
	put_descriptor(image, 0x1ec, 1, 2, 3);
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

	const auto result = parse_standard_imports(view, 0x40, 60,
		import_limits(1), diagnostics);

	BOOST_CHECK(result.exhausted);
	BOOST_CHECK_EQUAL(result.libraries.size(), 1);
	BOOST_CHECK_EQUAL(descriptor_reads, 2);
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

BOOST_AUTO_TEST_SUITE_END()
