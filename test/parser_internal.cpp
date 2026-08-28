#include <cstdint>
#include <limits>
#include <optional>

#include <boost/test/unit_test.hpp>

#include "manape/parser_internal.h"

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

BOOST_AUTO_TEST_SUITE_END()
