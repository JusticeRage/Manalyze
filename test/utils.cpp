/*
    This file is part of Manalyze.

    Manalyze is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Manalyze is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Manalyze.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <boost/test/unit_test.hpp>

#include <sstream>

#include "manacommons/color.h"
#include "manape/utils.h"

BOOST_AUTO_TEST_CASE(test_dosdate_to_string)
{
    const auto date_1 = utils::dosdate_to_string(0);
    const auto date_2 = utils::dosdate_to_string(0x40B349E2);
    // Test fallback to timestamp:
    const auto date_3 = utils::dosdate_to_string(1168460802);

    BOOST_ASSERT(date_1);
    BOOST_ASSERT(date_2);
    BOOST_ASSERT(date_3);
    BOOST_CHECK_EQUAL(*date_1, "1980-Jan-01 00:00:00");
    BOOST_CHECK_EQUAL(*date_2, "2012-May-19 09:15:04");
    BOOST_CHECK_EQUAL(*date_3, "2007-Jan-10 20:26:42");
}

BOOST_AUTO_TEST_CASE(test_timestamp_to_string)
{
    const auto date_1 = utils::timestamp_to_string(0);
    const auto date_2 = utils::timestamp_to_string(0x40B349E2);
    BOOST_ASSERT(date_1);
    BOOST_ASSERT(date_2);
    BOOST_CHECK_EQUAL(*date_1, "1970-Jan-01 00:00:00");
    BOOST_CHECK_EQUAL(*date_2, "2004-May-25 13:28:02");
}

BOOST_AUTO_TEST_CASE(test_is_actually_posix)
{
    BOOST_CHECK(!utils::is_actually_posix(0, 0x530b3da0));
    BOOST_CHECK(utils::is_actually_posix(0x530b3da0, 0x530b3da0));
    BOOST_CHECK(utils::is_actually_posix(0x530b3da3, 0x530b3da0));
    BOOST_CHECK(utils::is_actually_posix(0x530b3d90, 0x530b3da0));
    BOOST_CHECK(!utils::is_actually_posix(0x40b349e2, 0x4fb6e609));
}

BOOST_AUTO_TEST_CASE(test_log_level_parsing)
{
    utils::LogLevel level = utils::LogLevel::WARNING;

    BOOST_CHECK(utils::parse_log_level("off", level));
    BOOST_CHECK(level == utils::LogLevel::OFF);
    BOOST_CHECK(utils::parse_log_level("ERROR", level));
    BOOST_CHECK(level == utils::LogLevel::ERROR);
    BOOST_CHECK(utils::parse_log_level("warning", level));
    BOOST_CHECK(level == utils::LogLevel::WARNING);
    BOOST_CHECK(utils::parse_log_level("info", level));
    BOOST_CHECK(level == utils::LogLevel::INFO);
    BOOST_CHECK(utils::parse_log_level("debug", level));
    BOOST_CHECK(level == utils::LogLevel::DEBUG);
    BOOST_CHECK(!utils::parse_log_level("nope", level));
}

BOOST_AUTO_TEST_CASE(test_log_level_stream_filtering)
{
    const auto previous = utils::get_log_level();
    std::ostringstream captured;
    std::streambuf* original = std::cerr.rdbuf(captured.rdbuf());

    utils::set_log_level(utils::LogLevel::OFF);
    PRINT_WARNING << "hidden warning" << std::endl;
    PRINT_ERROR << "hidden error" << std::endl;
    BOOST_CHECK(captured.str().empty());

    captured.str("");
    captured.clear();
    utils::set_log_level(utils::LogLevel::WARNING);
    PRINT_WARNING << "visible warning" << std::endl;
    BOOST_CHECK_NE(captured.str().find("visible warning"), std::string::npos);

    std::cerr.rdbuf(original);
    utils::set_log_level(previous);
}
