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

#include "config_parser.h"
#include "fixtures.h"

BOOST_FIXTURE_TEST_SUITE(config_parser, SetWorkingDirectory)

BOOST_AUTO_TEST_CASE(parse_config_basic)
{
	create_file("config_test.conf",
	            "pluginA.attr1=value1\n"
	            " pluginA . attr2 = value two \n"
	            "# comment\n"
	            "   # comment2\n"
	            "pluginB.attr3=   value3  \n"
	            "invalid\n"
	            "pluginC.=oops\n"
	            ".bad=oops\n");

	config conf = parse_config("config_test.conf");
	BOOST_CHECK_EQUAL(conf.size(), 2);

	auto itA = conf.find("pluginA");
	BOOST_ASSERT(itA != conf.end());
	BOOST_CHECK_EQUAL(itA->second.at("attr1"), "value1");
	BOOST_CHECK_EQUAL(itA->second.at("attr2"), "value two");

	auto itB = conf.find("pluginB");
	BOOST_ASSERT(itB != conf.end());
	BOOST_CHECK_EQUAL(itB->second.at("attr3"), "value3");

	BOOST_CHECK(conf.find("pluginC") == conf.end());
	BOOST_CHECK(conf.find("") == conf.end());

	fs::remove("config_test.conf");
}

BOOST_AUTO_TEST_SUITE_END()
