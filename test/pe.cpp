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
#include <boost/filesystem.hpp>

#include "manape/pe.h"

namespace unit = boost::unit_test::framework;
namespace fs = boost::filesystem;

class SetWorkingDirectory
{
public:
    SetWorkingDirectory()
    {
        // Save the current working directory
        _original_directory = fs::current_path().string();

        // Go to the test directory
        fs::path working_dir(unit::master_test_suite().argv[0]);
        working_dir = working_dir.parent_path();
        fs::current_path(working_dir / ".." / "test");
    }

    ~SetWorkingDirectory() {
        fs::current_path(_original_directory);
    }

private:
    std::string _original_directory;
};

BOOST_FIXTURE_TEST_CASE(parse_calc, SetWorkingDirectory)
{
    mana::PE pe("testfiles/calc.exe");
	BOOST_CHECK_EQUAL(pe.get_filesize(), 115200);

    // DOS Header
    boost::optional<mana::dos_header> pdos = pe.get_dos_header();
    BOOST_ASSERT(pdos);
    mana::dos_header dos = *pdos;
    BOOST_CHECK(dos.e_magic[0] == 'M' && dos.e_magic[1] == 'Z');
    BOOST_CHECK_EQUAL(dos.e_cblp, 0x90);
    BOOST_CHECK_EQUAL(dos.e_cp, 3);
    BOOST_CHECK_EQUAL(dos.e_crlc, 0);
    BOOST_CHECK_EQUAL(dos.e_cparhdr, 4);
    BOOST_CHECK_EQUAL(dos.e_minalloc, 0);
    BOOST_CHECK_EQUAL(dos.e_maxalloc, 0xFFFF);
    BOOST_CHECK_EQUAL(dos.e_ss, 0);
    BOOST_CHECK_EQUAL(dos.e_sp, 0xB8);
    BOOST_CHECK_EQUAL(dos.e_csum, 0);
    BOOST_CHECK_EQUAL(dos.e_ip, 0);
    BOOST_CHECK_EQUAL(dos.e_cs, 0);
    BOOST_CHECK_EQUAL(dos.e_lfarlc, 0x40);
    BOOST_CHECK_EQUAL(dos.e_ovno, 0);
    for (int i = 0 ; i < 4 ; ++i) {
		BOOST_CHECK_EQUAL(dos.e_res[i], 0);
	}
    BOOST_CHECK_EQUAL(dos.e_oemid, 0);
    BOOST_CHECK_EQUAL(dos.e_oeminfo, 0);
    for (int i = 0 ; i < 10 ; ++i) {
		BOOST_CHECK_EQUAL(dos.e_res2[i], 0);
	}
    BOOST_CHECK_EQUAL(dos.e_lfanew, 0xF0);
}
