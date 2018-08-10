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

#include "fixtures.h"

SetWorkingDirectory::SetWorkingDirectory()
{
	// Save the current working directory
	_original_directory = fs::current_path().string();

	// Go to the test directory
	fs::path working_dir(unit::master_test_suite().argv[0]);
	working_dir = working_dir.parent_path();
	fs::current_path(working_dir / ".." / "test");
}

// ----------------------------------------------------------------------------

SetWorkingDirectory::~SetWorkingDirectory() {
	fs::current_path(_original_directory);
}

// ----------------------------------------------------------------------------

void create_file(const fs::path & ph, const std::string & contents)
{
	std::ofstream f(ph.c_str());
	if (!f)
		throw fs::filesystem_error("Could not create a file",
			ph, bs::error_code(errno, bs::system_category()));
	if (!contents.empty()) {
		f << contents;
	}
}

// ----------------------------------------------------------------------------

SetupFiles::SetupFiles()
{
	create_file("fox", "The quick brown fox jumps over the lazy dog");
	create_file("empty");
}

// ----------------------------------------------------------------------------

SetupFiles::~SetupFiles()
{
	fs::remove("fox");
	fs::remove("empty");
}