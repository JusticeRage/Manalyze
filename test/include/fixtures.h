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

#pragma once

#include <fstream>
#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/shared_ptr.hpp>

namespace unit	= boost::unit_test::framework;
namespace fs	= boost::filesystem;
namespace bs	= boost::system;

typedef boost::shared_ptr<std::string> pString;

// ----------------------------------------------------------------------------

/**
* Fixture setting the current directory to "[project_dir]/test/".
* The initial working directory is restored after the test.
*/
class SetWorkingDirectory
{
public:
	SetWorkingDirectory();
	~SetWorkingDirectory();
private:
	std::string _original_directory;
};

// ----------------------------------------------------------------------------

/**
 * @brief	Creates a file with arbitrary content.
 *
 * @param	const fs::path & ph The path of the file to create.
 * @param	const std::string & contents The contents of the file.
 *
 * Function taken from boost::filesystem's unit tests
 */
void create_file(const fs::path & ph, const std::string & contents = std::string());

// ----------------------------------------------------------------------------

/**
 *	@brief	Fixture which creates two files in the current directory.
 *
 *	The first one contains "The quick brown fox jumps over the lazy dog", and
 *	the other one is empty.
 */
class SetupFiles {

public:
	SetupFiles();
	~SetupFiles();
};