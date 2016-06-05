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

#include "fixtures.h"
#include "manape/pe.h"
#include "import_hash.h"

// ----------------------------------------------------------------------------
BOOST_FIXTURE_TEST_SUITE(resources, SetWorkingDirectory)
// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(parse_imports)
{
	mana::PE pe("testfiles/manatest.exe");
	BOOST_ASSERT(pe.get_imported_dlls());
	auto dlls = *pe.get_imported_dlls();
	BOOST_ASSERT(dlls.size() == 8);
	std::vector<std::string> expected_dlls;
	expected_dlls.push_back("KERNEL32.dll");
	expected_dlls.push_back("MSVCP140.dll");
	expected_dlls.push_back("VCRUNTIME140.dll");
	expected_dlls.push_back("api-ms-win-crt-runtime-l1-1-0.dll");
	expected_dlls.push_back("api-ms-win-crt-math-l1-1-0.dll");
	expected_dlls.push_back("api-ms-win-crt-stdio-l1-1-0.dll");
	expected_dlls.push_back("api-ms-win-crt-locale-l1-1-0.dll");
	expected_dlls.push_back("api-ms-win-crt-heap-l1-1-0.dll");
	BOOST_ASSERT(dlls == expected_dlls);

	BOOST_ASSERT(pe.get_imported_functions("KERNEL32.dll"));
	auto functions = *pe.get_imported_functions("KERNEL32.dll");
	BOOST_ASSERT(functions.size() == 15);
	std::vector<std::string> expected_functions;
	expected_functions.push_back("WriteProcessMemory");
	expected_functions.push_back("OpenProcess");
	expected_functions.push_back("CreateRemoteThread");
	expected_functions.push_back("SetUnhandledExceptionFilter");
	expected_functions.push_back("GetCurrentProcess");
	expected_functions.push_back("TerminateProcess");
	expected_functions.push_back("IsProcessorFeaturePresent");
	expected_functions.push_back("QueryPerformanceCounter");
	expected_functions.push_back("GetCurrentProcessId");
	expected_functions.push_back("GetCurrentThreadId");
	expected_functions.push_back("GetSystemTimeAsFileTime");
	expected_functions.push_back("InitializeSListHead");
	expected_functions.push_back("IsDebuggerPresent");
	expected_functions.push_back("GetModuleHandleW");
	expected_functions.push_back("UnhandledExceptionFilter");
	BOOST_CHECK(functions == expected_functions);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(find_imports)
{
	// Find functions by regular expression
	mana::PE pe("testfiles/manatest.exe");
	auto pfunctions = pe.find_imports(".*basic_ostream.*", "MSVCP\\d{3}.dll|KERNEL32.dll");
	BOOST_ASSERT(pfunctions);
	BOOST_ASSERT(pfunctions->size() == 6);
	std::vector<std::string> expected_functions;
	expected_functions.push_back("??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QAEAAV01@P6AAAVios_base@1@AAV21@@Z@Z");
	expected_functions.push_back("??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QAEAAV01@P6AAAV01@AAV01@@Z@Z");
	expected_functions.push_back("?cout@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A");
	expected_functions.push_back("?_Osfx@?$basic_ostream@DU?$char_traits@D@std@@@std@@QAEXXZ");
	expected_functions.push_back("?flush@?$basic_ostream@DU?$char_traits@D@std@@@std@@QAEAAV12@XZ");
	expected_functions.push_back("?put@?$basic_ostream@DU?$char_traits@D@std@@@std@@QAEAAV12@D@Z");
	BOOST_CHECK(*pfunctions == expected_functions);

	// Verify that the same search on all DLLs returns the same results
	pfunctions = pe.find_imports(".*basic_ostream.*");
	BOOST_ASSERT(pfunctions);
	BOOST_CHECK(*pfunctions == expected_functions);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(find_dlls)
{
	mana::PE pe("testfiles/manatest.exe");
	auto dll = pe.find_imported_dlls("Kernel32.dll");
	BOOST_ASSERT(dll);
	BOOST_CHECK_EQUAL(dll->size(), 1);

	dll = pe.find_imported_dlls("I DON'T EXIST");
	BOOST_ASSERT(dll);
	BOOST_CHECK_EQUAL(dll->size(), 0);

	dll = pe.find_imported_dlls(".*");
	BOOST_ASSERT(dll);
	BOOST_CHECK_EQUAL(dll->size(), 8);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(find_imports_no_match)
{
	mana::PE pe("testfiles/manatest.exe");
	auto pfunctions = pe.find_imports("I DON'T EXIST");
	BOOST_ASSERT(pfunctions);
	BOOST_CHECK(pfunctions->size() == 0);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(find_imports_case_insensitivity)
{
	mana::PE pe("testfiles/manatest.exe");
	auto pfunctions = pe.find_imports("WRITEPROCESSMEMORY");
	BOOST_ASSERT(pfunctions);
	BOOST_ASSERT(pfunctions->size() == 1);
	BOOST_CHECK_EQUAL(pfunctions->at(0), "WriteProcessMemory");

	// Try again with case sensitivity on.
	pfunctions = pe.find_imports("WRITEPROCESSMEMORY", ".*", true);
	BOOST_ASSERT(pfunctions);
	BOOST_ASSERT(pfunctions->size() == 0);
}

// ----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(hash_imports)
{
	mana::PE pe("testfiles/manatest.exe");
	std::string h = hash::hash_imports(pe);
	BOOST_CHECK(h == "924ac5aa343a9f838d5c16a5d77de2ec");
}

// ----------------------------------------------------------------------------
BOOST_AUTO_TEST_SUITE_END()
// ----------------------------------------------------------------------------
