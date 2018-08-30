*******************
Before contributing
*******************

If you're reading this, you're probably eager to start writing code, but please bear with me for a few more minutes: if you don't take into account the instructions contained on this page, your contributions to the project may be rejected regardless of their quality!

About the GPLv3 license
=======================

Manalyze is distributed under the terms of the `GPLv3 license <https://www.gnu.org/licenses/gpl-3.0.txt>`_. If you wish to contribute to the project's, you must agree to its terms and use the same license for code you submit. All source files should start with the following header::

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

If the code you are submitting depends on third-party libraries, make sure that their license is compatible - if it's not, we will not be able to accept your contribution. Refer to the `GNU website <https://www.gnu.org/licenses/license-list.en.html>`_ to check whether a particular license can be used alongside the GPLv3.

.. note:: If you would like to use any part of Manalyze in a commercial product but the GPL license isn't compatible with it, get in touch with the maintainer: dual-licensing options are available.

Coding style
============

All code contributions should make every effort to match Manalyze's coding style as closely as possible. Here are the most important things to look for:

* Naming conventions
    * Use CamelCase for class names (i.e. ``class MyShinyClass {};``).
    * Use lowercase for function names, function members and local variables. Separate words with underscores (i.e. ``void process_int(int i);``).
    * Use capital letters for global variables and program-wide contants, and underscores to separate words (i.e. ``#define NUMBER_OF_TRIES 10``).
    * Prefix private class method and member names with an underscore (i.e ``private: std::string _private_string;``).
    * Choose lowercase, preferably short namespace names (i.e. ``namespace plugins { ... }``).
* Code structure
    * All your code should reside in a meaningful namespace.
    * Declare class and functions in header (".h") files.
    * Protect header files against multiple inclusions with ``#pragma once``.
    * Inclusion of system headers should precede inclusion of user-defined headers. Boost headers are considered system headers.
    * Put function implementations in .cpp files.
    * Function declarations must be documented following the `Doxygen <https://www.stack.nl/~dimitri/doxygen/manual/docblocks.html>`_ convention. 
    * Please thoroughly explain non-intuitive code fragments with inline comments.
* Formatting
    * Do not put multiple statements on a single line (i.e. ``int a = 1; initialize(a);`` is not accepted.).
    * For improved readability, please insert the following separator between function declarations::

        // ----------------------------------------------------------------------------

    * Indent your code. You can use either tabluations or blocks of 4 spaces.
    * Also indent preprocessor directives::

        #ifdef BOOST_WINDOWS_API
        #	define PLUGIN_API __declspec(dllexport)
        #else
        #	define PLUGIN_API __attribute__((visibility("default")))
        #endif

    * Do not import whole namespaces in headers (i.e. ``using namespace std;`` is prohibited).
    * Pointer and reference being part of the type, write ``char* s1;`` or ``std::string& s2;`` instead of ``char *s1;`` or ``std::string &s2;``.
    * Trigraphs and digraphs are banned.
    * Never omit brackets in control structures.
    * Put brackets on a new line, unless there is only one line of code in the logic block::

		if (flag) { // Okay
			perform_action();
		}

		if (flag)
		{
			// Okay
			perform_first_action();
			perform_second_action();
		}

		if (flag) { // Not okay.
		    perform_first_action();
		    perform_second_action();
		}

		if (flag)
		{
		    perform_action(); // Frowned upon.
		}


* General recommendations
    * Use the const keyword wherever applicable.
    * Pass function parameters by constant references when possible (i.e. ``void process_string(const std::string& s);``).
    * Avoid global variables.
    * The ``goto`` keyword may be tolerated if it prevents code duplication and does not overly complicate the program flow. In particular, ``goto END;`` constructs can be used to go directly to the cleanup of a function before returning.
    * In order to prevent memory leaks, memory should not be managed manually. Use smart pointers.
    * For better encapsulation, prefer non-member non-friend functions `when adequate <http://cpptips.com/nmemfunc_encap>`_.

Getting Help
============

Here is how you can request some assistance for problems encountered while trying to contribute to the project:

* If you find a bug, or feel that the current API is not exhaustive enough for a something you're trying to do, create an issue on `GitHub <https://github.com/JusticeRage/Manalyze/issues>`_.
* If you find this documentation lacking and don't know how where to begin in order to work on a feature you have in mind, contact the project's maintainer directly over `e-mail <mailto:justicerage(at)manalyzer(dot)org>`_. If the volume gets out of hand, and IRC channel and/or mailing list will be created.
