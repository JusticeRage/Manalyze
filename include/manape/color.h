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

// Pretty printing functions from manacommons are only imported if available.
// This makes it easier to take the parser out of Manalyze and re-use it for other stuff.
#if defined WITH_MANACOMMONS
# include "manacommons/color.h"
#else
# define PRINT_ERROR std::cerr << "[!] Error: "
# define PRINT_WARNING std::cerr << "[*] Warning: "

# ifdef _DEBUG
#  define DEBUG_INFO " (" << __FILE__ << ":" << std::dec << std::dec << __LINE__ << ")"
#  define DEBUG_INFO_PE " (" << __FILE__ << ":" << std::dec << __LINE__ << ", " << *pe.get_path() << ")"
#  define DEBUG_INFO_INSIDEPE " (" << __FILE__ << ":" << std::dec << __LINE__ << ", " << *get_path() << ")"
# else
#  define DEBUG_INFO ""
#  define DEBUG_INFO_PE ""
#  define DEBUG_INFO_INSIDEPE ""
# endif
#endif
