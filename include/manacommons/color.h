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

#include <iostream>
#include <string>
#ifdef _WIN32
	#include "windows.h"
#else
	#include <unistd.h>
	#include <stdio.h>
#endif

#if defined _WIN32 && !defined DECLSPEC_MANACOMMONS
	#ifdef MANACOMMONS_EXPORT
		#define DECLSPEC_MANACOMMONS    __declspec(dllexport)
	#else
		#define DECLSPEC_MANACOMMONS    __declspec(dllimport)
	#endif
#elif !defined _WIN32 && !defined DECLSPEC_MANACOMMONS
	#define DECLSPEC_MANACOMMONS
#endif

namespace utils
{

enum Color { RED, GREEN, YELLOW, RESET };
enum class LogLevel { OFF = 0, ERROR = 1, WARNING = 2, INFO = 3, DEBUG = 4 };

/**
 *	@brief	Set the font in the terminal to the specified color.
 *
 *	@param	Color c	The new color of the text.
 */
void set_color(Color c);

/**
 *	@brief	Prints the input text to a stream, after having applied color to the terminal.
 *
 *	@param	const std::string& text The text to write.
 *	@param	Color c The color to write the text in.
 *	@param	The stream into which the text should be written.
 *	@param	const std::string& prefix An optional prefix string, which will be displayed in
 *			the default color.
 *	@param	const std::string& suffix An optional suffix string, which will be displayed in
 *			the default color.
 *
 *	@return	A reference to sink, so the operator "<<" can be chained.
 */
DECLSPEC_MANACOMMONS std::ostream& print_colored_text(const std::string& text,
													  Color c,
													  std::ostream& sink = std::cout,
													  const std::string& prefix = "",
													  const std::string& suffix = "");

/**
 *	@brief	Set the global logging level.
 */
DECLSPEC_MANACOMMONS void set_log_level(LogLevel level);

/**
 *	@brief	Retrieve the global logging level.
 */
DECLSPEC_MANACOMMONS LogLevel get_log_level();

/**
 *	@brief	Returns whether a message with the given level should be emitted.
 */
DECLSPEC_MANACOMMONS bool should_log(LogLevel level);

/**
 *	@brief	Parse a logging level from text.
 *
 *	Accepted values are: off, error, warning, info, debug.
 */
DECLSPEC_MANACOMMONS bool parse_log_level(const std::string& value, LogLevel& level);

/**
 *	@brief	Set log level from text.
 *
 *	@return	Whether parsing succeeded.
 */
DECLSPEC_MANACOMMONS bool set_log_level_from_string(const std::string& value);

/**
 *	@brief	Convert log level to text.
 */
DECLSPEC_MANACOMMONS const char* log_level_to_string(LogLevel level);

/**
 *	@brief	Streams used by logging macros.
 */
DECLSPEC_MANACOMMONS std::ostream& error_stream();
DECLSPEC_MANACOMMONS std::ostream& warning_stream();

#define PRINT_ERROR utils::error_stream()
#define PRINT_WARNING utils::warning_stream()


#define LOG_CAP 100

/**
 *	@brief	Checks whether warnings should still be printed.
 */
DECLSPEC_MANACOMMONS bool is_log_cap_reached();

// Macros to add around very verbose warnings to avoid flooding stderr.
#define CAPPED_LOGGING if (!utils::is_log_cap_reached()) {
#define CAPPED_LOGGING_END }

// TODO: Add these macros to all errors and warnings.
#ifdef _DEBUG
	#define DEBUG_INFO " (" << __FILE__ << ":" << std::dec << __LINE__ << ")"
	#define DEBUG_INFO_PE " (" << __FILE__ << ":" << std::dec << __LINE__ << ", " << *pe.get_path() << ")"
	#define DEBUG_INFO_INSIDEPE " (" << __FILE__ << ":" << std::dec << __LINE__ << ", " << *get_path() << ")"
#else
	#define DEBUG_INFO ""
	#define DEBUG_INFO_PE ""
	#define DEBUG_INFO_INSIDEPE ""
#endif

} //namespace utils
