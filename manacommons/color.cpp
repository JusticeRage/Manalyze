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

#include "manacommons/color.h"

#include <algorithm>
#include <atomic>
#include <cctype>

namespace utils
{

namespace {

class NullBuffer : public std::streambuf
{
public:
	int overflow(int c) override { return c; }
};

std::ostream& null_stream()
{
	static NullBuffer buffer;
	static std::ostream sink(&buffer);
	return sink;
}

std::atomic<LogLevel>& global_log_level()
{
	static std::atomic<LogLevel> level(LogLevel::WARNING);
	return level;
}

std::string lowercase(std::string value)
{
	std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
		return static_cast<char>(std::tolower(c));
	});
	return value;
}

} // namespace

#ifdef _WIN32

void set_color(Color c)
{
	HANDLE h = ::GetStdHandle(STD_OUTPUT_HANDLE);
	if (h == INVALID_HANDLE_VALUE) {
		return;
	}

	// Save console style on the first call. This is needed as cmd.exe and powershell.exe use different background and text colors.
	CONSOLE_SCREEN_BUFFER_INFO info;
	static WORD background = 0xFFFF;
	static WORD foreground = FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE; // Default to white.
	if (background == 0xFFFF)
	{
		if (!::GetConsoleScreenBufferInfo(h, &info)) {
			background = 0;  // Default to black.
		}
		else 
		{
			background = info.wAttributes & (BACKGROUND_BLUE | BACKGROUND_GREEN | BACKGROUND_INTENSITY | BACKGROUND_RED);
			foreground = info.wAttributes & (FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
		}
	}

	switch(c)
	{
	case RED:
		::SetConsoleTextAttribute(h, FOREGROUND_INTENSITY | FOREGROUND_RED | background);
		break;
	case GREEN:
		::SetConsoleTextAttribute(h, FOREGROUND_INTENSITY | FOREGROUND_GREEN | background);
		break;
	case YELLOW:
		::SetConsoleTextAttribute(h, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | background);
		break;
	case RESET:
		::SetConsoleTextAttribute(h, foreground | background);
		break;
	}

	// The handle should not be closed, otherwise writing to stdout will become impossible.
}

#else // Unix implementation

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_RESET   "\x1b[0m"

void set_color(Color c)
{
	if (!isatty(fileno(stdout))) {
		return;
	}
	switch (c)
	{
	case RED:
		std::cout << ANSI_COLOR_RED;
		break;
	case YELLOW:
		std::cout << ANSI_COLOR_YELLOW;
		break;
	case GREEN:
		std::cout << ANSI_COLOR_GREEN;
		break;
	case RESET:
		std::cout << ANSI_COLOR_RESET;
		break;
	}
}

#endif

std::ostream& print_colored_text(const std::string& text,
								 Color c,
								 std::ostream& sink,
								 const std::string& prefix,
								 const std::string& suffix)
{
	sink << prefix;
	set_color(c);
	sink << text;
	set_color(RESET);
	return sink << suffix;
}

void set_log_level(LogLevel level)
{
	global_log_level().store(level, std::memory_order_relaxed);
}

LogLevel get_log_level()
{
	return global_log_level().load(std::memory_order_relaxed);
}

bool should_log(LogLevel level)
{
	return static_cast<int>(get_log_level()) >= static_cast<int>(level);
}

bool parse_log_level(const std::string& value, LogLevel& level)
{
	const std::string normalized = lowercase(value);
	if (normalized == "off") {
		level = LogLevel::OFF;
		return true;
	}
	if (normalized == "error") {
		level = LogLevel::ERROR;
		return true;
	}
	if (normalized == "warning") {
		level = LogLevel::WARNING;
		return true;
	}
	if (normalized == "info") {
		level = LogLevel::INFO;
		return true;
	}
	if (normalized == "debug") {
		level = LogLevel::DEBUG;
		return true;
	}
	return false;
}

bool set_log_level_from_string(const std::string& value)
{
	LogLevel level;
	if (!parse_log_level(value, level)) {
		return false;
	}
	set_log_level(level);
	return true;
}

const char* log_level_to_string(LogLevel level)
{
	switch (level)
	{
	case LogLevel::OFF:
		return "off";
	case LogLevel::ERROR:
		return "error";
	case LogLevel::WARNING:
		return "warning";
	case LogLevel::INFO:
		return "info";
	case LogLevel::DEBUG:
		return "debug";
	default:
		return "warning";
	}
}

std::ostream& error_stream()
{
	if (!should_log(LogLevel::ERROR)) {
		return null_stream();
	}
	return print_colored_text("!", RED, std::cerr, "[", "] Error: ");
}

std::ostream& warning_stream()
{
	if (!should_log(LogLevel::WARNING)) {
		return null_stream();
	}
	return print_colored_text("*", YELLOW, std::cerr, "[", "] Warning: ");
}

bool is_log_cap_reached()
{
	if (!should_log(LogLevel::WARNING)) {
		return true;
	}

	static unsigned int log_count = 0;
	if (++log_count < LOG_CAP) {
		return false;
	}
	else if (log_count == LOG_CAP) {
		PRINT_ERROR << "Logging cap reached. Further verbose warnings will be ignored." << std::endl;
	}
	return true;
}

}
