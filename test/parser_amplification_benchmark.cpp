/*
    This file is part of Manalyze.

    Manalyze is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
*/

#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <system_error>
#include <vector>

#include "manape/pe.h"

namespace {

int usage(const char* program, const std::string& message)
{
	if (!message.empty()) std::cerr << message << '\n';
	std::cerr << "Usage: " << program << " --iterations COUNT FILE...\n";
	return EXIT_FAILURE;
}

} // namespace

int main(int argc, char* argv[])
{
	std::uint64_t iterations = 0;
	bool have_iterations = false;
	std::vector<std::string> paths;

	for (int index = 1; index < argc; ++index) {
		const std::string argument(argv[index]);
		if (argument == "--iterations") {
			if (have_iterations || index + 1 >= argc) {
				return usage(argv[0], "--iterations requires exactly one value");
			}
			const std::string value(argv[++index]);
			const auto parsed = std::from_chars(
				value.data(), value.data() + value.size(), iterations);
			if (parsed.ec != std::errc() || parsed.ptr != value.data() + value.size()
					|| iterations == 0) {
				return usage(argv[0], "--iterations must be a positive integer");
			}
			have_iterations = true;
		} else if (!argument.empty() && argument.front() == '-') {
			return usage(argv[0], "Unknown option: " + argument);
		} else {
			paths.push_back(argument);
		}
	}

	if (!have_iterations) return usage(argv[0], "--iterations is required");
	if (paths.empty()) return usage(argv[0], "At least one input file is required");

	std::uint64_t checksum = 0;
	const auto start = std::chrono::steady_clock::now();
	for (std::uint64_t iteration = 0; iteration < iterations; ++iteration) {
		for (const auto& path : paths) {
			mana::PE pe(path);
			if (!pe.is_valid()) {
				std::cerr << "Could not parse input file: " << path << '\n';
				return EXIT_FAILURE;
			}
			checksum += pe.get_filesize();
			checksum += pe.get_sections()->size();
		}
	}
	const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
		std::chrono::steady_clock::now() - start).count();

	std::cout << "{\"elapsed_ns\":" << elapsed
		<< ",\"iterations\":" << iterations
		<< ",\"samples\":" << iterations * paths.size()
		<< ",\"checksum\":" << checksum << "}\n";
	return EXIT_SUCCESS;
}
