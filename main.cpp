/*
    This file is part of Spike Guard.

    Spike Guard is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Spike Guard is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Spike Guard.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <iostream>
#include <iterator>
#include <string>
#include <vector>
#include <algorithm>

#include <boost/program_options.hpp>
#include <boost/tokenizer.hpp>
#include <boost/filesystem.hpp>

#include "plugin/plugin_manager.h"

#include "pe.h"
#include "resources.h"
#include "mandiant_modules.h"
#include "yara_wrapper.h"
#include "color.h"

namespace po = boost::program_options;

/**
 *	@brief	Parses and validates the command line options of the application.
 *
 *	@param	po::variables_map& vm The destination for parsed arguments
 *	@param	int argc The number of arguments
 *	@param	char**argv The raw arguments
 *
 *	@return	Whether the arguments are valid.
 */
bool parse_args(po::variables_map& vm, int argc, char**argv)
{
	po::options_description desc("Usage");
	desc.add_options()
		("help,h", "Displays this message.")
		("pe,p", po::value<std::vector<std::string> >(), "The PE to analyze. Also accepted as a positional argument. "
			"Multiple files may be specified.")
		("recursive,r", "Scan all files in a directory (subdirectories will be ignored).")
		("dump,d", po::value<std::vector<std::string> >(), 
			"Dumps PE information. Available choices are any combination of: "
			"all, dos (dos header), pe (pe header), opt (pe optional header) sections, imports, "
			"exports, resources, version, debug, tls, certificates, relocations")
		("hashes", "Calculate various hashes of the file (may slow down the analysis!)")
		("extract,x", po::value<std::string>(), "Extract the PE resources to the target directory.")
		("plugins", "Analyze the binary with additional plugins. (may slow down the analysis!)");


	po::positional_options_description p;
	p.add("pe", -1);

	try
	{
		po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
		po::notify(vm);
	}
	catch(po::error& e)	
	{
		PRINT_ERROR << "Could not parse command line (" << e.what() << ")." << std::endl << std::endl;
		return false;
	}

	if (vm.count("help") || !vm.count("pe")) 
	{
		std::cout << desc << std::endl;
		// TODO: Examples
		return false;
	}

	// Verify that all the input files exist.
	std::vector<std::string> input_files = vm["pe"].as<std::vector<std::string> >();
	for (std::vector<std::string>::iterator it = input_files.begin() ; it != input_files.end() ; ++it)
	{
		if (!boost::filesystem::exists(*it))
		{
			PRINT_ERROR << *it << " not found!" << std::endl;
			return false;
		}
	}
	return true;
}

/**
 *	@brief	Dumps select information from a PE.
 *
 *	@param	const std::vector<std::string>& categories The types of information to dump.
 *			For the list of accepted categories, refer to the program help or the source
 *			below.
 *	@param	const sg::PE& pe The PE to dump.
 *	@param	bool compute_hashes Whether hashes should be calculated.
 */
void handle_dump_option(const std::vector<std::string>& categories, bool compute_hashes, const sg::PE& pe)
{
	bool dump_all = (std::find(categories.begin(), categories.end(), "all") != categories.end());
	if (dump_all || std::find(categories.begin(), categories.end(), "dos") != categories.end()) {
		pe.dump_dos_header();
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "pe") != categories.end()) {
		pe.dump_pe_header();
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "opt") != categories.end()) {
		pe.dump_image_optional_header();
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "sections") != categories.end()) {
		pe.dump_section_table(std::cout, compute_hashes);
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "imports") != categories.end()) {
		pe.dump_imports();
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "exports") != categories.end()) {
		pe.dump_exports();
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "resources") != categories.end()) {
		pe.dump_resources(std::cout, compute_hashes);
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "version") != categories.end()) {
		pe.dump_version_info();
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "debug") != categories.end()) {
		pe.dump_debug_info();
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "relocations") != categories.end()) {
		pe.dump_relocations();
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "tls") != categories.end()) {
		pe.dump_tls();
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "certificates") != categories.end()) {
		pe.dump_certificates();
	}
}

/**
 *	@brief	Returns all the input files of the application
 *
 *	When the recursive option is specified, this function returns all the files in 
 *	the requested directory (or directories).
 *
 *	@param	po::variables_map& vm The (parsed) arguments of the application.
 *
 *	@return	A vector containing all the files to analyze.
 */
std::vector<std::string> get_input_files(po::variables_map& vm)
{
	std::vector<std::string> targets;
	if (vm.count("recursive")) 
	{
		std::vector<std::string> input = vm["pe"].as<std::vector<std::string> >();
		for (std::vector<std::string>::iterator it = input.begin() ; it != input.end() ; ++it)
		{
			if (!boost::filesystem::is_directory(*it)) {
				targets.push_back(*it);
			}
			else
			{
				boost::filesystem::directory_iterator end;
				for (boost::filesystem::directory_iterator dit(*it) ; dit != end ; ++dit)
				{
					if (!boost::filesystem::is_directory(*dit)) { // Ignore subdirectories
						targets.push_back(dit->path().string());
					}
				}
			}
		}
	}
	else {
		targets = vm["pe"].as<std::vector<std::string> >();
	}
	return targets;
}

int main(int argc, char** argv)
{
	std::cout << "* SGStatic 0.8 *" << std::endl << std::endl;
	po::variables_map vm;

	if (!parse_args(vm, argc, argv)) {
		return -1;
	}

	// Instantiate plugins now, and only once in case they have a long setup time.
	std::vector<plugin::pIPlugin> plugins;
	if (vm.count("plugins")) {
		plugins = plugin::PluginManager::get_instance().get_plugins();
	}

	// Perform analysis on all the input files
	std::vector<std::string> targets = get_input_files(vm);
	for (std::vector<std::string>::iterator it = targets.begin() ; it != targets.end() ; ++it)
	{
		sg::PE pe(*it);
		
		// Try to parse the PE
		if (!pe.is_valid()) 
		{
			PRINT_ERROR << "Could not parse " << *it << "!" << std::endl;
			yara::Yara y = yara::Yara();
			// In case of failure, we try to detect the file type to inform the user.
			// Maybe he made a mistake and specified a wrong file?
			if (boost::filesystem::exists(*it) && 
				!boost::filesystem::is_directory(*it) && 
				y.load_rules("resources/magic.yara"))
			{
				yara::matches m = y.scan_file(pe.get_path());
				if (m.size() > 0) 
				{
					std::cerr << "Detected file type(s):" << std::endl;
					for (yara::matches::iterator it = m.begin() ; it != m.end() ; ++it) {
						std::cerr << "\t" << (*it)->operator[]("description") << std::endl;
					}
				}	
			}
			std::cerr << std::endl;
			continue;
		}

		if (vm.count("dump")) 
		{
			// Categories may be comma-separated, so we have to separate them.
			std::vector<std::string> categories;
			boost::char_separator<char> sep(",");
			std::vector<std::string> dump_args = vm["dump"].as<std::vector<std::string> >();
			for (std::vector<std::string>::iterator it = dump_args.begin() ; it != dump_args.end() ; ++it)
			{
				boost::tokenizer<boost::char_separator<char> > tokens(*it, sep);
				for (boost::tokenizer<boost::char_separator<char> >::iterator tok_iter = tokens.begin();
					 tok_iter != tokens.end();
					 ++tok_iter) 
				{
					categories.push_back(*tok_iter);
				}
			}

			handle_dump_option(categories, vm.count("hashes") != 0, pe);
		}
		else { // No specific info required. Display the summary of the PE.
			pe.dump_summary();
		}

	
		if (vm.count("extract")) { // Extract resources if requested
			pe.extract_resources(vm["extract"].as<std::string>());
		}

		if (vm.count("hashes")) {
			pe.dump_hashes();
		}

		if (vm.count("plugins")) 
		{
			for (std::vector<plugin::pIPlugin>::iterator it = plugins.begin() ; it != plugins.end() ; ++it) 
			{
				plugin::pResult res = (*it)->analyze(pe);
				plugin::Result::pInformation info = res->get_information();
				plugin::Result::pString summary = res->get_summary();
				
				if (!info) {
					continue;
				}
				switch (res->get_level())
				{
					case plugin::Result::NO_OPINION:
						break;
					
					case plugin::Result::MALICIOUS:
						utils::print_colored_text("DANGEROUS", utils::RED, std::cout, "[ ", " ] ");
						break;

					case plugin::Result::SUSPICIOUS:
						utils::print_colored_text("SUSPICIOUS", utils::YELLOW, std::cout, "[ ", " ]");
						break;

					case plugin::Result::SAFE:
						utils::print_colored_text("SAFE", utils::GREEN, std::cout, "[ ", " ]");
						break;
				}

				if (summary) {
					std::cout << *summary << std::endl;
				}

				for (std::vector<std::string>::iterator it2 = info->begin() ; it2 != info->end() ; ++it2) {
					std::cout << "\t" << *it2 << std::endl;
				}
				if (info->size() > 0) {
					std::cout << std::endl;
				}
			}
		}

		if (it != targets.end() - 1) {
			std::cout << "--------------------------------------------------------------------------------" << std::endl << std::endl;
		}
	}

	return 0;
}
