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

#include "pe.h"
#include "resources.h"
#include "mandiant_modules.h"
#include "yara_wrapper.h"

namespace po = boost::program_options;

/**
 *	@brief	Parses and validates the command line options of the application.
 *
 *	@param	po::variables_map& vm The destination for parsed arguments
 *	@param	int argc The number of arguments
 *	@param	char**argv The raw arguments
 */
void parse_args(po::variables_map& vm, int argc, char**argv)
{
	po::options_description desc("Usage");
	desc.add_options()
		("help,h", "Displays this message.")
		("pe,p", po::value<std::string>(), "The PE to analyze. Also accepted as a positional argument.")
		("recursive,r", "Scan all files in a directory (subdirectories will be ignored).")
		("dump,d", po::value<std::vector<std::string> >(), 
			"Dumps PE information. Available choices are any combination of: "
			"all, dos (dos header), pe (pe header), optpe optional header() sections, imports, "
			"exports, resources, version, debug, tls, certificates, relocations")
		("extract,x", po::value<std::string>(), "Extract the PE resources to the target directory.")
		("peid", "Use PEiD signatures to determine packer/compiler info (may slow down the analysis!)")
		("clamav", "Use ClamAV signatures to check for known viruses (may slow down the analysis!)");


	po::positional_options_description p;
	p.add("pe", 1);

	try
	{
		po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
		po::notify(vm);
	}
	catch(po::error& e)	{
		std::cerr << "[!] Error: Could not parse command line (" << e.what() << ")." << std::endl << std::endl;
	}

	if (vm.count("help") || !vm.count("pe")) 
	{
		std::cout << desc << std::endl;
		// Examples
		exit(1);
	}
}

/**
 *	@brief	Dumps select information from a PE.
 *
 *	@param	const std::vector<std::string>& categories The types of information to dump.
 *			For the list of accepted categories, refer to the program help or the source
 *			below.
 *	@param	const sg::PE& pe The PE to dump.
 */
void handle_dump_option(const std::vector<std::string>& categories, const sg::PE& pe)
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
		pe.dump_section_table();
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "imports") != categories.end()) {
		pe.dump_imports();
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "exports") != categories.end()) {
		pe.dump_exports();
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "resources") != categories.end()) {
		pe.dump_resources();
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

int main(int argc, char** argv)
{
	std::cout << "* SGStatic 0.8 *" << std::endl << std::endl;
	po::variables_map vm;
	yara::Yara y_peid;
	yara::Yara y_clamav;

	parse_args(vm, argc, argv);

	// Recursive scan?

	sg::PE pe(vm["pe"].as<std::string>());

	// Load Yara if required
	if (vm.count("peid")) 
	{
		if (!y_peid.load_rules("resources/peid.yara")) 
		{
			std::cerr << "[!] Error: Could not load PEiD signatures!" << std::endl;
			exit(1);
		}
	}
	if (vm.count("clamav")) 
	{
		if (!y_clamav.load_rules("resources/clamav.yara")) 
		{
			std::cerr << "[!] Error: Could not load ClamAV signatures!" << std::endl;
			exit(1);
		}
	}
    
	// Try to parse the PE
	if (!pe.is_valid()) 
	{
		std::cerr << "[!] Error: Could not parse " << vm["pe"].as<std::string>() << "!" << std::endl;
        yara::Yara y = yara::Yara();
		// In case of failure, we try to detect the file type to inform the user.
		// Maybe he made a mistake and specified a wrong file?
		if (y.load_rules("resources/magic.yara"))
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
		return -1;
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

		handle_dump_option(categories, pe);
	}
	else // No specific info required. Display the summary of the PE.
	{
		pe.dump_summary();
	}

	
	if (vm.count("extract")) {
		pe.extract_resources(vm["extract"].as<std::string>());
	}

	if (vm.count("peid")) 
	{
		yara::matches m = y_peid.scan_file(pe.get_path());
		if (m.size() > 0) 
		{
			std::cout << "PEiD Signature:" << std::endl;
			for (yara::matches::iterator it = m.begin() ; it != m.end() ; ++it) {
				std::cout << "\t" << (*it)->operator[]("packer_name") << std::endl;
			}
		}
	}

	if (vm.count("clamav")) 
	{
		yara::matches m = y_clamav.scan_file(pe.get_path());
		if (m.size() > 0) 
		{
			std::cout << "ClamAV Signature:" << std::endl;
			for (yara::matches::iterator it = m.begin() ; it != m.end() ; ++it) {
				std::cout << "\t" << (*it)->operator[]("signature") << std::endl;
			}
		}
	}

	return 0;
}
