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

#include <iostream>
#include <iterator>
#include <string>
#include <vector>
#include <algorithm>

#include <boost/program_options.hpp>
#include <boost/tokenizer.hpp>
#include <boost/filesystem.hpp>
#include <boost/system/api_config.hpp>
#include <boost/assign/list_of.hpp>

#ifdef BOOST_WINDOWS_API
# include <direct.h>
# define chdir _chdir
#else
# include <unistd.h>
#endif

#include "plugin_framework/plugin_manager.h"

#include "config_parser.h"
#include "yara/yara_wrapper.h"

#include "manape/pe.h"
#include "manacommons/color.h"
#include "output_formatter.h"
#include "dump.h"

#define MANALYZE_VERSION "0.9"

#if defined WITH_OPENSSL
# include <openssl/opensslv.h>  // Used to display OpenSSL's version
#endif

namespace po = boost::program_options;
namespace bfs = boost::filesystem;

/**
 *	@brief	Prints the help message of the program.
 *
 *	@param	po::options_description& desc The boost::program_options argument descriptor.
 *	@param	const std::string& argv_0 argv[0], the program name.
 */
void print_help(po::options_description& desc, const std::string& argv_0)
{
	std::cout << desc << std::endl; // Standard usage

	// Plugin description
	std::vector<plugin::pIPlugin> plugins = plugin::PluginManager::get_instance().get_plugins();

	if (plugins.size() > 0)
	{
		std::cout << "Available plugins:" << std::endl;
		for (auto it = plugins.begin() ; it != plugins.end() ; ++it) {
			std::cout << "  - " << *(*it)->get_id() << ": " << *(*it)->get_description() << std::endl;
		}
		std::cout << "  - all: Run all the available plugins." << std::endl;
	}
	std::cout << std::endl;

	std::string filename = bfs::basename(argv_0);
	std::string extension = bfs::extension(argv_0);
	if (extension != "") {
		filename += extension;
	}

	std::cout << "Examples:" << std::endl;
	std::cout << "  " << filename << " program.exe" << std::endl;
	std::cout << "  " << filename << " -dresources -dexports -x out/ program.exe" << std::endl;
	std::cout << "  " << filename << " --dump=imports,sections --hashes program.exe" << std::endl;
	std::cout << "  " << filename << " -r malwares/ --plugins=peid,clamav --dump all" << std::endl;
}

// ----------------------------------------------------------------------------

/**
 *	@brief	Tokenizes arguments received on the command line.
 *
 *	Complex options may be specified multiple times (-dimports -dexports). When the
 *	long argument format is used (--dump=imports,exports), some additional processing
 *	has to take place to break them down.
 *
 *	@param	const std::vector<std::string>& args A vector containing the raw program_options arguments.
 *
 *	@return	A vector containing all the arguments.
 */
std::vector<std::string> tokenize_args(const std::vector<std::string>& args)
{
	// Categories may be comma-separated, so we have to separate them.
	std::vector<std::string> tokenized_args;
	boost::char_separator<char> sep(",");
	for (auto it = args.begin() ; it != args.end() ; ++it)
	{
		boost::tokenizer<boost::char_separator<char> > tokens(*it, sep);
		for (auto tok_iter = tokens.begin() ; tok_iter != tokens.end() ; ++tok_iter) {
			tokenized_args.push_back(*tok_iter);
		}
	}
	return tokenized_args;
}

// ----------------------------------------------------------------------------

/**
 *	@brief	Checks whether the given arguments are valid.
 *
 *	This consists in verifying that:
 *	- All the requested categories for the "dump" command exist
 *	- All the requested plugins exist
 *	- All the input files exist
 *	- The requested output formatter exists
 *
 *	If an error is detected, the help message is displayed.
 *
 *	@param	po::variables_map& vm The parsed arguments.
 *	@param	po::options_description& desc The description of the arguments (only so it can be
 *			passed to print_help if needed).
 *	@param	char** argv The raw arguments (only so it can be passed to print_help if needed).
 *
 *	@return	True if the arguments are all valid, false otherwise.
 */
bool validate_args(po::variables_map& vm, po::options_description& desc, char** argv)
{
	// Verify that the requested categories exist
	if (vm.count("dump"))
	{
		std::vector<std::string> selected_categories = tokenize_args(vm["dump"].as<std::vector<std::string> >());
		const std::vector<std::string> categories = boost::assign::list_of("all")("summary")("dos")("pe")("opt")("sections")
			("imports")("exports")("resources")("version")("debug")("tls")("config")("delay")("rich");
		for (auto it = selected_categories.begin() ; it != selected_categories.end() ; ++it)
		{
			std::vector<std::string>::const_iterator found = std::find(categories.begin(), categories.end(), *it);
			if (found == categories.end())
			{
				print_help(desc, argv[0]);
				std::cout << std::endl;
				PRINT_ERROR << "category " << *it << " does not exist!" << std::endl;
				return false;
			}
		}
	}

	// Verify that the requested plugins exist
	if (vm.count("plugins"))
	{
		std::vector<std::string> selected_plugins = tokenize_args(vm["plugins"].as<std::vector<std::string> >());
		std::vector<plugin::pIPlugin> plugins = plugin::PluginManager::get_instance().get_plugins();
		for (auto it = selected_plugins.begin() ; it != selected_plugins.end() ; ++it)
		{
			if (*it == "all") {
				continue;
			}

			auto found = std::find_if(plugins.begin(), plugins.end(), boost::bind(&plugin::name_matches, *it, _1));
			if (found == plugins.end())
			{
				print_help(desc, argv[0]);
				std::cout << std::endl;
				PRINT_ERROR << "plugin " << *it << " does not exist!" << std::endl;
				return false;
			}
		}
	}

	// Verify that all the input files exist.
	std::vector<std::string> input_files = vm["pe"].as<std::vector<std::string> >();
	for (auto it = input_files.begin() ; it != input_files.end() ; ++it)
	{
		if (!bfs::exists(*it))
		{
			PRINT_ERROR << *it << " not found!" << std::endl;
			return false;
		}
	}

	// Verify that the requested output formatter exists
	if (vm.count("output"))
	{
		auto formatters = boost::assign::list_of("raw")("json");
		auto found = std::find(formatters.begin(), formatters.end(), vm["output"].as<std::string>());
		if (found == formatters.end())
		{
			print_help(desc, argv[0]);
			std::cout << std::endl;
			PRINT_ERROR << "output formatter " << vm["output"].as<std::string>() << " does not exist!" << std::endl;
			return false;
		}
	}

	return true;
}

// ----------------------------------------------------------------------------

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
		("version,v", "Prints the program's version.")
		("pe", po::value<std::vector<std::string> >(), "The PE to analyze. Also accepted as a positional argument. "
			"Multiple files may be specified.")
		("recursive,r", "Scan all files in a directory (subdirectories will be ignored).")
		("output,o", po::value<std::string>(), "The output format. May be 'raw' (default) or 'json'.")
		("dump,d", po::value<std::vector<std::string> >(),
			"Dump PE information. Available choices are any combination of: "
			"all, summary, dos (dos header), pe (pe header), opt (pe optional header), sections, "
			"imports, exports, resources, version, debug, tls, config (image load configuration), "
			"delay (delay-load table), rich")
		("hashes", "Calculate various hashes of the file (may slow down the analysis!)")
		("extract,x", po::value<std::string>(), "Extract the PE resources and authenticode certificates "
			"to the target directory.")
		("plugins,p", po::value<std::vector<std::string> >(),
			"Analyze the binary with additional plugins. (may slow down the analysis!)");


	po::positional_options_description p;
	p.add("pe", -1);

	try
	{
		po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
		po::notify(vm);
	}
	catch(po::error& e)
	{
		PRINT_ERROR << "Could not parse the command line (" << e.what() << ")." << std::endl << std::endl;
		return false;
	}

	if (vm.count("version"))
	{
		std::stringstream ss;
		ss << "Manalyze " MANALYZE_VERSION " (Ivan Kwiatkowski, GPLv3 License) compiled with:" << std::endl;
		ss << "* Boost " BOOST_LIB_VERSION " (Boost.org, Boost Software License)" << std::endl;
		ss << "* Yara " << YR_MAJOR_VERSION << "." << YR_MINOR_VERSION << "." << YR_MICRO_VERSION << ". (Victor M. Alvarez, Apache 2.0 License)" << std::endl;
		ss << "* hash-library " << HASH_LIBRARY_VERSION << " (Stephan Brumme, ZLib License)." << std::endl;
		#if defined WITH_OPENSSL
			ss << "* " << OPENSSL_VERSION_TEXT << " (OpenSSL Project, OpenSSL License)" << std::endl;
		#endif
		std::cout << ss.str();
		exit(0);
	}
	else if (vm.count("help") || !vm.count("pe"))
	{
		print_help(desc, argv[0]);
		exit(0);
	}

	return validate_args(vm, desc, argv);
}

// ----------------------------------------------------------------------------

/**
 *	@brief	Dumps select information from a PE.
 *
 *	@param	io::OutputFormatter& formatter The object which will receive the output.
 *	@param	const std::vector<std::string>& categories The types of information to dump.
 *			For the list of accepted categories, refer to the program help or the source
 *			below.
 *	@param	const mana::PE& pe The PE to dump.
 *	@param	bool compute_hashes Whether hashes should be calculated.
 */
void handle_dump_option(io::OutputFormatter& formatter, const std::vector<std::string>& categories, bool compute_hashes, const mana::PE& pe)
{
	bool dump_all = (std::find(categories.begin(), categories.end(), "all") != categories.end());
	if (dump_all || std::find(categories.begin(), categories.end(), "summary") != categories.end()) {
		mana::dump_summary(pe, formatter);
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "dos") != categories.end())	{
		mana::dump_dos_header(pe, formatter);
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "pe") != categories.end()) {
		mana::dump_pe_header(pe, formatter);
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "opt") != categories.end()) {
		mana::dump_image_optional_header(pe, formatter);
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "sections") != categories.end()) {
		mana::dump_section_table(pe, formatter, compute_hashes);
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "imports") != categories.end()) {
		mana::dump_imports(pe, formatter);
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "exports") != categories.end()) {
		mana::dump_exports(pe, formatter);
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "resources") != categories.end()) {
		mana::dump_resources(pe, formatter, compute_hashes);
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "version") != categories.end()) {
		mana::dump_version_info(pe, formatter);
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "debug") != categories.end()) {
		mana::dump_debug_info(pe, formatter);
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "tls") != categories.end()) {
		mana::dump_tls(pe, formatter);
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "config") != categories.end()) {
		mana::dump_config(pe, formatter);
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "delay") != categories.end()) {
		mana::dump_dldt(pe, formatter);
	}
	if (dump_all || std::find(categories.begin(), categories.end(), "rich") != categories.end()) {
		mana::dump_rich_header(pe, formatter);
	}
}

// ----------------------------------------------------------------------------

/**
 *	@brief	Analyze the PE with each selected plugin.
 *
 *	@param	io::OutputFormatter& formatter The object which will receive the output.
 *	@param	const std::vector<std::string>& selected The names of the selected plugins.
 *	@param	const config& conf The configuration of the plugins.
 *	@param	const mana::PE& pe The PE to analyze.
 */
void handle_plugins_option(io::OutputFormatter& formatter,
						   const std::vector<std::string>& selected,
						   const config& conf,
						   const mana::PE& pe)
{
	bool all_plugins = std::find(selected.begin(), selected.end(), "all") != selected.end();
	std::vector<plugin::pIPlugin> plugins = plugin::PluginManager::get_instance().get_plugins();
	io::pNode plugins_node(new io::OutputTreeNode("Plugins", io::OutputTreeNode::LIST));

	for (auto it = plugins.begin() ; it != plugins.end() ; ++it)
	{
		// Verify that the plugin was selected
		if (!all_plugins && std::find(selected.begin(), selected.end(), *(*it)->get_id()) == selected.end()) {
			continue;
		}

		// Forward relevant configuration elements to the plugin.
		if (conf.count(*(*it)->get_id())) {
			(*it)->set_config(conf.at(*(*it)->get_id()));
		}

		plugin::pResult res = (*it)->analyze(pe);
		if (!res)
		{
			PRINT_WARNING << "Plugin " << *(*it)->get_id() << " returned a NULL result!" << std::endl;
			continue;
		}

		io::pNode output = res->get_output();
		if (!output || !res->get_information()->size()) {
			continue;
		}
		plugins_node->append(output);
	}

	formatter.add_data(plugins_node, *pe.get_path());
}

// ----------------------------------------------------------------------------

/**
 *	@brief	Returns all the input files of the application
 *
 *	When the recursive option is specified, this function returns all the files in
 *	the requested directory (or directories).
 *
 *	@param	po::variables_map& vm The (parsed) arguments of the application.
 *
 *	@return	A set (to weed out duplicates) containing all the files to analyze.
 */
std::set<std::string> get_input_files(po::variables_map& vm)
{
	std::set<std::string> targets;
	if (vm.count("recursive"))
	{
		std::vector<std::string> input = vm["pe"].as<std::vector<std::string> >();
		for (auto it = input.begin() ; it != input.end() ; ++it)
		{
			if (!bfs::is_directory(*it))
			{
				#if defined BOOST_WINDOWS_API
					std::string path = bfs::absolute(*it).string();
					std::replace(path.begin(), path.end(), '\\', '/');
					targets.insert(path);
				#else
					targets.insert(bfs::absolute(*it).string());
				#endif
			}
			else
			{
				bfs::directory_iterator end;
				for (bfs::directory_iterator dit(*it) ; dit != end ; ++dit)
				{
					if (!bfs::is_directory(*dit)) { // Ignore subdirectories
					#if defined BOOST_WINDOWS_API
						std::string path = bfs::absolute(dit->path()).string();
						std::replace(path.begin(), path.end(), '\\', '/');
						targets.insert(path);
					#else
						targets.insert(bfs::absolute(dit->path()).string());
					#endif
					}
				}
			}
		}
	}
	else
	{
		auto vect = vm["pe"].as<std::vector<std::string> >();
		for (auto it = vect.begin() ; it != vect.end() ; ++it)
		{
			if (!bfs::is_directory(*it)) {
				#if defined BOOST_WINDOWS_API
					std::string path = bfs::absolute(*it).string();
					std::replace(path.begin(), path.end(), '\\', '/');
					targets.insert(path);
				#else
					targets.insert(bfs::absolute(*it).string());
				#endif
			}
			else {
				PRINT_WARNING << *it << " is a directory. Skipping (use the -r option for recursive analyses)." << std::endl;
			}
		}
	}
	return targets;
}

// ----------------------------------------------------------------------------

/**
 *	@brief	Does the actual analysis
 */
void perform_analysis(const std::string& path,
					  po::variables_map& vm,
					  const std::string& extraction_directory,
					  const std::vector<std::string> selected_categories,
					  const std::vector<std::string> selected_plugins,
					  const config& conf,
					  boost::shared_ptr<io::OutputFormatter> formatter)
{
	mana::PE pe(path);

	// Try to parse the PE
	if (!pe.is_valid())
	{
		PRINT_ERROR << "Could not parse " << path << "!" << std::endl;
		yara::Yara y = yara::Yara();
		// In case of failure, we try to detect the file type to inform the user.
		// Maybe they made a mistake and specified a wrong file?
		if (bfs::exists(path) &&
			!bfs::is_directory(path) &&
			y.load_rules("yara_rules/magic.yara"))
		{
			yara::const_matches m = y.scan_file(*pe.get_path());
			if (m && m->size() > 0)
			{
				std::cerr << "Detected file type(s):\t" << std::endl;
				for (auto it = m->begin() ; it != m->end() ; ++it) {
					std::cerr << (*it)->operator[]("description") << std::endl;
				}
			}
		}
		std::cerr << std::endl;
		return;
	}

	if (vm.count("dump")) {
		handle_dump_option(*formatter, selected_categories, vm.count("hashes") != 0, pe);
	}
	else { // No specific info requested. Display the summary of the PE.
		dump_summary(pe, *formatter);
	}


	if (vm.count("extract")) // Extract resources if requested 
	{
		mana::extract_resources(pe, extraction_directory);
		mana::extract_authenticode_certificates(pe, extraction_directory);
	}

	if (vm.count("hashes")) {
		dump_hashes(pe, *formatter);
	}

	if (vm.count("plugins")) {
		handle_plugins_option(*formatter, selected_plugins, conf, pe);
	}
}

// ----------------------------------------------------------------------------

int main(int argc, char** argv)
{
	po::variables_map vm;
	std::string extraction_directory;
	std::vector<std::string> selected_plugins, selected_categories;

	// Load the dynamic plugins.
	bfs::path working_dir(argv[0]);
	working_dir = working_dir.parent_path();
	if (working_dir.empty()) {	// cmd.exe does not provide the full path to the executable.
		working_dir = ".";		// Running ./manalyze.exe results in working_dir being empty,
	}							// which makes this additional check necessary.

	// Linux: look for the configuration file in /etc/manalyze if
	// nothing is found in the current folder.
	#ifdef BOOST_POSIX_API
		if (!bfs::exists(working_dir / "manalyze.conf")) {
			working_dir = "/etc/manalyze";
		}
	#endif

	plugin::PluginManager::get_instance().load_all(working_dir.string());

	// Load the configuration
	config conf = parse_config((working_dir / "manalyze.conf").string());

	if (!parse_args(vm, argc, argv)) {
		return -1;
	}

	// Get all the paths now and make them absolute before changing the working directory
	std::set<std::string> targets = get_input_files(vm);
	if (vm.count("extract")) {
		extraction_directory = bfs::absolute(vm["extract"].as<std::string>()).string();
	}
	// Break complex arguments into a list once and for all.
	if (vm.count("plugins")) {
		selected_plugins = tokenize_args(vm["plugins"].as<std::vector<std::string> >());
	}
	if (vm.count("dump")) {
		selected_categories = tokenize_args(vm["dump"].as<std::vector<std::string> >());
	}

	// Instantiate the requested OutputFormatter
	boost::shared_ptr<io::OutputFormatter> formatter;
	if (vm.count("output") && vm["output"].as<std::string>() == "json") {
		formatter.reset(new io::JsonFormatter());
	}
	else // Default: use the human-readable output.
	{
		formatter.reset(new io::RawFormatter());
		formatter->set_header("* Manalyze " MANALYZE_VERSION " *");
	}

	// Set the working directory to Manalyze's folder.
	chdir(working_dir.string().c_str());

	// Do the actual analysis on all the input files
	unsigned int count = 0;
	for (auto it = targets.begin() ; it != targets.end() ; ++it)
	{
		perform_analysis(*it, vm, extraction_directory, selected_categories, selected_plugins, conf, formatter);
		if (++count % 1000 == 0) {
			formatter->format(std::cout, false); // Flush the formatter from time to time, to avoid eating up all the RAM when analyzing gigs of files.
		}
	}

	formatter->format(std::cout);

	if (vm.count("plugins"))
	{
		// Explicitly unload the plugins
		plugin::PluginManager::get_instance().unload_all();
	}

	return 0;
}
