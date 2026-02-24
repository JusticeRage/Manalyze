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
#include <string>
#include <vector>
#include <algorithm>
#include <future>
#include <set>
#include <sstream>
#include <utility>
#include <optional>

#include <filesystem>

#include "CLI11.hpp"

#ifdef _WIN32
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
#include "manacommons/paths.h"
#include "output_formatter.h"
#include "dump.h"
#include "cli.h"
#include "manalyze_version.h"

#if defined WITH_OPENSSL
# include <openssl/opensslv.h>  // Used to display OpenSSL's version
#endif

namespace bfs = std::filesystem;

namespace {

void apply_early_log_level_from_argv(int argc, char** argv)
{
	std::optional<utils::LogLevel> selected;
	for (int i = 1; i < argc; ++i)
	{
		const std::string arg = argv[i];
		if (arg == "-q" || arg == "--quiet")
		{
			selected = utils::LogLevel::ERROR;
			continue;
		}

		std::string value;
		if (arg.rfind("--log-level=", 0) == 0) {
			value = arg.substr(std::string("--log-level=").size());
		}
		else if (arg == "--log-level" && i + 1 < argc) {
			value = argv[++i];
		}

		if (!value.empty())
		{
			utils::LogLevel level = utils::LogLevel::WARNING;
			if (utils::parse_log_level(value, level)) {
				selected = level;
			}
		}
	}

	if (selected) {
		utils::set_log_level(*selected);
	}
}

} // namespace

/**
 *	@brief	Prints the help message of the program.
 *
 *	@param	CLI::App& app The CLI11 application descriptor.
 *	@param	const std::string& argv_0 argv[0], the program name.
 */
void print_help(const CLI::App& app, const std::string& argv_0)
{
	std::string help = app.help();
	std::istringstream help_stream(help);
	std::ostringstream help_out;
	std::string line;
	bool first_line = true;
	bool skipped_blank = false;
	while (std::getline(help_stream, line))
	{
		if (first_line)
		{
			if (line.rfind("Usage", 0) == 0) {
				line = "Usage:";
			}
			first_line = false;
		}
		else if (!skipped_blank && line.empty())
		{
			skipped_blank = true;
			continue;
		}
		help_out << line;
		if (!help_stream.eof()) {
			help_out << '\n';
		}
	}
	std::cout << help_out.str() << std::endl; // Standard usage

	// Plugin description
	std::vector<plugin::pIPlugin> plugins = plugin::PluginManager::get_instance().get_plugins();

	if (!plugins.empty())
	{
		std::cout << "Available plugins:" << std::endl;
		for (const auto& it : plugins) {
			std::cout << "  - " << *it->get_id() << ": " << *it->get_description() << std::endl;
		}
		std::cout << "  - all: Run all the available plugins." << std::endl;
	}
	std::cout << std::endl;

	bfs::path argv_path(argv_0);
	std::string filename = argv_path.stem().string();
	std::string extension = argv_path.extension().string();
	if (!extension.empty()) {
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
 *	@param	Options& opts The parsed arguments.
 *	@param	CLI::App& app The description of the arguments (only so it can be
 *			passed to print_help if needed).
 *	@param	char** argv The raw arguments (only so it can be passed to print_help if needed).
 *
 *	@return	True if the arguments are all valid, false otherwise.
 */
bool validate_args(const Options& opts, const CLI::App& app, char** argv)
{
	// Verify that the requested categories exist
	if (!opts.dump.empty())
	{
		const auto& selected_categories = opts.dump;
		const std::vector<std::string> categories = {"all", "summary", "dos", "pe", "opt", "sections", "imports", "exports", "resources", "version", "debug", "tls", "config", "delay", "rich"};
		for (const auto& it : selected_categories)
		{
			auto found = std::find(categories.begin(), categories.end(), it);
			if (found == categories.end())
			{
				print_help(app, argv[0]);
				std::cout << std::endl;
				PRINT_ERROR << "category " << it << " does not exist!" << std::endl;
				return false;
			}
		}
	}

	// Verify that the requested plugins exist
	if (!opts.plugins.empty())
	{
		const auto& selected_plugins = opts.plugins;
		std::vector<plugin::pIPlugin> plugins = plugin::PluginManager::get_instance().get_plugins();
		for (const auto& it : selected_plugins)
		{
			if (it == "all") {
				continue;
			}

			auto found = std::find_if(plugins.begin(), plugins.end(), [&](const plugin::pIPlugin& plugin) {
				return plugin::name_matches(it, plugin);
			});
			if (found == plugins.end())
			{
				print_help(app, argv[0]);
				std::cout << std::endl;
				PRINT_ERROR << "plugin " << it << " does not exist!" << std::endl;
				return false;
			}
		}
	}

	// Verify that all the input files exist.
	for (const auto& it : opts.pe)
	{
		if (!bfs::exists(it))
		{
			PRINT_ERROR << it << " not found!" << std::endl;
			return false;
		}
	}

	// Verify that the requested output formatter exists
	if (opts.output_set)
	{
		const std::vector<std::string> formatters = {"raw", "json"};
		auto found = std::find(formatters.begin(), formatters.end(), opts.output);
		if (found == formatters.end())
		{
			print_help(app, argv[0]);
			std::cout << std::endl;
			PRINT_ERROR << "output formatter " << opts.output << " does not exist!" << std::endl;
			return false;
		}
	}

	return true;
}

// ----------------------------------------------------------------------------

/**
 *	@brief	Parses and validates the command line options of the application.
 *
 *	@param	Options& opts The destination for parsed arguments
 *	@param	int argc The number of arguments
 *	@param	char**argv The raw arguments
 *
 *	@return	Whether the arguments are valid.
 */
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

	typedef std::tuple<std::shared_ptr<std::thread>, std::shared_future<plugin::pResult>, plugin::pIPlugin> plugin_job;
	std::vector<plugin_job> jobs;
	for (const auto& it : plugins)
	{
		// Verify that the plugin was selected
		if (!all_plugins && std::find(selected.begin(), selected.end(), *it->get_id()) == selected.end()) {
			continue;
		}

		// Forward relevant configuration elements to the plugin.
		if (conf.count(*it->get_id())) {
			it->set_config(conf.at(*it->get_id()));
		}

		std::promise<plugin::pResult> res_promise;
		std::shared_future<plugin::pResult> future(res_promise.get_future());

		std::shared_ptr<std::thread> t(std::make_shared<std::thread>(std::thread([](const plugin::pIPlugin& p, std::promise<plugin::pResult> r, const mana::PE* pe) {
			r.set_value(p->analyze(*pe));
		}, it, std::move(res_promise), &pe)));

		jobs.emplace_back(t, future, it);
	}

	for (auto j : jobs)
	{
		std::get<0>(j)->join();
		auto res = std::get<1>(j).get();
		if (!res)
		{
			PRINT_WARNING << "Plugin " << *std::get<2>(j)->get_id() << " returned a NULL result!" << std::endl;
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
 *	@param	Options& opts The (parsed) arguments of the application.
 *
 *	@return	A set (to weed out duplicates) containing all the files to analyze.
 */
std::set<std::string> get_input_files(const Options& opts)
{
	std::set<std::string> targets;
	if (opts.recursive)
	{
		for (const auto& it : opts.pe)
		{
			if (!bfs::is_directory(it))
			{
				#if defined _WIN32
					std::string path = bfs::absolute(it).string();
					std::replace(path.begin(), path.end(), '\\', '/');
					targets.insert(path);
				#else
					targets.insert(bfs::absolute(it).string());
				#endif
			}
			else
			{
					bfs::directory_iterator end;
					for (bfs::directory_iterator dit(it) ; dit != end ; ++dit)
					{
						if (!bfs::is_directory(*dit)) { // Ignore subdirectories
						#if defined _WIN32
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
		for (const auto& it : opts.pe)
		{
			if (!bfs::is_directory(it)) {
				#if defined _WIN32
					std::string path = bfs::absolute(it).string();
					std::replace(path.begin(), path.end(), '\\', '/');
					targets.insert(path);
				#else
					targets.insert(bfs::absolute(it).string());
				#endif
			}
			else {
				PRINT_WARNING << it << " is a directory. Skipping (use the -r option for recursive analyses)." << std::endl;
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
					  const Options& opts,
					  const std::string& extraction_directory,
					  const std::vector<std::string>& selected_categories,
					  const std::vector<std::string>& selected_plugins,
					  const config& conf,
					  std::shared_ptr<io::OutputFormatter> formatter)
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
			y.load_rules(mana::paths::resolve_data_path("yara_rules/magic.yara")))
		{
			yara::const_matches m = y.scan_file(*pe.get_path());
			if (m && !m->empty())
			{
				std::cerr << "Detected file type(s):" << std::endl;
				for (const auto& it : *m) {
					std::cerr << "\t" << (it)->operator[]("description") << std::endl;
				}
			}
		}
		std::cerr << std::endl;
		return;
	}

	if (!selected_categories.empty()) {
		handle_dump_option(*formatter, selected_categories, opts.hashes, pe);
	}
	else { // No specific info requested. Display the summary of the PE.
		dump_summary(pe, *formatter);
	}

	if (opts.extract_set) // Extract resources if requested 
	{
		mana::extract_resources(pe, extraction_directory);
		mana::extract_authenticode_certificates(pe, extraction_directory);
	}

	if (opts.hashes) {
		dump_hashes(pe, *formatter);
	}

	if (!selected_plugins.empty()) {
		handle_plugins_option(*formatter, selected_plugins, conf, pe);
	}
}

// ----------------------------------------------------------------------------

int main(int argc, char** argv)
{
	Options opts;
	std::string extraction_directory;
	std::vector<std::string> selected_plugins, selected_categories;

	mana::paths::initialize(argv[0]);
	apply_early_log_level_from_argv(argc, argv);
	const bfs::path config_dir(mana::paths::config_dir());
	const bfs::path plugin_dir(mana::paths::plugin_dir());

	// Initialize Yara and load plugins.
	yara::Yara::initialize();
	plugin::PluginManager::get_instance().load_all(plugin_dir.string());

	if (!parse_args(opts, argc, argv, print_help, validate_args)) {
		return -1;
	}
	if (opts.log_level_set) {
		utils::set_log_level_from_string(opts.log_level);
	}

	// Load the configuration
	config conf = parse_config((config_dir / "manalyze.conf").string());

	// Get all the paths now and make them absolute before changing the working directory
	std::set<std::string> targets = get_input_files(opts);
	if (opts.extract_set) {
		extraction_directory = bfs::absolute(opts.extract).string();
	}
	// Break complex arguments into a list once and for all.
	if (!opts.plugins.empty()) {
		selected_plugins = opts.plugins;
	}
	if (!opts.dump.empty()) {
		selected_categories = opts.dump;
	}

	// Instantiate the requested OutputFormatter
	std::shared_ptr<io::OutputFormatter> formatter;
	if (opts.output_set && opts.output == "json") {
		formatter.reset(new io::JsonFormatter());
	}
	else // Default: use the human-readable output.
	{
		formatter.reset(new io::RawFormatter());
		formatter->set_header("* Manalyze " MANALYZE_VERSION " *");
	}

	// Set the working directory to Manalyze's configuration folder.
	chdir(config_dir.string().c_str());

	// Do the actual analysis on all the input files
	unsigned int count = 0;
	for (const auto& it : targets)
	{
		perform_analysis(it, opts, extraction_directory, selected_categories, selected_plugins, conf, formatter);
		if (++count % 1000 == 0) {
			formatter->format(std::cout, false); // Flush the formatter from time to time, to avoid eating up all the RAM when analyzing gigs of files.
		}
	}

	formatter->format(std::cout);

	if (!selected_plugins.empty())
	{
		// Explicitly unload the plugins
		plugin::PluginManager::get_instance().unload_all();
	}

	// Cleanup
	yara::Yara::finalize();

	return 0;
}
