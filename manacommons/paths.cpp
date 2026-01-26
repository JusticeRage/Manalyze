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

#include "manacommons/paths.h"

#include <boost/filesystem.hpp>
#include <boost/system/api_config.hpp>

#include <cstdlib>
#include <sstream>

#ifdef BOOST_POSIX_API
# include <unistd.h>
# include <limits.h>
#endif

#ifdef BOOST_WINDOWS_API
# include <windows.h>
#endif

#ifndef MANALYZE_INSTALL_CONFIG_DIR
#define MANALYZE_INSTALL_CONFIG_DIR ""
#endif

#ifndef MANALYZE_INSTALL_DATA_DIR
#define MANALYZE_INSTALL_DATA_DIR ""
#endif

#ifndef MANALYZE_INSTALL_PLUGIN_DIR
#define MANALYZE_INSTALL_PLUGIN_DIR ""
#endif

#ifndef MANALYZE_INSTALL_CONFIG_SUBDIR
#define MANALYZE_INSTALL_CONFIG_SUBDIR ""
#endif

#ifndef MANALYZE_INSTALL_DATA_SUBDIR
#define MANALYZE_INSTALL_DATA_SUBDIR ""
#endif

#ifndef MANALYZE_INSTALL_PLUGIN_SUBDIR
#define MANALYZE_INSTALL_PLUGIN_SUBDIR ""
#endif

namespace mana {
namespace paths {

namespace bfs = boost::filesystem;

namespace {

std::string g_exe_dir;
std::string g_config_dir;
std::string g_data_dir;
std::string g_plugin_dir;
std::string g_cache_dir;
bool g_initialized = false;

std::string get_env_string(const char* name)
{
	const char* value = std::getenv(name);
	return value ? std::string(value) : std::string();
}

std::string get_env_path_candidate(const std::string& argv0)
{
	if (argv0.empty()) {
		return std::string();
	}

	const std::string path_env = get_env_string("PATH");
	if (path_env.empty()) {
		return std::string();
	}

#ifdef BOOST_WINDOWS_API
	const char separator = ';';
#else
	const char separator = ':';
#endif

	std::stringstream ss(path_env);
	std::string dir;
	while (std::getline(ss, dir, separator)) {
		if (dir.empty()) {
			continue;
		}
		const bfs::path candidate = bfs::path(dir) / argv0;
		if (bfs::exists(candidate)) {
			return bfs::absolute(candidate).parent_path().string();
		}
	}
	return std::string();
}

bool is_dir(const bfs::path& path)
{
	return !path.empty() && bfs::exists(path) && bfs::is_directory(path);
}

bool is_file(const bfs::path& path)
{
	return !path.empty() && bfs::exists(path) && bfs::is_regular_file(path);
}

std::string plugin_extension()
{
#ifdef BOOST_WINDOWS_API
	return ".dll";
#elif defined(__APPLE__)
	return ".dylib";
#else
	return ".so";
#endif
}

bfs::path derive_prefix(const bfs::path& exe_dir)
{
	if (exe_dir.empty()) {
		return bfs::path();
	}

	bfs::path prefix = exe_dir;
	if (exe_dir.filename() == "bin" || exe_dir.filename() == "sbin") {
		prefix = exe_dir.parent_path();
	}
	return prefix;
}

bfs::path apply_prefix(const bfs::path& prefix, const std::string& subdir)
{
	if (prefix.empty() || subdir.empty()) {
		return bfs::path();
	}

	bfs::path subdir_path(subdir);
	if (subdir_path.is_absolute()) {
		return subdir_path;
	}
	return prefix / subdir_path;
}

bool dir_has_plugins(const bfs::path& dir)
{
	if (!is_dir(dir)) {
		return false;
	}

	const std::string ext = plugin_extension();
	bfs::directory_iterator end_it;
	for (bfs::directory_iterator it(dir) ; it != end_it ; ++it) {
		if (!bfs::is_regular_file(it->status())) {
			continue;
		}

		const bfs::path& p = it->path();
		if (p.extension() != ext) {
			continue;
		}

		const std::string filename = p.filename().string();
		if (filename.find("libplugin_") == 0 || filename.find("plugin_") == 0) {
			return true;
		}
	}
	return false;
}

std::string get_executable_dir(const std::string& argv0)
{
#if defined(BOOST_POSIX_API) && !defined(__APPLE__)
	char buffer[PATH_MAX];
	const ssize_t len = ::readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
	if (len > 0) {
		buffer[len] = '\0';
		return bfs::path(buffer).parent_path().string();
	}
#elif defined(BOOST_WINDOWS_API)
	char buffer[MAX_PATH] = {0};
	const DWORD len = ::GetModuleFileNameA(nullptr, buffer, MAX_PATH);
	if (len > 0 && len < MAX_PATH) {
		return bfs::path(buffer).parent_path().string();
	}
#endif

	bfs::path argv_path(argv0);
	if (argv_path.has_parent_path()) {
		return argv_path.parent_path().string();
	}

	const std::string path_dir = get_env_path_candidate(argv0);
	if (!path_dir.empty()) {
		return path_dir;
	}

	return bfs::current_path().string();
}

std::string select_config_dir(const bfs::path& exe_dir)
{
	const std::string env_dir = get_env_string("MANALYZE_CONFIG_DIR");
	if (!env_dir.empty() && is_dir(env_dir)) {
		return env_dir;
	}

	if (is_file(exe_dir / "manalyze.conf")) {
		return exe_dir.string();
	}

	const bfs::path prefix = derive_prefix(exe_dir);
	const bfs::path prefix_dir = apply_prefix(prefix, MANALYZE_INSTALL_CONFIG_SUBDIR);
	if (is_file(prefix_dir / "manalyze.conf")) {
		return prefix_dir.string();
	}

	const bfs::path install_dir(MANALYZE_INSTALL_CONFIG_DIR);
	if (is_file(install_dir / "manalyze.conf")) {
		return install_dir.string();
	}

	if (is_dir(install_dir)) {
		return install_dir.string();
	}

	return exe_dir.string();
}

std::string select_data_dir(const bfs::path& exe_dir)
{
	const std::string env_dir = get_env_string("MANALYZE_DATA_DIR");
	if (!env_dir.empty() && is_dir(env_dir)) {
		return env_dir;
	}

	if (is_dir(exe_dir / "yara_rules")) {
		return exe_dir.string();
	}

	const bfs::path prefix = derive_prefix(exe_dir);
	const bfs::path prefix_dir = apply_prefix(prefix, MANALYZE_INSTALL_DATA_SUBDIR);
	if (is_dir(prefix_dir / "yara_rules")) {
		return prefix_dir.string();
	}

	const bfs::path install_dir(MANALYZE_INSTALL_DATA_DIR);
	if (is_dir(install_dir / "yara_rules")) {
		return install_dir.string();
	}

	if (is_dir(install_dir)) {
		return install_dir.string();
	}

	return exe_dir.string();
}

std::string select_plugin_dir(const bfs::path& exe_dir)
{
	const std::string env_dir = get_env_string("MANALYZE_PLUGIN_DIR");
	if (!env_dir.empty() && is_dir(env_dir)) {
		return env_dir;
	}

	if (dir_has_plugins(exe_dir)) {
		return exe_dir.string();
	}

	const bfs::path prefix = derive_prefix(exe_dir);
	const bfs::path prefix_dir = apply_prefix(prefix, MANALYZE_INSTALL_PLUGIN_SUBDIR);
	if (dir_has_plugins(prefix_dir)) {
		return prefix_dir.string();
	}

	const bfs::path install_dir(MANALYZE_INSTALL_PLUGIN_DIR);
	if (dir_has_plugins(install_dir)) {
		return install_dir.string();
	}

	if (is_dir(install_dir)) {
		return install_dir.string();
	}

	return exe_dir.string();
}

std::string select_cache_dir(const bfs::path& exe_dir)
{
	const std::string env_dir = get_env_string("MANALYZE_CACHE_DIR");
	if (!env_dir.empty()) {
		return env_dir;
	}

#ifdef BOOST_POSIX_API
	const std::string xdg_cache = get_env_string("XDG_CACHE_HOME");
	if (!xdg_cache.empty()) {
		return (bfs::path(xdg_cache) / "manalyze").string();
	}

	const std::string home = get_env_string("HOME");
	if (!home.empty()) {
		return (bfs::path(home) / ".cache" / "manalyze").string();
	}
#endif

#ifdef BOOST_WINDOWS_API
	const std::string local_app_data = get_env_string("LOCALAPPDATA");
	if (!local_app_data.empty()) {
		return (bfs::path(local_app_data) / "Manalyze").string();
	}
#endif

	return exe_dir.string();
}

void ensure_initialized()
{
	if (g_initialized) {
		return;
	}

	initialize(std::string());
}

} // namespace

void initialize(const std::string& argv0)
{
	if (g_initialized) {
		return;
	}

	bfs::path exe_dir = get_executable_dir(argv0);
	if (exe_dir.empty()) {
		exe_dir = ".";
	}

	exe_dir = bfs::absolute(exe_dir);
	g_exe_dir = exe_dir.string();
	g_config_dir = select_config_dir(exe_dir);
	g_data_dir = select_data_dir(exe_dir);
	g_plugin_dir = select_plugin_dir(exe_dir);
	g_cache_dir = select_cache_dir(exe_dir);

	if (!g_cache_dir.empty()) {
		g_cache_dir = bfs::absolute(bfs::path(g_cache_dir)).string();
	}
	g_initialized = true;
}

const std::string& exe_dir()
{
	ensure_initialized();
	return g_exe_dir;
}

const std::string& config_dir()
{
	ensure_initialized();
	return g_config_dir;
}

const std::string& data_dir()
{
	ensure_initialized();
	return g_data_dir;
}

const std::string& plugin_dir()
{
	ensure_initialized();
	return g_plugin_dir;
}

const std::string& cache_dir()
{
	ensure_initialized();
	return g_cache_dir;
}

std::string resolve_data_path(const std::string& relative_path)
{
	ensure_initialized();

	const bfs::path p(relative_path);
	if (p.is_absolute()) {
		return p.string();
	}

	return (bfs::path(g_data_dir) / p).string();
}

std::string resolve_config_path(const std::string& filename)
{
	ensure_initialized();

	const bfs::path p(filename);
	if (p.is_absolute()) {
		return p.string();
	}

	return (bfs::path(g_config_dir) / p).string();
}

std::string resolve_cache_path(const std::string& relative_path)
{
	ensure_initialized();

	const bfs::path p(relative_path);
	if (p.is_absolute()) {
		return p.string();
	}

	return (bfs::path(g_cache_dir) / p).string();
}

} // namespace paths
} // namespace mana
