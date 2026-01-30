#ifndef MANACOMMONS_PATHS_H
#define MANACOMMONS_PATHS_H

#include <string>

#if defined _WIN32 && !defined DECLSPEC_MANACOMMONS
	#if defined MANACOMMONS_EXPORT
		#define DECLSPEC_MANACOMMONS    __declspec(dllexport)
	#else
		#define DECLSPEC_MANACOMMONS    __declspec(dllimport)
	#endif
#elif !defined _WIN32 && !defined DECLSPEC_MANACOMMONS
	#define DECLSPEC_MANACOMMONS
#endif

namespace mana {
namespace paths {

DECLSPEC_MANACOMMONS void initialize(const std::string& argv0);

DECLSPEC_MANACOMMONS const std::string& exe_dir();
DECLSPEC_MANACOMMONS const std::string& config_dir();
DECLSPEC_MANACOMMONS const std::string& data_dir();
DECLSPEC_MANACOMMONS const std::string& plugin_dir();
DECLSPEC_MANACOMMONS const std::string& cache_dir();

DECLSPEC_MANACOMMONS std::string resolve_data_path(const std::string& relative_path);
DECLSPEC_MANACOMMONS std::string resolve_config_path(const std::string& filename);
DECLSPEC_MANACOMMONS std::string resolve_cache_path(const std::string& relative_path);

} // namespace paths
} // namespace mana

#endif // MANACOMMONS_PATHS_H
