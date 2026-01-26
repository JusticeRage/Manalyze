#ifndef MANACOMMONS_PATHS_H
#define MANACOMMONS_PATHS_H

#include <string>

namespace mana {
namespace paths {

void initialize(const std::string& argv0);

const std::string& exe_dir();
const std::string& config_dir();
const std::string& data_dir();
const std::string& plugin_dir();
const std::string& cache_dir();

std::string resolve_data_path(const std::string& relative_path);
std::string resolve_config_path(const std::string& filename);
std::string resolve_cache_path(const std::string& relative_path);

} // namespace paths
} // namespace mana

#endif // MANACOMMONS_PATHS_H
