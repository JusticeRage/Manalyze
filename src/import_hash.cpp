#include "import_hash.h"

namespace hash {

std::string hash_imports(const mana::PE& pe)
{
	std::stringstream ss;

	auto dlls = pe.get_imported_dlls();
	for (auto it = dlls->begin() ; it != dlls->end() ; ++it)
	{
		// Lowercase DLL and function names for import hashes
		std::string dll_name(bfs::basename(*it));
		std::transform(dll_name.begin(), dll_name.end(), dll_name.begin(), ::tolower);

		auto functions = pe.get_imported_functions(*it);
		for (auto it2 = functions->begin() ; it2 != functions->end() ; ++it2)
		{
			std::string function_name;

			// There's a little uncertainty about what should be done for functions imported by ordinal.
			// PEFile tries to resolve some of them, but when failures occur, they fall back to using dllname.ord123
			// as function name.
			//
			// This does not make a lot of sense to me. First of all, Windows DLL's ordinals are unreliable:
			// https://en.wikipedia.org/wiki/Dynamic-link_library#Symbol_resolution_and_binding
			// Secondly, using the function name only when we can resolve it seems much too implementation-
			// -dependant for my tastes. (What if one program suddenly translates more ordinals than the others?)
			//
			// Therefore, I propose a new imphash convention: if the function is imported by name, use the name.
			// Otherwise, use the ordinal number (i.e. dll_name.123).

			if ((*it2).find("#") == 0 && (*it2).length() > 1) { // Import by ordinal
				function_name = std::string((*it2).begin() + 1, (*it2).end());
			}
			else {
				function_name = *it2;
			}

			// Imports are comma-separated.
			if (it != dlls->begin() || it2 != functions->begin()) {
				ss << ",";
			}

			std::transform(function_name.begin(), function_name.end(), function_name.begin(), ::tolower);
			ss << dll_name << "." << function_name;
		}
	}

	std::string data = ss.str();
	std::vector<boost::uint8_t> bytes(data.begin(), data.end());
	auto h = hash::hash_bytes(*hash::ALL_DIGESTS[ALL_DIGESTS_MD5], bytes);
    if (h != nullptr) {
        return *h;
    }
    else {
        return "";
    }
}

} // !namespace hash
