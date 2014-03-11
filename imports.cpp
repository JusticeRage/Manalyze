#include "pe.h"

namespace sg {

std::vector<std::string> PE::get_imported_dlls() const
{
	std::vector<std::string> res;
	if (!_initialized) {
		return res;
	}

	for (std::vector<pimage_library_descriptor>::const_iterator it = _imports.begin() ; it != _imports.end() ; ++it) {
		res.push_back((*it)->first->NameStr);
	}
	return res;
}

// ----------------------------------------------------------------------------

std::vector<std::string> PE::get_imported_functions(const std::string& dll) const
{
	std::vector<std::string> res;
	if (!_initialized) {
		return res;
	}

	pimage_library_descriptor ild = pimage_library_descriptor();

	// We don't want to use PE::_find_imported_dlls: no regexp matching is necessary, since we only look for a simple exact name here.
	for (std::vector<pimage_library_descriptor>::const_iterator it = _imports.begin() ; it != _imports.end() ; ++it)
	{
		if ((*it)->first->NameStr == dll)
		{
			ild = *it;
			break;
		}
	}

	if (ild != NULL)
	{
		for (std::vector<pimport_lookup_table>::const_iterator it = ild->second.begin() ; it != ild->second.end() ; ++it)
		{
			if ((*it)->Name != "") {
				res.push_back((*it)->Name);
			}
			else 
			{
				std::stringstream ss;
				ss << "#" << ((*it)->AddressOfData & 0x7FFF);
				res.push_back(ss.str());
			}
		}
	}

	return res;
}

// ----------------------------------------------------------------------------

std::vector<pimage_library_descriptor> PE::_find_imported_dlls(const std::string& name_regexp) const
{
	std::vector<pimage_library_descriptor> res;
	if (!_initialized) {
		return res;
	}

	boost::regex e(name_regexp);
	for (std::vector<pimage_library_descriptor>::const_iterator it = _imports.begin() ; it != _imports.end() ; ++it)
	{
		if (boost::regex_match((*it)->first->NameStr, e)) {
			res.push_back(*it);
		}
	}
	return res;
}

// ----------------------------------------------------------------------------

std::vector<std::string> PE::find_imports(const std::string& function_name_regexp, 
										  const std::string& dll_name_regexp) const
{
	std::vector<std::string> matching_functions;
	if (!_initialized) {
		return matching_functions;
	}

	std::vector<pimage_library_descriptor> matching_dlls = _find_imported_dlls(dll_name_regexp);

	boost::regex e(dll_name_regexp);
	// Iterate on matching DLLs
	for (std::vector<pimage_library_descriptor>::const_iterator it = matching_dlls.begin() ; it != matching_dlls.end() ; ++it)
	{
		// Iterate on functions imported by each of these DLLs
		e = boost::regex(function_name_regexp);
		for (std::vector<pimport_lookup_table>::iterator it2 = (*it)->second.begin() ; it2 != (*it)->second.end() ; ++it2)
		{
			if ((*it2)->Name == "") { // Functions imported by ordinal are skipped.
				continue;
			}
			if (boost::regex_match((*it2)->Name, e)) {
				matching_functions.push_back((*it2)->Name);
			}
		}
	}
	return matching_functions;
}

}