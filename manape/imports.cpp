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

#include "manape/pe.h"
#include "manape/parser_internal.h"

#include <regex>
#include <set>

namespace mana {

// ----------------------------------------------------------------------------

bool PE::_parse_hint_name_table(pimport_lookup_table import) const
{
	// Import names are decoded by the bounded source-internal parser.
	return false;
}

// ----------------------------------------------------------------------------

bool PE::_parse_import_lookup_table(unsigned int offset, pImportedLibrary library) const
{
	// Import tables are traversed by the bounded source-internal parser.
	return false;
}

// ----------------------------------------------------------------------------

bool PE::_parse_imports()
{
	if (!_ioh || _file_handle == nullptr) { // Image Optional Header wasn't parsed successfully.
		return false;
	}

	detail::ImageView image{
		_file_size,
		_ioh->SizeOfHeaders,
		_ioh->SizeOfImage,
		_ioh->ImageBase,
		_ioh->FileAlignment,
		{},
		[this](std::uint64_t offset, void* destination, std::size_t size) {
			return _locked_read_at(offset, destination, size);
		},
	};
	image.sections.reserve(_sections.size());
	for (const auto& section : _sections) {
		image.sections.push_back({
			section->get_virtual_address(),
			section->get_virtual_size(),
			section->get_pointer_to_raw_data(),
			section->get_size_of_raw_data(),
		});
	}

	const detail::ImportLimits limits{
		65536,
		1000000,
		256ULL * 1024 * 1024,
		64ULL * 1024 * 1024,
		256ULL * 1024 * 1024,
	};
	const auto diagnostics = [](detail::ParserDiagnostic diagnostic) {
		switch (diagnostic) {
		case detail::ParserDiagnostic::import_extent_too_small:
			CAPPED_LOGGING_ERROR
			PRINT_ERROR << "Import directory extent contains no complete IMAGE_IMPORT_DESCRIPTOR."
				<< DEBUG_INFO_INSIDEPE << std::endl;
			CAPPED_LOGGING_END
			break;
		case detail::ParserDiagnostic::import_descriptor_unterminated:
			CAPPED_LOGGING_ERROR
			PRINT_ERROR << "Import descriptor table is not null-terminated within its mapped extent."
				<< DEBUG_INFO_INSIDEPE << std::endl;
			CAPPED_LOGGING_END
			break;
		case detail::ParserDiagnostic::import_budget_exhausted:
			CAPPED_LOGGING_ERROR
			PRINT_ERROR << "Import parsing work budget exhausted."
				<< DEBUG_INFO_INSIDEPE << std::endl;
			CAPPED_LOGGING_END
			break;
		case detail::ParserDiagnostic::import_malformed:
			CAPPED_LOGGING_ERROR
			PRINT_ERROR << "Could not read the IMAGE_IMPORT_DESCRIPTOR."
				<< DEBUG_INFO_INSIDEPE << std::endl;
			CAPPED_LOGGING_END
			break;
		default:
			break;
		}
	};
	const auto parsed = detail::parse_imports(image,
		_ioh->directories[IMAGE_DIRECTORY_ENTRY_IMPORT],
		_ioh->directories[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT],
		get_architecture() != PE::x86, limits, diagnostics);

	for (const auto& parsed_library : parsed.libraries) {
		pImportedLibrary library;
		if (parsed_library.delay_loaded) {
			library = pImportedLibrary(new ImportedLibrary(parsed_library.name));
		} else {
			if (!parsed_library.descriptor) continue;
			auto iid = std::make_shared<image_import_descriptor>(
				*parsed_library.descriptor);
			library = pImportedLibrary(new ImportedLibrary(parsed_library.name,
				iid));
		}
		for (const auto& parsed_function : parsed_library.functions) {
			library->add_import(std::make_shared<import_lookup_table>(
				parsed_function));
		}
		_imports.push_back(library);
	}
	if (parsed.delay_directory) {
		_delay_load_directory_table = *parsed.delay_directory;
	}

	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_delayed_imports()
{
	// Delay imports are parsed by _parse_imports() so both paths can share budgets.
	return true;
}

// ----------------------------------------------------------------------------

const_shared_strings PE::get_imported_dlls() const
{
	auto destination = std::make_shared<std::vector<std::string> >();
	if (!_initialized) {
		return destination;
	}

	for (auto it = _imports.begin() ; it != _imports.end() ; ++it)
	{
		pString s = (*it)->get_name();
		if (s != nullptr) {
			destination->push_back(*s);
		}
	}
	return destination;
}

// ----------------------------------------------------------------------------

const_shared_strings PE::get_imported_functions(const std::string& dll) const
{
	auto destination = std::make_shared<std::vector<std::string> >();
	if (!_initialized) {
		return destination;
	}

	// We don't want to use PE::_find_imported_dlls: no regexp matching is necessary, since we only look for a simple exact name here.
	auto found = std::find_if(_imports.begin(), _imports.end(), [dll](const pImportedLibrary& l)->bool {
		return l->get_name() && *l->get_name() == dll;
	});
	if (found == _imports.end() || !*found) {
		return destination;
	}
	auto library = *found;

	auto functions = library->get_imports();
	if (functions == nullptr) {
		return destination;
	}
	for (const auto& it : *functions)
	{
		if (it->Name != "") {
			destination->push_back(it->Name);
		}
		else
		{
			std::uint16_t ordinal = it->AddressOfData & 0x7FFF;
			destination->push_back(*nt::translate_ordinal(ordinal, dll));
		}
	}

	return destination;
}

// ----------------------------------------------------------------------------

size_t PE::count_imported_functions() const
{
	if (!_initialized) {
		return 0;
	}

	std::set<std::string> unique_imports;
	for (const auto& library : _imports)
	{
		auto imports = library->get_imports();
		if (imports == nullptr) {
			continue;
		}
		for (const auto& imported_symbol : *imports)
		{
			std::string name;
			if (imported_symbol->Name == "") {
				name = *nt::translate_ordinal(imported_symbol->AddressOfData & 0x7FFF, *library->get_name());
			}
			else {
				name = imported_symbol->Name;
			}
			unique_imports.insert(name);
		}
	}
	return unique_imports.size();
}

// ----------------------------------------------------------------------------

shared_imports PE::find_imported_dlls(const std::string& name_regexp,
									  bool  case_sensitivity) const
{
	std::vector<pImportedLibrary> destination;
	if (!_initialized) {
		return std::make_shared<const std::vector<pImportedLibrary> >(destination);
	}

	std::regex e;
	if (case_sensitivity) {
		e = std::regex(name_regexp);
	}
	else {
		e = std::regex(name_regexp, std::regex::icase);
	}

	for (auto it = _imports.begin() ; it != _imports.end() ; ++it)
	{
		pString name = (*it)->get_name();
		if (name != nullptr && std::regex_match(*name, e)) {
			destination.push_back(*it);
		}
	}
	return std::make_shared<const std::vector<pImportedLibrary> >(destination);
}

// ----------------------------------------------------------------------------

const_shared_strings PE::find_imports(const std::string& function_name_regexp,
									  const std::optional<std::string>& dll_name_regexp,
									  bool  case_sensitivity) const
{
	auto destination = std::make_shared<std::vector<std::string> >();
	if (!_initialized) {
		return destination;
	}

	std::regex e;
	if (case_sensitivity) {
		e = std::regex(function_name_regexp);
	}
	else {
		e = std::regex(function_name_regexp, std::regex::icase);
	}

	auto add_matching_imports = [&](const pImportedLibrary& library)
	{
		auto imported_functions = library->get_imports();
		if (imported_functions == nullptr) {
			return;
		}

		// Iterate on functions imported by each of these DLLs
		for (const auto& it2 : *imported_functions)
		{
			std::string name;
			if (it2->Name == "") {
				name = *nt::translate_ordinal(it2->AddressOfData & 0x7FFF, *library->get_name());
			}
			else {
				name = it2->Name;
			}
			// Functions may be imported multiple times, don't add the same one twice.
			if (std::regex_match(name, e) && std::find(destination->begin(), destination->end(), name) == destination->end()) {
				destination->push_back(name);
			}
		}
	};

	if (dll_name_regexp.has_value())
	{
		auto matching_dlls = find_imported_dlls(*dll_name_regexp, case_sensitivity);
		if (!matching_dlls || matching_dlls->empty()) {
			return destination;
		}

		// Iterate on matching DLLs only.
		for (const auto& it : *matching_dlls) {
			add_matching_imports(it);
		}
	}
	else
	{
		// No DLL filter: iterate on all imported DLLs.
		for (const auto& it : _imports) {
			add_matching_imports(it);
		}
	}

	return destination;
}

} // !namespace mana
