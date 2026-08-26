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

#if defined(__GLIBC__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "manape/pe.h"

#if defined(_WIN32)
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#endif
#include <algorithm>
#include <iterator>
#include <limits>
#include <stdexcept>

namespace mana {

namespace {

bool read_bounded_ascii_string(FILE* file, std::uint64_t remaining, std::string& output)
{
	output.clear();
	while (remaining-- != 0) {
		char value = 0;
		if (fread(&value, 1, 1, file) != 1) return false;
		if (value == '\0') return true;
		output.push_back(value);
	}
	return false;
}

bool read_bounded_utf16_string(FILE* file, std::uint64_t remaining, std::string& output)
{
	output.clear();
	if (remaining % 2 != 0) return false;

	std::vector<std::uint16_t> input;
	while (remaining != 0) {
		std::uint8_t bytes[2] = {};
		if (fread(bytes, 1, sizeof(bytes), file) != sizeof(bytes)) return false;
		remaining -= sizeof(bytes);
		const std::uint16_t value = static_cast<std::uint16_t>(bytes[0]) |
			(static_cast<std::uint16_t>(bytes[1]) << 8);
		if (value != 0) {
			input.push_back(value);
			continue;
		}

		try {
			utf8::utf16to8(input.begin(), input.end(), std::back_inserter(output));
			return true;
		}
		catch (utf8::invalid_utf16&) {
			output.clear();
			return false;
		}
	}
	return false;
}

} // namespace

PE::PE(const std::string& path)
	: _path(path),
	  _resource_path(path),
	  _initialized(false),
	  _io_mutex(std::make_shared<std::mutex>())
{
	FILE* f = fopen(_path.c_str(), "rb");
	if (f == nullptr)
	{
		PRINT_ERROR << "Could not open " << _path << "." << std::endl;
		return;
	}
	_file_handle = std::shared_ptr<FILE>(f, fclose);

	// Get the file size
	bool size_ok = true;
	if (fseek(_file_handle.get(), 0, SEEK_END)) {
		size_ok = false;
	}
	long end_pos = size_ok ? ftell(_file_handle.get()) : -1;
	if (end_pos < 0) {
		size_ok = false;
	}
	_file_size = size_ok ? static_cast<std::uint64_t>(end_pos) : 0;
	if (fseek(_file_handle.get(), 0, SEEK_SET)) {
		size_ok = false;
	}

	_initialize();
}

PE::PE(const std::string& display_path, pFile file_handle)
	: _path(display_path),
	  _resource_path(display_path),
	  _initialized(false),
	  _file_handle(file_handle),
	  _io_mutex(std::make_shared<std::mutex>())
{
	if (_file_handle == nullptr)
	{
		PRINT_ERROR << "Could not open " << _path << "." << std::endl;
		return;
	}

	bool size_ok = true;
	if (fseek(_file_handle.get(), 0, SEEK_END)) {
		size_ok = false;
	}
	long end_pos = size_ok ? ftell(_file_handle.get()) : -1;
	if (end_pos < 0) {
		size_ok = false;
	}
	_file_size = size_ok ? static_cast<std::uint64_t>(end_pos) : 0;
	if (fseek(_file_handle.get(), 0, SEEK_SET)) {
		size_ok = false;
	}

	_initialize();
}

void PE::_initialize()
{
	if (!_parse_dos_header()) {
		return;
	}

	if (!_parse_pe_header()) {
		return;
	}

	if (!_parse_image_optional_header()) {
		return;
	}

	if (!_parse_section_table()) {
		return;
	}

	// Failure is acceptable from here on.
	_initialized = true;
	_parse_coff_symbols();
	_parse_directories();
}

// ----------------------------------------------------------------------------

bool PE::_locked_read_at(std::uint64_t offset, void* dst, size_t size) const
{
	if (_file_handle == nullptr || _io_mutex == nullptr) {
		return false;
	}
	// FILE* fseek uses long offsets; reject offsets that cannot be represented.
	if (offset > static_cast<std::uint64_t>(std::numeric_limits<long>::max())) {
		return false;
	}
	if (size == 0) {
		return true;
	}

	std::lock_guard<std::mutex> guard(*_io_mutex);
	long saved = ftell(_file_handle.get());
	if (saved == -1) {
		return false;
	}
	bool ok = true;
	if (fseek(_file_handle.get(), static_cast<long>(offset), SEEK_SET)) {
		ok = false;
	}

	size_t read_bytes = 0;
	if (ok) {
		read_bytes = fread(dst, 1, size, _file_handle.get());
		if (read_bytes != size) {
			ok = false;
		}
	}

	if (fseek(_file_handle.get(), saved, SEEK_SET)) {
		ok = false;
	}
	return ok;
}

// ----------------------------------------------------------------------------

shared_bytes PE::_locked_read_vec(std::uint64_t offset, size_t size) const
{
	if (_file_handle == nullptr || _io_mutex == nullptr) {
		return nullptr;
	}
	if (offset > static_cast<std::uint64_t>(std::numeric_limits<long>::max())) {
		return nullptr;
	}

	auto res = std::make_shared<std::vector<std::uint8_t> >(size);
	if (size == 0) {
		return res;
	}
	if (!_locked_read_at(offset, &(*res)[0], size)) {
		return nullptr;
	}
	return res;
}


// ----------------------------------------------------------------------------

std::shared_ptr<PE> PE::create(const std::string& path) {
	return std::make_shared<PE>(path);
}

// ----------------------------------------------------------------------------

std::shared_ptr<PE> PE::create_from_bytes(const std::uint8_t* data,
											size_t size,
											const std::string& name_hint)
{
	if (data == nullptr || size == 0) {
		return std::make_shared<PE>(name_hint, pFile());
	}

#if defined(_WIN32)
	char temp_path[MAX_PATH + 1] = {0};
	char temp_file[MAX_PATH + 1] = {0};
	if (GetTempPathA(MAX_PATH, temp_path) == 0) {
		return std::make_shared<PE>(name_hint, pFile());
	}
	if (GetTempFileNameA(temp_path, "mna", 0, temp_file) == 0) {
		return std::make_shared<PE>(name_hint, pFile());
	}

	HANDLE hfile = CreateFileA(temp_file, GENERIC_READ | GENERIC_WRITE,
	                           FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
	                           FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
	                           nullptr);
	if (hfile == INVALID_HANDLE_VALUE) {
		return std::make_shared<PE>(name_hint, pFile());
	}

	size_t remaining = size;
	const std::uint8_t* cursor = data;
	while (remaining > 0) {
		DWORD chunk = (remaining > MAXDWORD) ? MAXDWORD : static_cast<DWORD>(remaining);
		DWORD written = 0;
		BOOL ok = WriteFile(hfile, cursor, chunk, &written, nullptr);
		if (!ok || written != chunk) {
			CloseHandle(hfile);
			return std::make_shared<PE>(name_hint, pFile());
		}
		remaining -= written;
		cursor += written;
	}
	SetFilePointer(hfile, 0, nullptr, FILE_BEGIN);

	int fd = _open_osfhandle(reinterpret_cast<intptr_t>(hfile), _O_RDONLY | _O_BINARY);
	if (fd == -1) {
		CloseHandle(hfile);
		return std::make_shared<PE>(name_hint, pFile());
	}

	FILE* f = _fdopen(fd, "rb");
	if (f == nullptr) {
		_close(fd);
		return std::make_shared<PE>(name_hint, pFile());
	}
	pFile handle(f, fclose);
	auto pe = std::make_shared<PE>(name_hint, handle);
	pe->_resource_path = temp_file;
	return pe;
#else
#if defined(__GLIBC__)
	auto buffer = std::make_shared<std::vector<std::uint8_t> >(size);
	memcpy(buffer->data(), data, size);
	FILE* f = fmemopen(buffer->data(), size, "rb");
	if (f == nullptr) {
		return std::make_shared<PE>(name_hint, pFile());
	}
	pFile handle(f, fclose);
	auto pe = std::make_shared<PE>(name_hint, handle);
	pe->_backing_store = buffer;
	return pe;
#else
	// Fallback to a temporary file on other POSIX platforms.
	FILE* f = tmpfile();
	if (f == nullptr) {
		return std::make_shared<PE>(name_hint, pFile());
	}
	if (size != fwrite(data, 1, size, f)) {
		fclose(f);
		return std::make_shared<PE>(name_hint, pFile());
	}
	fseek(f, 0, SEEK_SET);
	pFile handle(f, fclose);
	return std::make_shared<PE>(name_hint, handle);
#endif
#endif
}

// ----------------------------------------------------------------------------

void* PE::operator new(size_t size)
{
	void* p = malloc(size);
	if (p == nullptr)
		throw std::bad_alloc();
	return p;
}

// ----------------------------------------------------------------------------

void PE::operator delete(void* p) {
	free(p);
}


// ----------------------------------------------------------------------------

std::uint64_t PE::get_filesize() const {
	return _file_size;
}

// ----------------------------------------------------------------------------

PE::PE_ARCHITECTURE PE::get_architecture() const {
	return (_ioh->Magic == nt::IMAGE_OPTIONAL_HEADER_MAGIC.at("PE32+") ? PE::x64 : PE::x86);
}

// ----------------------------------------------------------------------------

shared_bytes PE::get_raw_bytes(size_t size) const
{
	if(_file_handle == nullptr) {
		return nullptr;
	}
	if (size > _file_size) {
		size = static_cast<size_t>(_file_size);
	}
	return _locked_read_vec(0, size);
}

// ----------------------------------------------------------------------------

shared_bytes PE::get_overlay_bytes(size_t size) const
{
    if (_file_handle == nullptr || !_ioh || size == 0) {
        return nullptr;
    }

    const auto sections = get_sections();
    if (!sections) {
        return nullptr;
    }

    // Find where the overlay data would be located.
    std::uint64_t max_offset = 0;

    // If the binary is signed, look after the authenticode signature.
    if (_ioh->directories[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress) 
    {
        max_offset = static_cast<uint64_t>(_ioh->directories[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress) + 
            _ioh->directories[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
    }
    else // Otherwise, look after the last section.
    {
        for (const auto& it : *sections)
        {
            if (static_cast<uint64_t>(it->get_pointer_to_raw_data()) + it->get_size_of_raw_data() > max_offset) {
                max_offset = static_cast<uint64_t>(it->get_pointer_to_raw_data()) + it->get_size_of_raw_data();
            }
        }
    }

    // The PE has no overlay data.
    if (max_offset >= get_filesize()) {
        return nullptr;
    }
    if (size > _file_size - max_offset) {
        size = static_cast<size_t>(_file_size - max_offset);
    }
    return _locked_read_vec(max_offset, size);
}

// ----------------------------------------------------------------------------

bool PE::_parse_dos_header()
{
	if (_file_handle == nullptr) {
		return false;
	}

	dos_header dos;
	memset(&dos, 0, sizeof(dos));
	if (sizeof(dos) > get_filesize())
	{
		PRINT_ERROR << "Input file is too small to be a valid PE." << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	if (sizeof(dos) != fread(&dos, 1, sizeof(dos), _file_handle.get()))
	{
		PRINT_ERROR << "Could not read the DOS Header." << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}
	if (dos.e_magic[0] != 'M' || dos.e_magic[1] != 'Z')
	{
		PRINT_ERROR << "DOS Header is invalid (wrong magic)." << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}
	_h_dos = dos;
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_pe_header()
{
	if (!_h_dos || _file_handle == nullptr) {
		return false;
	}

	pe_header peh;
	memset(&peh, 0, sizeof(peh));

	if (fseek(_file_handle.get(), _h_dos->e_lfanew, SEEK_SET))
	{
		PRINT_ERROR << "Could not reach PE header (fseek to offset " <<  _h_dos->e_lfanew << " failed)."
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}
	if (sizeof(peh) != fread(&peh, 1, sizeof(peh), _file_handle.get()))
	{
		PRINT_ERROR << "Could not read the PE Header." << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}
	if (peh.Signature[0] != 'P' || peh.Signature[1] != 'E' || peh.Signature[2] != '\x00' || peh.Signature[3] != '\x00')
	{
		PRINT_ERROR << "PE Header is invalid." << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}
	_h_pe = peh;
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_coff_symbols()
{
	if (!_h_pe || _file_handle == nullptr) {
		return false;
	}

	if (_h_pe->NumberOfSymbols == 0 || _h_pe->PointerToSymbolTable == 0) {
		return true;
	}

	if (fseek(_file_handle.get(), _h_pe->PointerToSymbolTable, SEEK_SET))
	{
		PRINT_ERROR << "Could not reach PE COFF symbols (fseek to offset " <<  _h_pe->PointerToSymbolTable << " failed)."
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	for (unsigned int i = 0 ; i < _h_pe->NumberOfSymbols ; ++i)
	{
		pcoff_symbol sym = std::make_shared<coff_symbol>();
		memset(sym.get(), 0, sizeof(coff_symbol));

		if (18 != fread(sym.get(), 1, 18, _file_handle.get())) // Each symbol has a fixed size of 18 bytes.
		{
			PRINT_ERROR << "Could not read a COFF symbol." << DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}

		if (sym->SectionNumber > _sections.size())
		{
			PRINT_WARNING << "COFF symbol's section number is bigger than the number of sections!"
						  << DEBUG_INFO_INSIDEPE << std::endl;
			continue;
		}

		_coff_symbols.push_back(sym);
	}

	// Read the COFF string table
	std::uint32_t table_size = 0;
	if (fread(&table_size, sizeof(table_size), 1, _file_handle.get()) != 1) {
		PRINT_ERROR << "Could not read the COFF String Table size."
			<< DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}
	if (table_size < sizeof(table_size)) {
		PRINT_ERROR << "COFF String Table size is smaller than its header."
			<< DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	const long payload_position = ftell(_file_handle.get());
	const std::uint64_t payload_size = table_size - sizeof(table_size);
	if (payload_position < 0 || static_cast<std::uint64_t>(payload_position) > _file_size ||
		payload_size > _file_size - static_cast<std::uint64_t>(payload_position))
	{
		PRINT_ERROR << "COFF String Table extends beyond the end of the file."
			<< DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	std::uint64_t remaining = payload_size;
	while (remaining != 0)
	{
		const long string_position = ftell(_file_handle.get());
		std::string value;
		if (string_position < 0 || !read_bounded_ascii_string(_file_handle.get(), remaining, value)) {
			PRINT_ERROR << "COFF String Table contains an unterminated string."
				<< DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}

		const long next_position = ftell(_file_handle.get());
		if (next_position <= string_position ||
			static_cast<std::uint64_t>(next_position - string_position) > remaining)
		{
			PRINT_ERROR << "Could not determine the consumed COFF String Table bytes."
				<< DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}
		remaining -= static_cast<std::uint64_t>(next_position - string_position);
		_coff_string_table.push_back(std::make_shared<std::string>(std::move(value)));
	}

	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_image_optional_header()
{
	if (!_h_pe || _file_handle == nullptr) {
		return false;
	}

	image_optional_header ioh;
	memset(&ioh, 0, sizeof(ioh));

	if (_h_pe->SizeOfOptionalHeader == 0)
	{
		PRINT_WARNING << "This PE has no Image Optional Header!." << DEBUG_INFO_INSIDEPE << std::endl;
		return true;
	}
	const std::uint64_t declared_size = _h_pe->SizeOfOptionalHeader;
	if (declared_size < sizeof(std::uint16_t)) {
		PRINT_ERROR << "SizeOfOptionalHeader is too small for IMAGE_OPTIONAL_HEADER."
			<< DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	if (fseek(_file_handle.get(), _h_dos->e_lfanew + sizeof(pe_header), SEEK_SET))
	{
		PRINT_ERROR << "Could not reach the Image Optional Header (fseek to offset "
			<<  _h_dos->e_lfanew + sizeof(pe_header) << " failed)." << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	if (sizeof(ioh.Magic) != fread(&ioh.Magic, 1, sizeof(ioh.Magic), _file_handle.get()))
	{
		PRINT_ERROR << "Could not read the Image Optional Header." << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	if (ioh.Magic != nt::IMAGE_OPTIONAL_HEADER_MAGIC.at("PE32") && ioh.Magic != nt::IMAGE_OPTIONAL_HEADER_MAGIC.at("PE32+"))
	{
		PRINT_ERROR << "Invalid Image Optional Header magic." << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	const std::uint64_t fixed_size =
		ioh.Magic == nt::IMAGE_OPTIONAL_HEADER_MAGIC.at("PE32+") ? 112 : 96;
	if (declared_size < fixed_size) {
		PRINT_ERROR << "SizeOfOptionalHeader is too small for IMAGE_OPTIONAL_HEADER."
			<< DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	// Read the rest of the first 0x18 bytes; subsequent fields differ by architecture.
	if (0x18 - sizeof(ioh.Magic) != fread(
		reinterpret_cast<std::uint8_t*>(&ioh) + sizeof(ioh.Magic),
		1, 0x18 - sizeof(ioh.Magic), _file_handle.get()))
	{
		PRINT_ERROR << "Could not read the Image Optional Header." << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	if (ioh.Magic == nt::IMAGE_OPTIONAL_HEADER_MAGIC.at("PE32"))
	{
		if (4 != fread(&ioh.BaseOfData, 1, 4, _file_handle.get()) || 4 != fread(&ioh.ImageBase, 1, 4, _file_handle.get()))
		{
			PRINT_ERROR << "Error reading the PE32 specific part of ImageOptionalHeader."
						<< DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}
	}
	else
	{
		// PE32+: BaseOfData doesn't exist, and ImageBase is a uint64.
		if (8 != fread(&ioh.ImageBase, 1, 8, _file_handle.get()))
		{
			PRINT_ERROR << "Error reading the PE32+ specific part of ImageOptionalHeader."
						<< DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}
	}

	// After this, PE32 and PE32+ structures are in sync for a while.
	if (0x28 != fread(&ioh.SectionAlignment, 1, 0x28, _file_handle.get()))
	{
		PRINT_ERROR << "Error reading the common part of ImageOptionalHeader."
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	// Reject malformed executables
	if (ioh.FileAlignment == 0 || ioh.SectionAlignment == 0)
	{
		PRINT_ERROR << "FileAlignment or SectionAlignment is null: the PE is invalid."
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	// The next 4 values may be uint32s or uint64s depending on whether this is a PE32+ header.
	// We store them in uint64s in any case.
	if (ioh.Magic == nt::IMAGE_OPTIONAL_HEADER_MAGIC.at("PE32+"))
	{
		if (40 != fread(&ioh.SizeofStackReserve, 1, 40, _file_handle.get()))
		{
			PRINT_ERROR << "Error reading SizeOfStackReserve for a PE32+ IMAGE OPTIONAL HEADER."
						<< DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}
	}
	else
	{
		fread(&ioh.SizeofStackReserve, 1, 4, _file_handle.get());
		fread(&ioh.SizeofStackCommit, 1, 4, _file_handle.get());
		fread(&ioh.SizeofHeapReserve, 1, 4, _file_handle.get());
		fread(&ioh.SizeofHeapCommit, 1, 4, _file_handle.get());
		fread(&ioh.LoaderFlags, 1, 4, _file_handle.get());
		fread(&ioh.NumberOfRvaAndSizes, 1, 4, _file_handle.get());
		if (feof(_file_handle.get()) || ferror(_file_handle.get()))
		{
			PRINT_ERROR << "Error reading SizeOfStackReserve for a PE32 IMAGE OPTIONAL HEADER." << DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}
	}

	// The Windows Loader disregards the value if it is greater than 0x10. This trick is supposedly used to crash parsers.
	// Source: http://opcode0x90.wordpress.com/2007/04/22/windows-loader-does-it-differently/
	// TODO: Move to an analysis module, since this denotes a suspicious intent.
	if (ioh.NumberOfRvaAndSizes > 0x10) {
		PRINT_WARNING << "NumberOfRvaAndSizes > 0x10. This PE may have manually been crafted." << DEBUG_INFO_INSIDEPE << std::endl;
	}

	const std::uint64_t available_directories = (declared_size - fixed_size) / 8;
	const std::uint32_t directory_count = std::min<std::uint32_t>(
		std::min<std::uint32_t>(ioh.NumberOfRvaAndSizes, 0x10),
		static_cast<std::uint32_t>(available_directories));
	for (std::uint32_t i = 0; i < directory_count; ++i)
	{
		if (8 != fread(&ioh.directories[i], 1, 8, _file_handle.get()))
		{
			PRINT_ERROR << "Could not read directory entry " << i << "." << DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}
	}

	_ioh = ioh;
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_section_table()
{
	if (!_h_pe || !_h_dos || _file_handle == nullptr) {
		return false;
	}

	if (fseek(_file_handle.get(), _h_dos->e_lfanew + sizeof(pe_header) + _h_pe->SizeOfOptionalHeader, SEEK_SET))
	{
		PRINT_ERROR << "Could not reach the Section Table (fseek to offset "
					<<  _h_dos->e_lfanew + sizeof(pe_header) + _h_pe->SizeOfOptionalHeader << " failed)."
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	for (int i = 0 ; i < _h_pe->NumberofSections ; ++i)
	{
		image_section_header sec;
		memset(&sec, 0, sizeof(image_section_header));
		if (sizeof(image_section_header) != fread(&sec, 1, sizeof(image_section_header), _file_handle.get()))
		{
			PRINT_ERROR << "Could not read section " << i << "." << DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}
		_sections.push_back(std::make_shared<Section>(sec, _file_handle, _file_size, _coff_string_table, _io_mutex));
	}

	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_debug()
{
	if (!_ioh || _file_handle == nullptr) {
		return false;
	}
	if (!_reach_directory(IMAGE_DIRECTORY_ENTRY_DEBUG, 28, "IMAGE_DEBUG_DIRECTORY")) { // No debug information.
		return true;
	}

	unsigned int size = 6 * sizeof(std::uint32_t) + 2 * sizeof(std::uint16_t);
	unsigned int number_of_entries = _ioh->directories[IMAGE_DIRECTORY_ENTRY_DEBUG].Size / size;

	for (unsigned int i = 0 ; i < number_of_entries ; ++i)
	{
		auto debug = std::make_shared<debug_directory_entry>();
		memset(debug.get(), 0, size);
		if (size != fread(debug.get(), 1, size, _file_handle.get()))
		{
			PRINT_ERROR << "Could not read the DEBUG_DIRECTORY_ENTRY" << DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}
		const long next_entry = ftell(_file_handle.get());
		if (next_entry < 0) {
			return false;
		}

		// VC++ Debug information
		if (debug->Type == nt::DEBUG_TYPES.at("IMAGE_DEBUG_TYPE_CODEVIEW"))
		{
			const std::uint64_t data_offset = debug->PointerToRawData;
			if (debug->SizeofData < sizeof(std::uint32_t) || data_offset > _file_size ||
				debug->SizeofData > _file_size - data_offset ||
				fseek(_file_handle.get(), debug->PointerToRawData, SEEK_SET))
			{
				PRINT_ERROR << "Invalid CodeView debug entry."
					<< DEBUG_INFO_INSIDEPE << std::endl;
				if (fseek(_file_handle.get(), next_entry, SEEK_SET)) return false;
				continue;
			}

			std::uint32_t signature = 0;
			if (fread(&signature, 1, sizeof(signature), _file_handle.get()) != sizeof(signature))
			{
				PRINT_ERROR << "Invalid CodeView debug entry."
					<< DEBUG_INFO_INSIDEPE << std::endl;
				if (fseek(_file_handle.get(), next_entry, SEEK_SET)) return false;
				continue;
			}

			const std::uint32_t fixed_size = signature == 0x53445352 ? 24 :
				signature == 0x3031424e ? 16 : 0;
			if (fixed_size == 0 || debug->SizeofData <= fixed_size)
			{
				PRINT_ERROR << "Invalid CodeView debug entry."
					<< DEBUG_INFO_INSIDEPE << std::endl;
				if (fseek(_file_handle.get(), next_entry, SEEK_SET)) return false;
				continue;
			}

			std::uint8_t fixed_data[20];
			const std::uint32_t remaining_fixed_size = fixed_size - sizeof(signature);
			std::string filename;
			if (fread(fixed_data, 1, remaining_fixed_size, _file_handle.get()) != remaining_fixed_size ||
				!read_bounded_ascii_string(_file_handle.get(), debug->SizeofData - fixed_size, filename))
			{
				PRINT_ERROR << "Invalid CodeView debug entry."
					<< DEBUG_INFO_INSIDEPE << std::endl;
				if (fseek(_file_handle.get(), next_entry, SEEK_SET)) return false;
				continue;
			}
			debug->Filename = filename;
			if (fseek(_file_handle.get(), next_entry, SEEK_SET)) return false;
		}
		else if (debug->Type == nt::DEBUG_TYPES.at("IMAGE_DEBUG_TYPE_MISC"))
		{
			image_debug_misc misc;
			constexpr unsigned int misc_size = 2 * sizeof(std::uint32_t) + 4 * sizeof(std::uint8_t);
			const std::uint64_t data_offset = debug->PointerToRawData;
			if (debug->SizeofData < misc_size || data_offset > _file_size ||
				debug->SizeofData > _file_size - data_offset)
			{
				PRINT_ERROR << "Invalid IMAGE_DEBUG_MISC bounds." << DEBUG_INFO_INSIDEPE << std::endl;
				if (fseek(_file_handle.get(), next_entry, SEEK_SET)) return false;
				continue;
			}
			memset(&misc, 1, misc_size);
			if (fseek(_file_handle.get(), debug->PointerToRawData, SEEK_SET) ||
				misc_size != fread(&misc, 1, misc_size, _file_handle.get()))
			{
				PRINT_ERROR << "Could not read IMAGE_DEBUG_MISC information." << DEBUG_INFO_INSIDEPE << std::endl;
				if (fseek(_file_handle.get(), next_entry, SEEK_SET)) return false;
				continue;
			}
			const bool is_unicode = misc.Unicode != 0;
			const unsigned int minimum_string_size = is_unicode ? 2 : 1;
			if (misc.Length < misc_size + minimum_string_size || misc.Length > debug->SizeofData ||
				(is_unicode && (misc.Length - misc_size) % 2 != 0))
			{
				PRINT_ERROR << "Invalid IMAGE_DEBUG_MISC Length." << DEBUG_INFO_INSIDEPE << std::endl;
				if (fseek(_file_handle.get(), next_entry, SEEK_SET)) return false;
				continue;
			}
			const std::uint64_t string_size = misc.Length - misc_size;
			const bool valid_string = is_unicode ?
				read_bounded_utf16_string(_file_handle.get(), string_size, misc.DbgFile) :
				read_bounded_ascii_string(_file_handle.get(), string_size, misc.DbgFile);
			if (!valid_string)
			{
				PRINT_ERROR << "Invalid IMAGE_DEBUG_MISC string." << DEBUG_INFO_INSIDEPE << std::endl;
				if (fseek(_file_handle.get(), next_entry, SEEK_SET)) return false;
				continue;
			}
			debug->Filename = misc.DbgFile;
			if (fseek(_file_handle.get(), next_entry, SEEK_SET)) return false;
		}
		_debug_entries.push_back(debug);
	}

	return true;
}

// ----------------------------------------------------------------------------

unsigned int PE::rva_to_offset(std::uint64_t rva) const
{
	if (!_ioh) // Image Optional Header was not parsed.
	{
		PRINT_ERROR << "Tried to convert a RVA into an offset, but ImageOptionalHeader was not parsed!"
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return 0;
	}

	// RVAs inside headers map directly to file offsets.
	if (rva < _ioh->SizeOfHeaders) {
		return static_cast<unsigned int>(rva & 0xFFFFFFFF);
	}

	// Special case: PE with no sections
	if (_sections.empty()) {
		return rva & 0xFFFFFFFF; // If the file is bigger than 4GB, this assumption may not be true.
	}

	// Find the corresponding section.
	pSection section = pSection();
	for (const auto& it : _sections)
	{
		if (is_address_in_section(rva, it))
		{
			section = it;
			break;
		}
	}

	if (section == nullptr)
	{
		// No section found. Maybe the VirsualSize is erroneous? Try with the RawSizeOfData.
		for (const auto& it : _sections)
		{
			if (is_address_in_section(rva, it, true))
			{
				section = it;
				break;
			}
		}

		if (section == nullptr) {  // No section matches the RVA.
			return 0;
		}
	}

	// The sections have to be aligned on FileAlignment bytes.
	// TODO: Move warning to a plugin?
	if (section->get_pointer_to_raw_data() % _ioh->FileAlignment != 0)
	{
		PRINT_WARNING << "The PE's sections are not aligned to its reported FileAlignment. "
					  << "It was almost certainly crafted manually."
					  << DEBUG_INFO_INSIDEPE << std::endl;
		int new_raw_pointer = (section->get_pointer_to_raw_data() / _ioh->FileAlignment) * _ioh->FileAlignment;
		return (rva - section->get_virtual_address() + new_raw_pointer) & 0xFFFFFFFF;
	}

	// Assume that the offset in the file can be stored inside an unsigned integer.
	// PEs whose size is bigger than 4 Go may not be parsed properly.
	return (rva - section->get_virtual_address() + section->get_pointer_to_raw_data()) & 0xFFFFFFFF;
}

// ----------------------------------------------------------------------------

unsigned int PE::offset_to_rva(std::uint64_t offset) const
{
	if (!_ioh) {
		PRINT_ERROR << "Tried to convert an offset into a RVA, but ImageOptionalHeader was not parsed!"
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return 0;
	}

	if (offset < _ioh->SizeOfHeaders) {
		return static_cast<unsigned int>(offset & 0xFFFFFFFF);
	}

	if (_sections.empty()) {
		return static_cast<unsigned int>(offset & 0xFFFFFFFF);
	}

	for (const auto& section : _sections)
	{
		std::uint32_t raw_ptr = section->get_pointer_to_raw_data();
		std::uint32_t raw_size = section->get_size_of_raw_data();
		std::uint32_t aligned_ptr = raw_ptr;

		if (raw_ptr % _ioh->FileAlignment != 0) {
			aligned_ptr = (raw_ptr / _ioh->FileAlignment) * _ioh->FileAlignment;
		}

		if (offset >= aligned_ptr && offset < static_cast<std::uint64_t>(aligned_ptr) + raw_size)
		{
			return static_cast<unsigned int>(
				(offset - aligned_ptr + section->get_virtual_address()) & 0xFFFFFFFF);
		}
	}

	return 0;
}

// ----------------------------------------------------------------------------

pSection PE::get_section_by_rva(std::uint64_t rva) const
{
	return find_section(static_cast<unsigned int>(rva), _sections);
}

// ----------------------------------------------------------------------------

pSection PE::get_section_by_offset(std::uint64_t offset) const
{
	for (const auto& section : _sections)
	{
		std::uint32_t raw_ptr = section->get_pointer_to_raw_data();
		std::uint32_t raw_size = section->get_size_of_raw_data();
		std::uint32_t aligned_ptr = raw_ptr;

		if (_ioh && raw_ptr % _ioh->FileAlignment != 0) {
			aligned_ptr = (raw_ptr / _ioh->FileAlignment) * _ioh->FileAlignment;
		}

		if (offset >= aligned_ptr && offset < static_cast<std::uint64_t>(aligned_ptr) + raw_size) {
			return section;
		}
	}

	return pSection();
}

// ----------------------------------------------------------------------------

shared_bytes PE::get_bytes_at_offset(std::uint64_t offset, size_t size) const
{
	if (_file_handle == nullptr || size == 0) {
		return nullptr;
	}
	if (offset >= _file_size) {
		return nullptr;
	}

	if (size > _file_size - offset) {
		size = static_cast<size_t>(_file_size - offset);
	}
	return _locked_read_vec(offset, size);
}

// ----------------------------------------------------------------------------

shared_bytes PE::get_data(std::uint64_t rva, size_t size) const
{
	unsigned int offset = rva_to_offset(rva);
	if (offset == 0 && rva != 0) {
		return nullptr;
	}
	return get_bytes_at_offset(offset, size);
}

// ----------------------------------------------------------------------------

unsigned int PE::_va_to_offset(std::uint64_t va) const
{
	if (!_ioh) // Image Optional Header was not parsed.
	{
		PRINT_ERROR << "Tried to convert a VA into an offset, but ImageOptionalHeader was not parsed!"
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return 0;
	}
	return va > _ioh->ImageBase ? rva_to_offset(va - _ioh->ImageBase) : 0;
}

// ----------------------------------------------------------------------------

bool PE::_reach_directory(int directory, std::uint64_t minimum_size,
	const char* structure_name) const
{
	if (_file_handle == nullptr) {
		return false;
	}
	const char* name = structure_name ? structure_name : "directory";

	if (directory < 0 || directory >= 0x10) // There can be no more than 16 directories.
	{
		PRINT_WARNING << "Tried to reach directory " << directory << ", maximum is 16."
					  << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	if (!_ioh) // Image Optional Header was not parsed.
	{
		PRINT_ERROR << "Tried to reach a directory, but ImageOptionalHeader was not parsed!"
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	const auto& entry = _ioh->directories[directory];
	if (entry.VirtualAddress == 0 && entry.Size == 0) {
		return false; // Requested directory is empty.
	}
	else if (entry.Size == 0) // Weird, but continue anyway.
	{
		PRINT_WARNING << "directory " << directory << " has a size of 0! This PE may have been manually crafted!"
					  << DEBUG_INFO_INSIDEPE << std::endl;
	}
	else if (entry.VirtualAddress == 0)
	{
		PRINT_ERROR << "Invalid " << name << " RVA: 0 with a non-null size."
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	if (entry.Size < minimum_size) {
		PRINT_ERROR << "Invalid " << name << " size."
			<< DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}
	const std::uint64_t offset = rva_to_offset(entry.VirtualAddress);
	if (!offset || offset > _file_size || minimum_size > _file_size - offset ||
		offset > static_cast<std::uint64_t>(std::numeric_limits<long>::max()) ||
		fseek(_file_handle.get(), static_cast<long>(offset), SEEK_SET)) {
		PRINT_ERROR << "Invalid " << name << " bounds."
			<< DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_directories()
{
	if (_file_handle == nullptr) {
		return false;
	}

	_parse_imports();
	_parse_delayed_imports();
	_parse_exports();
	_parse_resources();
	_parse_debug();
	_parse_relocations();
	_parse_tls();
	_parse_config();
	_parse_certificates();
	_parse_rich_header();
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_exports()
{
	if (!_ioh || _file_handle == nullptr) {
		return false;
	}
	if (!_reach_directory(IMAGE_DIRECTORY_ENTRY_EXPORT, 40, "IMAGE_EXPORT_DIRECTORY"))	{
		return true; // No exports
	}

	image_export_directory ied;

	// Don't overwrite the std::string at the end of the structure.
	unsigned int ied_size = 9*sizeof(std::uint32_t) + 2*sizeof(std::uint16_t);
	memset(&ied, 0, ied_size);

	if (ied_size != fread(&ied, 1, ied_size, _file_handle.get()))
	{
		PRINT_ERROR << "Could not read the IMAGE_EXPORT_DIRECTORY." << std::endl;
		return false;
	}

    _ied = ied;

	if (_ied->Characteristics != 0) {
		PRINT_WARNING << "IMAGE_EXPORT_DIRECTORY field Characteristics is reserved and should be 0!"
					  << DEBUG_INFO_INSIDEPE << std::endl; // TODO: Move to structural plugin?
	}
	if (_ied->NumberOfFunctions == 0) {
		return true; // No exports
	}

	// Read the export name
	unsigned int offset = rva_to_offset(_ied->Name);
	if (!offset || !utils::read_string_at_offset(_file_handle.get(), offset, _ied->NameStr))
	{
		PRINT_ERROR << "Could not read the exported DLL name." << DEBUG_INFO_INSIDEPE << std::endl;
		return true;
	}

	// Get the address and ordinal of each exported function
	offset = rva_to_offset(_ied->AddressOfFunctions);
	if (!offset || fseek(_file_handle.get(), offset, SEEK_SET))
	{
		PRINT_ERROR << "Could not reach exported functions address table."
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return true;
	}

	for (unsigned int i = 0 ; i < _ied->NumberOfFunctions ; ++i)
	{
		pexported_function ex = std::make_shared<exported_function>();
		if (4 != fread(&(ex->Address), 1, 4, _file_handle.get()))
		{
			PRINT_ERROR << "Could not read an exported function's address."
						<< DEBUG_INFO_INSIDEPE << std::endl;
			return true;
		}
		const std::uint64_t ordinal = static_cast<std::uint64_t>(_ied->Base) + i;
		if (ordinal > std::numeric_limits<std::uint32_t>::max())
		{
			PRINT_ERROR << "Export ordinal cannot be represented."
						<< DEBUG_INFO_INSIDEPE << std::endl;
			break;
		}
		ex->Ordinal = static_cast<std::uint32_t>(ordinal);

		// If the address is located in the export directory, then it is a forwarded export.
		image_data_directory export_dir = _ioh->directories[IMAGE_DIRECTORY_ENTRY_EXPORT];
		const std::uint64_t export_end = static_cast<std::uint64_t>(export_dir.VirtualAddress) + export_dir.Size;
		if (ex->Address > export_dir.VirtualAddress && ex->Address < export_end)
		{
			offset = rva_to_offset(ex->Address);
			if (!offset || !utils::read_string_at_offset(_file_handle.get(), offset, ex->ForwardName))
			{
				PRINT_ERROR << "Could not read a forwarded export name." << DEBUG_INFO_INSIDEPE << std::endl;
				return true;
			}
		}

		_exports.push_back(ex);
	}

    if (_ied->NumberOfNames == 0) {
        return true;
    }

	// Associate possible exported names with the RVAs we just obtained. First, read the name and ordinal table.
	const std::uint64_t names_offset = rva_to_offset(_ied->AddressOfNames);
	const std::uint64_t ords_offset = rva_to_offset(_ied->AddressOfNameOrdinals);
	const std::uint64_t count = _ied->NumberOfNames;
	if (!names_offset || names_offset > _file_size ||
		count > (_file_size - names_offset) / sizeof(std::uint32_t)) {
		PRINT_ERROR << "Invalid export name-pointer table extent."
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return true;
	}
	if (!ords_offset || ords_offset > _file_size ||
		count > (_file_size - ords_offset) / sizeof(std::uint16_t)) {
		PRINT_ERROR << "Invalid export ordinal table extent."
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return true;
	}

	std::vector<std::uint32_t> names;
	std::vector<std::uint16_t> ords;
	try
	{
		// ied.NumberOfNames is an untrusted value. Allocate in a try-catch block to prevent crashes. See issue #1.
		names.resize(_ied->NumberOfNames);
		ords.resize(_ied->NumberOfNames);
	}
	catch (const std::bad_alloc&)
	{
		PRINT_ERROR << "Could not allocate an array big enough to hold exported name RVAs. This PE may have been manually crafted."
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return true;
	}
	catch (const std::length_error&)
	{
		PRINT_ERROR << "Could not allocate an array big enough to hold exported name RVAs. This PE may have been manually crafted."
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return true;
	}
	if (fseek(_file_handle.get(), static_cast<long>(names_offset), SEEK_SET))
	{
		PRINT_ERROR << "Could not reach exported function's name table." << DEBUG_INFO_INSIDEPE << std::endl;
		return true;
	}

	if (_ied->NumberOfNames * sizeof(std::uint32_t) != fread(names.data(), 1, _ied->NumberOfNames * sizeof(std::uint32_t), _file_handle.get()))
	{
		PRINT_ERROR << "Could not read an exported function's name address." << DEBUG_INFO_INSIDEPE << std::endl;
		return true;
	}

	if (fseek(_file_handle.get(), static_cast<long>(ords_offset), SEEK_SET))
	{
		PRINT_ERROR << "Could not reach exported functions NameOrdinals table." << DEBUG_INFO_INSIDEPE << std::endl;
		return true;
	}
	if (_ied->NumberOfNames * sizeof(std::uint16_t) != fread(ords.data(), 1, _ied->NumberOfNames * sizeof(std::uint16_t), _file_handle.get()))
	{
		PRINT_ERROR << "Could not read an exported function's name ordinal." << DEBUG_INFO_INSIDEPE << std::endl;
		return true;
	}

	// Now match the names with with the exported addresses.
	for (unsigned int i = 0 ; i < _ied->NumberOfNames ; ++i)
	{
		offset = rva_to_offset(names[i]);
		if (!offset || ords[i] >= _exports.size() || !utils::read_string_at_offset(_file_handle.get(), offset, _exports.at(ords[i])->Name))
		{
			PRINT_ERROR << "Could not match an export name with its address!" << DEBUG_INFO_INSIDEPE << std::endl;
			return true;
		}
	}
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_relocations()
{
	if (!_ioh || _file_handle == nullptr) {
		return false;
	}

	if (!_reach_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC))	{ // No relocation table
		return true;
	}

	unsigned int remaining_size = _ioh->directories[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	constexpr unsigned int header_size = 2 * sizeof(std::uint32_t);
	while (remaining_size > 0)
	{
		if (remaining_size < header_size)
		{
			PRINT_ERROR << "Invalid IMAGE_BASE_RELOCATION BlockSize." << DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}
		pimage_base_relocation reloc = std::make_shared<image_base_relocation>();
		memset(reloc.get(), 0, header_size);
		if (header_size != fread(reloc.get(), 1, header_size, _file_handle.get()) || reloc->BlockSize > remaining_size)
		{
			PRINT_ERROR << "Could not read an IMAGE_BASE_RELOCATION!" << DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}

		// It seems that sometimes, the end of the section is padded with zeroes. Break here
		// instead of reaching EOF. I have encountered this oddity in 4d7ca8d467770f657305c16474b845fe.
		if (reloc->BlockSize == 0) {
			return true;
		}
		if (reloc->BlockSize < header_size ||
			(reloc->BlockSize - header_size) % sizeof(std::uint16_t) != 0)
		{
			PRINT_ERROR << "Invalid IMAGE_BASE_RELOCATION BlockSize." << DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}

		// The remaining fields are an array of shorts. The number is deduced from the block size.
		for (unsigned int i = 0 ; i < (reloc->BlockSize - header_size) / sizeof(std::uint16_t) ; ++i)
		{
			std::uint16_t type_or_offset = 0;
			if (sizeof(std::uint16_t) != fread(&type_or_offset, 1, sizeof(std::uint16_t), _file_handle.get()))
			{
				PRINT_ERROR << "Could not read an IMAGE_BASE_RELOCATION's TypeOrOffset!"
							<< DEBUG_INFO_INSIDEPE << std::endl;
				return false;
			}
			reloc->TypesOffsets.push_back(type_or_offset);
		}

		_relocations.push_back(reloc);
		remaining_size -= reloc->BlockSize;
	}
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_tls()
{
	if (!_ioh || _file_handle == nullptr) {
		return false;
	}

	const std::uint64_t directory_size =
		_ioh->Magic == nt::IMAGE_OPTIONAL_HEADER_MAGIC.at("PE32+") ? 40 : 24;
	if (!_reach_directory(IMAGE_DIRECTORY_ENTRY_TLS, directory_size, "IMAGE_TLS_DIRECTORY"))	{ // No TLS callbacks
		return true;
	}

	image_tls_directory tls;
	unsigned int size = 4*sizeof(std::uint64_t) + 2*sizeof(std::uint32_t);
	memset(&tls, 0, size);

	bool read_root = false;
	if (get_architecture() == x64) {
		read_root = fread(&tls, 1, size, _file_handle.get()) == size;
	}
	else
	{
		read_root =
			fread(&tls.StartAddressOfRawData, 1, sizeof(std::uint32_t), _file_handle.get()) == sizeof(std::uint32_t) &&
			fread(&tls.EndAddressOfRawData, 1, sizeof(std::uint32_t), _file_handle.get()) == sizeof(std::uint32_t) &&
			fread(&tls.AddressOfIndex, 1, sizeof(std::uint32_t), _file_handle.get()) == sizeof(std::uint32_t) &&
			fread(&tls.AddressOfCallbacks, 1, sizeof(std::uint32_t), _file_handle.get()) == sizeof(std::uint32_t) &&
			fread(&tls.SizeOfZeroFill, 1, 2 * sizeof(std::uint32_t), _file_handle.get()) == 2 * sizeof(std::uint32_t);
	}

	if (!read_root)
	{
		PRINT_ERROR << "Could not read the IMAGE_TLS_DIRECTORY." << DEBUG_INFO_INSIDEPE << std::endl;
		return true; // Non-fatal
	}

	// Go to the offset table
	unsigned int offset = _va_to_offset(tls.AddressOfCallbacks);
	if (!offset || fseek(_file_handle.get(), offset, SEEK_SET))
	{
		PRINT_ERROR << "Could not reach the TLS callback table." << DEBUG_INFO_INSIDEPE << std::endl;
		return true; // Non-fatal
	}

	std::uint64_t callback_address = 0;
	unsigned int callback_size = _ioh->Magic == nt::IMAGE_OPTIONAL_HEADER_MAGIC.at("PE32+") ? sizeof(std::uint64_t) : sizeof(std::uint32_t);
	while (true) // break on null callback
	{
		if (callback_size != fread(&callback_address, 1, callback_size, _file_handle.get()) || !callback_address) { // Exit condition.
			break;
		}
		tls.Callbacks.push_back(callback_address);
	}

	_tls = tls;
	return true;
}

// ----------------------------------------------------------------------------

/**
 *	@brief	Helper function which simplifies the process of reading a field from
 *			the file's load configuration while checking if there are enough
 *			bytes available.
 *			
 *	@param	source		A pointer to the file to read from.
 *	@param	destination	Where the read value is to be put.
 *	@param	field_size	The size of the value to read.
 *	@param	extent		The maximum number of bytes available to the structure.
 *	@param	read_bytes	The number of bytes read so far, will be incremented.
 *	
 *	@return	Whether the value should be read. If false, EOF has been reached or
 *			the structure has no more fields to read.
 */
bool read_config_field(FILE* source, void* destination,
	std::uint64_t field_size, std::uint64_t extent,
	std::uint64_t& read_bytes)
{
	if (read_bytes > extent || field_size > extent - read_bytes) return false;
	if (fread(destination, 1, static_cast<size_t>(field_size), source) != field_size) return false;
	read_bytes += field_size;
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_config()
{
	if (!_ioh || _file_handle == nullptr) {
		return false;
	}

	if (!_reach_directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, 4, "IMAGE_LOAD_CONFIG_DIRECTORY")) { // No load configuration
		return true;
	}

	image_load_config_directory config;
	memset(&config, 0, sizeof(config));
	if (sizeof(config.Size) != fread(&config.Size, 1, sizeof(config.Size), _file_handle.get()))
	{
		PRINT_ERROR << "Could not read the IMAGE_LOAD_CONFIG_DIRECTORY."
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return true; // Non fatal
	}
	if (config.Size < sizeof(config.Size))
	{
		PRINT_ERROR << "Invalid IMAGE_LOAD_CONFIG_DIRECTORY size."
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return true;
	}

	const auto& directory = _ioh->directories[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
	const std::uint64_t root_offset = rva_to_offset(directory.VirtualAddress);
	const std::uint64_t effective_extent = std::min<std::uint64_t>(config.Size,
		std::min<std::uint64_t>(directory.Size, _file_size - root_offset));
	const std::uint64_t architecture_field_size =
		_ioh->Magic == nt::IMAGE_OPTIONAL_HEADER_MAGIC.at("PE32") ? 4 : 8;
	std::uint64_t read_bytes = sizeof(config.Size);

	struct config_field {
		void* destination;
		std::uint64_t size;
	};
	const config_field fields[] = {
		{&config.TimeDateStamp, 4},
		{&config.MajorVersion, 2},
		{&config.MinorVersion, 2},
		{&config.GlobalFlagsClear, 4},
		{&config.GlobalFlagsSet, 4},
		{&config.CriticalSectionDefaultTimeout, 4},
		{&config.DeCommitFreeBlockThreshold, architecture_field_size},
		{&config.DeCommitTotalFreeThreshold, architecture_field_size},
		{&config.LockPrefixTable, architecture_field_size},
		{&config.MaximumAllocationSize, architecture_field_size},
		{&config.VirtualMemoryThreshold, architecture_field_size},
		{&config.ProcessAffinityMask, architecture_field_size},
		{&config.ProcessHeapFlags, 4},
		{&config.CSDVersion, 2},
		{&config.Reserved1, 2},
		{&config.EditList, architecture_field_size},
		{&config.SecurityCookie, architecture_field_size},
		{&config.SEHandlerTable, architecture_field_size},
		{&config.SEHandlerCount, architecture_field_size},
		{&config.GuardCFCheckFunctionPointer, architecture_field_size},
		{&config.GuardCFDispatchFunctionPointer, architecture_field_size},
		{&config.GuardCFFunctionTable, architecture_field_size},
		{&config.GuardCFFunctionCount, architecture_field_size},
		{&config.GuardFlags, 4},
		{&config.CodeIntegrity, 12},
		{&config.GuardAddressTakenIatEntryTable, architecture_field_size},
		{&config.GuardAddressTakenIatEntryCount, architecture_field_size},
		{&config.GuardLongJumpTargetTable, architecture_field_size},
		{&config.GuardLongJumpTargetCount, architecture_field_size}
	};
	for (const auto& field : fields)
	{
		if (!read_config_field(_file_handle.get(), field.destination, field.size,
			effective_extent, read_bytes)) {
			break;
		}
	}

	_config = config;
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_certificates()
{
	if (!_ioh || _file_handle == nullptr) {
		return false;
	}

	const auto& directory = _ioh->directories[IMAGE_DIRECTORY_ENTRY_SECURITY];
	const std::uint64_t directory_offset = directory.VirtualAddress;
	std::uint64_t remaining_bytes = directory.Size;
	constexpr std::uint64_t header_size = sizeof(std::uint32_t) + 2 * sizeof(std::uint16_t);

	if (directory_offset == 0) {
		return true;
	}
	if (directory_offset > _file_size || remaining_bytes > _file_size - directory_offset ||
		directory_offset > static_cast<std::uint64_t>(std::numeric_limits<long>::max()) ||
		fseek(_file_handle.get(), static_cast<long>(directory_offset), SEEK_SET))
	{
		PRINT_WARNING << "The PE's certificate directory is outside the file." << DEBUG_INFO_INSIDEPE << std::endl;
		return true;
	}

	while (remaining_bytes >= header_size)
	{
		pwin_certificate cert = std::make_shared<win_certificate>();
		memset(cert.get(), 0, header_size);
		if (header_size != fread(cert.get(), 1, header_size, _file_handle.get()))
		{
			PRINT_WARNING << "Could not read a WIN_CERTIFICATE's header." << std::endl;
			return true; // Recoverable error.
		}

		// The certificate may point to garbage. Although other values than the ones defined in nt_values.h
		// are allowed by the PE specification (but which ones?), this is a good heuristic to determine
		// whether we have landed in random bytes.
		if (*nt::translate_to_flag(cert->CertificateType, nt::WIN_CERTIFICATE_TYPES) == "UNKNOWN" &&
			*nt::translate_to_flag(cert->Revision, nt::WIN_CERTIFICATE_REVISIONS) == "UNKNOWN")
		{
			PRINT_WARNING << "The WIN_CERTIFICATE appears to be invalid." << DEBUG_INFO_INSIDEPE << std::endl;
			return true; // Recoverable error.
		}
		else if (cert->CertificateType != WIN_CERT_TYPE_PKCS_SIGNED_DATA)
		{
			PRINT_WARNING << "Encountered a certificate of type " 
						  << *nt::translate_to_flag(cert->CertificateType, nt::WIN_CERTIFICATE_TYPES)
						  << ", but only WIN_CERT_TYPE_PKCS_SIGNED_DATA is supported by Windows!"
						  << DEBUG_INFO_INSIDEPE << std::endl;
			// Get the certificate data anyway.
		}

		const std::uint64_t certificate_start = directory.Size - remaining_bytes;
		const std::uint64_t file_offset = directory_offset + certificate_start;
		const std::uint64_t padding = (8 - (cert->Length % 8)) % 8;
		const std::uint64_t consumed = static_cast<std::uint64_t>(cert->Length) + padding;
		if (cert->Length < header_size || consumed > remaining_bytes ||
			consumed > _file_size - file_offset)
		{
			PRINT_WARNING << "The WIN_CERTIFICATE and its alignment padding exceed the available certificate data."
						  << DEBUG_INFO_INSIDEPE << std::endl;
			return true;
		}

		const size_t payload_size = static_cast<size_t>(cert->Length - header_size);
		try {
			cert->Certificate.resize(payload_size);
		}
		catch (const std::exception& e)
		{
			PRINT_ERROR << "Failed to allocate enough space for a certificate! (" << e.what() << ")"
						<< DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}

		if (payload_size != 0 &&
			payload_size != fread(cert->Certificate.data(), 1, payload_size, _file_handle.get()))
		{
			PRINT_ERROR << "Could not read a WIN_CERTIFICATE's data."
						<< DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}
		if (padding != 0 && fseek(_file_handle.get(), static_cast<long>(padding), SEEK_CUR)) {
			return true;
		}
		remaining_bytes -= consumed;
		_certificates.push_back(cert);
	}

	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_rich_header()
{
	if (!_h_dos || _file_handle == nullptr) {
		return false;
	}

	// Start searching for the RICH header at offset 0, but before the PE header.
	if (fseek(_file_handle.get(), 0, SEEK_SET))	{
		return true;
	}

	unsigned int read;
	int bytes_left = _h_dos->e_lfanew;

	do
	{
		if (1 != fread(&read, 4, 1, _file_handle.get())) {
			break;
		}
		bytes_left -= 4;  // Stay between offset 0x80 and the PE header.
	} while (read != 0x68636952 && bytes_left > 0);

	if (read != 0x68636952)	{
		return true;  // The RICH magic was not found.
	}
	rich_header h;
	if (1 != fread(&h.xor_key, 4, 1, _file_handle.get())) 
	{
		PRINT_WARNING << "XOR key absent after the RICH header!" << DEBUG_INFO_INSIDEPE << std::endl;
		return true;
	}

	// Start parsing the values backwards.
	while (true)
	{
		if (fseek(_file_handle.get(), -16, SEEK_CUR)) 
		{
			PRINT_WARNING << "Error while reading the RICH header!" << DEBUG_INFO_INSIDEPE << std::endl;
			return true;
		}
		std::uint64_t data;
		if (1 != fread(&data, 8, 1, _file_handle.get())) 
		{
			PRINT_WARNING << "Error while reading the RICH header!" << DEBUG_INFO_INSIDEPE << std::endl;
			return true;
		}
		std::uint32_t count = (data >> 32) ^ h.xor_key;
		std::uint32_t id_value = (data & 0xFFFFFFFF) ^ h.xor_key;

		// Stop if we reach the start marker, "DanS".
		if (id_value == 0x536E6144) {
			break;
		}
		auto t = std::make_tuple(static_cast<std::uint16_t>((id_value >> 16) & 0xFFFF), static_cast<std::uint16_t>(id_value & 0xFFFF), count);
		h.values.insert(h.values.begin(), t);
	};

	// Keep a trace of where this header starts, as it is not easy to locate and is useful to calculate the checksum.
	h.file_offset = ftell(_file_handle.get()) - 8;
	_rich_header = h;
	return true;
}

} // !namespace mana
