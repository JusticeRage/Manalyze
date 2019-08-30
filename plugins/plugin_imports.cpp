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

#include <set>
#include <boost/algorithm/string/predicate.hpp>

#include "plugin_framework/plugin_interface.h"
#include "plugin_framework/auto_register.h"

#include "manacommons/color.h"
#include <yara/atoms.h>

namespace plugin {

enum REQUIREMENT { AT_LEAST_ONE = 1, AT_LEAST_TWO = 2, AT_LEAST_THREE = 3 };

// IsDebuggerPresent has been removed from this list, because it gets referenced in ___scrt_fastfail which seems to be present in any PE.
// The presence of this function is therefore not meaningful of any particular intent.
std::string anti_debug =
	"FindWindow(A|W)|(Zw|Nt)QuerySystemInformation|DbgBreakPoint|DbgPrint|"
	"CheckRemoteDebuggerPresent|CreateToolhelp32Snapshot|Toolhelp32ReadProcessMemory|"
	"OutputDebugString|SwitchToThread|NtQueryInformationProcess";	// Standard anti-debug API calls

std::string vanilla_injection = "(Nt)?VirtualAlloc.*|(Nt)?WriteProcessMemory|CreateRemoteThread(Ex)?|(Nt)?OpenProcess";

std::string process_hollowing = "(Nt)?WriteProcessMemory|(Nt)?WriteVirtualMemory|(Wow64)?SetThreadContext|(Nt)?ResumeThread|(Nt)?SetContextThread";

std::string power_loader = "FindWindow(A|W)|GetWindowLong(A|W)";

std::string atom_bombing = "GlobalAddAtom(A|W)|GlobalGetAtomName(A|W)|QueueUserAPC";

std::string process_doppelganging = "CreateTransaction|CreateFileTransacted|RollbackTransaction|(Nt)?WriteFile";

std::string keylogger_api = "SetWindowsHook(Ex)?|GetAsyncKeyState|GetForegroundWindow|AttachThreadInput|CallNextHook(Ex)?|MapVirtualKey(A|W|Ex)";

std::string raw_socket_api = "accept|bind|connect|recv|send|gethost(by)?name|inet_addr";

std::string http_api = "Internet.*|URL(Download|Open).*|WinHttp.*";

std::string registry_api = "Reg.*(Key|Value).*|SH.*(Reg|Key).*|SHQueryValueEx(A|W)|SHGetValue(A|W)";

std::string process_creation_api = "(Nt)?CreateProcess.*|system|WinExec|ShellExecute(A|W)";

std::string process_manipulation_api = "EnumProcess.*|(Nt)?OpenProcess|(Nt)?(Read|Write)ProcessMemory|Process32(First|Next)(A|W)?";

std::string service_manipulation_api = "OpenSCManager(A|W)|(Open|Control|Create|Delete)Service(A|W)?|QueryService.*|"
									   "ChangeServiceConfig(A|W)|EnumServicesStatus(Ex)?(A|W)";

std::string privilege_api = "AdjustTokenPrivileges|IsNTAdmin|LsaEnumerateLogonSessions|SamQueryInformationUser|"
							"SamIGetPrivateData|SfcTerminateWatcherThread|(Zw)?OpenProcessToken(Ex)?|(Zw)?DuplicateToken(Ex)?|"
							"(SHTest|Check)TokenMembership";

std::string dacl_api = "SetKernelObjectSecurity|SetFileSecurity(A|W)|SetNamedSecurityInfo(A|W)|SetSecurityInfo";

std::string dynamic_import = "(Co)?LoadLibrary(Ex)?(A|W)|GetProcAddress|LdrLoadDll|MmGetSystemRoutineAddress";

std::string packer_api = "(Nt)?VirtualAlloc(Ex)?|(Nt)?VirtualProtect(Ex)?";

std::string temporary_files = "GetTempPath(A|W)|(Create|Write)File(A|W)";

std::string hdd_enumeration = "GetVolumeInformation(ByHandle)?(A|W)|GetDriveType(A|W)|GetLogicalDriveStrings(A|W)";

std::string driver_enumeration = "EnumDeviceDrivers|GetDeviceDriver.*";

std::string eventlog_deletion = "EvtClearLog|ClearEventLog(A|W)";

std::string screenshot_api = "CreateCompatibleDC|GetDC(Ex)?|FindWindow(A|W)|PrintWindow|BitBlt";

std::string audio_api = "waveInOpen|DirectSoundCaptureCreate.*";

std::string shutdown_functions = "Initiate(System)?Shutdown(Ex)?(A|W)|LockWorkStation|ExitWindows(Ex)?";

std::string networking_api = "(Un)?EnableRouter|SetAdapterIpAddress|SetIp(Forward|Net|Statistics|TTL).*|SetPerTcp(6)?ConnectionEStats";

std::string netwksta_api = "NetWksta(GetInfo|UserEnum|UserGetInfo)";

// ----------------------------------------------------------------------------

/**
 *	@brief Counts the number of different function names in a vector.
 *
 *	A, W, Ex and Nt/Zw variants of the same function are considered to be the same.
 *
 *	@param v The vector containing the function names.
 *
 *	@return The number of different functions in the vector.
 */
size_t count_functions(const std::vector<std::string>& v)
{
	std::set<std::string> string_set;
	for (const std::string& s : v)
	{
		if (s.empty()) {
			continue;
		}
		std::string tmp(s);
		if (boost::algorithm::ends_with(tmp, "A") || boost::algorithm::ends_with(tmp, "W")) {
			tmp.pop_back();
		}
		if (tmp.size() > 2 && boost::algorithm::ends_with(tmp, "Ex")) {
			tmp = tmp.substr(0, tmp.size() - 2);
		}
        if (tmp.size() > 2 && (boost::algorithm::starts_with(tmp, "Nt") || boost::algorithm::starts_with(tmp, "Zw"))) {
            tmp = tmp.substr(2, tmp.size());
        }
		string_set.insert(tmp);
	}
	return string_set.size();
}

// ----------------------------------------------------------------------------

/**
 *	@brief	Checks the presence of some functions in the PE and updates the
 *			result accordingly.
 *
 *	@param	pe The PE in which the imports should be looked for.
 *	@param	func_regex The regular expression against which the
 *			imports should be matched.
 *	@param	level The severity level to set if the imports are found.
 *	@param	description The description to add to the result if
 *			matching imports are found.
 *	@param	req A criteria indicating how many matching imports should
 *			be found before updating the result.
 *	@param	res The result which will receive the information.
 *
 *	@return	Whether imports matching the requested criteria were found.
 */
bool check_functions(const mana::PE& pe,
					 const std::string& func_regex,
					 LEVEL level,
					 const std::string& description,
					 REQUIREMENT req,
					 pResult res)
{
	auto found_imports = pe.find_imports(func_regex);
	if (found_imports && count_functions(*found_imports) >= static_cast<unsigned int>(req))  // Safe cast: these are positive enum indexes
	{
		res->raise_level(level);
		io::pNode info = boost::make_shared<io::OutputTreeNode>(description,
																io::OutputTreeNode::STRINGS,
																io::OutputTreeNode::NEW_LINE);

		for (const auto& it : *found_imports) {
			info->append(it);
		}
		res->add_information(info);
		return true;
	}
	return false;
}

// ----------------------------------------------------------------------------

/**
 *	@brief	Checks the presence of a given imported library and updates the 
 *			result accordingly.
 *
 *	@param	pe The PE in which the imports should be looked for.
 *	@param	dll_regex The regular expression against which the
 *			imported libraries should be matched.
 *	@param	level The severity level to set if the imports are found.
 *	@param	description The description to add to the result if
 *			matching imports are found.
 *	@param	res The result which will receive the information.
 */
bool check_dlls(const mana::PE& pe,
				const std::string& dll_regex,
				LEVEL level,
				const std::string& description,
				pResult res)
{
	mana::const_shared_strings found_imports = pe.find_imports(".*", dll_regex);
	if (!found_imports->empty())
	{
		res->raise_level(level);
		io::pNode info = boost::make_shared<io::OutputTreeNode>(description,
																io::OutputTreeNode::STRINGS,
																io::OutputTreeNode::NEW_LINE);
		for (const auto& it : *found_imports) {
			info->append(it);
		}
		res->add_information(info);
		return true;
	}
	return false;
}

// ----------------------------------------------------------------------------

class ImportsPlugin : public IPlugin
{
public:
	int get_api_version() const override { return 1; }

	pString get_id() const override {
		return boost::make_shared<std::string>("imports");
	}

	pString get_description() const override {
		return boost::make_shared<std::string>("Looks for suspicious imports.");
	}

	pResult analyze(const mana::PE& pe) override
	{
		pResult res = create_result();
		check_functions(pe, dynamic_import, NO_OPINION, "[!] The program may be hiding some of its imports", AT_LEAST_TWO, res);
		check_functions(pe, anti_debug, SUSPICIOUS, "Functions which can be used for anti-debugging purposes", AT_LEAST_ONE, res);
		check_functions(pe, vanilla_injection, MALICIOUS, "Code injection capabilities", AT_LEAST_THREE, res);
		check_functions(pe, process_hollowing, MALICIOUS, "Code injection capabilities (process hollowing)", AT_LEAST_THREE, res);
		check_functions(pe, power_loader, MALICIOUS, "Code injection capabilities (PowerLoader)", AT_LEAST_TWO, res);
		check_functions(pe, atom_bombing, MALICIOUS, "Code injection capabilities (atom bombing)", AT_LEAST_THREE, res);
		check_functions(pe, process_doppelganging, MALICIOUS, "Code injection capabilities (process doppelganging)", AT_LEAST_THREE, res);
		check_functions(pe, registry_api, NO_OPINION, "Can access the registry", AT_LEAST_ONE, res);
		check_functions(pe, process_creation_api, NO_OPINION, "Possibly launches other programs", AT_LEAST_ONE, res);
		check_functions(pe, "(Nt|Zw).*", SUSPICIOUS, "Uses Windows's Native API", AT_LEAST_TWO, res);
		check_functions(pe, "Crypt.*", NO_OPINION, "Uses Microsoft's cryptographic API", AT_LEAST_ONE, res);
		check_functions(pe, temporary_files, NO_OPINION, "Can create temporary files", AT_LEAST_TWO, res);
		check_functions(pe, "Wlx.*", MALICIOUS, "Possibly attempts GINA replacement", AT_LEAST_THREE, res);
		check_functions(pe, keylogger_api, MALICIOUS, "Uses functions commonly found in keyloggers", AT_LEAST_TWO, res);
		check_functions(pe, packer_api, SUSPICIOUS, "Memory manipulation functions often used by packers", AT_LEAST_TWO, res);
		check_functions(pe, http_api, NO_OPINION, "Has Internet access capabilities", AT_LEAST_ONE, res);
		// WS2_32.dll seems to be imported by ordinal more often than not, so check for DLL presence instead of individual functions.
		check_dlls(pe, "WS2_32.dll", SUSPICIOUS, "Leverages the raw socket API to access the Internet", res);
		check_functions(pe, privilege_api, MALICIOUS, "Functions related to the privilege level", AT_LEAST_ONE, res);
		check_functions(pe, service_manipulation_api, SUSPICIOUS, "Interacts with services", AT_LEAST_ONE, res);
		check_functions(pe, hdd_enumeration, NO_OPINION, "Enumerates local disk drives", AT_LEAST_ONE, res);
		check_functions(pe, driver_enumeration, SUSPICIOUS, "Enumerates drivers present on the system", AT_LEAST_ONE, res);
		check_functions(pe, process_manipulation_api, SUSPICIOUS, "Manipulates other processes", AT_LEAST_ONE, res);
		check_functions(pe, eventlog_deletion, MALICIOUS, "Deletes entries from the event log", AT_LEAST_ONE, res);
		check_functions(pe, dacl_api, SUSPICIOUS, "Changes object ACLs", AT_LEAST_ONE, res);
		check_functions(pe, screenshot_api, SUSPICIOUS, "Can take screenshots", AT_LEAST_TWO, res);
		check_functions(pe, audio_api, SUSPICIOUS, "Can use the microphone to record audio", AT_LEAST_ONE, res);
		check_functions(pe, networking_api, SUSPICIOUS, "Modifies the network configuration", AT_LEAST_ONE, res);
        check_functions(pe, netwksta_api, SUSPICIOUS, "Queries user information on remote machines", AT_LEAST_ONE, res);
		check_functions(pe, "GetClipboardData", NO_OPINION, "Reads the contents of the clipboard", AT_LEAST_ONE, res);
		check_functions(pe, "IsUserAnAdmin", NO_OPINION, "Checks if it has admin rights", AT_LEAST_ONE, res);
		check_functions(pe, "Cert(Add|Open|Register|Remove|Save|Srv|Store).*", SUSPICIOUS, "Interacts with the certificate store", AT_LEAST_ONE, res);
		check_functions(pe, shutdown_functions, NO_OPINION, "Can shut the system down or lock the screen", AT_LEAST_ONE, res);

		switch (res->get_level())
		{
			case NO_OPINION:
				if (res->get_information() && res->get_information()->size() > 0) {
					res->set_summary("The PE contains common functions which appear in legitimate applications.");
				}
				break;
			case SUSPICIOUS:
				res->set_summary("The PE contains functions most legitimate programs don't use.");
				break;
			case MALICIOUS:
				res->set_summary("The PE contains functions mostly used by malware.");
				break;
			default:
				break;
		}

		return res;
	}
};

AutoRegister<ImportsPlugin> auto_register_imports;

} // !namespace plugin
