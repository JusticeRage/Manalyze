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

#include "plugin_framework/plugin_interface.h"
#include "plugin_framework/auto_register.h"

#include "manacommons/color.h"

namespace plugin {

enum REQUIREMENT { AT_LEAST_ONE = 1, AT_LEAST_TWO = 2, AT_LEAST_THREE = 3 };

std::string anti_debug =
	"IsDebuggerPresent|FindWindow|ZwQuerySystemInformation|DbgBreakPoint|DbgPrint|"
	"CheckRemoteDebuggerPresent|CreateToolhelp32Snapshot|Toolhelp32ReadProcessMemory|"
	"OutputDebugString|SwitchToThread|NtQueryInformationProcess"	// Standard anti-debug API calls
	"QueryPerformanceCounter";	// Techniques based on timing. GetTickCount ignored (too many false positives)

std::string vanilla_injection = "VirtualAlloc(.*)|WriteProcessMemory|CreateRemoteThread(Ex)?|OpenProcess";

std::string keylogger_api = "SetWindowsHook(Ex)?|GetAsyncKeyState|GetForegroundWindow|AttachThreadInput|CallNextHook(Ex)?|MapVirtualKey";

std::string raw_socket_api = "accept|bind|connect|recv|send|gethost(by)?name|inet_addr";

std::string wininet_api = "Internet(.*)|WSA(.*)|URLDownloadToFile(A|W)";

std::string registry_api = "Reg(.*)(Key|Value)(.*)|SH(.*)(Reg|Key)(.*)|SHQueryValueEx(A|W)|SHGetValue(A|W)";

std::string process_creation_api = "CreateProcess(.*)|system|WinExec|ShellExecute(A|W)";

std::string process_manipulation_api = "EnumProcess(.*)|OpenProcess|TerminateProcess|ReadProcessMemory|Process32(First|Next)(W)?";

std::string service_manipulation_api = "OpenSCManager(A|W)|(Open|Control|Create|Delete)Service(A|W)?|QueryService(.*)|"
									   "ChangeServiceConfig(A|W)|EnumServicesStatus(Ex)?(A|W)";

std::string privilege_api = "AdjustTokenPrivileges|IsNTAdmin|LsaEnumerateLogonSessions|SamQueryInformationUser|"
							"SamIGetPrivateData|SfcTerminateWatcherThread|(Zw)?OpenProcessToken(Ex)?|(Zw)?DuplicateToken(Ex)?|"
							"(SHTest|Check)TokenMembership";

std::string dacl_api = "SetKernelObjectSecurity|SetFileSecurity(A|W)|SetNamedSecurityInfo(A|W)|SetSecurityInfo";

std::string dynamic_import = "(Co)?LoadLibrary(Ex)?(A|W)|GetProcAddress|LdrLoadDll|MmGetSystemRoutineAddress";

std::string packer_api = "VirtualAlloc|VirtualProtect";

std::string temporary_files = "GetTempPath(A|W)|(Create|Write)File(A|W)";

std::string driver_enumeration = "EnumDeviceDrivers|GetDeviceDriver(.*)";

std::string eventlog_deletion = "EvtClearLog|ClearEventLog(A|W)";

std::string screenshot_api = "CreateCompatibleDC|GetDC(Ex)?|FindWindow|PrintWindow|BitBlt";

std::string audio_api = "waveInOpen|DirectSoundCaptureCreate(.*)";

std::string shutdown_functions = "Initiate(System)?Shutdown(Ex)?(A|W)|LockWorkStation|ExitWindows(Ex)?";

std::string networking_api = "(Un)?EnableRouter|SetAdapterIpAddress|SetIp(Forward|Net|Statistics|TTL)(.*)|SetPerTcp(6)?ConnectionEStats";

/**
 *	@brief	Checks the presence of some functions in the PE and updates the
 *			result accordingly.
 *
 *	@param	const mana::PE& pe The PE in which the imports should be looked for.
 *	@param	const std::string& regex The regular expression against which the
 *			imports should be matched.
 *	@param	Result::LEVEL level The severity level to set if the imports are found.
 *	@param	const std::string& description The description to add to the result if
 *			matching imports are found.
 *	@param	REQUIREMENT req A criteria indicating how much matching imports should
 *			be found before updating the result.
 *	@param	pResult res The result which will receive the information.
 */
void check_functions(const mana::PE& pe,
					 const std::string& regex,
					 LEVEL level,
					 const std::string& description,
					 REQUIREMENT req,
					 pResult res)
{
	mana::const_shared_strings found_imports = pe.find_imports(regex);
	if (found_imports->size() >= static_cast<unsigned int>(req))  // Safe cast: these are positive enum indexes
	{
		res->raise_level(level);
		io::pNode info = boost::make_shared<io::OutputTreeNode>(description,
																io::OutputTreeNode::STRINGS,
																io::OutputTreeNode::NEW_LINE);

		for (std::vector<std::string>::const_iterator it = found_imports->begin() ; it != found_imports->end() ; ++it) {
			info->append(*it);
		}
		res->add_information(info);
	}
}

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
		check_functions(pe, "", NO_OPINION, "Can access the registry", AT_LEAST_ONE, res);
		check_functions(pe, process_creation_api, NO_OPINION, "Possibly launches other programs", AT_LEAST_ONE, res);
		check_functions(pe, "(Nt|Zw)(.*)", SUSPICIOUS, "Uses Windows' Native API", AT_LEAST_TWO, res);
		check_functions(pe, "Crypt(.*)", NO_OPINION, "Uses Microsoft's cryptographic API", AT_LEAST_ONE, res);
		check_functions(pe, temporary_files, NO_OPINION, "Can create temporary files", AT_LEAST_TWO, res);
		check_functions(pe, "Wlx(.*)", MALICIOUS, "Possibly attempts GINA replacement", AT_LEAST_THREE, res);
		check_functions(pe, keylogger_api, MALICIOUS, "Uses functions commonly found in keyloggers", AT_LEAST_TWO, res);
		check_functions(pe, packer_api, SUSPICIOUS, "Memory manipulation functions often used by packers", AT_LEAST_TWO, res);
		check_functions(pe, raw_socket_api, SUSPICIOUS, "Leverages the raw socket API to access the Internet", AT_LEAST_ONE, res);
		check_functions(pe, wininet_api, NO_OPINION, "Has Internet access capabilities", AT_LEAST_ONE, res);
		check_functions(pe, privilege_api, MALICIOUS, "Functions related to the privilege level", AT_LEAST_ONE, res);
		check_functions(pe, service_manipulation_api, SUSPICIOUS, "Interacts with services", AT_LEAST_ONE, res);
		check_functions(pe, driver_enumeration, SUSPICIOUS, "Enumerates drivers present on the system", AT_LEAST_ONE, res);
		check_functions(pe, process_manipulation_api, SUSPICIOUS, "Manipulates other processes", AT_LEAST_ONE, res);
		check_functions(pe, eventlog_deletion, MALICIOUS, "Deletes entries from the event log", AT_LEAST_ONE, res);
		check_functions(pe, dacl_api, SUSPICIOUS, "Changes object ACLs", AT_LEAST_ONE, res);
		check_functions(pe, screenshot_api, SUSPICIOUS, "Can take screenshots", AT_LEAST_TWO, res);
		check_functions(pe, audio_api, SUSPICIOUS, "Can use the microphone to record audio.", AT_LEAST_ONE, res);
		check_functions(pe, networking_api, SUSPICIOUS, "Modifies the network configuration", AT_LEAST_ONE, res);
		check_functions(pe, "GetClipboardData", NO_OPINION, "Reads the contents of the clipboard", AT_LEAST_ONE, res);
		check_functions(pe, "IsUserAnAdmin", NO_OPINION, "Checks if it has admin rights", AT_LEAST_ONE, res);
		check_functions(pe, "Cert(Add|Open|Register|Remove|Save|Srv|Store)(.*)", SUSPICIOUS, "Interacts with the certificate store", AT_LEAST_ONE, res);
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
				res->set_summary("The PE contains functions mostly used by malwares.");
				break;
			default:
				break;
		}

		return res;
	}
};

AutoRegister<ImportsPlugin> auto_register_imports;

} // !namespace plugin
