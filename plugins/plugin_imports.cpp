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

std::string vanilla_injection = "VirtualAlloc(.*)|WriteProcessMemory|CreateRemoteThread|OpenProcess";

std::string keylogger_api = "SetWindowsHook(Ex)?|GetAsyncKeyState|GetForegroundWindow|AttachThreadInput|CallNextHook(Ex)?|MapVirtualKey";

std::string raw_socket_api = "accept|bind|connect|recv|send|gethost(by)?name|inet_addr";

std::string wininet_api = "Internet(.*)|WSA(.*)|URLDownloadToFile(A|W)";

std::string process_creation_api = "CreateProcess(.*)|system|WinExec|ShellExecute(A|W)";

std::string privilege_api = "AdjustTokenPrivileges|IsNTAdmin|LsaEnumerateLogonSessions|SamQueryInformationUse|"
							"SamIGetPrivateData|SfcTerminateWatcherThread|(Zw)?OpenProcessToken(Ex)?|(Zw)?DuplicateToken(Ex)?";

std::string dynamic_import = "LoadLibrary(A|W)|GetProcAddress|LdrLoadDll|MmGetSystemRoutineAddress";

std::string packer_api = "VirtualAlloc|VirtualProtect";

std::string temporary_files = "GetTempPath(A|W)|(Create|Write)File(A|W)";

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
		io::pNode info = io::pNode(new io::OutputTreeNode(description,
														  io::OutputTreeNode::STRINGS,
														  io::OutputTreeNode::NEW_LINE));

		for (std::vector<std::string>::const_iterator it = found_imports->begin() ; it != found_imports->end() ; ++it) {
			info->append(*it);
		}
		res->add_information(info);
	}
}

class ImportsPlugin : public IPlugin
{
public:
	int get_api_version() override { return 1; }

	pString get_id() const override {
		return pString(new std::string("imports"));
	}

	pString get_description() const override {
		return pString(new std::string("Looks for suspicious imports."));
	}

	pResult analyze(const mana::PE& pe) override
	{
		pResult res = create_result();
		check_functions(pe, dynamic_import, NO_OPINION, "[!] The program may be hiding some of its imports", AT_LEAST_TWO, res);
		check_functions(pe, anti_debug, SUSPICIOUS, "Functions which can be used for anti-debugging purposes", AT_LEAST_ONE, res);
		check_functions(pe, vanilla_injection, MALICIOUS, "Code injection capabilities", AT_LEAST_THREE, res);
		check_functions(pe, "Reg(.*)(Key|Value)(.*)", NO_OPINION, "Can access the registry", AT_LEAST_ONE, res);
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
