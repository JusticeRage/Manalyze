/*
    This file is part of Spike Guard.

    Spike Guard is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Spike Guard is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Spike Guard.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma comment (lib, "wintrust")

#include <sstream>
#include <windows.h> // Windows-only plugin (1)
#include <Softpub.h>
#include "plugin_framework/plugin_interface.h"

/*
 * (1) I wish I could have implemented this in a platform-independent fashion.
 * Sadly, parsing PKCS#7 is quite annoying, and I was unable to find an easy to use,
 * portable, lightweight cryptography library supporting it. For a while, I considered
 * implementing it on my own, but then I figured that you need to be on Windows to have
 * access to the CAs trusted by the OS anyway.
*/

namespace plugin {

/**
 *	@brief	This plugin uses the Windows API to verify the digital signature of a PE.
 */
class AuthenticodePlugin : public IPlugin
{
public:
	int get_api_version() { return 1; }

	pString get_id() { 
		return pString(new std::string("authenticode"));
	}

	pString get_description() { 
		return pString(new std::string("Checks if the digital signature (authenticode) of the PE is valid."));
	}

	pResult analyze(const sg::PE& pe) 
	{
		pResult res(new Result());
		
		WINTRUST_FILE_INFO file_info;
		memset(&file_info, 0, sizeof(file_info));
		file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
		std::string path = pe.get_path();
		std::wstring wide_path(path.begin(), path.end());
		file_info.pcwszFilePath = wide_path.c_str();

		WINTRUST_DATA data;
		memset(&data, 0, sizeof(data));
		data.cbStruct = sizeof(data);
		data.dwUIChoice = WTD_UI_NONE;
		data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN; // Check revocations for the whole chain.
		data.dwUnionChoice = WTD_CHOICE_FILE;
		data.dwStateAction = WTD_STATEACTION_VERIFY;
		data.pFile = &file_info;

		GUID guid_verify = WINTRUST_ACTION_GENERIC_VERIFY_V2;
		int error_code;


		int retval = ::WinVerifyTrust(0, &guid_verify, &data);
		switch (retval)
		{
			case ERROR_SUCCESS:
				res->set_level(Result::SAFE);
				res->set_summary("The PE's digital signature is valid.");
				break;
			case TRUST_E_EXPLICIT_DISTRUST:
				res->set_level(Result::MALICIOUS);
				res->set_summary("The PE's digital signature has been explicitly blacklisted.");
			case TRUST_E_NOSIGNATURE:
				error_code = ::GetLastError();
				if (TRUST_E_NOSIGNATURE == error_code || TRUST_E_SUBJECT_FORM_UNKNOWN == error_code || TRUST_E_PROVIDER_UNKNOWN == error_code)
				{
					// No digital signature.
					break;
				}
				res->set_summary("Unknown error encountered while reading the signature.");
				break;
			case TRUST_E_BAD_DIGEST:
				res->set_level(Result::MALICIOUS);
				res->set_summary("The PE's digital signature is invalid.");
				break;
			case CERT_E_UNTRUSTEDROOT:
				res->set_level(Result::SUSPICIOUS);
				res->set_summary("The root certificate of the signature is not trusted.");
				break;
			default:
				std::stringstream ss;
				ss << "Unknown error encountered while reading the signature (0x" << std::hex << retval << ").";
				res->set_summary(ss.str());
				break;
		}

		if (res->get_level() != Result::NO_OPINION)
		{
			// Get the publisher's identity
		}

		return res;
	}
};

extern "C"
{
	PLUGIN_API IPlugin* create() { return new AuthenticodePlugin(); }
	PLUGIN_API void destroy(IPlugin* p) { if (p) delete p; }
};


} // !namespace plugin