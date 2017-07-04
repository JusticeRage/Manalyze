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

#pragma once
#pragma comment(lib, "wintrust")
#pragma comment(lib, "crypt32.lib")

#include <sstream>
#include <Windows.h> // Windows-only plugin (1)
#include <Softpub.h>
#include <mscat.h>
#include <WinTrust.h>
#include <boost/format.hpp>

#include "manape/utils.h"
#include "manacommons/utf8/utf8.h"

#include "plugin_framework/plugin_interface.h"

/*
* (1) I wish I could have implemented this in a platform-independent fashion.
* Sadly, parsing PKCS#7 is quite annoying, and I was unable to find an easy to use,
* portable, lightweight cryptography library supporting it. For a while, I considered
* implementing it on my own, but then I figured that you need to be on Windows to have
* access to the CAs trusted by the OS anyway.
*/

namespace plugin
{

/**
 *	@brief	Retrieves the information about the publisher / issuer present in the
 *			certificate.
 *
 *	@param	file_path The file to analyze.
 *	@param	result The result into which the information should be
 *			appended.
 */
void get_certificate_info(const std::wstring& file_path, plugin::pResult result);

// ----------------------------------------------------------------------------

/**
*	@brief	Verifies if a PE is known in a Windows security catalog.
*
*	Many Microsoft binaries do not embed a certificate. Instead, they are known
*	by hash by the OS. This function verifies whether this is the case.
*
*	@param	pe	The PE to assess.
*	@param	res	A result object to update in case any information is found.
*/
void check_catalog_signature(const mana::PE& pe, pResult res);

// ----------------------------------------------------------------------------

/**
 *	@brief	Helper function designed to create information and insert it into a result
 *			based on a read unicode string.
 *
 *	The information appended to the result will look like this: "type: data"
 *
 *	@param	type The description of the data.
 *	@param	data The contents of the information
 *	@param	result The result to update.
 *
 */
void make_information(const std::string& type, const std::wstring& data, pResult result);

// ----------------------------------------------------------------------------

/**
 *	@brief	Looks for well-known company names in the RT_VERSION resource of the PE.
 *
 *	Defined in plugin_authenticode_common.cpp.
 */
void check_version_info(const mana::PE& pe, pResult res);

// ----------------------------------------------------------------------------

/**
 *	@brief	Helper function which performs the call to WinVerifyTrust and 
 *			updates the result object accordingly.
 *			
 *	@param	guid	The GUID describing the action to perform.
 *	@param	data	A structure containing the necessary information to 
 *					perform the verification.
 *			res		The result object to update.
 */
void do_winverifytrust(GUID& guid, WINTRUST_DATA& data, pResult res);

// ----------------------------------------------------------------------------

/**
 *	@brief	Reads the information related to the PE's publisher in the digital signature.
 *
 *	@param	info A structure returned by CryptMsgGetParam.
 *	@param	result The result to fill with the obtained information.
 */
void get_publisher_information(PCMSG_SIGNER_INFO info, pResult result);

// ----------------------------------------------------------------------------

/**
 *	@brief	A wrapper around GetCertNameString.
 *
 *	It simplifies the process of querying information by hiding the complexity of having to
 *	call the function twice (one for the size, and one for the result) and having to allocate
 *	memory in between.
 *
 *	@param	context The certificate context to query
 *	@param	type A GetCertNameString argument which is just forwarded.
 *	@param	flags A GetCertNameString argument which is just forwarded.
 *	@param	description A description of the queried parameter, tu display in the result.
 *	@param	result The result to update with the obtained information.
 */
void GetCertNameString_wrapper(PCCERT_CONTEXT context, DWORD type, DWORD flags, const std::string& description, pResult result);

}