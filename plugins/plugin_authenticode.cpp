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

#pragma comment(lib, "wintrust")
#pragma comment(lib, "crypt32.lib")

#include <sstream>
#include <stdlib.h>
#include <Windows.h> // Windows-only plugin (1)
#include <Softpub.h>
#include <WinCrypt.h>

#include "manape/utils.h"

#include "plugin_framework/plugin_interface.h"
#include "yara/yara_wrapper.h"

/*
 * (1) I wish I could have implemented this in a platform-independent fashion.
 * Sadly, parsing PKCS#7 is quite annoying, and I was unable to find an easy to use,
 * portable, lightweight cryptography library supporting it. For a while, I considered
 * implementing it on my own, but then I figured that you need to be on Windows to have
 * access to the CAs trusted by the OS anyway.
 */

namespace plugin {

/**
 *	@brief	Retrieves the information about the publisher / issuer present in the
 *			certificate.
 *
 *	@param	const std::string& file_path The file to analyze.
 *	@param	plugin::pResult result The result into which the information should be
 *			appended.
 */
void get_certificate_info(const std::wstring& file_path, plugin::pResult result);

/**
 *	@brief	Helper function designed to create information and insert it into a result
 *			based on a read unicode string.
 *
 *	The information appended to the result will look like this: "type: data"
 *
 *	@param	const std::string& type The description of the data.
 *	@param	const std::wstring& data The contents of the information
 *	@param	pResult result The result to update.
 *
 */
void make_information(const std::string& type, const std::wstring& data, pResult result)
{
	auto conv = boost::shared_array<char>(new char[data.size() + 1]);
	memset(conv.get(), 0, sizeof(char) * (data.size() + 1));
	wcstombs(conv.get(), data.c_str(), data.size());

	std::stringstream ss;
	ss << type << ": " << conv.get();
	result->add_information(ss.str());
}

/**
 *	@brief	Looks for well-known company names in the RT_VERSION resource of the PE.
 *
 *	The idea behind this check is that if the binary is unsigned but pretends to come from
 *	Microsoft, Adobe, etc. then it is very likely a malware.
 *
 *	@param	const mana::PE& pe The PE to analyze.
 *	@param	pResult res The result to update if something is found.
 */
void check_version_info(const mana::PE& pe, pResult res);

/**
 *	@brief	This plugin uses the Windows API to verify the digital signature of a PE.
 */
class AuthenticodePlugin : public IPlugin
{
public:
	int get_api_version() override { return 1; }

	pString get_id() const override {
		return boost::make_shared<std::string>("authenticode");
	}

	pString get_description() const override {
		return boost::make_shared<std::string>("Checks if the digital signature of the PE is valid.");
	}

	pResult analyze(const mana::PE& pe) override
	{
		pResult res = create_result();

		WINTRUST_FILE_INFO file_info;
		memset(&file_info, 0, sizeof(file_info));
		file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
		std::string path = *pe.get_path();
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
				res->set_level(SAFE);
				res->set_summary("The PE's digital signature is valid.");
				break;
			case TRUST_E_EXPLICIT_DISTRUST:
				res->set_level(MALICIOUS);
				res->set_summary("The PE's digital signature has been explicitly blacklisted.");
			case TRUST_E_NOSIGNATURE:
				error_code = ::GetLastError();
				if (TRUST_E_NOSIGNATURE == error_code ||
					TRUST_E_SUBJECT_FORM_UNKNOWN == error_code ||
					TRUST_E_PROVIDER_UNKNOWN == error_code)
				{
					// No digital signature.
					break;
				}
				res->set_summary("Unknown error encountered while reading the signature.");
				break;
			case TRUST_E_BAD_DIGEST:
				res->set_level(MALICIOUS);
				res->set_summary("The PE's digital signature is invalid.");
				break;
			case CERT_E_REVOKED:
				res->set_level(MALICIOUS);
				res->set_summary("The PE's certificate was explicitly revoked by its issuer.");
				break;
			case CERT_E_EXPIRED:
				res->set_level(SUSPICIOUS);
				res->set_summary("The PE's certificate has expired.");
				break;
			default:
				std::stringstream ss;
				ss << "Unknown error encountered while reading the signature (0x" << std::hex << retval << ").";
				res->set_summary(ss.str());
				break;
		}

		if (res->get_level() != NO_OPINION) {
			get_certificate_info(wide_path, res);
		}
		else { // No certificate: try to determine if the application should be signed.
			check_version_info(pe, res);
		}

		// Close a handle that was opened by the verification
		data.dwStateAction = WTD_STATEACTION_CLOSE;
		::WinVerifyTrust(0, &guid_verify, &data);

		return res;
	}
};

// ----------------------------------------------------------------------------

extern "C"
{
	PLUGIN_API IPlugin* create() { return new AuthenticodePlugin(); }
	PLUGIN_API void destroy(IPlugin* p) { if (p) delete p; }
};

// ----------------------------------------------------------------------------

std::string make_error(const std::string& message)
{
	std::stringstream ss;
	ss << message << " (Windows error code: 0x" << std::hex << ::GetLastError() << ")";
	return ss.str();
}

// ----------------------------------------------------------------------------

/**
 *	@brief	Reads the information related to the PE's publisher in the digital signature.
 *
 *	@param	PCMSG_SIGNER_INFO info A structure returned by CryptMsgGetParam.
 *	@param	pResult result The result to fill with the obtained information.
 */
void get_publisher_information(PCMSG_SIGNER_INFO info, pResult result)
{
	DWORD size;
	DWORD res;
	PSPC_SP_OPUS_INFO opus = nullptr;

	for (unsigned int i = 0 ; i < info->AuthAttrs.cAttr ; ++i)
	{
		if (::lstrcmpA(SPC_SP_OPUS_INFO_OBJID, info->AuthAttrs.rgAttr[i].pszObjId) == 0)
		{
			res = ::CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,		// Encoding
									  SPC_SP_OPUS_INFO_OBJID,						// OID defining the structure type
									  info->AuthAttrs.rgAttr[i].rgValue[0].pbData,	// Structure to decode
									  info->AuthAttrs.rgAttr[i].rgValue[0].cbData,	// Size of the structure
									  0,											// Flags
									  nullptr,											// NULL buffer: return the needed size
									  &size);										// Destination of the size

			if (!res)
			{
				result->add_information(make_error("Could not get certificate information: CryptDecodeObject failed."));
				goto END;
			}

			opus =  (PSPC_SP_OPUS_INFO) malloc(size);
			if (!opus)
			{
				result->add_information(make_error("Could not get certificate information: malloc failed."));
				goto END;
			}

			res = ::CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,		// Encoding
									  SPC_SP_OPUS_INFO_OBJID,						// OID defining the structure type
									  info->AuthAttrs.rgAttr[i].rgValue[0].pbData,	// Structure to decode
									  info->AuthAttrs.rgAttr[i].rgValue[0].cbData,	// Size of the structure
									  0,											// Flags
									  opus,											// The structure to fill
									  &size);										// Destination of the size

			if (!res)
			{
				result->add_information(make_error("Could not get certificate information: CryptDecodeObject failed."));
				goto END;
			}

			if (opus->pwszProgramName != nullptr)
			{
				std::wstring wide_program_name(opus->pwszProgramName);
				make_information("Program name", wide_program_name, result);
			}
			if (opus->pPublisherInfo != nullptr)
			{
				std::wstring wide_publisher_info;
				switch (opus->pPublisherInfo->dwLinkChoice)
				{
					case SPC_URL_LINK_CHOICE:
						wide_publisher_info.assign(opus->pPublisherInfo->pwszUrl);
						break;
					case SPC_FILE_LINK_CHOICE:
						wide_publisher_info.assign(opus->pPublisherInfo->pwszFile);
						break;
				}
				make_information("Publisher information", wide_publisher_info, result);
			}
			if (opus->pMoreInfo != nullptr)
			{
				std::wstring wide_more_info;
				switch (opus->pMoreInfo->dwLinkChoice)
				{
				case SPC_URL_LINK_CHOICE:
					wide_more_info.assign(opus->pMoreInfo->pwszUrl);
					break;
				case SPC_FILE_LINK_CHOICE:
					wide_more_info.assign(opus->pMoreInfo->pwszFile);
					break;
				}
				make_information("Additional information", wide_more_info, result);
			}
		}
	}

	END:
	free(opus);
}

// ----------------------------------------------------------------------------

/**
 *	@brief	A wrapper around GetCertNameString.
 *
 *	It simplifies the process of querying information by hiding the complexity of having to
 *	call the function twice (one for the size, and one for the result) and having to allocate
 *	memory in between.
 *
 *	@param	PCCERT_CONTEXT context The certificate context to query
 *	@param	DWORD type A GetCertNameString argument which is just forwarded.
 *	@param	DWORD flags A GetCertNameString argument which is just forwarded.
 *	@param	const std::string& description A description of the queried parameter, tu display in the result.
 *	@param	pResult result The result to update with the obtained information.
 */
void GetCertNameString_wrapper(PCCERT_CONTEXT context, DWORD type, DWORD flags, const std::string& description, pResult result)
{

	DWORD size;
	std::stringstream ss;

	size = ::CertGetNameString(context,	// The certificate context
							   type,
							   flags,
							   nullptr,	// ...I'm not too sure what this is.
							   nullptr,	// Destination buffer is NULL - we want the size for now
							   0);		// Size of the destination buffer

	if (size == 0)
	{
		result->add_information(make_error("Could not get certificate details: CertGetNameString failed."));
		return;
	}

	char* name = (char*) malloc(size);
	if (name == nullptr)
	{
		result->add_information(make_error("Could not get certificate details: malloc failed."));
		return;
	}

	if (!::CertGetNameString(context,	// The certificate context
							 type,
							 flags,
							 nullptr,	// ...I'm not too sure what this is.
							 name,		// Destination buffer
							 size))		// Size of the destination buffer)
	{
		result->add_information(make_error("Could not get certificate details: CertGetNameString failed."));
		goto END;
	}

	if (name[0] == '\0') { // No information
		goto END;
	}

	result->add_information(description, name);

END:
	free(name);
}

// ----------------------------------------------------------------------------

void get_certificate_details(PCMSG_SIGNER_INFO info, HCERTSTORE hStore, pResult result)
{
	CERT_INFO cert_info;
	PCCERT_CONTEXT context;

	cert_info.Issuer = info->Issuer;
	cert_info.SerialNumber = info->SerialNumber;

	context = ::CertFindCertificateInStore(hStore,									// Handle to the certificate store
										   X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,	// Encoding
										   0,										// No flags
										   CERT_FIND_SUBJECT_CERT,					// Find a certificate matching a serial number and an issuer
										   &cert_info,								// The data to look for
										   nullptr);								// NULL on the first call - used to find the next matching certificate.

	if (!context)
	{
		result->add_information(make_error("Could not get certificate information: CertFindCertificateInStore failed."));
		return;
	}

	GetCertNameString_wrapper(context, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, "Issued by", result);
	GetCertNameString_wrapper(context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, "Issued to", result);
	GetCertNameString_wrapper(context, CERT_NAME_EMAIL_TYPE, 0, "Subject's email", result);

	if (!context) {
		::CertFreeCertificateContext(context);
	}
}

// ----------------------------------------------------------------------------

void get_certificate_timestamp(PCMSG_SIGNER_INFO info, pResult result)
{
	PCMSG_SIGNER_INFO cs_info = nullptr;
	FILETIME file_time;
	SYSTEMTIME system_time;
	struct tm time;
	char date_string[100];
	BOOL res;
	DWORD size;



	for (unsigned int i = 0 ; i < info->UnauthAttrs.cAttr ; ++i)
	{
		// 1) Get the CMSG_SIGNER_INFO structure
		if (::lstrcmpA(szOID_RSA_counterSign, info->UnauthAttrs.rgAttr[i].pszObjId) == 0)
		{
			res = ::CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,		// Encoding
									  PKCS7_SIGNER_INFO,							// Structure of the data to decode
									  info->UnauthAttrs.rgAttr[i].rgValue->pbData,	// The data to decode
									  info->UnauthAttrs.rgAttr[i].rgValue->cbData,	// Size of the data to decode
									  0,											// Flags
									  nullptr,										// Destination buffer is null - we only want the size
									  &size);										// Put the size here
			if (!res)
			{
				result->add_information(make_error("Could not get certificate timestamp: CryptDecodeObject failed."));
				return;
			}

			cs_info = (PCMSG_SIGNER_INFO) malloc(size);
			if (cs_info == nullptr)
			{
				result->add_information(make_error("Could not get certificate timestamp: malloc failed."));
				return;
			}

			res = ::CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,		// Encoding
									  PKCS7_SIGNER_INFO,							// Structure of the data to decode
									  info->UnauthAttrs.rgAttr[i].rgValue->pbData,	// The data to decode
									  info->UnauthAttrs.rgAttr[i].rgValue->cbData,	// Size of the data to decode
									  0,											// Flags
									  cs_info,										// Destination buffer
									  &size);										// Size of the destination buffer
			if (!res)
			{
				result->add_information(make_error("Could not get certificate timestamp: CryptDecodeObject failed."));
				goto END;
			}
			break;
		}
	}

	if (cs_info == nullptr) { // Timestamp unavailable
		goto END;
	}

	// 2) Read the FILETIME data from it
	for (unsigned int i = 0 ; i < cs_info->AuthAttrs.cAttr ; ++i)
	{
		if (::lstrcmpA(szOID_RSA_signingTime, cs_info->AuthAttrs.rgAttr[i].pszObjId) == 0)
		{
			size = sizeof(FILETIME);
			res = ::CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
									  szOID_RSA_signingTime,
									  cs_info->AuthAttrs.rgAttr[i].rgValue->pbData,
									  cs_info->AuthAttrs.rgAttr[i].rgValue->cbData,
									  0,
									  &file_time,
									  &size);
			if (!res)
			{
				result->add_information(make_error("Could not get certificate timestamp: CryptDecodeObject failed."));
				goto END;
			}

			if (!::FileTimeToSystemTime(&file_time, &system_time))
			{
				result->add_information(make_error("Could not convert certificate timestamp: FileTimeToSystemTime failed."));
				goto END;
			}

			time.tm_hour = system_time.wHour;
			time.tm_min = system_time.wMinute;
			time.tm_mday = system_time.wDay;
			time.tm_mon = system_time.wMonth - 1;
			time.tm_sec = system_time.wSecond;
			time.tm_year = system_time.wYear - 1900;
			strftime(date_string, sizeof(date_string), "%Y-%b-%d %H:%M:%S %z", &time);

			std::stringstream ss;
			ss << "Signing time: " << date_string;
			result->add_information(ss.str());
		}
	}

	END:
	free(cs_info);
}

// ----------------------------------------------------------------------------

void get_certificate_info(const std::wstring& file_path, pResult result)
{
	HCERTSTORE hStore = nullptr;
	HCRYPTMSG hMsg = nullptr;
	PCMSG_SIGNER_INFO info = nullptr;

	BOOL res = ::CryptQueryObject(CERT_QUERY_OBJECT_FILE,						// The function targets a file (as opposed to a memory structure)
								  file_path.c_str(),							// The file to query
								  CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,	// The content is an embedded PKCS #7 signed message
								  CERT_QUERY_FORMAT_FLAG_BINARY,				// The content should be returned in binary format
								  0,											// Reserved
								  0,											// We don't care about the encoding...
								  0,											// ...we don't care about the content type...
								  0,											// ...and we don't care about the format type either.
								  &hStore,										// Destination of the certificate store
								  &hMsg,										// Destination of the message
								  nullptr);										// No context
	if (!res)
	{
		result->add_information(make_error("Could not get certificate information: CryptQueryObject failed."));
		goto END;
	}

	DWORD info_size;
	res = CryptMsgGetParam(hMsg,					// Handle to the cryptographic message
						   CMSG_SIGNER_INFO_PARAM,	// Information about the message signer
						   0,						// Index of the required parameter - means nothing here.
						   nullptr,					// NULL buffer: return the needed size.
						   &info_size);				// Destination of the size
	if (!res)
	{
		result->add_information(make_error("Could not get certificate information: CryptMsgGetParam failed."));
		goto END;
	}

	info = (PCMSG_SIGNER_INFO) malloc(info_size);
	if (!info)
	{
		result->add_information(make_error("Could not get certificate information: malloc failed."));
		goto END;
	}

	res = CryptMsgGetParam(hMsg,					// Handle to the cryptographic message
						   CMSG_SIGNER_INFO_PARAM,	// Information about the message signer
						   0,						// Index of the required parameter - means nothing here.
						   info,					// NULL buffer: return the needed size.
						   &info_size);				// Destination of the size
	if (!res)
	{
		result->add_information(make_error("Could not get certificate information: CryptMsgGetParam failed."));
		goto END;
	}

	get_publisher_information(info, result);
	get_certificate_details(info, hStore, result);
	get_certificate_timestamp(info, result);

	END:
	free(info);

	if (hStore != nullptr) {
		::CertCloseStore(hStore, 0);
	}
	if (hMsg != nullptr) {
		::CryptMsgClose(hMsg);
	}
}

// ----------------------------------------------------------------------------

void check_version_info(const mana::PE& pe, pResult res)
{
	// Find the VERSION_INFO resource
	auto resources = pe.get_resources();
	mana::pResource version_info;
	for (auto it = resources->begin() ; it != resources->end() ; ++it)
	{
		if (*(*it)->get_type() == "RT_VERSION")
		{
			version_info = *it;
			break;
		}
	}

	// No RT_VERSION resource, we're done.
	if (!version_info) {
		return;
	}

	yara::Yara y;
	if (!y.load_rules("yara_rules/company_names.yara"))
	{
		std::cerr << "Could not load company_names.yara!" << std::endl;
		return;
	}
	auto m = y.scan_bytes(*version_info->get_raw_data());
	if (m && m->size() > 0)
	{
		std::stringstream ss;
		auto found_strings = m->at(0)->get_found_strings();
		if (found_strings.size() > 0)
		{
			ss << "PE pretends to be from " << *(m->at(0)->get_found_strings().begin())
				<< " but is not signed!";
			res->set_summary(ss.str());
			res->raise_level(MALICIOUS);
		}
	}
}


} // !namespace plugin
