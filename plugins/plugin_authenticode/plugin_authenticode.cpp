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

#include "plugins/plugin_authenticode/plugin_authenticode.h"

namespace plugin {

/**
 *	@brief	This plugin uses the Windows API to verify the digital signature of a PE.
 */
class AuthenticodePlugin : public IPlugin
{
public:
	int get_api_version() const override { return 1; }

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
		do_winverifytrust(guid_verify, data, res);

		if (res->get_level() != NO_OPINION) {
			get_certificate_info(wide_path, res);
		}
		else { // If no certificate was found, check if the file is known in the security catalog:
			//check_catalog_signature(pe, res);
		}

		// Still not verified: try to determine if the application should be signed.
		if (res->get_level() == NO_OPINION) {
			check_version_info(pe, res);
		}

		// Close a handle that was opened by the verification
		data.dwStateAction = WTD_STATEACTION_CLOSE;
		::WinVerifyTrust(nullptr, &guid_verify, &data);

		return res;
	}
};

// ----------------------------------------------------------------------------

extern "C"
{
	PLUGIN_API IPlugin* create() { return new AuthenticodePlugin(); }
	PLUGIN_API void destroy(IPlugin* p) { delete p; }
};

// ----------------------------------------------------------------------------

std::string make_error(const std::string& message)
{
	std::stringstream ss;
	ss << message << " (Windows error code: 0x" << std::hex << ::GetLastError() << ")";
	return ss.str();
}

// ----------------------------------------------------------------------------

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

void GetCertNameString_wrapper(PCCERT_CONTEXT context, DWORD type, DWORD flags, const std::string& description, pResult result)
{

	DWORD size;

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

	char* name = static_cast<char*>(malloc(size));
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

	::CertFreeCertificateContext(context);
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

			cs_info = static_cast<PCMSG_SIGNER_INFO>(malloc(size));
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

	info = static_cast<PCMSG_SIGNER_INFO>(malloc(info_size));
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

void do_winverifytrust(GUID& guid, WINTRUST_DATA& data, pResult res)
{
	int error_code;

	// According to the documentation, INVALID_HANDLE_VALUE should be accepted here.
	// https://msdn.microsoft.com/en-us/library/windows/desktop/aa388208(v=vs.85).aspx
	int retval = ::WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &guid, &data);
	switch (retval)
	{
	case ERROR_SUCCESS:
		res->set_level(SAFE);
		if (data.dwUnionChoice == WTD_CHOICE_CATALOG) {
			res->set_summary("The PE is a trusted Microsoft binary.");
			res->add_information("The file's hash is recognized by Windows.");
		}
		else {
			res->set_summary("The PE's digital signature is valid.");
		}
		break;
	case TRUST_E_EXPLICIT_DISTRUST:
		res->set_level(MALICIOUS);
		res->set_summary("The PE's digital signature has been explicitly blacklisted.");
		break;
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
}

// ----------------------------------------------------------------------------

/**
 *	@brief	A simple function used to translate the PE path into a std::wstring
 *			as is required by Microsoft's API.
 *
 *	@param	s The string to convert.
 *
 *	@return	a std::wstring representing the input.
 */
std::wstring multibytetowide_helper(const std::string& s)
{
	size_t input_len = s.length() + 1;
	size_t len = ::MultiByteToWideChar(CP_ACP, 0, s.c_str(), input_len, nullptr, 0);
	auto buffer = new wchar_t[len];
	::MultiByteToWideChar(CP_ACP, 0, s.c_str(), input_len, buffer, len);
	std::wstring r(buffer);
	delete[] buffer;
	return r;
}

// ----------------------------------------------------------------------------

void make_information(const std::string& type, const std::wstring& data, pResult result)
{
	std::stringstream ss;
	std::string out;
	try
	{
		std::vector<boost::uint8_t> utf8result;
		utf8::utf16to8(data.begin(), data.end(), std::back_inserter(utf8result));
		out = std::string(utf8result.begin(), utf8result.end());
	}
	catch (utf8::invalid_utf16&)
	{
		PRINT_WARNING << "[plugin_authenticode] Couldn't convert a string from UTF-16 to UTF-8!"
					  << DEBUG_INFO << std::endl;
		return;
	}
	ss << type << ": " << out;
	result->add_information(ss.str());
}

// ----------------------------------------------------------------------------

void check_catalog_signature(const mana::PE& pe, pResult res)
{
	PVOID context = nullptr;
	PVOID catalog = nullptr;
	DWORD size = 0;
	PBYTE hash_buffer = nullptr;
	std::wstring wpath(multibytetowide_helper(*pe.get_path()));
	std::wstringstream ss;
	std::wstring member_tag;
	CATALOG_INFO info;
	WINTRUST_DATA data;
	WINTRUST_CATALOG_INFO catalog_info;
	GUID guid_verify = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	// First, obtain the catalog containing the corresponding signatures from Windows.
	if (!::CryptCATAdminAcquireContext(&context, nullptr, 0))	{
		return;
	}
	auto handle = ::CreateFile(pe.get_path()->c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
	if (handle == INVALID_HANDLE_VALUE)	{
		goto end;
	}
	::CryptCATAdminCalcHashFromFileHandle(handle, &size, nullptr, 0);  // One call to get the size...
	if (size == 0) {
		goto end;
	}
	hash_buffer = static_cast<PBYTE>(calloc(size, 1));
	if (!::CryptCATAdminCalcHashFromFileHandle(handle, &size, hash_buffer, 0) || hash_buffer == nullptr) { // ...and one to get the hash.
		goto end;
	}

	// The hash is used as a reference in the catalog. Convert it to a string.
	for (unsigned int i = 0; i < size; i++)	{
		ss << boost::wformat(L"%02X") % hash_buffer[i];
	}
	member_tag.assign(ss.str());

	catalog = ::CryptCATAdminEnumCatalogFromHash(context, hash_buffer, size, 0, nullptr);
	if (!catalog || !CryptCATCatalogInfoFromContext(catalog, &info, 0))	{
		goto end;
	}

	// We have obtained a valid catalog and its information. Verify that the binary is known.
	memset(&data, 0, sizeof(WINTRUST_DATA));
	data.cbStruct = sizeof(WINTRUST_DATA);
	data.dwUIChoice = WTD_UI_NONE;
	data.dwUnionChoice = WTD_CHOICE_CATALOG;
	data.dwStateAction = WTD_STATEACTION_VERIFY;
	memset(&catalog_info, 0, sizeof(WINTRUST_CATALOG_INFO));
	catalog_info.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
	catalog_info.pcwszCatalogFilePath = info.wszCatalogFile;
	catalog_info.pcwszMemberFilePath = wpath.c_str();
	catalog_info.pcwszMemberTag = member_tag.c_str();
	data.pCatalog = &catalog_info;
	do_winverifytrust(guid_verify, data, res);

	end:
	if (catalog != nullptr) ::CryptCATAdminReleaseCatalogContext(context, catalog, 0);
	if (context != nullptr) ::CryptCATAdminReleaseContext(context, 0);
	if (handle != INVALID_HANDLE_VALUE) ::CloseHandle(handle);
	free(hash_buffer);
}


} // !namespace plugin
