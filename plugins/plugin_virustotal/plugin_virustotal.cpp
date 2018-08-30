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

#include <boost/system/api_config.hpp>

#if defined BOOST_WINDOWS_API && !defined _WIN32_WINNT
	#define _WIN32_WINNT 0x0501
#endif

#include <stdio.h>
#include <boost/asio.hpp>
#if defined WITH_OPENSSL
# include <boost/asio/ssl.hpp>
#endif

#include "plugin_framework/plugin_interface.h"
#include "plugin_framework/auto_register.h"

#include "manacommons/color.h"
#include "hash-library/hashes.h"
#include "plugins/plugin_virustotal/json_spirit/json_spirit.h"

namespace bai = boost::asio::ip;
namespace js = json_spirit;

namespace plugin {

#if defined WITH_OPENSSL
	namespace ssl = boost::asio::ssl;
	typedef   ssl::stream<bai::tcp::socket> sslsocket;
#endif

/**
 *	@brief	Queries VirusTotal for a given hash.
 *
 *	Depending on whether OpenSSL is available, one of two versions of this function will
 *	be compiled. One of them connects to VirusTotal through HTTPS, and the other one 
 *	through plain HTTP.
 *
 *	@param	const std::string& hash The hash of the program whose AV results we want.
 *	@param	const std::string& api_key The VirusTotal API key used to submit queries.
 *	@param	std::string& destination The string which will receive the REST JSON response.
 *
 *	@return	Whether the query was completed successfully.
 */
bool query_virus_total(const std::string& hash, const std::string& api_key, std::string& destination);


class VirusTotalPlugin : public IPlugin
{
public:
	int get_api_version() const override { return 1; }

	pString get_id() const override {
		return boost::make_shared<std::string>("virustotal");
	}

	pString get_description() const override {
		return boost::make_shared<std::string>("Checks existing AV results on VirusTotal.");
	}

	pResult analyze(const mana::PE& pe) override
	{
		pResult res = create_result();

		if (_config == nullptr || !_config->count("api_key")) // No API key provided.
		{
			PRINT_WARNING << "The VirusTotal API key was not found in the configuration file." << std::endl;
			return res;
		}
		else if (_config->at("api_key") == "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
		{
			PRINT_WARNING << "Please edit the configuration file with your VirusTotal API key." << std::endl;
			return res;
		}

		std::string sha256_hash = *hash::hash_file(*hash::ALL_DIGESTS[ALL_DIGESTS_SHA256], *pe.get_path());
		std::string json;

		try {
			if (!query_virus_total(sha256_hash, _config->at("api_key"), json)) {
				return res;
			}
		}
		catch (std::exception& e)
		{
			PRINT_ERROR << "Query to VirusTotal failed (" << e.what() << ")." << std::endl;
			return res;
		}

		// Parse the JSON.
		js::Value val;
		if (!js::read(json, val) || val.type() != js::obj_type)
		{
			PRINT_ERROR << "Could not parse JSON retrieved from VirusTotal!" << std::endl;
			return res;
		}

		js::Object root = val.get_obj();
		int total = 0, positives = 0;
		std::string scan_date;
		for (const auto& it : root)
		{
			if (it.name_ == "response_code")
			{
				if (!it.value_.get_int()) // Response Code = 0: VT does not know the file.
				{
					res->set_level(SUSPICIOUS); // Because VT knows all the files.
					res->set_summary("No VirusTotal score.");
					res->add_information("This file has never been scanned on VirusTotal.");
					return res;
				}
				else if (it.value_.get_int() == -2) // Response Code = -2: scan queued.
				{
					res->set_summary("No VirusTotal score.");
					res->add_information("A scan of the file is currently queued.");
					return res;
				}
			}
			else if (it.name_ == "total") {
				total = it.value_.get_int();
			}
			else if (it.name_ == "positives") {
				positives = it.value_.get_int();
			}
			else if (it.name_ == "scan_date") {
				scan_date = it.value_.get_str();
			}
			else if (it.name_ == "scans")
			{
				// Iterate on each AV's report
				js::Object scans = it.value_.get_obj();
				for (const auto& it2 : scans)
				{
					// Iterate on each report's elements
					js::Object scan = it2.value_.get_obj();
					for (const auto& it3 : scan)
					{
						if (it3.name_ == "detected" && !it3.value_.get_bool()) { // Not detected by this AV
							break; // No result to read
						}
						else if (it3.name_ == "result")
						{
							std::stringstream av_result;
							res->add_information(it2.name_, it3.value_.get_str());
							break; // The information has been found, ignore whatever is left
						}
					}
				}
			}
		}

		std::stringstream ss;
		ss << "VirusTotal score: " << positives << "/" << total << " (Scanned on " << scan_date << ")";
		res->set_summary(ss.str());
		if (positives == 0) 
		{
			res->set_level(SAFE);
			res->add_information("All the AVs think this file is safe.");
		}
		else if (positives < 3) { // Allow reasonable doubt for paranoid AVs
			res->set_level(SUSPICIOUS);
		}
		else {
			res->set_level(MALICIOUS);
		}

		return res;
	}
};

// ----------------------------------------------------------------------------

/**
 *	@brief	Performs the actual communication with the API after the communication
 *			has been established.
 *
 *	@param	const std::string& hash The hash of the program whose AV results we want.
 *	@param	const std::string& api_key The VirusTotal API key used to submit queries.
 *	@param	std::string& destination The string which will receive the REST JSON response.
 *	@param	sslsocket& socket or bai::tcp::socket& socket The socket connected to the API.
 *			Its type will vary depending on whether OpenSSL is available (in which case,
 *			the socket will automatically be an SSL socket).
 */
#if defined WITH_OPENSSL
bool vt_api_interact(const std::string& hash,
					 const std::string& api_key,
					 std::string& destination,
					 sslsocket& socket)
#else
bool vt_api_interact(const std::string& hash,
					 const std::string& api_key,
					 std::string& destination,
					 bai::tcp::socket& socket)
#endif
{
	// Build the request
	boost::asio::streambuf request;
	std::stringstream ss;
	ss << "apikey=" << api_key << "&resource=" << hash << "\r\n";
	std::string post_data = ss.str();
	std::ostream request_stream(&request);
	request_stream << "POST /vtapi/v2/file/report HTTP/1.1\r\n";
	request_stream << "Host: www.virustotal.com \r\n";
	request_stream << "Content-Length: " << post_data.size() << "\r\n";
	request_stream << "Connection: close\r\n\r\n";
	request_stream << post_data;

	// Send the request.
	boost::asio::write(socket, request);

	// Read the response status line.
	boost::asio::streambuf response;
	boost::asio::read_until(socket, response, "\r\n");

	// Check that response is OK.
	std::istream response_stream(&response);
	std::string http_version;
	response_stream >> http_version;
	unsigned int status_code;
	response_stream >> status_code;
	std::string status_message;
	std::getline(response_stream, status_message);
	if (!response_stream || http_version.substr(0, 5) != "HTTP/")
	{
		PRINT_ERROR << "[plugin_virustotal] Received a malformed response from the server." << std::endl;
		return false;
	}
	if (status_code != 200)
	{
		if (status_code == 204)	{
			PRINT_ERROR << "[plugin_virustotal] VirusTotal API request rate limit reached!" << std::endl;
		}
		else if (status_code == 403) {
			PRINT_ERROR << "[plugin_virustotal] VirusTotal API access denied. Please verify that your API key is valid." << std::endl;
		}
		else {
			PRINT_ERROR << "[plugin_virustotal] VirusTotal query returned with status code " << status_code << "." << std::endl;
		}
		return false;
	}

	// Skip the response headers.
	std::string header;
	while (std::getline(response_stream, header) && header != "\r");

	// Write whatever content we already have to output.
	ss.str("");
	ss.clear();
	if (response.size() > 0) {
		ss << &response;
	}

	// Read until EOF, writing data to output as we go.
	boost::system::error_code error;
	while (boost::asio::read(socket, response, boost::asio::transfer_at_least(1), error)) {
		ss << &response;
	}
	
	// This #define mess is necessary because OpenSSL 1.1 does no longer define SSL_SHORT_READ,
	// but earlier Boost versions (such as 1.55.0) do not define ssl::error::stream_truncated yet.

	#if defined WITH_OPENSSL && defined SSL_R_SHORT_READ
	// SSL connexions may be terminated by a short read error.
	if (error != boost::asio::error::eof && error.value() != ERR_PACK(ERR_LIB_SSL, 0, SSL_R_SHORT_READ)) {
	#elif defined WITH_OPENSSL
	if (error != boost::asio::error::eof && error != ssl::error::stream_truncated) {
	#else
	if (error != boost::asio::error::eof) {
	#endif
		PRINT_ERROR << "[plugin_virustotal] Could not read the response (" << error.message() << ")." << std::endl;
		return false;
	}
	else if (error == boost::asio::error::eof)
	{
		#if defined WITH_OPENSSL
			socket.shutdown();
		#else
			socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send);
		#endif
	}

	destination = ss.str();
	return true;
}

// ----------------------------------------------------------------------------

#if !defined WITH_OPENSSL
// Version of the function which establishes a plain HTTP connection.
bool query_virus_total(const std::string& hash, const std::string& api_key, std::string& destination)
{
	boost::asio::io_service io_service;

	// Get a list of endpoints corresponding to the server name.
	bai::tcp::resolver resolver(io_service);
	bai::tcp::resolver::query query("www.virustotal.com", "http");
	bai::tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
	bai::tcp::resolver::iterator end;

	// Try each endpoint until we successfully establish a connection.
	bai::tcp::socket socket(io_service);
	boost::system::error_code error = boost::asio::error::host_not_found;
	while (error && endpoint_iterator != end)
	{
		socket.close();
		socket.connect(*endpoint_iterator++, error);
	}
	if (error)
	{
		PRINT_ERROR << "Could not resolve www.virustotal.com (plugin_virustotal)! " << error.message() << std::endl;
		return false;
	}

	return vt_api_interact(hash, api_key, destination, socket);
}
#endif

// ----------------------------------------------------------------------------

#if defined WITH_OPENSSL
// Version of the function which establishes an SSL connection.
bool query_virus_total(const std::string& hash, const std::string& api_key, std::string& destination)
{
	ssl::context ctx(ssl::context::sslv23);
	ctx.set_default_verify_paths();

	boost::asio::io_service io_service;

	// Get a list of endpoints corresponding to the server name.
	bai::tcp::resolver resolver(io_service);
	bai::tcp::resolver::query query("www.virustotal.com", "https");
	bai::tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
	bai::tcp::resolver::iterator end;

	// Try each endpoint until we successfully establish a connection.
	sslsocket socket(io_service, ctx);
	boost::system::error_code error = boost::asio::error::host_not_found;
	while (error && endpoint_iterator != end)
	{
		socket.next_layer().close();
		socket.next_layer().connect(*endpoint_iterator++, error);
		socket.set_verify_mode(ssl::verify_peer);
		socket.set_verify_callback(ssl::rfc2818_verification("www.virustotal.com"));
		socket.handshake(sslsocket::client, error);
	}
	if (error)
	{
		PRINT_ERROR << "[plugin_virustotal] Could not connect to www.virustotal.com: " << error.message() << std::endl;
		return false;
	}

	return vt_api_interact(hash, api_key, destination, socket);
}
#endif

// ----------------------------------------------------------------------------

extern "C"
{
	PLUGIN_API IPlugin* create() { return new VirusTotalPlugin(); }
	PLUGIN_API void destroy(IPlugin* p) { delete p; }
};

} // !namespace plugin
