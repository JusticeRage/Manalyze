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

#include <string>
#include <vector>
#include <boost/shared_ptr.hpp>

#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/bio.h>

#include "plugin_framework/plugin_interface.h"
#include "plugins/plugin_authenticode/asn1.h"
#include "plugins/plugin_authenticode/pe_authenticode_digest.h"

typedef std::vector<boost::uint8_t> bytes;
typedef boost::shared_ptr<PKCS7>  pPKCS7;
typedef boost::shared_ptr<BIO>    pBIO;

namespace plugin {

/**
 *	@brief	Looks for well-known company names in the RT_VERSION resource of the PE.
 *
 *	Defined in plugin_authenticode_common.cpp.
 */
void check_version_info(const mana::PE& pe, pResult res);

} // !namespace plugin