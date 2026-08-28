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
#include <sstream>
#include <vector>
#include <memory>
#include <cstdint>

#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/opensslv.h>

#include "manacommons/color.h"

typedef std::vector<std::uint8_t> bytes;
typedef std::shared_ptr<PKCS7>    pPKCS7;
typedef std::shared_ptr<BIO>      pBIO;

// A simple struct describing the authenticode digest.
// The first member is the algorithm used (OID), and the second member is the digest.
struct AuthenticodeDigest
{
    std::string algorithm;
    bytes digest;
};


#if OPENSSL_VERSION_NUMBER >= 0x01010000f
// Redefine the ASN1_OBJECT structure for OpenSSL >= 1.1 as it can't seem to find it otherwise.
struct asn1_object_st
{
    const char *sn, *ln;
    int nid;
    int length;
    const unsigned char *data;  /* data remains const after init */
    int flags;                  /* Should we free this one */
};
#endif

namespace plugin {

const std::string SPC_INDIRECT_DATA("1.3.6.1.4.1.311.2.1.4");
const std::string SPC_PE_IMAGE_DATAOBJ("1.3.6.1.4.1.311.2.1.15");

/**
 *  @brief  Converts an hexadecimal OID into its string representation.
 *
 *  @param  const bytes& in The raw OID bytes.
 *
 *  @return A string containing the OID in its (somewhat) human-readable form.
 */
std::string OID_to_string(const bytes& in);

// ----------------------------------------------------------------------------

/**
 *  @brief  This function asserts that a PKCS7 object has a valid structure
 *          before attempting any operations on it.
 *
 *  @param  pPKCS7 p The PKCS7 object to verify.
 *
 *  @return Whether the object can be used safely to verify an Authenticode signature.
 */

// ----------------------------------------------------------------------------

bool check_pkcs_sanity(const pPKCS7& p);

/**
 *  @brief  This function parses an ASN1 SpcIndirectDataContent object.
 *
 *  The SpcIndirectDataContent contains the digest and algorithm of the authenticode
 *  hash generated for the PE. This function's role is to go down the ASN1 rabbit hole
 *  and retrieve this information so that the digest can be computed independently and
 *  verified against the information contained in this signature.
 *
 *  @param  ASN1_STRING* asn1 The ASN1 string pointing to the SpcIndirectDataContent object.
 *  @param  AuthenticodeDigest& digest The structure into which the digest information will be put.
 *
 *  @return Whether the ASN1 was parsed successfully.
 */
bool parse_spc_asn1(const ASN1_STRING* asn1, AuthenticodeDigest& digest);

} // !namespace plugin
