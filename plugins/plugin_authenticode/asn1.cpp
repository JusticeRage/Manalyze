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

#include "plugins/plugin_authenticode/asn1.h"

namespace plugin {

std::string OID_to_string(const bytes& in)
{
    if (in.empty()) {
        return "";
    }
    std::stringstream ss;

    int b = in[0] % 40;
    int a = (in[0] - b) / 40;
    ss << a << "." << b;

    for (unsigned int i = 1 ; i < in.size() ; ++i)
    {
        ss << ".";
        if (in[i] < 128) {
            ss << static_cast<int>(in[i]); // Do not interpret as a char.
        }
        else
        {
            if (i+1 >= in.size()) // Don't read outside of the bounds.
            {
                PRINT_WARNING << "[plugin_authenticode] Tried to convert a malformed OID!" << std::endl;
                return "";
            }
            ss << static_cast<int>((in[i]-128)*128 + in[i+1]);
            ++i;
        }
    }
    return ss.str();
}

// ----------------------------------------------------------------------------

bool check_pkcs_sanity(const pPKCS7& p)
{
    if (p == nullptr)
    {
        PRINT_WARNING << "[plugin_authenticode] Error reading the PKCS7 certificate." << std::endl;
        return false;
    }

    if (!PKCS7_type_is_signed(p.get()))
    {
        PRINT_WARNING << "[plugin_authenticode] The PKCS7 structure is not signed!" << std::endl;
        return false;
    }

    // The SpcIndirectDataContent structure of the signature cannot be accessed directly
    // with OpenSSL's API. Retrieve the information manually.
    if (p->d.sign == nullptr ||
        p->d.sign->contents == nullptr ||
        p->d.sign->contents->type == nullptr ||
        p->d.sign->contents->type->data == nullptr ||
        p->d.sign->contents->d.other == nullptr ||
        p->d.sign->contents->d.other->value.asn1_string == nullptr)
    {
        PRINT_WARNING << "[plugin_authenticode] Unable to access the "
                         "SpcIndirectDataContent structure." << std::endl;
        return false;
    }

    // Assert that the data indeed points to a SpcIndirectDataContent object by checking the OID.
    bytes oid(p->d.sign->contents->type->data,
              p->d.sign->contents->type->data + p->d.sign->contents->type->length);
    if (OID_to_string(oid) != SPC_INDIRECT_DATA)
    {
        PRINT_WARNING << "[plugin_authenticode] Unable to access the "
                         "SpcIndirectDataContent structure." << std::endl;
        return false;
    }

    return true;
}

// ----------------------------------------------------------------------------

long asn1_read(const unsigned char** data,
               long max_length,
               const std::string& expected,
               const std::string& object_name)
{
    int tag = 0, xclass = 0;
    long size = 0;

    ASN1_get_object(data, &size, &tag, &xclass, max_length); // Return value ignored. Who knows what this function returns?
    std::string tag_s = ASN1_tag2str(tag);
    if (tag_s != expected)
    {
        PRINT_WARNING << "[plugin_authenticode] The " << object_name << " ASN1 string is malformed!" << std::endl;
        PRINT_WARNING << "(Expected " << expected << ", but got " << tag_s << " instead.)" << std::endl;
        return 0;
    }
    return size;
}

// ----------------------------------------------------------------------------

bool parse_spc_asn1(ASN1_STRING* asn1, AuthenticodeDigest& digest)
{
    const unsigned char* asn1_data = asn1->data;
    bytes buffer;

    // Start at the SpcIndirectDataContent..
    long size = asn1_read(&asn1_data, asn1->length, "SEQUENCE", "SpcIndirectDataContent");
    if (size == 0) {
        return false;
    }
    // Read the SpcAttributeTypeAndOptionalValue.
    size = asn1_read(&asn1_data, asn1->length, "SEQUENCE", "SpcAttributeTypeAndOptionalValue");
    if (size == 0) {
        return false;
    }
    // Read SpcAttributeTypeAndOptionalValue->type
    size = asn1_read(&asn1_data, asn1->length, "OBJECT", "type");
    if (size == 0) {
        return false;
    }
    // Assert that the type read has the expected OID.
    buffer.assign(asn1_data, asn1_data + size);
    if(OID_to_string(buffer) != SPC_PE_IMAGE_DATAOBJ)
    {
        PRINT_WARNING << "[plugin_authenticode] The SpcAttributeTypeAndOptionalValue has an invalid type!" << std::endl;
        return false;
    }
    asn1_data += size; // Skip over the OID.
    // Read SpcAttributeTypeAndOptionalValue->value (SpcPeImageData)
    size = asn1_read(&asn1_data, asn1->length, "SEQUENCE", "SpcPeImageData");
    if (size == 0) {
        return false;
    }
    asn1_data += size; // Skip the structure.

    // Read the DigestInfo.
    size = asn1_read(&asn1_data, asn1->length, "SEQUENCE", "DigestInfo");
    if (size == 0) {
        return false;
    }
    // Read DigestInfo->AlgorithmIdentifier
    size = asn1_read(&asn1_data, asn1->length, "SEQUENCE", "AlgorithmIdentifier");
    if (size == 0) {
        return false;
    }
    // Read DigestInfo->AlgorithmIdentifier->algorithm)
    size = asn1_read(&asn1_data, asn1->length, "OBJECT", "algorithm");
    if (size == 0) {
        return false;
    }
    buffer.assign(asn1_data, asn1_data + size);
    digest.algorithm = OID_to_string(buffer);
    asn1_data += size;
    // Read and skip DigestInfo->AlgorithmIdentifier->parameters
    size = asn1_read(&asn1_data, asn1->length, "NULL", "parameters");
    // Read the digest.
    size = asn1_read(&asn1_data, asn1->length, "OCTET STRING", "digest");
    if (size == 0) {
        return false;
    }
    digest.digest.assign(asn1_data, asn1_data + size);

    return true;
}

} // !namespace plugin