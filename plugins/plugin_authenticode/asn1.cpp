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

#include <cstddef>
#include <limits>
#include <utility>

namespace {

struct Asn1View
{
    const unsigned char* data = nullptr;
    std::size_t size = 0;
};

bool asn1_read(const unsigned char*& cursor,
               std::size_t& remaining,
               int expected_tag,
               bool expected_constructed,
               const char* object_name,
               Asn1View& value)
{
    value = Asn1View();
    if (!cursor || remaining == 0 ||
        remaining > static_cast<std::size_t>(std::numeric_limits<long>::max()))
    {
        PRINT_ERROR << "[plugin_authenticode] Invalid " << object_name
                    << " ASN.1 input span." << std::endl;
        return false;
    }

    const unsigned char* temporary = cursor;
    long value_length = 0;
    int tag = 0;
    int object_class = 0;
    const int result = ASN1_get_object(&temporary, &value_length, &tag,
                                       &object_class, static_cast<long>(remaining));
    const bool constructed = (result & V_ASN1_CONSTRUCTED) != 0;
    if ((result & 0x80) != 0 || (result & 0x01) != 0 ||
        value_length < 0 || object_class != V_ASN1_UNIVERSAL ||
        tag != expected_tag || constructed != expected_constructed)
    {
        PRINT_ERROR << "[plugin_authenticode] Invalid " << object_name
                    << " ASN.1 object." << std::endl;
        return false;
    }

    const std::ptrdiff_t header_difference = temporary - cursor;
    if (header_difference < 0 ||
        static_cast<std::size_t>(header_difference) > remaining)
    {
        PRINT_ERROR << "[plugin_authenticode] Invalid " << object_name
                    << " ASN.1 header extent." << std::endl;
        return false;
    }
    const std::size_t header_size = static_cast<std::size_t>(header_difference);
    if (static_cast<std::size_t>(value_length) > remaining - header_size)
    {
        PRINT_ERROR << "[plugin_authenticode] Invalid " << object_name
                    << " ASN.1 value extent." << std::endl;
        return false;
    }

    value.data = temporary;
    value.size = static_cast<std::size_t>(value_length);
    const std::size_t consumed = header_size + value.size;
    cursor += consumed;
    remaining -= consumed;
    return true;
}

bool no_trailing_bytes(std::size_t remaining, const char* object_name)
{
    if (remaining == 0)
    {
        return true;
    }
    PRINT_ERROR << "[plugin_authenticode] Invalid " << object_name
                << " ASN.1 object: trailing bytes." << std::endl;
    return false;
}

} // namespace

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

bool parse_spc_asn1(const ASN1_STRING* asn1, AuthenticodeDigest& digest)
{
    const int encoded_length = asn1 ? ASN1_STRING_length(asn1) : 0;
    if (encoded_length <= 0)
    {
        PRINT_ERROR << "[plugin_authenticode] Invalid SpcIndirectDataContent"
                       " ASN.1 input span." << std::endl;
        return false;
    }
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    const unsigned char* cursor = ASN1_STRING_get0_data(asn1);
#else
    const unsigned char* cursor = ASN1_STRING_data(const_cast<ASN1_STRING*>(asn1));
#endif
    if (!cursor)
    {
        PRINT_ERROR << "[plugin_authenticode] Invalid SpcIndirectDataContent"
                       " ASN.1 input span." << std::endl;
        return false;
    }
    std::size_t remaining = static_cast<std::size_t>(encoded_length);

    Asn1View root;
    if (!asn1_read(cursor, remaining, V_ASN1_SEQUENCE, true,
                   "SpcIndirectDataContent", root))
    {
        return false;
    }
    const unsigned char* root_cursor = root.data;
    std::size_t root_remaining = root.size;

    Asn1View attribute;
    if (!asn1_read(root_cursor, root_remaining, V_ASN1_SEQUENCE, true,
                   "SpcAttributeTypeAndOptionalValue", attribute))
    {
        return false;
    }
    const unsigned char* attribute_cursor = attribute.data;
    std::size_t attribute_remaining = attribute.size;

    Asn1View attribute_oid;
    if (!asn1_read(attribute_cursor, attribute_remaining, V_ASN1_OBJECT, false,
                   "type", attribute_oid))
    {
        return false;
    }
    const bytes attribute_oid_bytes(attribute_oid.data,
                                    attribute_oid.data + attribute_oid.size);
    if (OID_to_string(attribute_oid_bytes) != SPC_PE_IMAGE_DATAOBJ)
    {
        PRINT_ERROR << "[plugin_authenticode] Invalid SpcAttributeTypeAndOptionalValue type OID."
                    << std::endl;
        return false;
    }

    Asn1View pe_image_data;
    if (!asn1_read(attribute_cursor, attribute_remaining, V_ASN1_SEQUENCE, true,
                   "SpcPeImageData", pe_image_data) ||
        !no_trailing_bytes(attribute_remaining, "SpcAttributeTypeAndOptionalValue"))
    {
        return false;
    }

    Asn1View digest_info;
    if (!asn1_read(root_cursor, root_remaining, V_ASN1_SEQUENCE, true,
                   "DigestInfo", digest_info))
    {
        return false;
    }
    const unsigned char* digest_cursor = digest_info.data;
    std::size_t digest_remaining = digest_info.size;

    Asn1View algorithm_identifier;
    if (!asn1_read(digest_cursor, digest_remaining, V_ASN1_SEQUENCE, true,
                   "AlgorithmIdentifier", algorithm_identifier))
    {
        return false;
    }
    const unsigned char* algorithm_cursor = algorithm_identifier.data;
    std::size_t algorithm_remaining = algorithm_identifier.size;

    Asn1View algorithm_oid;
    if (!asn1_read(algorithm_cursor, algorithm_remaining, V_ASN1_OBJECT, false,
                   "algorithm", algorithm_oid))
    {
        return false;
    }
    const bytes algorithm_oid_bytes(algorithm_oid.data,
                                    algorithm_oid.data + algorithm_oid.size);

    Asn1View parameters;
    if (!asn1_read(algorithm_cursor, algorithm_remaining, V_ASN1_NULL, false,
                   "AlgorithmIdentifier parameters", parameters) ||
        parameters.size != 0)
    {
        PRINT_ERROR << "[plugin_authenticode] Invalid AlgorithmIdentifier parameters."
                    << std::endl;
        return false;
    }
    if (!no_trailing_bytes(algorithm_remaining, "AlgorithmIdentifier"))
    {
        return false;
    }

    Asn1View digest_value;
    if (!asn1_read(digest_cursor, digest_remaining, V_ASN1_OCTET_STRING, false,
                   "digest", digest_value) ||
        !no_trailing_bytes(digest_remaining, "DigestInfo") ||
        !no_trailing_bytes(root_remaining, "SpcIndirectDataContent") ||
        !no_trailing_bytes(remaining, "SpcIndirectDataContent encoding"))
    {
        return false;
    }

    AuthenticodeDigest parsed;
    parsed.algorithm = OID_to_string(algorithm_oid_bytes);
    if (parsed.algorithm.empty())
    {
        PRINT_ERROR << "[plugin_authenticode] Invalid algorithm OID." << std::endl;
        return false;
    }
    parsed.digest.assign(digest_value.data, digest_value.data + digest_value.size);
    digest = std::move(parsed);
    return true;
}

} // !namespace plugin
