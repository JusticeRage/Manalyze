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

#include "plugins/plugin_authenticode/plugin_authenticode_openssl.h"

namespace plugin
{

/**
 *  @brief  Returns the contents of an OpenSSL BIO as a string.
 *
 *  @param  pBIO bio The BIO to convert.
 *
 *  @return A string containing the contents of the BIO.
 */
std::string bio_to_string(const pBIO& bio)
{
    BUF_MEM* buf = nullptr; // The memory pointed by this is freed with the BIO.
    BIO_get_mem_ptr(bio.get(), &buf);
    if (buf == nullptr || buf->length == 0)
    {
        PRINT_WARNING << "[plugin_authenticode] Tried to convert an empty BIO." << std::endl;
        return "";
    }
    return std::string(buf->data, buf->length);
}

// ----------------------------------------------------------------------------
 
/**
 *  @brief  Returns the contents of an OpenSSL X509_NAME as a string.
 *
 *  @param  X509_NAME* name A pointer to the X509_NAME to convert.
 *
 *  @return A string containing the contents of the X509_NAME.
 */
std::string X509_NAME_to_string(X509_NAME* name)
{
    pBIO bio_out(BIO_new(BIO_s_mem()), BIO_free);
    X509_NAME_print_ex(bio_out.get(), name, 0, 0);
    return bio_to_string(bio_out);
}

// ----------------------------------------------------------------------------

/**
 *  @brief  Shorthand function used to get the CN part of an X509_NAME.
 *
 *  X509_NAMEs have the following format after having been converted to a
 *  string: "C=US, O=Thawte, Inc., CN=Thawte Code Signing CA - G2". This
 *  function simply returns the CN part.
 *
 *  @param  const std::string& x509_name The string containing the certificate
 *          information.
 *
 *  @return A string containing the CN of the X509_NAME. 
 */
std::string get_CN(const std::string& x509_name)
{
    auto pos = x509_name.find("CN=");
    if (pos == std::string::npos)
    {
        PRINT_WARNING << "[plugin_authenticode] Trying to obtain the Common Name of a malformed string! (" 
            << x509_name << ")" << std::endl;
        return "";
    }
    
    try
    {
        // Skip "CN=" and go until the next '/' or the end of the string.
        // Some CNs look like this: CN=Someone/emailAddress=address@provider.com
        return x509_name.substr(pos + 3, x509_name.find_first_of("/,", pos + 3) - pos - 3);
    }
    catch (std::out_of_range&)
    {
        PRINT_WARNING << "[plugin_authenticode] Trying to obtain the Common Name of a malformed string! (" 
            << x509_name << ")" << std::endl;
        return "";
    }
}

// ----------------------------------------------------------------------------

/**
 * Function which converts a byte array into an hexadecimal string.
 * @param buffer The byte array to convert.
 * @return An hexadecimal representation of the input data.
 */
std::string hexlify(const bytes& buffer)
{
    std::string result;
    for (const auto& b : buffer)
    {
        static const char dec2hex[17] = "0123456789abcdef";
        result += dec2hex[(b >> 4) & 15];
        result += dec2hex[b        & 15];
    }
    return result;
}

// ----------------------------------------------------------------------------

/**
 *  @brief  This function navigates through the digital signature's
 *          certificate chain to retrieve the successive common names.
 *
 *  @param  pPKCS7 p The PKCS7 object containing the digital signature.
 *  @param  pResult res The result in which the names should be added.
 */
void add_certificate_information(const pPKCS7& p, const pResult& res)
{
    STACK_OF(X509)* signers = PKCS7_get0_signers(p.get(), nullptr, 0);
    if (signers == nullptr)
    {
        PRINT_WARNING << "[plugin_authenticode] Could not obtain the certificate signers" << std::endl;
        return;
    }
    
    for (int i = 0 ; i < sk_X509_num(signers) ; ++i)
    {
        // X509_NAMEs don't need to be freed.
        X509_NAME* issuer = X509_get_issuer_name(sk_X509_value(signers, i));
        X509_NAME* subject = X509_get_subject_name(sk_X509_value(signers, i));
        std::string issuer_str = X509_NAME_to_string(issuer);
        std::string subject_str = X509_NAME_to_string(subject);
        res->add_information("Signer: " + get_CN(subject_str));
        res->add_information("Issuer: " + get_CN(issuer_str));
    }
    
    sk_X509_free(signers);
}

// ----------------------------------------------------------------------------

/**
 *  @brief  This plugin verifies the authenticode signature of a PE file.
 *
 *  This is the *nix reimplementation of the AuthenticodePlugin which is only
 *  availale on Windows (where digital signatures can be checked easily through
 *  the native API).
 *  This version relies on OpenSSL to perform similar operations. One key 
 *  difference is that the trusted certificate base is not available from
 *  an *nix host and therefore the plugin is unable to determine if the
 *  issuer is trusted. 
 */
class OpenSSLAuthenticodePlugin : public IPlugin
{
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
        
        auto certs = pe.get_certificates();
        if (certs == nullptr || certs->empty()) // No authenticode signature.
        {
			check_version_info(pe, res);
            return res;
        }
        
        for (const auto& it : *certs)
        {
            // Disregard non-PKCS7 certificates. According to the spec, they are not
            // supported by Windows.
            if (it->CertificateType != WIN_CERT_TYPE_PKCS_SIGNED_DATA) {
                continue;
            }
            
            // Copy the certificate bytes into an OpenSSL BIO.
            pBIO bio(BIO_new_mem_buf(&it->Certificate[0], it->Certificate.size()), BIO_free);
            if (bio == nullptr) 
            {
                PRINT_WARNING << "[plugin_authenticode] Could not initialize a BIO." << std::endl;
                continue;
            }
            
            pPKCS7 p(d2i_PKCS7_bio(bio.get(), nullptr), PKCS7_free);
            if (p == nullptr || !check_pkcs_sanity(p))
            {
                PRINT_WARNING << "[plugin_authenticode] Error reading the PKCS7 certificate." << std::endl;
                continue;
            }

            AuthenticodeDigest digest;
            if (!parse_spc_asn1(p->d.sign->contents->d.other->value.asn1_string, digest))
            {
                PRINT_WARNING << "[plugin_authenticode] Could not read the digest information." << std::endl;
                continue;
            }

            // The PKCS7 certificate has been loaded successfully. Perform verifications.
            add_certificate_information(p, res);

            // Verify that the authenticode hash is valid.
            auto authenticode_check = get_authenticode_hash(pe, digest.algorithm);
            if (!authenticode_check.empty() && authenticode_check != hexlify(digest.digest))
            {
                res->raise_level(MALICIOUS);
                res->set_summary("The PE's digital signature is invalid.");
                res->add_information("The file was modified after it was signed.");
            }
            else {
                res->set_summary("The PE is digitally signed.");
            }
            
        }
        
        return res;
    }
};

// ----------------------------------------------------------------------------

extern "C"
{
    PLUGIN_API IPlugin* create() { return new OpenSSLAuthenticodePlugin(); }
    PLUGIN_API void destroy(IPlugin* p) { delete p; }
};

} //!namespace plugin
