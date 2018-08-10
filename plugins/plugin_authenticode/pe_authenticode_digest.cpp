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

#include "pe_authenticode_digest.h"

namespace plugin {

std::string get_authenticode_hash(const mana::PE& pe, const std::string& digest_oid)
{
    hash::pHash h = hash::create_hash(digest_oid);
    if (h == nullptr)
    {
        PRINT_WARNING << "[plugin_authenticode] Hashing algorithm " << digest_oid << " is not supported." << std::endl;
        return "";
    }

    auto dosh = pe.get_dos_header();
    auto peh = pe.get_pe_header();
    auto ioh = pe.get_image_optional_header();
    auto sections = pe.get_sections();
    if (!dosh || !peh || !ioh || !sections)
    {
        PRINT_WARNING << "The PE hasn't been parsed properly!" << std::endl;  // Should never be reached.
        return "";
    }

    // The authenticode specification describes a 15-step process to compute the PE's digest.
    // Sadly, it doesn't work for slightly malformed executables (i.e. unusual SizeOfHeaders, spacing
    // between sections, etc. The following way is much simpler and works in all cases: just hash everything
    // before the certificate data, only excluding two fields (Checksum and the IMAGE_DIRECTORY_ENTRY_SECURITY
    // information.
    FILE* f = fopen(pe.get_path()->c_str(), "rb");
    auto size = dosh->e_lfanew + sizeof(mana::pe_header) + 0x40; // Offset of the Checksum.
    boost::scoped_array<boost::uint8_t> buffer(new boost::uint8_t[size]);
    fread(&buffer.operator[](0), 1, size, f);
    h->add(&buffer.operator[](0), size);
    // Hash everything up to the Checksum then skip it.
    fseek(f, 4, SEEK_CUR);
    // Now reach the SECURITY directory information. For x64 binaries, it's 0x10 bytes further.
    size = 0x3C;
    if (pe.get_architecture() == mana::PE::x64) {
        size += 0x10;
    }
    buffer.reset(new boost::uint8_t[size]);
    fread(&buffer.operator[](0), 1, size, f);
    h->add(&buffer.operator[](0), size);
    // Again, hash everything up to here then skip the ignored field.
    fseek(f, 8, SEEK_CUR);

    // Now hash everything else in the file up to the certificate data.
    if (ioh->directories[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress < ftell(f))
    {
        PRINT_WARNING << "[plugin_authenticode] Error: the certificate data is located in the PE header. "
                         "The PE was almost certainly crafted manually." << std::endl;
        return h->getHash(); // Return the current meaningless hash to make sure the verification will fail.
    }

    size_t remaining = ioh->directories[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress - static_cast<size_t>(ftell(f));
    while (remaining)
    {
        size_t chunk_size = std::min(remaining, static_cast<size_t>(4096));
        buffer.reset(new boost::uint8_t[chunk_size]);
        auto read_bytes = fread(&buffer.operator[](0), 1, chunk_size, f);
        if (read_bytes == 0) { // Read error or EOF. Try hashing what we have, but things are bleak.
            break;
        }
        h->add(&buffer.operator[](0), read_bytes);
        remaining -= read_bytes;
    }
    fclose(f);

    // Usually, I would need to use a smart pointer here as the received std::string is allocated in another module.
    // However, this is Linux only code, so there won't be a memory corruption when this plugin tries to free it.
    return h->getHash();
}

} // !namespace plugin