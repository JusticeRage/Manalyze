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

    auto bytes = pe.get_raw_bytes(ioh->SizeOfHeaders);
    if (bytes == nullptr)
    {
        PRINT_ERROR << "[plugin_authenticode] Could not load the PE headers in memory." << std::endl;
        return "";
    }

    // Start hashing the file as described in the Authenticode documentation.
    // Step 3: hash the file up to ioh.Checksum.
    auto offset = dosh->e_lfanew + sizeof(mana::pe_header) + 0x40;
    h->add(&bytes->at(0), offset);

    // Step 4: skip the Checksum
    offset += 4;

    // Step 5: hash the file up to the Certificate Table entry.
    size_t bytes_to_read = 0x1C;
    if (pe.get_architecture() == mana::PE::x64) {
        bytes_to_read += 0x10;      // The Image Optional Header is longer for x64 binaries.
    }
    bytes_to_read += 0x20;          // Reach the SECURITY directory entry.
    h->add(&bytes->at(offset), bytes_to_read);

    // Step 6 omitted: Manalyze has already parsed the directories.
    // Step 7: hash the rest of the Image Optional Header, including the section table.
    offset += bytes_to_read + 8;    // Skip the SECURITY directory.
    h->add(&bytes->at(offset), bytes->size() - offset);

    // Step 8:
    auto sum_of_bytes_hashed = ioh->SizeOfHeaders;

    // Step 9 omitted: Manalyze already has a list of sections.
    // Step 10: Sort the sections in ascending PointerToRawData order.
    std::sort(sections->begin(), sections->end(),
              [](mana::pSection a, mana::pSection b) -> bool {
        return a->get_pointer_to_raw_data() < b->get_pointer_to_raw_data();
    });

    // Step 11-13: Hash each section.
    for (const auto& s : *sections)
    {
        if (s->get_size_of_raw_data() == 0) {
            continue;
        }
        auto data = s->get_raw_data();
        h->add(&data->at(0), data->size());
        sum_of_bytes_hashed += s->get_size_of_raw_data();
    }

    // Step 14: Check for additional data at the end of the file
    auto length_of_additional_data = pe.get_filesize() - sum_of_bytes_hashed
            - ioh->directories[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
    if (length_of_additional_data > 0)
    {
        FILE* f = fopen(pe.get_path()->c_str(), "rb");
        fseek(f, sum_of_bytes_hashed, SEEK_SET);
        boost::scoped_array<boost::uint8_t> buffer(new boost::uint8_t[length_of_additional_data]);
        fread(&buffer.operator[](0), 1, length_of_additional_data, f);
        h->add(&buffer.operator[](0), length_of_additional_data);
        fclose(f);
    }

    // Step 15: Finalize hash
    // Usually, I would need to use a smart pointer here as the received std::string is allocated in another module.
    // However, this is Linux only code, so there won't be a memory corruption when this plugin tries to free it.
    return h->getHash();
}

} // !namespace plugin