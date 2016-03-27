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

#include <set>
#include <vector>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/make_shared.hpp>

#include "output_formatter.h"
#include "manape/pe.h"
#include "manape/imports.h"
#include "hash-library/hashes.h"
#include "hash-library/ssdeep.h"
#include "yara/yara_wrapper.h"

namespace mana
{

void dump_dos_header(const mana::PE& pe, io::OutputFormatter& formatter);
void dump_pe_header(const mana::PE& pe, io::OutputFormatter& formatter);
void dump_image_optional_header(const mana::PE& pe, io::OutputFormatter& formatter);
void dump_section_table(const mana::PE& pe, io::OutputFormatter& formatter, bool compute_hashes = false);
void dump_imports(const mana::PE& pe, io::OutputFormatter& formatter);
void dump_exports(const mana::PE& pe, io::OutputFormatter& formatter);
void dump_resources(const mana::PE& pe, io::OutputFormatter& formatter, bool compute_hashes = false);
void dump_version_info(const mana::PE& pe, io::OutputFormatter& formatter);
void dump_debug_info(const mana::PE& pe, io::OutputFormatter& formatter);
void dump_tls(const mana::PE& pe, io::OutputFormatter& formatter);
void dump_summary(const mana::PE& pe, io::OutputFormatter& formatter);
void dump_hashes(const mana::PE& pe, io::OutputFormatter& formatter);

/**
 * @brief   Detects the filetype of a given resource based on magic numbers contained
 *          inside it.
 *
 * @param   mana::pResource resource The resource whose type we want to identify.
 * @return  yara::const_matches The list of matches found by Yara (only one in most
 *          cases, but so-called polyglot files can be of multiple file types at the
 *          same type.
 */
yara::const_matches detect_filetype(mana::pResource resource);

/**
 * @brief   Extracts resources from a PE file.
 *
 * @param   const mana::PE& pe The PE whose resources we want extracted.
 * @param   const std::string& destination_folder The folder into which the
 *          extracted files should be placed.
 *
 * @return  Whether the extraction was successful.
 */
bool extract_resources(const mana::PE& pe, const std::string& destination_folder);

} // !namespace sg
