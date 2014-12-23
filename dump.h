/*
This file is part of Spike Guard.

Spike Guard is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Spike Guard is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Spike Guard.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _DUMP_H_
#define _DUMP_H_

#include "output_formatter.h"
#include "pe.h"
#include "imports.h"
#include "hash-library/hashes.h"
#include "hash-library/ssdeep.h"

namespace sg
{

void dump_dos_header(const sg::PE& pe, io::OutputFormatter& formatter);
void dump_pe_header(const sg::PE& pe, io::OutputFormatter& formatter);
void dump_image_optional_header(const sg::PE& pe, io::OutputFormatter& formatter);
void dump_section_table(const sg::PE& pe, io::OutputFormatter& formatter, bool compute_hashes = false);
void dump_imports(const sg::PE& pe, io::OutputFormatter& formatter);
void dump_exports(const sg::PE& pe, io::OutputFormatter& formatter);
void dump_resources(const sg::PE& pe, io::OutputFormatter& formatter, bool compute_hashes = false);
void dump_version_info(const sg::PE& pe, io::OutputFormatter& formatter);
void dump_debug_info(const sg::PE& pe, io::OutputFormatter& formatter);
void dump_tls(const sg::PE& pe, io::OutputFormatter& formatter);
void dump_summary(const sg::PE& pe, io::OutputFormatter& formatter);
void dump_hashes(const sg::PE& pe, io::OutputFormatter& formatter);

} // !namespace sg

#endif // !_DUMP_H_