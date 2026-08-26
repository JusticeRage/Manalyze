# Parser Boundary Safety Design

## Goal

Eliminate the confirmed malformed-input memory, arithmetic, and declared-boundary defects without rejecting valid unusual PE files. Bounds come from the PE's declared structures and the physical file, not from estimates of what a normal executable looks like.

This is Stage 1 of a broader hardening effort. Algorithmic amplification and cumulative work budgets are deliberately deferred to a separate design so that compatibility-sensitive limits are not mixed into direct safety fixes.

## Compatibility Policy

Manalyze remains a tolerant parser:

- A malformed optional directory or individual record does not invalidate an otherwise analyzable PE.
- A malformed record is omitted, an error is logged using the existing logging macros, and parsing resumes at the next sibling when its location is known safely.
- Valid records parsed before or after a malformed sibling remain available.
- Essential DOS, PE, and optional-header failures retain their existing effect on `PE::is_valid()`.
- Large and unusual structures remain accepted when their complete declared representation is physically present and their arithmetic is representable.
- No new normal-file heuristic or arbitrary count cap is introduced in Stage 1.

Repeated malformed records use the existing capped-logging pattern so diagnostics cannot become an amplification vector. Parser-specific messages identify the rejected structure and invalid field where useful.

## Existing Underflow Fixes

The current working-tree fixes for relocation blocks and `IMAGE_DEBUG_MISC` remain part of the change.

Relocation parsing validates the directory remainder before reading an eight-byte block header. A nonzero block must be at least eight bytes, fit the declared relocation-directory remainder, and contain an integral number of two-byte entries before any subtraction. An all-zero block continues to be accepted as section padding.

`IMAGE_DEBUG_MISC` parsing validates `PointerToRawData`, `SizeofData`, and `Length` against the physical file and the 12-byte fixed header before subtraction. ASCII data must contain at least one bounded byte; UTF-16 data must contain at least one complete code unit and have an even payload length.

## Debug Directory

Each debug-directory entry is parsed independently. The parser saves the next directory-entry position before following `PointerToRawData` and restores that position on every success or failure path.

For CodeView entries:

- `SizeofData` must contain the fixed CodeView header and at least one bounded filename byte.
- `[PointerToRawData, PointerToRawData + SizeofData)` must fit in the physical file, checked with subtraction-first arithmetic.
- The signature and fixed fields are read only after those checks.
- The filename reader receives exactly `SizeofData - fixed_header_size`; it cannot consume adjacent debug data or the rest of the file.
- A filename that is not terminated within that extent is malformed.

An invalid CodeView or MISC entry logs an error, is not appended to `_debug_entries`, and does not prevent later debug entries from being parsed.

## Authenticode ASN.1

`asn1_read()` becomes a checked local TLV operation. Its caller supplies the current pointer and the actual remaining bytes, not the original ASN.1 length for every nested object.

For every TLV:

- `ASN1_get_object()` error flags are checked.
- Header consumption cannot exceed the remaining span.
- The returned value length cannot exceed the bytes remaining after the header.
- Pointer advancement and `bytes::assign()` occur only after those checks.
- Skipped nested structures consume exactly their validated encoded value.

Malformed `SpcIndirectDataContent` logs an error and causes only that certificate to be ignored. Other certificates and non-Authenticode analysis continue normally.

## Export Tables

Export-name allocations are validated against their actual table locations before either vector is resized.

The parser resolves `AddressOfNames` and `AddressOfNameOrdinals`, verifies both offsets are inside the file, and checks:

- `NumberOfNames <= bytes_after_name_offset / sizeof(uint32_t)`
- `NumberOfNames <= bytes_after_ordinal_offset / sizeof(uint16_t)`

These division-based checks avoid multiplication overflow and allow any count physically represented by the file. Allocation handles both `std::bad_alloc` and `std::length_error`. A failed or impossible name table is omitted without discarding already parsed exported addresses.

Forwarded-export range endpoints and `Base + index` ordinal arithmetic are widened before addition. Values that cannot be represented by the public 32-bit fields are logged and omitted rather than wrapped.

## COFF String Table

The four-byte COFF string-table size includes the size field itself. The parser therefore requires a size of at least four and defines the payload extent as exactly `size - 4` bytes after the field.

Every string must terminate within the remaining payload. Empty strings may retain their existing representation, but parsing cannot consume bytes after the declared table. EOF, a missing terminator, or a table extent beyond the physical file logs an error and stops only COFF string-table parsing.

## Resource Version Information

Before skipping a `VarFileInfo` structure, the parser verifies that its declared `Length` is at least the bytes already consumed. The skip distance is calculated only after that comparison, must remain within the resource's declared data extent, and must be representable by `fseek`.

The same resource-relative extent is used by subsequent version-info structures so their reads cannot cross into adjacent resources or overlays. A malformed nested structure logs an error and returns no interpreted version object; it does not remove the raw resource or affect other resources.

## Offset And Directory Arithmetic

Resource-relative RVA and file-offset additions are performed in 64 bits. The sum must be representable by the receiving API and map into the physical file before seeking.

The fixed root structure for export, debug, and TLS directories must fit both the declared directory size and the physical file. Load configuration is versioned: its four-byte `Size` field must fit first, and each subsequent field must fit the smallest of that structure size, the declared directory extent, and the physical file. This preserves legitimate older load-configuration variants. Referenced tables that the PE format permits outside a root directory are checked against their own physical extents rather than incorrectly forced inside the root directory.

Optional-header parsing consumes no more than `SizeOfOptionalHeader`. The declared size must contain the architecture-specific fixed fields that are actually read. Data-directory entries are read only when each complete eight-byte entry fits the declared optional-header extent. An undersized essential optional header follows the existing invalid-PE path and logs the specific size error.

## Testing

Implementation follows red-green TDD. Compact in-memory variants of existing PE fixtures cover:

- CodeView sizes below the fixed header, filenames without an in-range terminator, payloads beyond EOF, valid bounded filenames, and a malformed entry followed by a valid sibling.
- Truncated and over-declared nested Authenticode TLVs, valid digest extraction, and a malformed certificate followed by another analyzable certificate.
- Export name counts whose name or ordinal table does not physically fit, counts at the physical boundary, forwarded-range overflow, and ordinal overflow. Allocation exceptions remain defensive fallback paths rather than tests that depend on exhausting the test host.
- COFF sizes below four, payloads beyond EOF, unterminated final strings, exact-boundary strings, and ordinary valid tables.
- `VarFileInfo.Length` below consumed bytes, a skip crossing the resource extent, and valid version resources with and without `VarFileInfo`.
- Overflowing resource-relative additions, undersized fixed directory roots, undersized optional headers, and valid unusual directory layouts whose referenced tables live outside the root directory.
- The existing relocation and MISC underflow cases, odd lengths, physical bounds, valid zero relocation padding, and valid bounded ASCII and UTF-16 MISC records.

Error-path tests capture diagnostics and verify the relevant structure name is logged. Recovery tests verify that malformed records are omitted while later valid siblings remain available.

Verification consists of a clean build, all Boost.Test cases, `git diff --check`, and focused AddressSanitizer and UndefinedBehaviorSanitizer runs over the new malformed fixtures. ASN.1 completion requires sanitizer evidence that truncated TLVs cause no out-of-bounds pointer advance or copy.

## Deferred Stage 2

The following amplification findings require a separate compatibility design:

- Quadratic Rich-header insertion.
- Unbounded import-descriptor traversal and repeated long library names.
- COFF one-object-per-byte amplification beyond the direct extent correction.
- Resource-name replication across many leaves.
- Repeated processing of overlapping section and resource ranges.
- TLS callback traversal without a practical work budget.
- Aggregate plugin and dump work over overlapping ranges.

Stage 2 should first replace quadratic operations, intern repeated values, and cache identical range work. Any remaining cumulative limits must be exceptionally high, named, logged, tested on both sides, and approved independently.

## Non-Goals

- Introducing a repository-wide bounded-reader abstraction.
- Treating an invalid optional directory as an invalid PE.
- Enforcing typical counts, filename lengths, section counts, or resource sizes.
- Redesigning public PE structure types.
- Adding process-level resource limits to Manalyzer.org in this stage.
