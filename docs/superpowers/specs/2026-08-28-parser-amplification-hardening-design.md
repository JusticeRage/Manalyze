# Parser Amplification Hardening Design

## Goal

Bound attacker-controlled parser and analysis work without substantially increasing parser complexity or slowing ordinary analysis. Stage 2 first removes avoidable quadratic operations, repeated decoding, and repeated materialization. Exceptionally high, named budgets then bound residual linear work.

This design follows the direct boundary-safety work completed in Stage 1. It preserves Manalyze's tolerant parsing model: malformed optional structures do not invalidate an otherwise analyzable PE, safe siblings remain available, and unusual but valid files are accepted up to explicit documented work limits.

## Approach

Stage 2 deliberately avoids a parser-wide cache, shared range abstraction, object-layout changes, and a plugin ABI bump. Those mechanisms add synchronization, ownership, invalidation, and compatibility risks that are not yet justified by measurements.

Work is divided into four independently implementable and reviewable plans:

1. Linearize Rich-header parsing and eliminate COFF object-per-record materialization.
2. Bound import and TLS traversal by mapped extents and parser-specific budgets.
3. Eliminate repeated resource decoding and quadratic duplicate lookup while adding a metadata budget.
4. Reuse bytes within dump/plugin operations and apply deterministic analysis-byte budgets.

Each plan must preserve behavior below its approved limits and include before-and-after operation or read-count evidence for the amplification path it changes.

## Compatibility And Recovery

- Section and resource metadata objects, order, names, identifiers, timestamps, and public APIs remain unchanged.
- Exact or partially overlapping section ranges remain distinct metadata entries.
- Existing resource semantics remain unchanged: exact `(offset, size)` duplicate payloads are omitted, while partial overlaps remain accepted.
- Referenced import names, thunk tables, resource payloads, and TLS callback arrays are bounded by their own mapped or physical representation rather than incorrectly forced into the referring directory's fixed root.
- A cache may reuse deterministic decoding of the same physical structure, but each logical traversal still consumes its documented budget.
- Failed reads and budget-dependent failures are not cached.
- Each component records budget exhaustion locally and attempts one named capped diagnostic for that domain. Diagnostic visibility remains subject to the existing process-wide logging cap; parser and analysis results do not depend on that cap.
- Rich or COFF exhaustion stops only that optional structure.
- Import and TLS exhaustion preserves entries parsed before the limit and does not stop later PE directories.
- Resource metadata-budget exhaustion retains the existing transactional behavior and clears resources produced by the current resource parse.
- Dump or plugin exhaustion preserves parser metadata, skips complete remaining ranges in stable input order, and reports that the corresponding analysis is incomplete. Hashing and scanning are never performed on a partial range.

## Shared Work-Budget Primitive

A small internal `WorkBudget` value type tracks a 64-bit remaining amount and supports an overflow-safe all-or-nothing charge. It has no global state and no dependency on wall-clock timing. Unit tests instantiate it with small limits to verify exact-boundary behavior without allocating production-scale fixtures.

Every parser or analyzer owns its budget. Concurrent plugins do not race for a shared work counter, so analysis results are deterministic regardless of scheduling. Disabled analysis and cache hits for already completed work do not consume unrelated budgets.

The production limits are:

| Domain | Limit |
| --- | ---: |
| Rich-header entries | 1,048,576 |
| COFF symbol records | 1,048,576 |
| COFF string-table bytes scanned | 256 MiB |
| Import descriptors | 65,536 |
| Aggregate imported functions | 1,000,000 |
| Aggregate physical import-string bytes decoded | 256 MiB |
| Aggregate materialized DLL-name bytes | 64 MiB |
| Aggregate materialized imported-function name bytes | 256 MiB |
| TLS callbacks | 1,048,576 |
| Resource directory entries | Existing 10,000 limit |
| Aggregate physical resource-name bytes decoded | 64 MiB |
| Aggregate materialized resource metadata bytes | 64 MiB |

Automatic section and resource processing receives a logical-byte budget calculated from the physical file size:

```text
min(4 GiB, max(64 MiB, 16 * file_size))
```

The multiplication is saturating. Each built-in analyzer receives its budget deterministically. Materializing a range once and reusing those bytes for several operations charges the range once; processing another logical range charges its complete size even if it physically overlaps an earlier range.

The constants remain internal implementation details rather than public API. The `WorkBudget` primitive is tested immediately below, at, and above boundaries using small values. Parser algorithms accept an internal budget reference so focused tests can exercise exhaustion with compact fixtures; production entry points always construct the approved limits. A representative benign corpus must remain below all production limits before release. Raising limits later is compatibility-safe.

## Mapped-Range Semantics

Import and TLS traversal share one internal mapped-span resolver. It does not change the public `rva_to_offset()` API.

- RVA arithmetic and TLS ImageBase subtraction are checked before conversion. A TLS `AddressOfCallbacks` below ImageBase or at/above `SizeOfImage` is invalid.
- RVAs below `SizeOfHeaders` map directly to physically present header bytes, bounded by both `SizeOfHeaders` and the file size.
- Sections are considered in their existing table order, preserving current first-match behavior for overlaps. The resolver first uses the virtual span and then the existing raw-size fallback for malformed images whose `VirtualSize` is too small.
- A position inside physically backed section data maps to the remaining initialized raw bytes, using the existing file-alignment compatibility rule and physical-file checks.
- A position after initialized raw data but inside a section's valid virtual span maps to implicit zero-fill rather than adjacent file bytes.
- A span ends at the selected header or section boundary. Traversal must resolve the next mapped span explicitly rather than continuing through unrelated raw data.
- Ordinary import fields are RVAs. Their existing direct-file-offset fallback remains available only when no mapped span exists, is bounded by the physical file, and is charged against the import-string budget.
- TLS `AddressOfCallbacks` is a VA and receives no direct-file fallback. Callback table slots are mapped and bounded; the callback target values read from those slots are reported as data and are not required to point into the image.

## Rich Header

Rich-header parsing currently walks records backward and inserts every decoded entry at the beginning of a vector, producing quadratic element movement.

The parser will:

1. Use file-sized unsigned offsets for the DOS-stub scan and backward traversal.
2. Derive a safe possible-entry count from the physically backed candidate extent.
3. Append decoded entries while walking backward.
4. Reverse the vector once after locating the decoded `DanS` marker.
5. Move the completed result into the PE rather than copying it.

A missing marker discards the candidate. Exceeding the Rich-entry budget also discards the optional Rich header and emits one capped diagnostic. Entry ordering and the existing file offset remain unchanged for accepted headers.

## COFF Tables

COFF parsing currently allocates one shared object per symbol and one shared string per NUL-delimited string-table element, although no public getter or current analysis consumes the retained objects.

The parser will preflight the complete fixed-record extent before iteration using subtraction-first arithmetic. It will validate records through one stack object and cap repeated malformed-record diagnostics. It will not populate the existing private symbol container.

The string-table location and declared extent retain the Stage 1 physical-boundary checks. The payload is validated using buffered constant-memory scanning, including the requirement that the final represented string terminates inside the table. No object is allocated for each empty or ordinary string. Existing private storage remains present and empty to avoid an object-layout change in Stage 2.

The symbol-record and string-byte budgets stop only COFF parsing. They do not invalidate the PE or affect section metadata already parsed.

Correct long COFF section-name support is not introduced by this work. Executable-image section parsing currently occurs before COFF parsing, and changing that behavior is a separate compatibility feature.

## Imports

Import descriptors will be read only while complete 20-byte records fit the declared import-directory extent. A nonzero import RVA with zero declared size retains tolerant behavior by falling back to its containing initialized mapped span, whether physically present headers or a section; traversal never falls through to another span or overlay bytes. An undersized nonzero extent contains no complete descriptor and produces a named diagnostic.

Referenced DLL names and thunk data remain allowed outside the descriptor table. Names use a bounded reader and must terminate within their own initialized mapped range or physically bounded compatibility fallback. Decoded library and function names are cached by normalized source location and allowed extent. Before every buffered read, the reader reserves and charges the complete requested chunk against the physical string budget; it never reads or examines uncharged bytes. Failed decodes retain their charge, while a successful cache hit does not decode or recharge physical bytes.

Repeated descriptors remain distinct logical libraries even when they share a cached name. Each descriptor charges the full DLL-name length before materializing its retained library object, and each by-name imported function charges its full retained name length before insertion. These logical charges bound repeated copies even when decoding was shared.

Thunk-table decoding is cached by table RVA and architecture. Duplicate imported functions are tracked with a hash set rather than repeated linear searches. The existing per-library import limit is corrected to stop before storing entry 10,001, while the aggregate function budget bounds work across all descriptors.

Stage 2 does not expand or reinterpret delay-load descriptor discovery. The currently handled delay descriptor retains its existing RVA/VA interpretation and single-record behavior. Once that descriptor resolves through the existing path, its DLL and thunk processing shares the per-PE function, physical-string, and materialized-string budgets with standard imports. Correct `Attributes`-dependent VA/RVA semantics and full delay-descriptor-array traversal require a separate compatibility design.

Descriptor, function, or name-byte exhaustion preserves previously parsed libraries and imports, emits one capped import diagnostic, and ends only import parsing.

## TLS Callbacks

TLS callback traversal uses mapped-image semantics rather than scanning raw file bytes until EOF. The callback table remains allowed outside the fixed TLS directory root.

For each pointer-sized callback entry, the parser verifies that the address belongs to initialized mapped data. Entering valid implicit zero-filled image data is equivalent to encountering the required null terminator. Reaching the mapped extent without a null terminator emits a named diagnostic and preserves callbacks already parsed.

PE32 and PE32+ retain their respective pointer widths while public callback values remain normalized to 64 bits. The callback budget is charged before appending each nonzero callback.

## Resources

A parse-local resource context caches successfully decoded physical directories and data entries by resource-relative offset. Cached directories retain their advertised entry count. Every logical use, including a cache hit, charges that count against the existing 10,000-entry budget. `limit_exceeded` is never cached because it depends on the caller's remaining budget.

Repeated physical names are decoded once within the parse context. Before every buffered read, the decoder reserves and charges the complete requested chunk; it never reads or examines uncharged bytes. Failed attempts retain their charge, while successful cache hits do not recharge physical decoding. Type metadata is resolved once per root entry, and resource-name metadata once per type entry, rather than rebuilt inside every leaf iteration. Existing `Resource` fields and getters remain unchanged, so constructing a final Resource may still copy strings into its public representation.

The parser tracks accepted exact `(offset, size)` payload identities in a hash set, replacing the quadratic vector scan. It preserves the existing first-entry-wins behavior and capped duplicate warning. Partial overlaps remain accepted and distinct.

Before constructing each retained Resource, the parser charges the combined type, name, and language byte lengths that the object will store. This logical charge applies even when physical name decoding was cached, bounding replication across many leaves. Exhausting either the physical name-decoding budget or the materialized metadata budget aborts the resource parse transactionally and clears its partial results, matching existing directory-budget behavior.

The current function-static duplicate-warning flag is replaced by parse-local state in the resource context. Each PE attempts the warning once, eliminating its cross-file data race and scheduling-dependent suppression while retaining first-entry-wins behavior.

## Dump And Bundled Plugins

Local consumers will avoid repeated materialization without introducing cross-component shared ownership:

- Section dump materializes a section once and reuses the bytes for emitted hashes and entropy.
- Resource dump materializes a resource once and reuses the bytes for entropy, file-type detection, and emitted hashes.
- The resources plugin reuses one materialization for Yara and fallback entropy.
- `magic.yara` is compiled once per dump or plugin run rather than once per resource.
- Section and resource collections are snapshotted once per operation instead of repeatedly calling copying getters.
- Section/resource dumping computes only digest algorithms included in its output.

Different plugin rule sets and whole-file analyses remain separate semantic operations. Stage 2 does not combine Yara namespaces or alter plugin result ordering.

The approved logical-byte formula applies independently to these built-in consumers, with one budget lasting for one PE analysis:

- Section dump hashes and entropy.
- Resource dump entropy, file-type detection, and hashes.
- Resource extraction, with one budget covering file-type detection, RT_STRING/bitmap/icon/cursor interpretation, and output.
- Packer-plugin section entropy.
- Resources-plugin Yara and fallback entropy.
- Authenticode-plugin reads of version resources.
- `dump_version_info()` and summary-time RT_VERSION interpretation.

Each consumer charges a complete logical range before its first byte-dependent operation and processes metadata in stable parser order. Reusing the same materialization for that consumer's later operations does not recharge it. If the next complete range does not fit, that range and all later expensive ranges for the consumer are skipped and one capped incomplete-analysis diagnostic is attempted. Other consumers retain independent budgets.

Public `get_raw_data()` and `interpret_as()` calls made by Python or other external consumers are caller-directed and do not share these automatic-analysis budgets. Fixed-count whole-file hashes and Yara scans are not charged by this range budget because attacker-controlled section/resource multiplicity does not determine their invocation count.

## Testing

Implementation follows red-green TDD. Tests generate malformed or repetitive structures in memory rather than committing large denial-of-service samples.

### Rich And COFF

- Large ordered Rich headers preserve first, middle, and final values with linear construction.
- A large candidate without `DanS` is discarded promptly.
- Rich budget boundary cases preserve ordinary PE validity.
- COFF symbol extents at and beyond the physical boundary are handled without per-record retention.
- Repeated empty COFF strings remain accepted within the byte budget without one allocation per input byte.
- Existing Stage 1 COFF extent and termination regressions remain unchanged.

### Imports And TLS

- Import terminators at the declared boundary are accepted.
- Descriptors beyond the declared extent are ignored with a named diagnostic.
- The zero-size compatibility fallback stops at its containing mapped span, with separate cases for physically present headers and initialized sections.
- Names terminate exactly at their mapped boundary and cannot consume adjacent data or overlays.
- Many descriptors sharing one long name or thunk table preserve descriptor output while reusing decoding.
- Per-library and aggregate import limits are tested on both sides.
- Physical import-string and materialized DLL/function-name budgets are tested below, at, and above compact injected limits.
- Failed and unterminated import-name decodes consume physical budget before reads and cannot restart uncharged work.
- The existing delay-import fixture retains its output while sharing the aggregate function/string budgets after resolution.
- TLS arrays outside the fixed root remain accepted for PE32 and PE32+.
- Null termination at initialized and implicit-zero-fill boundaries is accepted.
- Missing termination and callback-budget exhaustion preserve earlier callbacks.

### Resources And Analysis

- Repeated physical directories are decoded once but charged on every logical traversal.
- The existing exact 10,000-entry success/failure behavior and transactional clearing remain intact.
- Repeated long names preserve getter values and remain independently mutable to callers.
- Physical resource-name and materialized metadata budgets are tested below, at, and above compact injected limits.
- Failed resource-name decodes consume physical budget, and either name-budget exhaustion path clears partial resources transactionally.
- Exact duplicate ranges retain first-entry-wins behavior in expected linear time.
- Duplicate warnings are parse-local and race-free when separate PEs are parsed concurrently.
- Partial overlaps remain represented independently.
- Dump and plugin output values remain identical while read counters demonstrate one materialization per operation.
- Analysis-byte budgets are tested at formula boundaries, with reuse hits, overlapping ranges, and stable skip order.
- Existing concurrent section/resource reads receive focused ThreadSanitizer coverage.

## Performance And Release Gates

Timing-only assertions are not used as correctness tests. Deterministic operation, allocation, or read counters demonstrate the intended complexity change where practical.

Before each plan is accepted:

- The full Release test suite passes.
- Focused AddressSanitizer and UndefinedBehaviorSanitizer runs cover new malformed fixtures.
- Concurrency changes receive focused ThreadSanitizer coverage.
- `git diff --check` passes.
- An independent review verifies compatibility, recovery, and limit placement.

Before Stage 2 is released, generated adversarial inputs and a fixed ordinary-file corpus are compared with baseline commit `a9b53a29db2e4fecaafb320b6bfe32b5d1aaac92`. The required corpus consists of every valid tracked PE under `test/testfiles` plus the ordinary PE32, PE32+, resource, import, TLS, Rich, and COFF fixtures generated by the tests. An optional larger local corpus may supplement but not replace this reproducible gate.

A Release benchmark parses the fixed corpus 100 times per sample in one process, performs seven baseline runs and seven candidate runs on the same host, and compares medians. A candidate blocks release if total median parser time regresses by more than 5% and more than 2 ms per corpus iteration.

Output compatibility is checked through JSON. The comparison parses each output document, replaces only the absolute corpus-root prefix in source-path strings with a fixed token, and compares the complete resulting trees including array order; no finding, metadata, or diagnostic field is excluded. Any benign budget exhaustion, sanitizer finding, unexplained output difference, or threshold failure requires investigation and explicit approval before release.

## Deferred Work And Non-Goals

- A shared physical-range source or parser-wide byte cache.
- Resource partial-overlap rejection or interval deduplication.
- Combining separate Yara rule sets into one scan.
- Public `PE`, `Section`, or `Resource` layout changes.
- A plugin API or ABI version bump.
- Process-level CPU, memory, or wall-clock enforcement.
- Strict DER canonicality or broader Authenticode OID semantics.

Measurements from this conservative work may justify a later design for shared range ownership or process-level isolation. Those changes require separate compatibility and concurrency review rather than being folded into Stage 2 opportunistically.
