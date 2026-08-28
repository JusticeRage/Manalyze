#!/usr/bin/env python3

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import statistics
import struct
import subprocess
import sys
import tempfile


BENIGN_RICH_ENTRIES = 8
ADVERSARIAL_RICH_ENTRIES = 8192
ADVERSARIAL_COFF_RECORDS = 32768
ADVERSARIAL_COFF_STRING_BYTES = 1024 * 1024
BUDGET_DIAGNOSTICS = (
    "Rich header entry budget exhausted",
    "COFF symbol-record budget exhausted",
    "COFF string-table byte budget exhausted",
)


class GateError(Exception):
    pass


def run_checked(command, *, env=None, description):
    try:
        result = subprocess.run(
            [str(part) for part in command], env=env, text=True,
            capture_output=True, check=False, errors="replace",
        )
    except OSError as error:
        raise GateError(f"Could not run {description}: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic"
        raise GateError(f"{description} failed with status {result.returncode}: {detail}")
    return result


def write_u32(data, offset, value):
    struct.pack_into("<I", data, offset, value)


def write_u64(data, offset, value):
    struct.pack_into("<Q", data, offset, value)


def make_rich_pe(base, entry_count, include_dans=True):
    data = bytearray(base)
    original_pe_offset = struct.unpack_from("<I", data, 0x3c)[0]
    rich_offset = 0x80
    key = 0x12345678
    rich_size = (entry_count + 2) * 8
    rich_end = (rich_offset + rich_size + 3) & ~3
    new_pe_offset = max(original_pe_offset + 4, rich_end)
    shift = new_pe_offset - original_pe_offset
    data[original_pe_offset:original_pe_offset] = bytes(shift)
    data[0x40:new_pe_offset] = bytes(new_pe_offset - 0x40)
    write_u32(data, 0x3c, new_pe_offset)

    marker = 0x536E6144 if include_dans else 0x11111111
    write_u64(data, rich_offset, (key << 32) | (marker ^ key))
    for index in range(entry_count):
        build = index & 0xFFFF
        product = (index * 3) & 0xFFFF
        identifier = (build << 16) | product
        count = index + 1
        write_u64(
            data, rich_offset + (index + 1) * 8,
            ((count ^ key) << 32) | (identifier ^ key),
        )
    write_u32(data, rich_offset + (entry_count + 1) * 8, 0x68636952)
    write_u32(data, rich_offset + (entry_count + 1) * 8 + 4, key)
    return bytes(data)


def make_coff_pe(base, declared_records, physical_records, string_payload):
    data = bytearray(base)
    symbol_offset = len(data)
    data.extend(bytes(physical_records * 18))
    write_u32(data, 0xFC, symbol_offset)
    write_u32(data, 0x100, declared_records)
    data.extend(struct.pack("<I", 4 + len(string_payload)))
    data.extend(string_payload)
    return bytes(data)


def validate_fixture(validator, path):
    run_checked(
        [validator, "--iterations", "1", path],
        description=f"validator for {path}",
    )


def tracked_mz_paths(repo):
    result = run_checked(
        ["git", "-C", repo, "ls-files", "-z", "--", "test/testfiles"],
        description="tracked-fixture query",
    )
    paths = []
    for encoded in result.stdout.split("\0"):
        if not encoded:
            continue
        relative = Path(encoded)
        source = repo / relative
        try:
            magic = source.read_bytes()[:2]
        except OSError as error:
            raise GateError(f"Could not read tracked fixture {source}: {error}") from error
        if magic == b"MZ":
            paths.append(relative)
    return sorted(paths, key=lambda path: path.as_posix())


def prepare(args):
    repo = Path(args.repo).resolve()
    validator = Path(args.validator).resolve()
    output = Path(args.output).resolve()
    tracked = tracked_mz_paths(repo)

    if output.exists():
        if output.is_dir():
            shutil.rmtree(output)
        else:
            output.unlink()
    ordinary_dir = output / "ordinary"
    adversarial_dir = output / "adversarial"
    ordinary_dir.mkdir(parents=True)
    adversarial_dir.mkdir()

    ordinary = []
    for relative in tracked:
        source = repo / relative
        validate_fixture(validator, source)
        destination = ordinary_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        ordinary.append((Path("ordinary") / relative).as_posix())

    base_path = repo / "test/testfiles/manatest.exe"
    try:
        base = base_path.read_bytes()
    except OSError as error:
        raise GateError(f"Could not read generation base {base_path}: {error}") from error

    generated = {
        "ordinary/generated-rich.exe": make_rich_pe(base, BENIGN_RICH_ENTRIES),
        "ordinary/generated-coff.exe": make_coff_pe(base, 1, 1, b"ordinary\0"),
        "adversarial/rich-8192-entries.exe": make_rich_pe(
            base, ADVERSARIAL_RICH_ENTRIES,
        ),
        "adversarial/rich-8192-no-dans.exe": make_rich_pe(
            base, ADVERSARIAL_RICH_ENTRIES, include_dans=False,
        ),
        "adversarial/coff-32768-records.exe": make_coff_pe(
            base, ADVERSARIAL_COFF_RECORDS, ADVERSARIAL_COFF_RECORDS, b"",
        ),
        "adversarial/coff-1m-empty-strings.exe": make_coff_pe(
            base, 1, 1, bytes(ADVERSARIAL_COFF_STRING_BYTES),
        ),
    }
    for relative, data in generated.items():
        destination = output / relative
        destination.write_bytes(data)
        validate_fixture(validator, destination)

    ordinary.extend(path for path in generated if path.startswith("ordinary/"))
    adversarial = [path for path in generated if path.startswith("adversarial/")]
    manifest = {
        "ordinary": sorted(ordinary),
        "adversarial": sorted(adversarial),
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8",
    )


def load_manifest(corpus):
    manifest_path = corpus / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise GateError(f"Could not load corpus manifest {manifest_path}: {error}") from error
    if set(manifest) != {"ordinary", "adversarial"}:
        raise GateError("Corpus manifest must contain only ordinary and adversarial arrays")
    for group in ("ordinary", "adversarial"):
        if not isinstance(manifest[group], list) or not all(
                isinstance(path, str) for path in manifest[group]):
            raise GateError(f"Corpus manifest {group} member must be an array of paths")
    return manifest


def corpus_paths(corpus, relative_paths):
    paths = []
    root = corpus.resolve()
    for relative in relative_paths:
        path = (corpus / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as error:
            raise GateError(f"Corpus path escapes root: {relative}") from error
        if not path.is_file():
            raise GateError(f"Corpus file does not exist: {path}")
        paths.append(path)
    return paths


def normalize_tree(value, corpus_prefix):
    if isinstance(value, str):
        if value.startswith(corpus_prefix):
            return "<CORPUS>" + value[len(corpus_prefix):]
        return value
    if isinstance(value, list):
        return [normalize_tree(item, corpus_prefix) for item in value]
    if isinstance(value, dict):
        normalized = {}
        for key, item in value.items():
            normalized_key = normalize_tree(key, corpus_prefix)
            if normalized_key in normalized:
                raise GateError(f"Normalization produced duplicate key: {normalized_key}")
            normalized[normalized_key] = normalize_tree(item, corpus_prefix)
        return normalized
    return value


def run_analyzer(executable, repo, corpus, paths, empty_plugins):
    environment = os.environ.copy()
    environment.update({
        "MANALYZE_CONFIG_DIR": str(repo / "bin"),
        "MANALYZE_DATA_DIR": str(repo / "bin"),
        "MANALYZE_PLUGIN_DIR": str(empty_plugins),
    })
    result = run_checked(
        [executable, "-o", "json", "--dump", "all", "--log-level", "warning", *paths],
        env=environment,
        description=f"analyzer {executable}",
    )
    try:
        document = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise GateError(f"Analyzer {executable} emitted invalid JSON: {error}") from error
    return document, result.stderr


def output(args):
    repo = Path(args.repo).resolve()
    corpus = Path(args.corpus).resolve()
    manifest = load_manifest(corpus)
    paths = corpus_paths(corpus, manifest["ordinary"] + manifest["adversarial"])
    empty_plugins = corpus / "empty-plugins"
    if empty_plugins.exists():
        if empty_plugins.is_dir():
            shutil.rmtree(empty_plugins)
        else:
            empty_plugins.unlink()
    empty_plugins.mkdir()

    baseline_tree, _ = run_analyzer(
        Path(args.baseline).resolve(), repo, corpus, paths, empty_plugins,
    )
    candidate_tree, candidate_stderr = run_analyzer(
        Path(args.candidate).resolve(), repo, corpus, paths, empty_plugins,
    )
    for diagnostic in BUDGET_DIAGNOSTICS:
        if diagnostic in candidate_stderr:
            raise GateError(f"Candidate emitted budget diagnostic: {diagnostic}")

    prefix = str(corpus)
    baseline_tree = normalize_tree(baseline_tree, prefix)
    candidate_tree = normalize_tree(candidate_tree, prefix)
    if baseline_tree != candidate_tree:
        raise GateError("Normalized analyzer JSON trees differ")


def parse_benchmark_result(result, iterations, path_count, description):
    try:
        document = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise GateError(f"{description} emitted invalid JSON: {error}") from error
    expected = {"elapsed_ns", "iterations", "samples", "checksum"}
    if set(document) != expected:
        raise GateError(f"{description} emitted an unexpected JSON schema")
    if any(isinstance(document[key], bool) or not isinstance(document[key], int)
           for key in expected):
        raise GateError(f"{description} emitted a non-integer benchmark value")
    if document["elapsed_ns"] < 0 or document["iterations"] != iterations:
        raise GateError(f"{description} emitted invalid timing metadata")
    if document["samples"] != iterations * path_count:
        raise GateError(f"{description} emitted an invalid sample count")
    return document


def benchmark_sample(benchmark, libdir, paths, description):
    environment = os.environ.copy()
    environment["LD_LIBRARY_PATH"] = str(libdir)
    result = run_checked(
        [benchmark, "--iterations", "100", *paths],
        env=environment,
        description=description,
    )
    return parse_benchmark_result(result, 100, len(paths), description)


def ensure_equal_checksums(samples, description):
    checksums = {sample["checksum"] for sample in samples}
    if len(checksums) != 1:
        raise GateError(f"{description} checksums differ")


def performance(args):
    benchmark = Path(args.benchmark).resolve()
    baseline_libdir = Path(args.baseline_libdir).resolve()
    candidate_libdir = Path(args.candidate_libdir).resolve()
    corpus = Path(args.corpus).resolve()
    manifest = load_manifest(corpus)
    ordinary = corpus_paths(corpus, manifest["ordinary"])
    adversarial = corpus_paths(corpus, manifest["adversarial"])
    if not ordinary:
        raise GateError("The ordinary corpus must not be empty")

    baseline = [benchmark_sample(
        benchmark, baseline_libdir, ordinary, f"baseline ordinary sample {index + 1}",
    ) for index in range(7)]
    candidate = [benchmark_sample(
        benchmark, candidate_libdir, ordinary, f"candidate ordinary sample {index + 1}",
    ) for index in range(7)]
    ensure_equal_checksums(baseline + candidate, "Ordinary corpus")

    baseline_adversarial = None
    candidate_adversarial = None
    if adversarial:
        baseline_adversarial = benchmark_sample(
            benchmark, baseline_libdir, adversarial, "baseline adversarial sample",
        )
        candidate_adversarial = benchmark_sample(
            benchmark, candidate_libdir, adversarial, "candidate adversarial sample",
        )
        ensure_equal_checksums(
            [baseline_adversarial, candidate_adversarial], "Adversarial corpus",
        )

    baseline_times = [sample["elapsed_ns"] for sample in baseline]
    candidate_times = [sample["elapsed_ns"] for sample in candidate]
    baseline_median = statistics.median(baseline_times)
    candidate_median = statistics.median(candidate_times)
    delta = candidate_median - baseline_median
    per_iteration_delta = delta / 100
    report = {
        "ordinary": {
            "baseline_ns": baseline_times,
            "candidate_ns": candidate_times,
            "baseline_median_ns": baseline_median,
            "candidate_median_ns": candidate_median,
            "candidate_delta_per_iteration_ns": per_iteration_delta,
        },
        "adversarial": {
            "baseline_ns": baseline_adversarial["elapsed_ns"]
                if baseline_adversarial else None,
            "candidate_ns": candidate_adversarial["elapsed_ns"]
                if candidate_adversarial else None,
            "blocking": False,
        },
    }
    print(json.dumps(report, sort_keys=True))
    if candidate_median * 100 > baseline_median * 105 and delta > 200_000_000:
        raise GateError("Ordinary corpus performance exceeded both release thresholds")


def compile_probe(cxx, root, temporary, label):
    source = temporary / f"{label}-probe.cpp"
    executable = temporary / f"{label}-probe"
    source.write_text(
        "#include <iostream>\n"
        "#include \"manape/pe.h\"\n"
        "int main() {\n"
        "  std::cout << sizeof(mana::PE) << ' ' << alignof(mana::PE) << ' '\n"
        "            << sizeof(mana::rich_header) << ' '\n"
        "            << alignof(mana::rich_header) << '\\n';\n"
        "}\n",
        encoding="utf-8",
    )
    run_checked(
        [cxx, "-std=c++17", "-I" + str(root / "include"), source, "-o", executable],
        description=f"{label} ABI probe compilation",
    )
    result = run_checked([executable], description=f"{label} ABI probe")
    values = result.stdout.split()
    if len(values) != 4 or any(not value.isdigit() for value in values):
        raise GateError(f"{label} ABI probe emitted invalid output")
    return tuple(int(value) for value in values)


def member_block(root):
    header = root / "include/manape/pe.h"
    try:
        lines = header.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise GateError(f"Could not read PE header {header}: {error}") from error
    start_pattern = re.compile(r"^\s*std::string\s+_path\s*;")
    end_pattern = re.compile(r"\b_rich_header\s*;")
    starts = [index for index, line in enumerate(lines) if start_pattern.search(line)]
    if len(starts) != 1:
        raise GateError(f"Could not identify unique _path data member in {header}")
    start = starts[0]
    ends = [index for index in range(start, len(lines)) if end_pattern.search(lines[index])]
    if len(ends) != 1:
        raise GateError(f"Could not identify unique _rich_header data member in {header}")
    return "\n".join(lines[start:ends[0] + 1]) + "\n"


def dynamic_symbols(nm, library, label):
    result = run_checked(
        [nm, "-D", "--defined-only", "-C", library],
        description=f"{label} dynamic-symbol query",
    )
    symbols = set()
    for line in result.stdout.splitlines():
        fields = line.split(None, 2)
        symbol = fields[-1] if fields else ""
        pe_marker = "mana::PE::"
        pe_member = pe_marker in symbol and not symbol.split(pe_marker, 1)[1].startswith("_")
        type_symbol = ("typeinfo" in symbol or "vtable" in symbol) and (
            "mana::PE" in symbol or "mana::rich_header" in symbol
        )
        if pe_member or type_symbol:
            symbols.add(symbol)
    return symbols


def abi(args):
    baseline_root = Path(args.baseline_root).resolve()
    candidate_root = Path(args.candidate_root).resolve()
    cxx = args.cxx or os.environ.get("CXX") or "c++"
    nm = args.nm

    with tempfile.TemporaryDirectory() as directory:
        temporary = Path(directory)
        baseline_probe = compile_probe(cxx, baseline_root, temporary, "baseline")
        candidate_probe = compile_probe(cxx, candidate_root, temporary, "candidate")
    if baseline_probe != candidate_probe:
        raise GateError(
            f"ABI size/alignment probes differ: {baseline_probe} != {candidate_probe}"
        )

    if member_block(baseline_root) != member_block(candidate_root):
        raise GateError("PE data-member block from _path through _rich_header differs")

    if os.name == "nt":
        print("Dynamic symbol subset phase is Unix-only", file=sys.stderr)
        return
    baseline_symbols = dynamic_symbols(nm, Path(args.baseline_lib).resolve(), "baseline")
    candidate_symbols = dynamic_symbols(nm, Path(args.candidate_lib).resolve(), "candidate")
    missing = sorted(baseline_symbols - candidate_symbols)
    if missing:
        raise GateError("Candidate is missing baseline symbols: " + ", ".join(missing))


def parser():
    command_parser = argparse.ArgumentParser(description="Rich/COFF release gate harness")
    subparsers = command_parser.add_subparsers(dest="command", required=True)

    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--repo", required=True)
    prepare_parser.add_argument("--validator", required=True)
    prepare_parser.add_argument("--output", required=True)
    prepare_parser.set_defaults(function=prepare)

    output_parser = subparsers.add_parser("output")
    output_parser.add_argument("--repo", required=True)
    output_parser.add_argument("--baseline", required=True)
    output_parser.add_argument("--candidate", required=True)
    output_parser.add_argument("--corpus", required=True)
    output_parser.set_defaults(function=output)

    abi_parser = subparsers.add_parser("abi")
    abi_parser.add_argument("--baseline-root", required=True)
    abi_parser.add_argument("--candidate-root", required=True)
    abi_parser.add_argument("--baseline-lib", required=True)
    abi_parser.add_argument("--candidate-lib", required=True)
    abi_parser.add_argument("--cxx")
    abi_parser.add_argument("--nm", default="nm")
    abi_parser.set_defaults(function=abi)

    performance_parser = subparsers.add_parser("performance")
    performance_parser.add_argument("--benchmark", required=True)
    performance_parser.add_argument("--baseline-libdir", required=True)
    performance_parser.add_argument("--candidate-libdir", required=True)
    performance_parser.add_argument("--corpus", required=True)
    performance_parser.set_defaults(function=performance)
    return command_parser


def main():
    args = parser().parse_args()
    try:
        args.function(args)
    except GateError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
