#!/usr/bin/env python3

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "test" / "parser_amplification_gate.py"
BENCHMARK = Path(os.environ.get(
    "PARSER_AMPLIFICATION_BENCHMARK",
    "/tmp/opencode/manalyze-rich-coff-dev/bin/parser-amplification-benchmark",
))
FIXTURE = ROOT / "test" / "testfiles" / "manatest.exe"
ADVERSARIAL_NAMES = [
    "adversarial/rich-8192-entries.exe",
    "adversarial/rich-8192-no-dans.exe",
    "adversarial/coff-32768-records.exe",
    "adversarial/coff-1m-empty-strings.exe",
]


def write_executable(path, source):
    path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class GateTestCase(unittest.TestCase):
    def run_gate(self, *args, env=None):
        process_env = os.environ.copy()
        if env:
            process_env.update(env)
        return subprocess.run(
            [sys.executable, str(GATE), *map(str, args)],
            cwd=ROOT,
            env=process_env,
            text=True,
            capture_output=True,
            check=False,
        )

    def assert_usage_error(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("usage:", result.stderr.lower())


class CommandLineTests(GateTestCase):
    def test_gate_rejects_missing_and_unknown_subcommands(self):
        self.assert_usage_error(self.run_gate())
        self.assert_usage_error(self.run_gate("unknown"))

    def test_every_gate_required_argument_is_enforced(self):
        commands = {
            "prepare": ["--repo", ROOT, "--validator", BENCHMARK, "--output", "corpus"],
            "output": [
                "--repo", ROOT, "--baseline", "old", "--candidate", "new",
                "--corpus", "corpus",
            ],
            "abi": [
                "--baseline-root", "old-root", "--candidate-root", "new-root",
                "--baseline-lib", "old.so", "--candidate-lib", "new.so",
            ],
            "performance": [
                "--benchmark", BENCHMARK, "--baseline-libdir", "old-libs",
                "--candidate-libdir", "new-libs", "--corpus", "corpus",
            ],
        }
        for command, arguments in commands.items():
            for index in range(0, len(arguments), 2):
                missing = arguments[:index] + arguments[index + 2:]
                with self.subTest(command=command, option=arguments[index]):
                    self.assert_usage_error(self.run_gate(command, *missing))

    def test_benchmark_rejects_invalid_arguments_without_json(self):
        cases = [
            ["--iterations", "1"],
            ["--unknown", str(FIXTURE)],
            ["--iterations", "0", str(FIXTURE)],
            ["--iterations", "many", str(FIXTURE)],
            ["--iterations", "18446744073709551616", str(FIXTURE)],
            ["--iterations", "1", str(ROOT / "missing.exe")],
        ]
        for arguments in cases:
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    [str(BENCHMARK), *arguments], text=True, capture_output=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_benchmark_reports_exact_schema_counts_and_stable_checksum(self):
        single = subprocess.run(
            [str(BENCHMARK), "--iterations", "2", str(FIXTURE)],
            text=True, capture_output=True, check=False,
        )
        repeated = subprocess.run(
            [str(BENCHMARK), "--iterations", "2", str(FIXTURE), str(FIXTURE)],
            text=True, capture_output=True, check=False,
        )
        repeated_again = subprocess.run(
            [str(BENCHMARK), "--iterations", "2", str(FIXTURE), str(FIXTURE)],
            text=True, capture_output=True, check=False,
        )
        for result in (single, repeated, repeated_again):
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
        single_json = json.loads(single.stdout)
        repeated_json = json.loads(repeated.stdout)
        repeated_again_json = json.loads(repeated_again.stdout)
        expected_keys = {"elapsed_ns", "iterations", "samples", "checksum"}
        self.assertEqual(set(single_json), expected_keys)
        self.assertEqual(set(repeated_json), expected_keys)
        self.assertEqual(single_json["iterations"], 2)
        self.assertEqual(single_json["samples"], 2)
        self.assertEqual(repeated_json["iterations"], 2)
        self.assertEqual(repeated_json["samples"], 4)
        self.assertGreater(single_json["checksum"], 0)
        self.assertEqual(repeated_json["checksum"], single_json["checksum"] * 2)
        self.assertEqual(repeated_again_json["checksum"], repeated_json["checksum"])


class PrepareTests(GateTestCase):
    def test_prepare_is_deterministic_complete_and_domain_scoped(self):
        tracked_mz = []
        tracked = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "-z", "--", "test/testfiles"],
            capture_output=True, check=True,
        ).stdout.split(b"\0")
        for raw_path in filter(None, tracked):
            relative = raw_path.decode()
            if (ROOT / relative).read_bytes()[:2] == b"MZ":
                tracked_mz.append("ordinary/" + relative)

        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first"
            second = Path(temporary) / "second"
            for output in (first, second):
                result = self.run_gate(
                    "prepare", "--repo", ROOT, "--validator", BENCHMARK,
                    "--output", output,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

            first_bytes = (first / "manifest.json").read_bytes()
            self.assertEqual(first_bytes, (second / "manifest.json").read_bytes())
            manifest = json.loads(first_bytes)
            self.assertEqual(set(manifest), {"ordinary", "adversarial"})
            self.assertEqual(manifest["ordinary"], sorted(manifest["ordinary"]))
            self.assertEqual(manifest["adversarial"], sorted(manifest["adversarial"]))
            self.assertTrue(set(tracked_mz).issubset(manifest["ordinary"]))
            self.assertIn("ordinary/generated-rich.exe", manifest["ordinary"])
            self.assertIn("ordinary/generated-coff.exe", manifest["ordinary"])
            self.assertEqual(manifest["adversarial"], sorted(ADVERSARIAL_NAMES))
            self.assertNotIn(
                "ordinary/test/testfiles/00a1aa21f20d81a28b8b4cd39109d9ec",
                manifest["ordinary"],
            )
            for relative in manifest["ordinary"] + manifest["adversarial"]:
                self.assertTrue((first / relative).is_file(), relative)

    def test_prepare_fails_if_validator_rejects_a_tracked_mz(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            validator = temporary / "validator"
            write_executable(validator, """
                #!/usr/bin/env python3
                import pathlib
                import sys
                if pathlib.Path(sys.argv[-1]).name == "manatest2.exe":
                    sys.exit(9)
                print('{"elapsed_ns":1,"iterations":1,"samples":1,"checksum":1}')
            """)
            result = self.run_gate(
                "prepare", "--repo", ROOT, "--validator", validator,
                "--output", temporary / "corpus",
            )
            self.assertNotEqual(result.returncode, 0)


class OutputTests(GateTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.corpus = self.base / "corpus"
        (self.corpus / "ordinary").mkdir(parents=True)
        (self.corpus / "adversarial").mkdir()
        for relative in ("ordinary/one.exe", "adversarial/two.exe"):
            (self.corpus / relative).write_bytes(b"MZ")
        (self.corpus / "manifest.json").write_text(json.dumps({
            "ordinary": ["ordinary/one.exe"],
            "adversarial": ["adversarial/two.exe"],
        }), encoding="utf-8")
        self.expected_paths = [
            str((self.corpus / "ordinary/one.exe").resolve()),
            str((self.corpus / "adversarial/two.exe").resolve()),
        ]

    def tearDown(self):
        self.temporary.cleanup()

    def make_analyzer(self, name, document, *, stderr="", status=0):
        analyzer = self.base / name
        control = analyzer.with_suffix(".control.json")
        control.write_text(json.dumps({
            "document": document,
            "stderr": stderr,
            "status": status,
            "repo": str(ROOT),
            "corpus": str(self.corpus.resolve()),
            "paths": self.expected_paths,
        }), encoding="utf-8")
        write_executable(analyzer, """
            #!/usr/bin/env python3
            import json
            import os
            from pathlib import Path
            import sys

            config = json.loads(Path(__file__).with_suffix('.control.json').read_text())
            expected = ['-o', 'json', '--dump', 'all', '--log-level', 'warning', *config['paths']]
            valid = (
                sys.argv[1:] == expected
                and os.environ.get('MANALYZE_CONFIG_DIR') == config['repo'] + '/bin'
                and os.environ.get('MANALYZE_DATA_DIR') == config['repo'] + '/bin'
                and os.environ.get('MANALYZE_PLUGIN_DIR') == config['corpus'] + '/empty-plugins'
                and Path(os.environ['MANALYZE_PLUGIN_DIR']).is_dir()
                and not any(Path(os.environ['MANALYZE_PLUGIN_DIR']).iterdir())
            )
            if not valid:
                print('bad analyzer invocation or environment', file=sys.stderr)
                sys.exit(97)
            print(config['stderr'], file=sys.stderr, end='')
            if isinstance(config['document'], str):
                print(config['document'], end='')
            else:
                json.dump(config['document'], sys.stdout)
            sys.exit(config['status'])
        """)
        return analyzer

    def run_output(self, baseline_document, candidate_document, **candidate_options):
        baseline = self.make_analyzer("baseline", baseline_document)
        candidate = self.make_analyzer("candidate", candidate_document, **candidate_options)
        return self.run_gate(
            "output", "--repo", ROOT, "--baseline", baseline,
            "--candidate", candidate, "--corpus", self.corpus,
        )

    def test_equal_complete_trees_succeed(self):
        document = {"files": [{"path": self.expected_paths[0], "values": [1, 2]}]}
        result = self.run_output(document, document)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_every_tree_difference_fails(self):
        cases = [
            ({"value": 1}, {"value": 2}),
            ({"one": 1, "two": 2}, {"one": 1}),
            ({"one": 1}, {"one": 1, "two": 2}),
            ({"values": [1, 2]}, {"values": [2, 1]}),
            ({"old": 1}, {"new": 1}),
        ]
        for baseline, candidate in cases:
            with self.subTest(baseline=baseline, candidate=candidate):
                result = self.run_output(baseline, candidate)
                self.assertNotEqual(result.returncode, 0)

    def test_invalid_json_and_analyzer_failure_fail(self):
        invalid = self.run_output({"value": 1}, "not-json")
        failed = self.run_output({"value": 1}, {"value": 1}, status=3)
        self.assertNotEqual(invalid.returncode, 0)
        self.assertNotEqual(failed.returncode, 0)

    def test_candidate_budget_diagnostics_fail(self):
        diagnostics = [
            "Rich header entry budget exhausted",
            "COFF symbol-record budget exhausted",
            "COFF string-table byte budget exhausted",
        ]
        for diagnostic in diagnostics:
            with self.subTest(diagnostic=diagnostic):
                result = self.run_output({}, {}, stderr=diagnostic + "\n")
                self.assertNotEqual(result.returncode, 0)

    def test_only_corpus_root_prefixes_in_keys_and_values_are_normalized(self):
        root = str(self.corpus.resolve())
        baseline = {
            root + "/ordinary/one.exe": root + "/adversarial/two.exe",
            "nested": [root, "prefix " + root],
        }
        normalized = {
            "<CORPUS>/ordinary/one.exe": "<CORPUS>/adversarial/two.exe",
            "nested": ["<CORPUS>", "prefix " + root],
        }
        self.assertEqual(self.run_output(baseline, normalized).returncode, 0)

        embedded_changed = dict(normalized)
        embedded_changed["nested"] = ["<CORPUS>", "prefix <CORPUS>"]
        self.assertNotEqual(self.run_output(baseline, embedded_changed).returncode, 0)


class PerformanceTests(GateTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.corpus = self.base / "corpus"
        (self.corpus / "ordinary").mkdir(parents=True)
        (self.corpus / "adversarial").mkdir()
        for relative in ("ordinary/a.exe", "ordinary/b.exe", "adversarial/c.exe"):
            (self.corpus / relative).write_bytes(b"MZ")
        (self.corpus / "manifest.json").write_text(json.dumps({
            "ordinary": ["ordinary/a.exe", "ordinary/b.exe"],
            "adversarial": ["adversarial/c.exe"],
        }), encoding="utf-8")
        self.baseline_libdir = self.base / "baseline-libs"
        self.candidate_libdir = self.base / "candidate-libs"
        self.baseline_libdir.mkdir()
        self.candidate_libdir.mkdir()
        self.log = self.base / "invocations.jsonl"
        self.config = self.base / "benchmark-config.json"
        self.benchmark = self.base / "benchmark"
        write_executable(self.benchmark, """
            #!/usr/bin/env python3
            import json
            import os
            from pathlib import Path
            import sys

            config = json.loads(Path(os.environ['FAKE_BENCHMARK_CONFIG']).read_text())
            library_path = os.environ.get('LD_LIBRARY_PATH', '').split(os.pathsep)[0]
            variant = 'baseline' if library_path == config['baseline_libdir'] else 'candidate'
            paths = sys.argv[3:]
            group = 'adversarial' if all('/adversarial/' in path for path in paths) else 'ordinary'
            record = {
                'variant': variant,
                'group': group,
                'argv': sys.argv[1:],
                'library_path': library_path,
            }
            log = Path(config['log'])
            previous = log.read_text().splitlines() if log.exists() else []
            index = sum(
                json.loads(line)['variant'] == variant and json.loads(line)['group'] == group
                for line in previous
            )
            with log.open('a', encoding='utf-8') as output:
                output.write(json.dumps(record) + '\\n')
            behavior = config.get('behavior', {})
            if behavior.get('status_variant') == variant:
                sys.exit(8)
            if behavior.get('malformed_variant') == variant:
                print('not-json')
                sys.exit(0)
            values = config[variant + '_' + group]
            elapsed = values[min(index, len(values) - 1)]
            checksum = config.get(variant + '_' + group + '_checksum', 101 if group == 'ordinary' else 202)
            print(json.dumps({
                'elapsed_ns': elapsed,
                'iterations': int(sys.argv[2]),
                'samples': int(sys.argv[2]) * len(paths),
                'checksum': checksum,
            }))
        """)

    def tearDown(self):
        self.temporary.cleanup()

    def run_performance(self, baseline, candidate, *, adversarial=(1, 1), behavior=None,
                        checksums=None):
        configuration = {
            "baseline_libdir": str(self.baseline_libdir),
            "candidate_libdir": str(self.candidate_libdir),
            "log": str(self.log),
            "baseline_ordinary": baseline,
            "candidate_ordinary": candidate,
            "baseline_adversarial": [adversarial[0]],
            "candidate_adversarial": [adversarial[1]],
            "behavior": behavior or {},
        }
        if checksums:
            configuration.update(checksums)
        self.config.write_text(json.dumps(configuration), encoding="utf-8")
        self.log.unlink(missing_ok=True)
        return self.run_gate(
            "performance", "--benchmark", self.benchmark,
            "--baseline-libdir", self.baseline_libdir,
            "--candidate-libdir", self.candidate_libdir,
            "--corpus", self.corpus,
            env={"FAKE_BENCHMARK_CONFIG": str(self.config)},
        )

    def records(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_runs_exactly_seven_ordinary_samples_per_variant_at_100_iterations(self):
        result = self.run_performance([100] * 7, [100] * 7)
        self.assertEqual(result.returncode, 0, result.stderr)
        records = self.records()
        for variant, libdir in (
                ("baseline", self.baseline_libdir), ("candidate", self.candidate_libdir)):
            ordinary = [r for r in records if r["variant"] == variant and r["group"] == "ordinary"]
            self.assertEqual(len(ordinary), 7)
            for record in ordinary:
                self.assertEqual(record["argv"][:2], ["--iterations", "100"])
                self.assertEqual(record["library_path"], str(libdir))
                self.assertEqual(record["argv"][2:], [
                    str((self.corpus / "ordinary/a.exe").resolve()),
                    str((self.corpus / "ordinary/b.exe").resolve()),
                ])

    def test_uses_medians_not_extrema(self):
        result = self.run_performance(
            [1, 100, 100, 100, 100, 100, 10_000_000_000],
            [1, 104, 104, 104, 104, 104, 10_000_000_000],
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_threshold_boundaries_and_conjunction(self):
        cases = [
            (100_000_000, 105_000_000, True, "exactly five percent"),
            (100_000_000, 300_000_000, True, "exactly two milliseconds"),
            (1_000_000_000, 1_060_000_000, True, "percentage only"),
            (10_000_000_000, 10_250_000_000, True, "absolute only"),
            (100_000_000, 301_000_000, False, "both exceeded"),
        ]
        for baseline, candidate, succeeds, label in cases:
            with self.subTest(label=label):
                result = self.run_performance([baseline] * 7, [candidate] * 7)
                self.assertEqual(result.returncode == 0, succeeds, result.stderr)

    def test_adversarial_timing_is_reported_but_nonblocking(self):
        result = self.run_performance(
            [100_000_000] * 7, [100_000_000] * 7,
            adversarial=(1, 99_999_999_999),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("adversarial", result.stdout.lower())

    def test_malformed_json_nonzero_status_and_checksum_mismatch_fail(self):
        cases = [
            ({"malformed_variant": "candidate"}, None),
            ({"status_variant": "candidate"}, None),
            ({}, {"candidate_ordinary_checksum": 999}),
        ]
        for behavior, checksums in cases:
            with self.subTest(behavior=behavior, checksums=checksums):
                result = self.run_performance(
                    [100] * 7, [100] * 7, behavior=behavior, checksums=checksums,
                )
                self.assertNotEqual(result.returncode, 0)


class AbiTests(GateTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.baseline_root = self.base / "baseline"
        self.candidate_root = self.base / "candidate"
        for root in (self.baseline_root, self.candidate_root):
            (root / "include/manape").mkdir(parents=True)
            self.write_header(root, "int _middle;")
            (root / "probe.txt").write_text("8 8 24 8\n", encoding="utf-8")
        self.baseline_lib = self.base / "baseline.so"
        self.candidate_lib = self.base / "candidate.so"
        self.baseline_lib.touch()
        self.candidate_lib.touch()
        public = [
            "mana::PE::PE(std::__cxx11::basic_string<char> const&)",
            "mana::PE::get_filesize() const",
            "typeinfo for mana::PE",
            "vtable for mana::PE",
            "typeinfo for mana::rich_header_t",
        ]
        self.write_symbols(self.baseline_lib, public)
        self.write_symbols(self.candidate_lib, public)
        self.cxx = self.base / "cxx"
        self.nm = self.base / "nm"
        self.make_tools()

    def tearDown(self):
        self.temporary.cleanup()

    def write_header(self, root, middle):
        (root / "include/manape/pe.h").write_text(textwrap.dedent(f"""
            class PE {{
                std::string _before;
                std::string _path;
                {middle}
                std::optional<rich_header> _rich_header;
                int _after;
            }};
        """), encoding="utf-8")

    def write_symbols(self, library, symbols):
        library.with_suffix(library.suffix + ".symbols").write_text(
            "\n".join(symbols) + "\n", encoding="utf-8",
        )

    def make_tools(self, *, cxx_status=0, nm_status=0):
        write_executable(self.cxx, f"""
            #!/usr/bin/env python3
            from pathlib import Path
            import stat
            import sys
            if {cxx_status}:
                sys.exit({cxx_status})
            include = next(arg[2:] for arg in sys.argv if arg.startswith('-I'))
            output = Path(sys.argv[sys.argv.index('-o') + 1])
            values = (Path(include).parents[0] / 'probe.txt').read_text().strip()
            output.write_text('#!/bin/sh\\nprintf "%s\\n" "' + values + '"\\n')
            output.chmod(output.stat().st_mode | stat.S_IXUSR)
        """)
        write_executable(self.nm, f"""
            #!/usr/bin/env python3
            from pathlib import Path
            import sys
            if {nm_status}:
                sys.exit({nm_status})
            if sys.argv[1:4] != ['-D', '--defined-only', '-C']:
                sys.exit(96)
            symbols = Path(sys.argv[4] + '.symbols').read_text().splitlines()
            for index, symbol in enumerate(symbols):
                print(f'{{index:016x}} T {{symbol}}')
        """)

    def run_abi(self, *, cxx=None, nm=None):
        return self.run_gate(
            "abi", "--baseline-root", self.baseline_root,
            "--candidate-root", self.candidate_root,
            "--baseline-lib", self.baseline_lib,
            "--candidate-lib", self.candidate_lib,
            "--cxx", cxx or self.cxx, "--nm", nm or self.nm,
        )

    def test_equal_probes_and_baseline_symbol_subset_succeed(self):
        result = self.run_abi()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_changed_size_alignment_member_block_or_removed_symbol_fails(self):
        with self.subTest(reason="probe"):
            (self.candidate_root / "probe.txt").write_text("16 8 24 8\n", encoding="utf-8")
            self.assertNotEqual(self.run_abi().returncode, 0)
            (self.candidate_root / "probe.txt").write_text("8 8 24 8\n", encoding="utf-8")
        with self.subTest(reason="member block"):
            self.write_header(self.candidate_root, "long _middle;")
            self.assertNotEqual(self.run_abi().returncode, 0)
            self.write_header(self.candidate_root, "int _middle;")
        with self.subTest(reason="symbol"):
            self.write_symbols(self.candidate_lib, ["mana::PE::get_filesize() const"])
            self.assertNotEqual(self.run_abi().returncode, 0)

    def test_added_candidate_private_symbol_succeeds(self):
        symbols = self.candidate_lib.with_suffix(".so.symbols").read_text()
        self.candidate_lib.with_suffix(".so.symbols").write_text(
            symbols + "mana::detail::private_helper()\n", encoding="utf-8",
        )
        result = self.run_abi()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_removed_baseline_private_pe_symbol_succeeds(self):
        symbols = self.baseline_lib.with_suffix(".so.symbols").read_text()
        self.baseline_lib.with_suffix(".so.symbols").write_text(
            symbols + "mana::PE::_parse_private()\n", encoding="utf-8",
        )
        result = self.run_abi()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_or_failing_tools_fail(self):
        missing = self.base / "missing-tool"
        self.assertNotEqual(self.run_abi(cxx=missing).returncode, 0)
        self.assertNotEqual(self.run_abi(nm=missing).returncode, 0)
        self.make_tools(cxx_status=4)
        self.assertNotEqual(self.run_abi().returncode, 0)
        self.make_tools(nm_status=5)
        self.assertNotEqual(self.run_abi().returncode, 0)


if __name__ == "__main__":
    unittest.main()
