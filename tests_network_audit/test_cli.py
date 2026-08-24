"""CLI input handling.

The first thing anyone hits is the argument layer, so a missing file has to say
so plainly rather than surfacing a pathlib traceback, and wildcards have to work
on PowerShell -- which, unlike bash, hands ``*.txt`` to a native command
unexpanded.
"""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from nokia_network_audit.cli import (
    detect_transcript_type,
    looks_like_command_list,
    main,
    resolve_inputs,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
BASELINE_COMMANDS = REPO_ROOT / "baseline_commands"


class TranscriptTypeDetectionTests(unittest.TestCase):
    def test_real_captures_are_routed_to_the_right_parser(self):
        expected = {"ixr_r6.txt": "sros", "sar_8.txt": "sros", "pss_8.txt": "pss"}
        for name, want in expected.items():
            with self.subTest(name):
                text = (FIXTURES / name).read_text(encoding="utf-8")
                self.assertEqual(detect_transcript_type(text), want)

    def test_a_counter_containing_1830_does_not_look_like_an_1830(self):
        # Verbatim from a 7250 IXR-R6: the digits "1830" sit inside the packet
        # counter 6183078. A substring test sent the whole capture to the
        # optical parser, which then reported no ports and no platform.
        text = (
            "A:MOPN001_7250# show system information\n"
            "System Type            : 7250 IXR-R6\n"
            "A:MOPN001_7250# show port detail\n"
            "Multicast Pckts  :             6183078  CRC/Align Errors :        0\n"
        )
        self.assertEqual(detect_transcript_type(text), "sros")

    def test_pss_is_recognised_by_its_own_labels(self):
        text = (
            "MOPN001_1830# show general system-identification\n"
            "Shelf type               : PSS-8\n"
            "MOPN001_1830# show shelf inventory *\n"
        )
        self.assertEqual(detect_transcript_type(text), "pss")


class CommandListDetectionTests(unittest.TestCase):
    """Guard against auditing the command list instead of the device output.

    ``baseline_commands/*.txt`` is what you type at a device; a capture is what
    it prints back. Mixing them up produced a device with no ports and no LAGs
    and still exited 0, which reads as a clean audit of nothing.
    """

    def test_shipped_command_lists_are_recognised(self):
        for path in sorted(BASELINE_COMMANDS.glob("*.txt")):
            with self.subTest(path.name):
                self.assertTrue(
                    looks_like_command_list(path.read_text(encoding="utf-8"))
                )

    def test_real_captures_are_not_mistaken_for_command_lists(self):
        for path in sorted(FIXTURES.glob("*.txt")):
            with self.subTest(path.name):
                self.assertFalse(
                    looks_like_command_list(path.read_text(encoding="utf-8"))
                )

    def test_command_list_is_refused_with_an_explanation(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = main([str(BASELINE_COMMANDS / "7250-ixr-r6.txt")])
        self.assertEqual(code, 2)
        self.assertIn("looks like a command list", stderr.getvalue())


class ResolveInputsTests(unittest.TestCase):
    def test_directory_expands_to_transcripts(self):
        # Derived from the directory, not hardcoded: adding a fixture should not
        # break an unrelated test about directory expansion.
        expected = sorted(p.name for p in FIXTURES.glob("*.txt"))
        found, missing = resolve_inputs([str(FIXTURES)])
        self.assertEqual(missing, [])
        self.assertEqual([p.name for p in found], expected)

    def test_wildcard_is_expanded_here_not_by_the_shell(self):
        found, missing = resolve_inputs([str(FIXTURES / "*.txt")])
        self.assertEqual(missing, [])
        self.assertEqual(len(found), len(list(FIXTURES.glob("*.txt"))))

    def test_missing_paths_are_reported_not_raised(self):
        # The path must be one that cannot exist, rather than a plausible
        # relative name: a working copy may well grow a real captures/7250.log.
        with tempfile.TemporaryDirectory() as tmp:
            absent = str(Path(tmp) / "nope" / "7250.log")
        found, missing = resolve_inputs([absent])
        self.assertEqual(found, [])
        self.assertEqual(missing, [absent])

    def test_unmatched_wildcard_is_missing_rather_than_empty_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            found, missing = resolve_inputs([str(Path(tmp) / "*.log")])
        self.assertEqual(found, [])
        self.assertEqual(len(missing), 1)

    def test_duplicates_are_collapsed(self):
        target = str(FIXTURES / "pss_8.txt")
        found, missing = resolve_inputs([target, target, str(FIXTURES)])
        self.assertEqual(missing, [])
        self.assertEqual(len(found), len(list(FIXTURES.glob("*.txt"))))

    def test_capture_root_of_run_directories_is_expanded(self):
        # The layout the capture button writes: one run directory per shelf, each
        # holding transcript.txt. Pointing at the root is the obvious way to audit
        # a whole walk, and it used to report "holds no .txt/.log files".
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("SITE-A_7705-sar-8_20260804T0000Z", "SITE-B_7250-ixr-r6_20260804T0100Z"):
                run = root / name
                run.mkdir()
                (run / "transcript.txt").write_text("A:X# show system information\n")
                (run / "audit.json").write_text("{}")
            found, missing = resolve_inputs([str(root)])
        self.assertEqual(missing, [])
        self.assertEqual([p.name for p in found], ["transcript.txt"] * 2)
        self.assertEqual(
            [p.parent.name for p in found],
            [
                "SITE-A_7705-sar-8_20260804T0000Z",
                "SITE-B_7250-ixr-r6_20260804T0100Z",
            ],
        )

    def test_loose_transcripts_take_precedence_over_run_directories(self):
        # Descending is a fallback for an otherwise-empty directory, not a recurse
        # -- an output directory holding both must not audit its own subfolders.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "top.log").write_text("A:X# show system information\n")
            run = root / "SITE-A_7705-sar-8_20260804T0000Z"
            run.mkdir()
            (run / "transcript.txt").write_text("A:X# show system information\n")
            found, missing = resolve_inputs([str(root)])
        self.assertEqual(missing, [])
        self.assertEqual([p.name for p in found], ["top.log"])

    def test_a_directory_of_empty_run_directories_is_still_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "run-1").mkdir()
            (root / "run-1" / "notes.json").write_text("{}")
            found, missing = resolve_inputs([str(root)])
        self.assertEqual(found, [])
        self.assertEqual(missing, [str(root)])

    def test_non_transcript_files_in_a_directory_are_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "keep.log").write_text("A:X# show system information\n")
            (root / "skip.json").write_text("{}")
            found, missing = resolve_inputs([str(root)])
        self.assertEqual([p.name for p in found], ["keep.log"])
        self.assertEqual(missing, [])


class MainTests(unittest.TestCase):
    def test_missing_transcript_exits_two_with_a_readable_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            absent = str(Path(tmp) / "nope" / "7250.log")
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = main([absent])
        self.assertEqual(code, 2)
        message = stderr.getvalue()
        self.assertIn("Could not find these transcripts", message)
        self.assertIn(absent, message)
        self.assertNotIn("Traceback", message)

    def test_empty_transcript_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            blank = Path(tmp) / "blank.log"
            blank.write_text("   \n\n")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                code = main([str(blank), "--output", str(Path(tmp) / "out")])
        self.assertEqual(code, 2)
        self.assertIn("is empty", stderr.getvalue())

    def test_the_newest_capture_of_a_device_wins(self):
        # Re-capturing is normal: a chained run revisits a device, and you re-run
        # after a change. Refusing the whole batch over it was unhelpful.
        original = FIXTURES / "pss_8.txt"
        with tempfile.TemporaryDirectory() as tmp:
            newer = Path(tmp) / "newer.log"
            newer.write_text(
                "# Captured UTC: 2030-01-01T00:00:00+00:00\n"
                + original.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = main(
                    [str(original), str(newer), "--output", str(Path(tmp) / "out")]
                )
            self.assertEqual(code, 0)
            printed = stdout.getvalue()
        self.assertIn("Superseded by a newer capture", printed)
        self.assertIn("using", printed)
        # The run directory, not just "transcript.txt", identifies the capture.
        self.assertIn("newer.log", printed)

    def test_capture_time_prefers_the_header_over_the_file(self):
        from nokia_network_audit.cli import capture_time

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "t.log"
            path.write_text("# Captured UTC: 2026-07-31T18:08:21+00:00\nx\n")
            header = capture_time(path, path.read_text())
            plain = capture_time(path, "no header here\n")
        self.assertNotEqual(header, plain)
        self.assertGreater(header, 0)

    def test_a_transcript_of_bare_commands_is_flagged(self):
        # The signature of a desynchronised read: prompts and commands echoed
        # back, no output behind them.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "commands-only.log"
            path.write_text(
                "A:SITE-A# show port\n"
                "A:SITE-A# show lag detail\n"
                "A:SITE-A# show chassis detail\n",
                encoding="utf-8",
            )
            stderr = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                code = main([str(path), "--output", str(Path(tmp) / "out")])
        self.assertEqual(code, 0)
        self.assertIn("not just the commands", stderr.getvalue())

    def test_a_narrow_but_real_capture_is_not_flagged(self):
        # sar_8_system.txt holds chassis, timing, redundancy, CPU and LLDP but no
        # ports or LAGs. Warning about a perfectly good capture only teaches you
        # to ignore the warning.
        with tempfile.TemporaryDirectory() as tmp:
            stderr = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                code = main(
                    [
                        str(FIXTURES / "sar_8_system.txt"),
                        "--output",
                        str(Path(tmp) / "out"),
                    ]
                )
        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), "")

    def test_full_run_writes_both_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main([str(FIXTURES), "--output", str(out)])
            self.assertEqual(code, 0)
            report = json.loads((out / "audit.json").read_text(encoding="utf-8"))
            self.assertEqual(
                len(report["devices"]), len(list(FIXTURES.glob("*.txt")))
            )
            self.assertTrue((out / "audit.md").exists())
        # Each transcript is named alongside the device it produced.
        printed = stdout.getvalue()
        for device_id in ("MOPN001_7250", "MOPN001_7705", "MOPN001_1830"):
            self.assertIn(device_id, printed)


if __name__ == "__main__":
    unittest.main()
