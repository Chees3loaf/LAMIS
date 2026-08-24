"""Transcript-splitting and field-reading primitives.

Both cases here came from a capture taken off live hardware, not from
speculation about the format.
"""

import unittest

from nokia_network_audit.parsers.common import (
    capture_host,
    field,
    normalize_state,
    split_command_sections,
    strip_ansi,
)


class CommandSplitTests(unittest.TestCase):
    def test_output_line_containing_a_hash_is_not_a_prompt(self):
        # Verbatim from a 7250 IXR-R6 "show system information". Treating this
        # as a prompt invented a section named after the software version and
        # truncated the real section at that line.
        text = (
            "A:MOPN001_7250# show system information\n"
            "System Name            : MOPN001_7250\n"
            "System Type            : 7250 IXR-R6\n"
            "Last Boot Config Header: # TiMOS-B-25.10.R2 both/hops64 Nokia 7250 IXR\n"
            "                         Copyright (c) 2000-2025 Nokia.\n"
            "Management IPv4 Addr   : 10.9.102.140/22\n"
            "A:MOPN001_7250# show card state\n"
            "1      iom-ixr-r6                        up    up\n"
        )
        sections = split_command_sections(text)
        self.assertEqual(
            sorted(sections), ["show card state", "show system information"]
        )
        # The whole of the first command's output stays in one piece.
        body = sections["show system information"]
        self.assertIn("System Type            : 7250 IXR-R6", body)
        self.assertIn("Management IPv4 Addr", body)

    def test_prompt_forms_across_platforms(self):
        text = (
            "A:MOPN001_7250# show port\n"
            "a\n"
            "*A:SITE-A# show lag\n"
            "b\n"
            "A:SITE-A>config>router# show router interface\n"
            "c\n"
            "MOPN001_1830# show general name\n"
            "d\n"
        )
        sections = split_command_sections(text)
        self.assertEqual(
            sorted(sections),
            ["show general name", "show lag", "show port", "show router interface"],
        )

    def test_channel_rows_with_a_hash_are_not_prompts(self):
        # The 1830 labels filter channels "ITU#33".
        text = (
            "MOPN001_1830# show interface sfdc8b *\n"
            " 1/10/9330 Channel      ITU#33                    Bi  Down  Down\n"
            " 1/10/9340 Channel      ITU#34                    Bi  Down  Down\n"
        )
        sections = split_command_sections(text)
        self.assertEqual(list(sections), ["show interface sfdc8b *"])

    def test_transcript_without_prompts_is_returned_whole(self):
        sections = split_command_sections("no prompts here\njust output\n")
        self.assertEqual(list(sections), ["transcript"])


class StripTests(unittest.TestCase):
    def test_colour_sequences_are_removed(self):
        text = "\x1b[1;31m CR SA    00/01/27 EQPT PWR 1/7 \x1b[0m"
        self.assertEqual(strip_ansi(text), " CR SA    00/01/27 EQPT PWR 1/7 ")

    def test_bell_is_removed_but_tabs_and_newlines_survive(self):
        # SR OS rings the bell on "MINOR: CLI BGP is not configured."
        self.assertEqual(
            strip_ansi("MINOR: CLI BGP is not configured.\x07\n\tkeep"),
            "MINOR: CLI BGP is not configured.\n\tkeep",
        )

    def test_crlf_is_normalised(self):
        self.assertEqual(strip_ansi("a\r\nb"), "a\nb")


class CaptureHostTests(unittest.TestCase):
    def test_header_host_is_read(self):
        text = "# Nokia Network Audit raw baseline transcript\n# Host: 10.9.102.139\n"
        self.assertEqual(capture_host(text), "10.9.102.139")

    def test_absent_header_yields_none(self):
        self.assertIsNone(capture_host("A:SITE-A# show port\n"))

    def test_a_host_column_in_output_is_not_the_capture_host(self):
        # Only a "#"-prefixed header line counts, not arbitrary output.
        self.assertIsNone(capture_host("  Host : 1.2.3.4\nHost: 5.6.7.8\n"))


class FieldTests(unittest.TestCase):
    BLOCK = (
        "Description        : 10/100 Ethernet TX\n"
        "Interface          : 1/5/8                      Oper Speed       : 1 Gbps\n"
        "Admin State        : up                         Oper Duplex      : full\n"
        "Oper State         : up - Active in LAG 2       Config Duplex    : N/A\n"
        "Configured Address : 24:f6:8d:f2:85:1a\n"
    )

    def test_left_column_value_stops_before_the_right_column(self):
        self.assertEqual(field(self.BLOCK, "Interface"), "1/5/8")
        self.assertEqual(field(self.BLOCK, "Admin State"), "up")

    def test_right_column_labels_are_found(self):
        # These never appear at the start of a line.
        self.assertEqual(field(self.BLOCK, "Oper Speed"), "1 Gbps")
        self.assertEqual(field(self.BLOCK, "Config Duplex"), "N/A")

    def test_values_containing_colons_are_not_truncated(self):
        self.assertEqual(field(self.BLOCK, "Configured Address"), "24:f6:8d:f2:85:1a")

    def test_qualified_state_reduces_to_its_keyword(self):
        self.assertEqual(field(self.BLOCK, "Oper State"), "up - Active in LAG 2")
        self.assertEqual(normalize_state(field(self.BLOCK, "Oper State")), "up")
        self.assertEqual(normalize_state("up/active"), "up")
        self.assertIsNone(normalize_state(None))


if __name__ == "__main__":
    unittest.main()
