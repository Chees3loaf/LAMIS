"""Nokia leaves 'Part Number' EMPTY for third-party pluggables.

Real capture from usuma1-l9r2 (a ROADM shelf with copper SFPs added to the
LAN3/LAN4 ports). The OSC SFP is a Nokia part and fills all four columns; the
two Finisar copper SFPs report a serial and nothing else:

     Location   Module Type                    Part Number        Serial Number
    1/3/OSCSFP1  SWE1GOL                       3AL82260AAAA       ALLU25--OF50000209
     1/10/LAN3   1000B-T                                          NDHAEXU
     1/10/LAN4   1000B-T                                          N8DEVPQ

Every parser split on whitespace and assigned tokens positionally, so the
blank column collapsed: the serial slid into the part slot and rows that came
up one token short were dropped. The audit parser was worse -- its separators
were ``\\s+`` (which crosses newlines) with no guard on the trailing groups, so
LAN3 ate ``1/10/LAN4`` as its serial and LAN4 was never emitted at all.
"""
import unittest
from unittest.mock import MagicMock

from scripts.Nokia_PSI import Script
from scripts.Network.Nokia_PSI_Audit import parse_interface_inventory
from scripts._nokia_1830_family import iface_column_offsets, split_iface_row


# Verbatim from the device, column alignment preserved.
IFACE_INVENTORY = (
    "usuma1-l9r2# show interface inv *\n"
    "\n"
    "     Location   Module Type                             Part Number        Serial Number\n"
    "--------------------------------------------------------------------------------------------------\n"
    "   1/3/OSCSFP1  SWE1GOL                                 3AL82260AAAA       ALLU25--OF50000209\n"
    "    1/10/LAN3   1000B-T                                                    NDHAEXU\n"
    "    1/10/LAN4   1000B-T                                                    N8DEVPQ\n"
    "\n"
    "usuma1-l9r2# "
)


class TestColumnOffsets(unittest.TestCase):
    def test_header_offsets_found(self):
        pn_col, sn_col = iface_column_offsets(IFACE_INVENTORY)
        self.assertIsNotNone(pn_col)
        self.assertIsNotNone(sn_col)
        self.assertLess(pn_col, sn_col)

    def test_flattened_table_yields_no_offsets(self):
        # wexpect can collapse the table onto one line; offsets taken from a
        # line that also holds data rows would be meaningless.
        flat = " ".join(IFACE_INVENTORY.split())
        self.assertEqual(iface_column_offsets(flat), (None, None))


class TestSplitIfaceRow(unittest.TestCase):
    def test_four_column_row_unchanged(self):
        pn_col, sn_col = iface_column_offsets(IFACE_INVENTORY)
        row = "   1/3/OSCSFP1  SWE1GOL                                 3AL82260AAAA       ALLU25--OF50000209"
        self.assertEqual(
            split_iface_row(row, pn_col, sn_col),
            ("1/3/OSCSFP1", "SWE1GOL", "3AL82260AAAA", "ALLU25--OF50000209"),
        )

    def test_blank_part_number_keeps_serial_in_serial_column(self):
        pn_col, sn_col = iface_column_offsets(IFACE_INVENTORY)
        row = "    1/10/LAN3   1000B-T                                                    NDHAEXU"
        self.assertEqual(
            split_iface_row(row, pn_col, sn_col),
            ("1/10/LAN3", "1000B-T", "", "NDHAEXU"),
        )

    def test_lone_value_classified_by_shape_without_header(self):
        # No column offsets available -> fall back to the Nokia PN shape.
        self.assertEqual(
            split_iface_row("1/10/LAN3 1000B-T NDHAEXU"),
            ("1/10/LAN3", "1000B-T", "", "NDHAEXU"),
        )
        self.assertEqual(
            split_iface_row("1/3/OSCSFP1 SWE1GOL 3AL82260AAAA"),
            ("1/3/OSCSFP1", "SWE1GOL", "3AL82260AAAA", ""),
        )

    def test_too_few_tokens_rejected(self):
        self.assertIsNone(split_iface_row("1/10/LAN3 1000B-T"))
        self.assertIsNone(split_iface_row(""))


class TestPSIModuleInventory(unittest.TestCase):
    def _df(self):
        script = Script.__new__(Script)
        script.db_cache = MagicMock()
        script.db_cache.lookup_part.return_value = "SFP OSC 1GbE EULH"
        return Script.extract_module_inventory(script, IFACE_INVENTORY, ip="1.2.3.4")

    def test_all_three_pluggables_present(self):
        names = list(self._df()["Name"])
        self.assertEqual(
            names,
            ["Module 1/3/OSCSFP1", "Module 1/10/LAN3", "Module 1/10/LAN4"],
        )

    def test_copper_sfps_keep_their_serials(self):
        df = self._df().set_index("Name")
        self.assertEqual(df.loc["Module 1/10/LAN3", "Serial Number"], "NDHAEXU")
        self.assertEqual(df.loc["Module 1/10/LAN4", "Serial Number"], "N8DEVPQ")

    def test_absent_part_number_stays_blank_not_a_serial(self):
        df = self._df().set_index("Name")
        self.assertEqual(df.loc["Module 1/10/LAN3", "Part Number"], "")
        self.assertEqual(df.loc["Module 1/10/LAN4", "Part Number"], "")

    def test_absent_part_number_is_not_labelled_not_found(self):
        # "Not Found" means the catalog was asked and missed. The device
        # simply reported no part, so the catalog must not be consulted.
        df = self._df().set_index("Name")
        self.assertEqual(df.loc["Module 1/10/LAN3", "Description"], "")

    def test_nokia_part_still_parsed_and_looked_up(self):
        df = self._df().set_index("Name")
        row = df.loc["Module 1/3/OSCSFP1"]
        self.assertEqual(row["Part Number"], "3AL82260AA")  # 10-char catalog key
        self.assertEqual(row["Serial Number"], "ALLU25--OF50000209")
        self.assertEqual(row["Description"], "SFP OSC 1GbE EULH")


class TestAuditInterfaceInventory(unittest.TestCase):
    def test_all_three_rows_emitted(self):
        rows = parse_interface_inventory(IFACE_INVENTORY)
        self.assertEqual(
            [r["iface_name"] for r in rows],
            ["1/3/OSCSFP1", "1/10/LAN3", "1/10/LAN4"],
        )

    def test_lan4_no_longer_swallowed_as_lan3_serial(self):
        rows = {r["iface_name"]: r for r in parse_interface_inventory(IFACE_INVENTORY)}
        self.assertEqual(rows["1/10/LAN3"]["serial"], "NDHAEXU")
        self.assertNotIn("/", rows["1/10/LAN3"]["serial"])

    def test_serial_does_not_land_in_the_part_field(self):
        rows = {r["iface_name"]: r for r in parse_interface_inventory(IFACE_INVENTORY)}
        # 'manufacturer' is where this parser stores the part number.
        self.assertEqual(rows["1/10/LAN3"]["manufacturer"], "")
        self.assertEqual(rows["1/10/LAN4"]["manufacturer"], "")
        self.assertEqual(rows["1/3/OSCSFP1"]["manufacturer"], "3AL82260AAAA")

    def test_flattened_output_still_parses_every_row(self):
        # The unanchored scan exists for wexpect's single-line output; it must
        # keep working, and must still not consume a following location.
        flat = " ".join(IFACE_INVENTORY.split())
        rows = {r["iface_name"]: r for r in parse_interface_inventory(flat)}
        self.assertEqual(
            sorted(rows), ["1/10/LAN3", "1/10/LAN4", "1/3/OSCSFP1"]
        )
        self.assertEqual(rows["1/10/LAN3"]["serial"], "NDHAEXU")
        self.assertEqual(rows["1/10/LAN4"]["serial"], "N8DEVPQ")

    def test_pss_style_four_column_row_unaffected(self):
        text = (
            "     Location   Module Type          Part Number        Serial Number\n"
            "-------------------------------------------------------------------\n"
            "    1/2/OSCSFP  SEUL1.2O             3AL82081AAAA       ALLU25-LTC49000915\n"
        )
        rows = parse_interface_inventory(text)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["manufacturer"], "3AL82081AAAA")
        self.assertEqual(rows[0]["serial"], "ALLU25-LTC49000915")


if __name__ == "__main__":
    unittest.main()
