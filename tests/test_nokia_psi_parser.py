import unittest

from scripts.Nokia_PSI import Script


class TestNokiaPSIShelfDetailParser(unittest.TestCase):
    def test_extract_shelf_detail_from_system_identification(self):
        script = Script.__new__(Script)
        output = (
            "ramantest1#  show general system-identification\n\n"
            "Vendor                   : Nokia\n"
            "Product                  : 1830\n"
            "Shelf type               : PSI-4L\n"
            "EC type                  : MEC2L\n"
            "Serial number            : CN2503MAB0D\n"
            "Current OAMP MAC address : 0c:4b:48:2c:52:3d\n\n"
            "ramantest1#\n"
        )

        df = Script.extract_shelf_detail(script, output, ip="10.0.0.1")

        self.assertEqual(df.iloc[0]["System Name"], "ramantest1")
        self.assertEqual(df.iloc[0]["System Type"], "PSI-4L")

    def test_extract_shelf_detail_legacy_show_shelf_1_still_supported(self):
        script = Script.__new__(Script)
        output = (
            "Name : LEGACY-PSI\n"
            "Programmed Type : PSI-8L\n"
        )

        df = Script.extract_shelf_detail(script, output)

        self.assertEqual(df.iloc[0]["System Name"], "LEGACY-PSI")
        self.assertEqual(df.iloc[0]["System Type"], "PSI-8L")


if __name__ == "__main__":
    unittest.main()
