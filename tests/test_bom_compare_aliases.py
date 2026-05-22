"""Regression tests for BoM-comparison part-number alias correlation.

Bundle SKUs on the Sales side (e.g. 3HE13584AA "7250 IXR-R6 CHASSIS
BUNDLE") fulfill the same physical hardware as the bare-component SKU
the Factory ships (3HE11278AA "7250 IXR-R6 CHASSIS"). Without an alias
map, a Sales BoM that lists the bundle and a Factory BoM that lists the
bare chassis would report a 100% shortfall — every bundle line "missing"
and every chassis line "unused". The alias loader in
``gui.bom_compare_frame`` collapses both forms into a single canonical
key before the diff so the comparison reflects what's actually shippable.
"""
import json
import os
import tempfile
import unittest

from gui.bom_compare_frame import (
    canonical_part,
    fold_aliased_parts,
    load_part_aliases,
)


class TestLoadPartAliases(unittest.TestCase):
    """The on-disk JSON loader handles missing files, malformed payloads,
    vendor-prefixed keys, and mixed-case entries without crashing the
    BoM comparison flow."""

    def _write(self, payload):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        self.addCleanup(os.unlink, path)
        return path

    def test_ships_with_3HE13584AA_to_3HE11278AA_pair(self):
        """The bundled data file (data/part_aliases.json) must include
        the chassis-bundle pair the operator originally requested."""
        aliases = load_part_aliases()
        self.assertEqual(aliases.get("3HE13584AA"), "3HE11278AA")

    def test_returns_empty_when_file_missing(self):
        self.assertEqual(load_part_aliases("/does/not/exist.json"), {})

    def test_returns_empty_when_payload_malformed(self):
        path = self._write({"aliases": "not a dict"})
        self.assertEqual(load_part_aliases(path), {})

    def test_returns_empty_when_top_level_not_dict(self):
        path = self._write(["just", "a", "list"])
        self.assertEqual(load_part_aliases(path), {})

    def test_strips_vendor_prefix_on_keys_and_values(self):
        # 1P / P prefixes are packaging markers — strip on both sides so
        # alias lookup is uniform regardless of how the BoM typed it.
        path = self._write({
            "aliases": {
                "1P3HE13584AA": "P3HE11278AA",
                "3HE99999AA":   "3HE88888AA",
            }
        })
        aliases = load_part_aliases(path)
        self.assertEqual(aliases.get("3HE13584AA"), "3HE11278AA")
        self.assertEqual(aliases.get("3HE99999AA"), "3HE88888AA")

    def test_uppercases_keys_and_values(self):
        path = self._write({"aliases": {"3he13584aa": "3he11278aa"}})
        aliases = load_part_aliases(path)
        self.assertIn("3HE13584AA", aliases)
        self.assertEqual(aliases["3HE13584AA"], "3HE11278AA")

    def test_drops_entries_with_non_string_values(self):
        # JSON itself coerces dict keys to strings on serialize, so the
        # only realistic non-string injection is a null / numeric value.
        path = self._write({"aliases": {
            "3HE13584AA": "3HE11278AA",
            "BAD":        None,
            "ALSO_BAD":   12345,
        }})
        aliases = load_part_aliases(path)
        self.assertEqual(aliases, {"3HE13584AA": "3HE11278AA"})

    def test_drops_entries_with_empty_keys_or_values(self):
        path = self._write({"aliases": {
            "3HE13584AA": "3HE11278AA",
            "":           "3HE11278AA",
            "OK":         "",
        }})
        aliases = load_part_aliases(path)
        self.assertEqual(aliases, {"3HE13584AA": "3HE11278AA"})


class TestCanonicalPart(unittest.TestCase):
    """``canonical_part`` collapses aliases via the loaded map and
    strips vendor prefixes for lookup uniformity."""

    def setUp(self):
        self.aliases = {"3HE13584AA": "3HE11278AA"}

    def test_known_alias_resolves_to_canonical(self):
        self.assertEqual(canonical_part("3HE13584AA", self.aliases), "3HE11278AA")

    def test_unknown_part_returns_self_uppercased(self):
        self.assertEqual(canonical_part("3HE99999AA", self.aliases), "3HE99999AA")

    def test_canonical_part_returns_self(self):
        # The bare chassis SKU should round-trip — it's already canonical.
        self.assertEqual(canonical_part("3HE11278AA", self.aliases), "3HE11278AA")

    def test_vendor_prefix_stripped_before_lookup(self):
        self.assertEqual(canonical_part("1P3HE13584AA", self.aliases), "3HE11278AA")
        self.assertEqual(canonical_part("P3HE13584AA",  self.aliases), "3HE11278AA")

    def test_case_insensitive_lookup(self):
        self.assertEqual(canonical_part("3he13584aa", self.aliases), "3HE11278AA")

    def test_empty_input_returns_empty(self):
        self.assertEqual(canonical_part("", self.aliases), "")
        self.assertEqual(canonical_part(None, self.aliases), "")


class TestFoldAliasedParts(unittest.TestCase):
    """``fold_aliased_parts`` collapses Sales and Factory parse results
    into canonical keys, summing per-site quantities and preferring the
    canonical SKU's description so the Missing BOM tab is consistent
    with what's actually shipped."""

    def setUp(self):
        self.aliases = {"3HE13584AA": "3HE11278AA"}

    def test_no_aliases_returns_input_unchanged(self):
        parts = {"3HE13584AA": {"desc": "BUNDLE", "site_qty": {"STJO": 1}}}
        self.assertIs(fold_aliased_parts(parts, {}), parts)

    def test_aliased_part_folds_into_canonical_key(self):
        parts = {
            "3HE13584AA": {"desc": "7250 IXR-R6 CHASSIS BUNDLE", "site_qty": {"STJO": 2}},
        }
        folded = fold_aliased_parts(parts, self.aliases)
        self.assertNotIn("3HE13584AA", folded)
        self.assertIn("3HE11278AA", folded)
        self.assertEqual(folded["3HE11278AA"]["site_qty"], {"STJO": 2})

    def test_canonical_only_input_is_passthrough(self):
        parts = {
            "3HE11278AA": {"desc": "7250 IXR-R6 CHASSIS", "site_qty": {"STJO": 2}},
        }
        folded = fold_aliased_parts(parts, self.aliases)
        self.assertEqual(folded["3HE11278AA"]["site_qty"], {"STJO": 2})
        self.assertEqual(folded["3HE11278AA"]["desc"], "7250 IXR-R6 CHASSIS")

    def test_both_forms_present_quantities_sum_and_canonical_desc_wins(self):
        # Sales BoM with one of each (e.g. a quirky line-item split) should
        # roll up to 3 chassis total and display the bare-chassis text.
        parts = {
            "3HE13584AA": {"desc": "7250 IXR-R6 CHASSIS BUNDLE", "site_qty": {"STJO": 1}},
            "3HE11278AA": {"desc": "7250 IXR-R6 CHASSIS",        "site_qty": {"STJO": 2}},
        }
        folded = fold_aliased_parts(parts, self.aliases)
        self.assertEqual(list(folded.keys()), ["3HE11278AA"])
        self.assertEqual(folded["3HE11278AA"]["site_qty"], {"STJO": 3})
        self.assertEqual(folded["3HE11278AA"]["desc"], "7250 IXR-R6 CHASSIS")

    def test_per_site_quantities_sum_across_sites(self):
        parts = {
            "3HE13584AA": {"desc": "B", "site_qty": {"STJO": 1, "MNCR": 2}},
            "3HE11278AA": {"desc": "C", "site_qty": {"STJO": 1, "ALSN": 3}},
        }
        folded = fold_aliased_parts(parts, self.aliases)
        self.assertEqual(
            folded["3HE11278AA"]["site_qty"],
            {"STJO": 2, "MNCR": 2, "ALSN": 3},
        )


class TestEndToEndShortfallScenario(unittest.TestCase):
    """End-to-end behavior: Sales says "1 bundle at STJO", Factory says
    "1 bare chassis at STJO" — after folding through aliases the diff
    must report ZERO shortfall instead of a unit missing."""

    def test_bundle_on_sales_chassis_on_factory_yields_no_shortfall(self):
        aliases = {"3HE13584AA": "3HE11278AA"}
        sales = {
            "3HE13584AA": {"desc": "7250 IXR-R6 CHASSIS BUNDLE", "site_qty": {"STJO001": 1}},
        }
        factory = {
            "3HE11278AA": {"desc": "7250 IXR-R6 CHASSIS", "site_qty": {"STJO001": 1}},
        }
        sales = fold_aliased_parts(sales, aliases)
        factory = fold_aliased_parts(factory, aliases)
        # The comparison logic in BomCompareFrame._compare does:
        #   short = sales_qty - factory_qty  (per site, must be > 0)
        s_qty = sales["3HE11278AA"]["site_qty"]["STJO001"]
        f_qty = factory["3HE11278AA"]["site_qty"].get("STJO001", 0)
        self.assertEqual(s_qty - f_qty, 0)

    def test_bundle_with_no_factory_chassis_still_shortfalls(self):
        """If Factory doesn't ship any chassis at all, the bundle line
        still surfaces as a shortfall — under the canonical part number."""
        aliases = {"3HE13584AA": "3HE11278AA"}
        sales = fold_aliased_parts(
            {"3HE13584AA": {"desc": "BUNDLE", "site_qty": {"STJO001": 2}}},
            aliases,
        )
        factory = fold_aliased_parts({}, aliases)
        s_qty = sales["3HE11278AA"]["site_qty"]["STJO001"]
        f_qty = factory.get("3HE11278AA", {}).get("site_qty", {}).get("STJO001", 0)
        self.assertEqual(s_qty - f_qty, 2)


if __name__ == "__main__":
    unittest.main()
