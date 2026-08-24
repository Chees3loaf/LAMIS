"""Read-only command-line audit for a published ATLAS RLS route bundle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from utils.rls_config.deliverable_audit import (
    audit_route_deliverable,
    load_golden_fixture,
)  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify a route bundle's hashes, candidate safety boundary, "
            "workbook formulas, and reviewed route facts."
        )
    )
    parser.add_argument("bundle", type=Path)
    parser.add_argument("golden", type=Path)
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the full machine-readable audit report.",
    )
    args = parser.parse_args(argv)

    report = audit_route_deliverable(
        args.bundle,
        load_golden_fixture(args.golden),
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        result = "PASS" if report.passed else "FAIL"
        print(
            f"{result}: {report.checked_shelves} shelves, "
            f"{report.checked_spans} spans, "
            f"{report.checked_hashes} hashes, "
            f"{report.checked_cli_files} CLI candidates"
        )
        for finding in report.findings:
            print(
                f"{finding.severity.upper()} {finding.code} "
                f"{finding.field}: {finding.message}"
            )
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
