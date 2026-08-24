"""Release-scoped Doc Search filters for Ciena RLS.

The corpus holds both R4.0 and R4.2 manuals. ATLAS generates configuration only for
R4.0, so an operator must be able to pin the release — otherwise a question about the
supported release can be answered with verbatim CLI from the rejected one.

Filters match case-insensitive substrings against the *filename* (see
DocIndex.search's doc_filter), so these tests work off representative names rather
than requiring the real index.
"""
from __future__ import annotations

import pytest

from utils.ai.assistant import PLATFORM_CHOICES

R40_DOCS = [
    "323-2051-101_(RLS_R4.0_OAM_Communications)_Issue2.pdf",
    "323-2051-190_(RLS_R4.0_CLI_Reference)_Issue1.pdf",
    "323-2051-310_(RLS_R4.0_Equip_Facility_Protect)_Issue4.pdf",
    "6500_RLS_R4.0_RN_Issue3.pdf",
    "NTRN10WA_(RLS_R4.0_Planning_Guide)_Issue3.pdf",
    # the upgrade procedures carry a three-part release, R4.0.0
    "NTRN38WA.1_(6500_RLS_R4.0.0_Software_Upgrade_Procedure)_Issue2.pdf",
    "NTRN38WA.2_(6500_RLS_R4.0.0_Software_Upgrade_Procedure)_Issue2.pdf",
]

R42_DOCS = [
    "323-2051-013_(6500_RLS_R4.2_Release_Notes)_Issue1.pdf",
    "323-2051-190_(RLS_R4.2_CLI_Reference)_Issue1.pdf",
    "323-2051-201_(RLS_R4.2_Installation_Guide)_Issue 1.pdf",
    # this one omits the "R" -- the reason the R4.2 filter needs two substrings
    "323-2051-310_(RLS_4.2_Equip_Facility_Protect)_Issue1.pdf",
    "NTRN10WE_(RLS_R4.2_Planning_Guide)_Issue1.pdf",
]


def _filter_for(label: str):
    for name, subs in PLATFORM_CHOICES:
        if name == label:
            return subs
    raise AssertionError(f"{label!r} missing from PLATFORM_CHOICES")


def _matches(subs, doc_name: str) -> bool:
    """Mirror DocIndex.search: case-insensitive substring against the filename."""
    return any(s.lower() in doc_name.lower() for s in subs)


def test_release_scoped_choices_exist():
    labels = [label for label, _ in PLATFORM_CHOICES]
    assert "Ciena RLS R4.0" in labels
    assert "Ciena RLS R4.2" in labels
    # the release-agnostic entry stays, for deliberate cross-release searching
    assert "Ciena RLS" in labels


@pytest.mark.parametrize("doc", R40_DOCS)
def test_r40_filter_selects_r40_docs(doc):
    assert _matches(_filter_for("Ciena RLS R4.0"), doc)


@pytest.mark.parametrize("doc", R42_DOCS)
def test_r42_filter_selects_r42_docs(doc):
    assert _matches(_filter_for("Ciena RLS R4.2"), doc)


@pytest.mark.parametrize("doc", R42_DOCS)
def test_r40_filter_excludes_r42_docs(doc):
    """The whole point: R4.0 scoping must never surface R4.2 text."""
    assert not _matches(_filter_for("Ciena RLS R4.0"), doc)


@pytest.mark.parametrize("doc", R40_DOCS)
def test_r42_filter_excludes_r40_docs(doc):
    assert not _matches(_filter_for("Ciena RLS R4.2"), doc)


def test_the_release_filters_do_not_overlap():
    r40, r42 = _filter_for("Ciena RLS R4.0"), _filter_for("Ciena RLS R4.2")
    for doc in R40_DOCS + R42_DOCS:
        assert not (_matches(r40, doc) and _matches(r42, doc)), f"{doc} matched both"


def test_generic_rls_filter_still_covers_both_releases():
    generic = _filter_for("Ciena RLS")
    for doc in R40_DOCS + R42_DOCS:
        assert _matches(generic, doc)


def test_r42_filter_needs_both_spellings():
    """323-2051-310 omits the R, so a single 'RLS_R4.2' substring would miss it."""
    odd_one_out = "323-2051-310_(RLS_4.2_Equip_Facility_Protect)_Issue1.pdf"
    assert not _matches(["RLS_R4.2"], odd_one_out)
    assert _matches(_filter_for("Ciena RLS R4.2"), odd_one_out)


def test_release_filters_do_not_catch_other_platforms():
    unrelated = [
        "323-1851-190_(6500_R16.9_TL1)_Issue1.pdf",
        "3KC71311QAAATHZZA_Vol1_1830_PSS_Release_23.6_CLI_Guide.pdf",
        "323-1955-691_saos_10-11-02_mib_reference_rev_a.pdf",
    ]
    for label in ("Ciena RLS R4.0", "Ciena RLS R4.2"):
        for doc in unrelated:
            assert not _matches(_filter_for(label), doc), f"{label} wrongly matched {doc}"
