"""RiskView model: construction, consistency rules, no scalar risk score."""

from __future__ import annotations

import dataclasses

import pytest

from contextfence.core.errors import ValidationError
from contextfence.core.models.enums import EvidenceCategory, Severity
from contextfence.core.models.risk import RiskView


def test_empty_risk_view_is_valid() -> None:
    rv = RiskView(highest_severity=None)
    assert rv.highest_severity is None
    assert rv.categories == frozenset()
    assert dict(rv.category_confidence) == {}
    assert rv.semantic_evidence_available is False
    assert rv.evidence_count == 0


def test_valid_populated_risk_view() -> None:
    rv = RiskView(
        highest_severity=Severity.HIGH,
        categories=frozenset(
            {EvidenceCategory.PERSONAL_DATA, EvidenceCategory.EXTERNAL_DATA_TRANSFER}
        ),
        category_confidence={
            EvidenceCategory.PERSONAL_DATA: 0.97,
            EvidenceCategory.EXTERNAL_DATA_TRANSFER: 0.80,
        },
        semantic_evidence_available=True,
        evidence_count=2,
    )
    assert rv.highest_severity is Severity.HIGH
    assert EvidenceCategory.PERSONAL_DATA in rv.categories
    assert rv.category_confidence[EvidenceCategory.PERSONAL_DATA] == pytest.approx(0.97)


def test_risk_view_is_frozen() -> None:
    rv = RiskView(highest_severity=None)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rv.evidence_count = 5  # type: ignore[misc]


def test_risk_view_has_no_scalar_risk_score() -> None:
    # ARCHITECTURE.md §3.4 / §7: severity and confidence stay separate; there is
    # deliberately no single collapsed "score".
    rv = RiskView(highest_severity=None)
    for forbidden in ("risk_score", "score", "risk_level", "combined"):
        assert not hasattr(rv, forbidden)


def test_category_present_requires_highest_severity() -> None:
    with pytest.raises(ValidationError):
        RiskView(
            highest_severity=None,
            categories=frozenset({EvidenceCategory.CREDENTIAL}),
            category_confidence={EvidenceCategory.CREDENTIAL: 0.9},
            evidence_count=1,
        )


def test_category_confidence_keys_must_be_subset_of_categories() -> None:
    with pytest.raises(ValidationError):
        RiskView(
            highest_severity=Severity.LOW,
            categories=frozenset({EvidenceCategory.CREDENTIAL}),
            category_confidence={EvidenceCategory.PERSONAL_DATA: 0.5},
            evidence_count=1,
        )


@pytest.mark.parametrize("bad", [-0.1, 1.5, float("nan"), True, "0.5"])
def test_category_confidence_values_are_validated(bad: object) -> None:
    with pytest.raises(ValidationError):
        RiskView(
            highest_severity=Severity.LOW,
            categories=frozenset({EvidenceCategory.CREDENTIAL}),
            category_confidence={EvidenceCategory.CREDENTIAL: bad},  # type: ignore[dict-item]
            evidence_count=1,
        )


def test_semantic_flag_must_be_bool() -> None:
    with pytest.raises(ValidationError):
        RiskView(highest_severity=None, semantic_evidence_available=1)  # type: ignore[arg-type]


def test_evidence_count_must_be_non_negative_int() -> None:
    with pytest.raises(ValidationError):
        RiskView(highest_severity=None, evidence_count=-1)
    with pytest.raises(ValidationError):
        # bool is statically an int subtype; the runtime guard still rejects it.
        RiskView(highest_severity=None, evidence_count=True)


def test_highest_severity_must_be_enum() -> None:
    with pytest.raises(ValidationError):
        RiskView(highest_severity="HIGH")  # type: ignore[arg-type]
