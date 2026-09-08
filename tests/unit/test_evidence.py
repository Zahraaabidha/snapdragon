"""Evidence model: construction, confidence bounds, severity/confidence split."""

from __future__ import annotations

import dataclasses

import pytest

from contextfence.core.errors import ValidationError
from contextfence.core.models.enums import EvidenceCategory, EvidenceSource, Severity
from contextfence.core.models.evidence import Evidence


def make_evidence(**overrides: object) -> Evidence:
    params: dict[str, object] = {
        "source": EvidenceSource.SECRET_DETECTOR,
        "category": EvidenceCategory.CREDENTIAL,
        "severity": Severity.CRITICAL,
        "confidence": 0.99,
    }
    params.update(overrides)
    return Evidence(**params)  # type: ignore[arg-type]


def test_valid_construction() -> None:
    ev = make_evidence(metadata={"match_offset": "12", "note": "synthetic"})
    assert ev.source is EvidenceSource.SECRET_DETECTOR
    assert ev.category is EvidenceCategory.CREDENTIAL
    assert ev.severity is Severity.CRITICAL
    assert ev.confidence == pytest.approx(0.99)
    assert ev.metadata["match_offset"] == "12"


def test_evidence_is_frozen() -> None:
    ev = make_evidence()
    with pytest.raises(dataclasses.FrozenInstanceError):
        ev.confidence = 0.1  # type: ignore[misc]


def test_metadata_is_read_only() -> None:
    ev = make_evidence(metadata={"k": "v"})
    with pytest.raises(TypeError):
        ev.metadata["k"] = "other"  # type: ignore[index]


def test_default_metadata_is_empty_mapping() -> None:
    assert dict(make_evidence().metadata) == {}


@pytest.mark.parametrize("bad", [-0.01, 1.01, 2.0, -1.0, float("nan"), float("inf")])
def test_confidence_out_of_range_or_non_finite_is_rejected(bad: float) -> None:
    with pytest.raises(ValidationError):
        make_evidence(confidence=bad)


@pytest.mark.parametrize("bad", [True, False, "0.9", None, Severity.HIGH])
def test_confidence_must_be_a_real_number(bad: object) -> None:
    with pytest.raises(ValidationError):
        make_evidence(confidence=bad)


def test_confidence_accepts_bounds_and_ints() -> None:
    assert make_evidence(confidence=0).confidence == 0.0
    assert make_evidence(confidence=1).confidence == 1.0


def test_severity_must_be_enum_not_string_or_number() -> None:
    with pytest.raises(ValidationError):
        make_evidence(severity="CRITICAL")
    with pytest.raises(ValidationError):
        make_evidence(severity=0.99)


def test_severity_and_confidence_are_independent_axes() -> None:
    # Same severity, very different confidence -- both representable.
    high_conf = make_evidence(severity=Severity.CRITICAL, confidence=0.99)
    low_conf = make_evidence(severity=Severity.CRITICAL, confidence=0.10)
    assert high_conf.severity is low_conf.severity
    assert high_conf.confidence != low_conf.confidence

    # Low impact but certain, and high impact but unsure -- both representable.
    assert (
        make_evidence(severity=Severity.LOW, confidence=0.99).severity is Severity.LOW
    )
    critical_unsure = make_evidence(severity=Severity.CRITICAL, confidence=0.05)
    assert critical_unsure.severity is Severity.CRITICAL
    assert critical_unsure.confidence == pytest.approx(0.05)


def test_passing_severity_as_confidence_and_vice_versa_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Evidence(
            source=EvidenceSource.SECRET_DETECTOR,
            category=EvidenceCategory.CREDENTIAL,
            severity=0.9,  # type: ignore[arg-type]
            confidence=Severity.CRITICAL,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("bad_meta", [{"k": 1}, {1: "v"}, {"k": None}, "notamap", 5])
def test_metadata_must_be_str_to_str_mapping(bad_meta: object) -> None:
    with pytest.raises(ValidationError):
        make_evidence(metadata=bad_meta)
