"""PiiDetector: conservative synthetic PII patterns, no value leakage."""

from __future__ import annotations

import pytest

from contextfence.analysis.pii import PiiDetector
from contextfence.core.models.decision import Decision
from contextfence.core.models.enums import (
    DataClassification,
    EvidenceCategory,
    EvidenceSource,
    Severity,
)
from contextfence.core.models.evidence import Evidence
from tests.unit._factories import valid_event

EMAIL = "alex.doe@synthetic.invalid"
PHONE_NANP = "555-010-1234"
PHONE_INTL = "+44 20 7946 0958"
CARD_LUHN_OK = "4111 1111 1111 1111"  # documented Visa test PAN (passes Luhn)
CARD_LUHN_BAD = "1234 5678 9012 3456"


def _analyze(**overrides: object) -> tuple[Evidence, ...]:
    return PiiDetector().analyze(valid_event(**overrides))


@pytest.mark.parametrize(
    "text, rule",
    [
        (f"contact {EMAIL} please", "PII.EMAIL"),
        (f"call {PHONE_NANP}", "PII.PHONE_NUMBER"),
        (f"intl {PHONE_INTL}", "PII.PHONE_NUMBER"),
        (f"card {CARD_LUHN_OK}", "PII.PAYMENT_CARD"),
    ],
)
def test_detects_supported_synthetic_pii(text: str, rule: str) -> None:
    findings = _analyze(resource=text)
    assert rule in {e.metadata["rule_id"] for e in findings}
    for e in findings:
        assert e.source is EvidenceSource.PII_DETECTOR
        assert e.category is EvidenceCategory.PERSONAL_DATA
        assert e.severity is Severity.HIGH


def test_declared_personal_data_classification_is_flagged() -> None:
    findings = _analyze(data_classification=DataClassification.REGULATED)
    assert "PII.DECLARED_CLASSIFICATION" in {e.metadata["rule_id"] for e in findings}


def test_avoids_obvious_false_positives() -> None:
    assert _analyze(resource="192.168.10.11") == ()  # dotted quad
    assert _analyze(resource="build 2026-01-02 ok") == ()  # date
    assert _analyze(resource="order 9876543210 shipped") == ()  # bare digit run
    assert _analyze(resource="version 10.20.30.40") == ()  # version string
    assert _analyze(resource=f"luhn-fail {CARD_LUHN_BAD}") == ()
    assert _analyze(resource="email us at support (no address here)") == ()


def test_pii_value_never_appears_in_metadata() -> None:
    findings = _analyze(resource=f"{EMAIL} {PHONE_NANP} {CARD_LUHN_OK}")
    assert findings
    for e in findings:
        blob = " ".join(e.metadata.values())
        for literal in (EMAIL, PHONE_NANP, "4111", "1111111111111111"):
            assert literal not in blob


def test_returns_evidence_not_decision() -> None:
    for e in _analyze(resource=EMAIL):
        assert isinstance(e, Evidence)
        assert not isinstance(e, Decision)


def test_input_event_is_not_mutated() -> None:
    event = valid_event(resource=f"{EMAIL} {CARD_LUHN_OK}")
    snapshot = repr(event)
    PiiDetector().analyze(event)
    assert repr(event) == snapshot
