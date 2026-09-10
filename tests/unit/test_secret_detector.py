"""SecretDetector: synthetic secret shapes only, no value leakage."""

from __future__ import annotations

import pytest

from contextfence.analysis.secrets import SecretDetector
from contextfence.core.models.decision import Decision
from contextfence.core.models.enums import (
    DataClassification,
    EvidenceCategory,
    EvidenceSource,
    Severity,
)
from contextfence.core.models.evidence import Evidence
from tests.unit._factories import valid_event

# --- synthetic, non-functional test values --------------------------------
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # AWS-documented example id
JWT = (
    "eyJhbGciOiJIUzI1NiJ9."
    "eyJzdWIiOiJzeW50aGV0aWMiLCJuIjoxfQ."
    "c3ludGhldGljLXNpZ25hdHVyZS12YWx1ZQ"
)
PRIVATE_KEY_HEADER = "-----BEGIN RSA PRIVATE KEY-----"
BEARER = "Bearer synthetic-tok-abcdefghij0123456789"
ASSIGNMENT = 'api_key = "sk_test_SYNTHETIC_abc123DEF456ghi"'

_ALL_SECRET_LITERALS = [
    AWS_KEY,
    JWT,
    "synthetic-tok-abcdefghij0123456789",
    "sk_test_SYNTHETIC_abc123DEF456ghi",
]


def _analyze(**overrides: object) -> tuple[Evidence, ...]:
    return SecretDetector().analyze(valid_event(**overrides))


@pytest.mark.parametrize(
    "text, expected_rule",
    [
        (AWS_KEY, "SECRET.AWS_ACCESS_KEY_ID"),
        (JWT, "SECRET.JWT"),
        (f"header {PRIVATE_KEY_HEADER} body", "SECRET.PRIVATE_KEY_BLOCK"),
        (f"Authorization: {BEARER}", "SECRET.BEARER_TOKEN"),
        (ASSIGNMENT, "SECRET.CREDENTIAL_ASSIGNMENT"),
    ],
)
def test_detects_supported_synthetic_secret_shapes(
    text: str, expected_rule: str
) -> None:
    findings = _analyze(resource=text)
    rules = {e.metadata["rule_id"] for e in findings}
    assert expected_rule in rules
    for e in findings:
        assert isinstance(e, Evidence)
        assert e.source is EvidenceSource.SECRET_DETECTOR
        assert e.category is EvidenceCategory.CREDENTIAL


def test_credential_file_path_is_flagged_without_a_literal_secret() -> None:
    findings = _analyze(resource="repo/config/.env")
    assert any(
        e.metadata["rule_id"].startswith("SECRET.CREDENTIAL_FILE") for e in findings
    )


def test_declared_credential_classification_is_flagged() -> None:
    findings = _analyze(data_classification=DataClassification.CREDENTIAL)
    marker = next(
        e for e in findings if e.metadata["rule_id"] == "SECRET.DECLARED_CLASSIFICATION"
    )
    assert marker.severity is Severity.CRITICAL
    assert "CREDENTIAL" in marker.metadata["signal"]


def test_secret_value_never_appears_in_evidence_metadata() -> None:
    findings = _analyze(
        resource=f"{AWS_KEY} {JWT} {PRIVATE_KEY_HEADER} {ASSIGNMENT}",
        destination=f"https://x.invalid/?a={BEARER}",
    )
    assert findings
    for e in findings:
        blob = " ".join(e.metadata.values())
        for literal in _ALL_SECRET_LITERALS:
            assert literal not in blob
            assert literal.lower() not in blob.lower()


def test_ordinary_safe_text_produces_no_evidence() -> None:
    assert _analyze(resource="src/contextfence/core/models/event.py") == ()
    assert _analyze(resource="notes about the parser refactor") == ()
    # placeholder assignments are ignored
    assert _analyze(resource='password = "changeme"') == ()
    assert _analyze(resource="password = your_password_here") == ()
    assert _analyze(resource="the password field is required") == ()


def test_returns_evidence_not_decision() -> None:
    for e in _analyze(resource=AWS_KEY):
        assert isinstance(e, Evidence)
        assert not isinstance(e, Decision)


def test_severity_and_confidence_are_separate_values() -> None:
    (evidence, *_rest) = _analyze(resource=PRIVATE_KEY_HEADER)
    assert isinstance(evidence.severity, Severity)
    assert isinstance(evidence.confidence, float)
    assert 0.0 <= evidence.confidence <= 1.0


def test_input_event_is_not_mutated() -> None:
    event = valid_event(resource=f"{AWS_KEY} {ASSIGNMENT}")
    snapshot = repr(event)
    SecretDetector().analyze(event)
    SecretDetector().analyze(event)
    assert repr(event) == snapshot
    assert event.requested_capabilities == ("fs.read",)
