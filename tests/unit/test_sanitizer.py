"""Phase 5: deterministic local sanitization."""

from __future__ import annotations

import pytest

from contextfence.core.models.enums import EvidenceCategory, EvidenceSource, Severity
from contextfence.core.models.evidence import Evidence
from contextfence.enforcement.sanitizer import (
    SUPPORTED_RULE_IDS,
    SanitizeFinding,
    findings_from_evidence,
    sanitize_text,
)

# --- synthetic, non-real test values ------------------------------------
EMAIL = "alex.doe@synthetic.invalid"
PHONE = "+1 (555) 010-1234"
CARD = "4111 1111 1111 1111"  # documented Visa test PAN (passes Luhn)
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # AWS-documented example id


def _finding(
    rule_id: str,
    start: int,
    length: int,
    category: EvidenceCategory = EvidenceCategory.PERSONAL_DATA,
) -> SanitizeFinding:
    return SanitizeFinding(
        rule_id=rule_id, category=category, start=start, length=length
    )


def _locate(text: str, needle: str, rule_id: str) -> SanitizeFinding:
    start = text.index(needle)
    return _finding(rule_id, start, len(needle))


# --- original never mutated / never leaked ----------------------------


def test_original_input_is_unchanged() -> None:
    text = f"contact {EMAIL} today"
    original_copy = str(text)
    result = sanitize_text(text, [_locate(text, EMAIL, "PII.EMAIL")])
    assert result.ok
    assert text == original_copy
    assert result.sanitized_text != text
    assert result.sanitized_text is not text


def test_sanitized_text_never_contains_the_original_value() -> None:
    text = f"{EMAIL} / {PHONE} / {CARD}"
    result = sanitize_text(
        text,
        [
            _locate(text, EMAIL, "PII.EMAIL"),
            _locate(text, PHONE, "PII.PHONE_NUMBER"),
            _locate(text, CARD, "PII.PAYMENT_CARD"),
        ],
    )
    assert result.ok and result.sanitized_text is not None
    for value in (EMAIL, PHONE, CARD, "4111", "555"):
        assert value not in result.sanitized_text


def test_summary_holds_no_original_substring_only_structural_metadata() -> None:
    text = f"mail {EMAIL} end"
    result = sanitize_text(text, [_locate(text, EMAIL, "PII.EMAIL")])
    assert result.ok
    for span in result.summary.applied:
        blob = " ".join(
            [
                span.marker,
                span.original_charset,
                span.original_fingerprint,
                str(span.original_length),
                *span.rule_ids,
            ]
        )
        assert EMAIL not in blob
        assert "alex" not in blob
        assert span.original_fingerprint.startswith("sha256:")


# --- supported categories ------------------------------------------------


@pytest.mark.parametrize(
    "value, rule_id",
    [(EMAIL, "PII.EMAIL"), (PHONE, "PII.PHONE_NUMBER"), (CARD, "PII.PAYMENT_CARD")],
)
def test_supported_pii_values_are_sanitized(value: str, rule_id: str) -> None:
    text = f"before {value} after"
    result = sanitize_text(text, [_locate(text, value, rule_id)])
    assert result.ok
    assert result.sanitized_text == f"before [REDACTED:{rule_id}] after"
    assert value not in (result.sanitized_text or "")


def test_supported_rule_ids_are_exactly_the_pii_set() -> None:
    assert {"PII.EMAIL", "PII.PHONE_NUMBER", "PII.PAYMENT_CARD"} == SUPPORTED_RULE_IDS


# --- multiple findings, surrounding text intact -----------------------


def test_multiple_findings_and_surrounding_text_preserved() -> None:
    text = f"Hi {EMAIL}, please call {PHONE}. Regards."
    result = sanitize_text(
        text,
        [
            _locate(text, EMAIL, "PII.EMAIL"),
            _locate(text, PHONE, "PII.PHONE_NUMBER"),
        ],
    )
    assert result.ok
    assert result.sanitized_text == (
        "Hi [REDACTED:PII.EMAIL], please call [REDACTED:PII.PHONE_NUMBER]. Regards."
    )
    assert result.summary.sanitized_span_count == 2


def test_repeated_value_gets_a_stable_marker() -> None:
    text = f"{EMAIL} ... {EMAIL}"
    result = sanitize_text(
        text,
        [
            _finding("PII.EMAIL", 0, len(EMAIL)),
            _finding("PII.EMAIL", text.rindex(EMAIL), len(EMAIL)),
        ],
    )
    assert result.ok
    assert result.sanitized_text == "[REDACTED:PII.EMAIL] ... [REDACTED:PII.EMAIL]"


# --- overlapping findings --------------------------------------------


def test_overlapping_findings_are_merged_without_leaking_the_tail() -> None:
    text = f"x{EMAIL}y"
    # two findings that overlap: [1, 1+len) and [5, 1+len)
    findings = [
        _finding("PII.EMAIL", 1, len(EMAIL)),
        _finding("PII.PHONE_NUMBER", 5, len(EMAIL) - 4),
    ]
    result = sanitize_text(text, findings)
    assert result.ok
    assert result.sanitized_text == "x[REDACTED:PII.EMAIL+PII.PHONE_NUMBER]y"
    assert EMAIL not in (result.sanitized_text or "")
    assert result.summary.sanitized_span_count == 1


def test_adjacent_non_overlapping_findings_stay_separate() -> None:
    text = "ab@c.decd"  # not real; just spans
    findings = [_finding("PII.EMAIL", 0, 5), _finding("PII.EMAIL", 5, 4)]
    result = sanitize_text(text, findings)
    assert result.ok
    assert result.summary.sanitized_span_count == 2


# --- invalid spans / fail closed ------------------------------------


@pytest.mark.parametrize(
    "start, length",
    [(-1, 5), (0, 0), (0, -3), (100, 5), (5, 999)],
)
def test_invalid_span_fails_closed_and_cannot_leak(start: int, length: int) -> None:
    text = f"secret-ish {EMAIL} here"
    result = sanitize_text(text, [_finding("PII.EMAIL", start, length)])
    assert result.ok is False
    assert result.sanitized_text is None
    assert EMAIL not in result.failure_reason


def test_no_findings_with_sanitize_intent_fails_closed() -> None:
    result = sanitize_text("some payload", [])
    assert result.ok is False
    assert result.sanitized_text is None


def test_empty_text_with_no_findings_fails_closed_not_crash() -> None:
    result = sanitize_text("", [])
    assert result.ok is False
    assert result.sanitized_text is None


def test_empty_text_with_a_finding_fails_closed_on_span() -> None:
    result = sanitize_text("", [_finding("PII.EMAIL", 0, 3)])
    assert result.ok is False


# --- secrets stay protected ----------------------------------------


def test_credential_finding_fails_closed_and_is_never_downgraded() -> None:
    text = f"key {AWS_KEY} tail"
    result = sanitize_text(
        text,
        [
            SanitizeFinding(
                rule_id="SECRET.AWS_ACCESS_KEY_ID",
                category=EvidenceCategory.CREDENTIAL,
                start=text.index(AWS_KEY),
                length=len(AWS_KEY),
            )
        ],
    )
    assert result.ok is False
    assert result.sanitized_text is None
    assert AWS_KEY not in result.failure_reason


def test_secret_rule_id_on_a_non_credential_category_still_fails_closed() -> None:
    text = f"tok {AWS_KEY}"
    result = sanitize_text(
        text,
        [
            SanitizeFinding(
                rule_id="SECRET.BEARER_TOKEN",
                category=EvidenceCategory.PERSONAL_DATA,
                start=text.index(AWS_KEY),
                length=len(AWS_KEY),
            )
        ],
    )
    assert result.ok is False


def test_declared_classification_signal_fails_closed() -> None:
    # a non-locatable personal-data finding cannot be span-sanitized
    result = sanitize_text(
        "payload asserted to be personal data",
        [
            SanitizeFinding(
                "PII.DECLARED_CLASSIFICATION", EvidenceCategory.PERSONAL_DATA, -1, 0
            )
        ],
    )
    assert result.ok is False


def test_unsupported_pii_rule_fails_closed() -> None:
    text = "ssn 123-45-6789 here"
    result = sanitize_text(
        text,
        [SanitizeFinding("PII.SSN", EvidenceCategory.PERSONAL_DATA, 4, 11)],
    )
    assert result.ok is False


# --- findings_from_evidence -----------------------------------------


def test_findings_from_evidence_reads_phase2_span_metadata() -> None:
    evidence = [
        Evidence(
            source=EvidenceSource.PII_DETECTOR,
            category=EvidenceCategory.PERSONAL_DATA,
            severity=Severity.HIGH,
            confidence=0.9,
            metadata={
                "rule_id": "PII.EMAIL",
                "match_offset": "8",
                "match_length": "26",
            },
        ),
        Evidence(  # not a sanitizable category -> ignored
            source=EvidenceSource.DESTINATION_CLASSIFIER,
            category=EvidenceCategory.EXTERNAL_DATA_TRANSFER,
            severity=Severity.MEDIUM,
            confidence=0.8,
            metadata={"rule_id": "DESTINATION.EXTERNAL"},
        ),
    ]
    findings = findings_from_evidence(evidence)
    assert len(findings) == 1
    assert findings[0].rule_id == "PII.EMAIL"
    assert findings[0].start == 8
    assert findings[0].length == 26


def test_findings_from_evidence_marks_missing_span_as_non_locatable() -> None:
    evidence = [
        Evidence(
            source=EvidenceSource.PII_DETECTOR,
            category=EvidenceCategory.PERSONAL_DATA,
            severity=Severity.HIGH,
            confidence=0.9,
            metadata={"rule_id": "PII.DECLARED_CLASSIFICATION"},
        )
    ]
    (finding,) = findings_from_evidence(evidence)
    assert finding.locatable is False


def test_findings_from_evidence_does_not_mutate_evidence() -> None:
    ev = Evidence(
        source=EvidenceSource.PII_DETECTOR,
        category=EvidenceCategory.PERSONAL_DATA,
        severity=Severity.HIGH,
        confidence=0.9,
        metadata={"rule_id": "PII.EMAIL", "match_offset": "1", "match_length": "2"},
    )
    before = repr(ev)
    findings_from_evidence([ev])
    assert repr(ev) == before


# --- determinism -------------------------------------------------------


def test_sanitization_is_deterministic() -> None:
    text = f"a {EMAIL} b {PHONE} c"
    findings = [
        _locate(text, EMAIL, "PII.EMAIL"),
        _locate(text, PHONE, "PII.PHONE_NUMBER"),
    ]
    first = sanitize_text(text, findings)
    for _ in range(10):
        again = sanitize_text(text, list(reversed(findings)))
        assert again.sanitized_text == first.sanitized_text
