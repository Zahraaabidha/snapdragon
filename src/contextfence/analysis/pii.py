"""Deterministic PII detector.

A conservative set of high-precision patterns (email, structured phone number,
Luhn-valid payment card) over the event's text fields, plus the
adapter-declared ``data_classification`` of ``PERSONAL_DATA`` / ``REGULATED``.

Aggressive/generalised matching is deliberately avoided to keep the
false-positive rate low (task brief; SECURITY.md §9). Evidence only -- never a
decision, and never the matched value in metadata.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from contextfence.analysis.detector import iter_text_fields
from contextfence.analysis.redaction import span_metadata, value_metadata
from contextfence.core.models.enums import (
    DataClassification,
    EvidenceCategory,
    EvidenceSource,
    Severity,
)
from contextfence.core.models.event import SecurityEvent
from contextfence.core.models.evidence import Evidence

__all__ = ["PiiDetector"]

_NAMESPACE = "PII"

_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}\b"
)

# Phone: require some structure (a separator or an explicit country code) so bare
# digit runs, dotted-quad IPs and dates do not match.
_PHONE_RE = re.compile(
    r"(?<![\w.])"
    r"(?:\+\d{1,3}[ .\-]?)?"
    r"(?:\(\d{3}\)|\d{3})"
    r"[ .\-]"
    r"\d{3}"
    r"[ .\-]?"
    r"\d{4}"
    r"(?![\w])"
)
_PHONE_INTL_RE = re.compile(r"(?<![\w.])\+\d{2}[ .\-]?\d(?:[ .\-]?\d){7,12}(?![\w])")

_CARD_CANDIDATE_RE = re.compile(r"(?<![\w])(?:\d[ \-]?){12,18}\d(?![\w])")


@dataclass(frozen=True)
class _TextRule:
    rule_id: str
    pattern: re.Pattern[str]
    severity: Severity
    confidence: float


_TEXT_RULES: tuple[_TextRule, ...] = (
    _TextRule("PII.EMAIL", _EMAIL_RE, Severity.HIGH, 0.9),
    _TextRule("PII.PHONE_NUMBER", _PHONE_RE, Severity.HIGH, 0.55),
    _TextRule("PII.PHONE_NUMBER", _PHONE_INTL_RE, Severity.HIGH, 0.55),
)


def _luhn_ok(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = ord(char) - 48
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


class PiiDetector:
    """Deterministic personal-data evidence producer."""

    namespace: str = _NAMESPACE
    source: EvidenceSource = EvidenceSource.PII_DETECTOR
    primary_category: EvidenceCategory = EvidenceCategory.PERSONAL_DATA

    def analyze(self, event: SecurityEvent) -> tuple[Evidence, ...]:
        findings: list[Evidence] = []

        for field, text in iter_text_fields(event):
            findings.extend(self._scan_text(field, text))

        classification = event.data_classification
        if classification in (
            DataClassification.PERSONAL_DATA,
            DataClassification.REGULATED,
        ):
            findings.append(
                self._evidence(
                    rule_id="PII.DECLARED_CLASSIFICATION",
                    severity=Severity.HIGH,
                    confidence=0.9,
                    metadata={"signal": f"data_classification={classification.value}"},
                )
            )

        return tuple(findings)

    def _scan_text(self, field: str, text: str) -> list[Evidence]:
        out: list[Evidence] = []
        for rule in _TEXT_RULES:
            for match in rule.pattern.finditer(text):
                out.append(
                    self._match_evidence(
                        rule.rule_id, rule.severity, rule.confidence, field, match
                    )
                )
        for match in _CARD_CANDIDATE_RE.finditer(text):
            digits = re.sub(r"\D", "", match.group(0))
            if len(digits) < 13 or len(digits) > 19 or not _luhn_ok(digits):
                continue
            out.append(
                self._match_evidence(
                    "PII.PAYMENT_CARD", Severity.HIGH, 0.8, field, match
                )
            )
        return out

    def _match_evidence(
        self,
        rule_id: str,
        severity: Severity,
        confidence: float,
        field: str,
        match: re.Match[str],
    ) -> Evidence:
        meta = span_metadata(
            field=field, start=match.start(), length=len(match.group(0))
        )
        meta.update(value_metadata(match.group(0), prefix="pii"))
        return self._evidence(
            rule_id=rule_id, severity=severity, confidence=confidence, metadata=meta
        )

    def _evidence(
        self,
        *,
        rule_id: str,
        severity: Severity,
        confidence: float,
        metadata: dict[str, str],
    ) -> Evidence:
        return Evidence(
            source=self.source,
            category=self.primary_category,
            severity=severity,
            confidence=confidence,
            metadata={"rule_id": rule_id, **metadata},
        )
