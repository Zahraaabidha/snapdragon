"""Deterministic secret / credential detector.

Recognises a small, high-signal set of synthetic secret shapes in the text
fields of a :class:`~contextfence.core.models.event.SecurityEvent`, plus two
signals that do not depend on matching a literal value: a resource path that
names a well-known credential file, and an adapter-declared
``data_classification`` of ``CREDENTIAL`` / ``SECRET``.

This is intentionally *not* an exhaustive secret scanner (ARCHITECTURE.md §3.3,
SECURITY.md §9: detection is imperfect by design). It never returns a decision
and never places a matched value -- or any substring of one -- into evidence
metadata; only structural facts (length, character classes, a truncated
fingerprint, match offset) are recorded.
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

__all__ = ["SecretDetector", "credential_path_rule"]

_NAMESPACE = "SECRET"

# Placeholder values that a CREDENTIAL_ASSIGNMENT match should be ignored for.
_PLACEHOLDERS = frozenset(
    {
        "changeme",
        "example",
        "none",
        "null",
        "placeholder",
        "redacted",
        "secret",
        "todo",
        "true",
        "false",
        "xxxxxxxx",
        "your_api_key",
        "your_token",
    }
)


@dataclass(frozen=True)
class _ContentRule:
    rule_id: str
    pattern: re.Pattern[str]
    severity: Severity
    confidence: float
    #: regex group holding the sensitive portion to fingerprint (0 = whole match)
    value_group: int = 0


_CONTENT_RULES: tuple[_ContentRule, ...] = (
    _ContentRule(
        rule_id="SECRET.PRIVATE_KEY_BLOCK",
        pattern=re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        ),
        severity=Severity.CRITICAL,
        confidence=0.98,
    ),
    _ContentRule(
        rule_id="SECRET.AWS_ACCESS_KEY_ID",
        pattern=re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|AIPA)[A-Z2-7]{16}\b"),
        severity=Severity.CRITICAL,
        confidence=0.9,
    ),
    _ContentRule(
        rule_id="SECRET.JWT",
        pattern=re.compile(
            r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
        ),
        severity=Severity.HIGH,
        confidence=0.85,
    ),
    _ContentRule(
        rule_id="SECRET.BEARER_TOKEN",
        pattern=re.compile(r"(?i)\bbearer\s+(?P<tok>[A-Za-z0-9._~+/=-]{16,})"),
        severity=Severity.HIGH,
        confidence=0.75,
        value_group=1,
    ),
)

_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?P<key>api[_-]?key|access[_-]?token|client[_-]?secret|secret[_-]?key|"
    r"auth[_-]?token|api[_-]?secret|password|passwd|token|secret)\b"
    r"\s*[:=]\s*(?P<q>[\"'`]?)(?P<val>[^\s\"'`]{8,})(?P=q)"
)

# Basenames / path fragments that denote a credential-bearing file.
_CREDENTIAL_PATH_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("SECRET.CREDENTIAL_FILE.DOTENV", re.compile(r"(?:^|[\\/])\.env(?:\.[\w.-]+)?$")),
    (
        "SECRET.CREDENTIAL_FILE.PRIVATE_KEY",
        re.compile(r"(?:^|[\\/])id_(?:rsa|dsa|ecdsa|ed25519)$"),
    ),
    (
        "SECRET.CREDENTIAL_FILE.KEY_MATERIAL",
        re.compile(r"\.(?:pem|pfx|p12|key|keystore|jks)$", re.IGNORECASE),
    ),
    (
        "SECRET.CREDENTIAL_FILE.CLOUD_CREDENTIALS",
        re.compile(r"(?:^|[\\/])\.aws[\\/]credentials$"),
    ),
    (
        "SECRET.CREDENTIAL_FILE.DOTFILE",
        re.compile(r"(?:^|[\\/])\.(?:npmrc|pgpass|netrc)$"),
    ),
)


def credential_path_rule(resource: str) -> str | None:
    """Return the rule id if ``resource`` names a known credential file, else None."""

    for rule_id, pattern in _CREDENTIAL_PATH_RULES:
        if pattern.search(resource):
            return rule_id
    return None


def _looks_like_placeholder(value: str) -> bool:
    low = value.lower()
    if low in _PLACEHOLDERS:
        return True
    if re.fullmatch(r"[*x.\-_ ]+", value):
        return True
    if re.fullmatch(r"[<${].*[>}]", value):
        return True
    return low.startswith(("your_", "example", "changeme", "<", "${"))


def _assignment_confidence(value: str) -> float | None:
    if _looks_like_placeholder(value):
        return None
    classes = sum(
        (
            any(c.islower() for c in value),
            any(c.isupper() for c in value),
            any(c.isdigit() for c in value),
            any(not c.isalnum() for c in value),
        )
    )
    if classes < 2:
        return None
    return 0.6 if len(value) >= 12 else 0.45


class SecretDetector:
    """Deterministic secret / credential evidence producer."""

    namespace: str = _NAMESPACE
    source: EvidenceSource = EvidenceSource.SECRET_DETECTOR
    primary_category: EvidenceCategory = EvidenceCategory.CREDENTIAL

    def analyze(self, event: SecurityEvent) -> tuple[Evidence, ...]:
        findings: list[Evidence] = []

        for field, text in iter_text_fields(event):
            findings.extend(self._scan_text(field, text))

        path_rule = credential_path_rule(event.resource)
        if path_rule is not None:
            findings.append(
                self._evidence(
                    rule_id=path_rule,
                    severity=Severity.HIGH,
                    confidence=0.7,
                    metadata={"matched_field": "resource"},
                )
            )

        classification = event.data_classification
        if classification in (DataClassification.CREDENTIAL, DataClassification.SECRET):
            findings.append(
                self._evidence(
                    rule_id="SECRET.DECLARED_CLASSIFICATION",
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    metadata={"signal": f"data_classification={classification.value}"},
                )
            )

        return tuple(findings)

    def _scan_text(self, field: str, text: str) -> list[Evidence]:
        out: list[Evidence] = []
        for rule in _CONTENT_RULES:
            for match in rule.pattern.finditer(text):
                secret_part = (
                    match.group(rule.value_group)
                    if rule.value_group
                    else match.group(0)
                )
                meta = span_metadata(
                    field=field, start=match.start(), length=len(match.group(0))
                )
                meta.update(value_metadata(secret_part or "", prefix="secret"))
                out.append(
                    self._evidence(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        metadata=meta,
                    )
                )

        for match in _ASSIGNMENT_RE.finditer(text):
            value = match.group("val")
            confidence = _assignment_confidence(value)
            if confidence is None:
                continue
            meta = span_metadata(
                field=field, start=match.start(), length=len(match.group(0))
            )
            meta.update(value_metadata(value, prefix="secret"))
            meta["assigned_name_kind"] = "credential-like-identifier"
            out.append(
                self._evidence(
                    rule_id="SECRET.CREDENTIAL_ASSIGNMENT",
                    severity=Severity.HIGH,
                    confidence=confidence,
                    metadata=meta,
                )
            )
        return out

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
