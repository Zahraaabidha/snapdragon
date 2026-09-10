"""Deterministic destination detector.

Looks at ``event.destination`` together with ``event.action`` and
``event.data_classification`` and produces evidence when the destination is
security-relevant: it is external, it is in an unsupported/malformed form, or an
egress action names no destination at all. Purely local destinations
(loopback, private ranges, ``*.local``, ``file:`` URLs, filesystem paths)
produce no evidence.

This is classification evidence, not a decision -- whether an external transfer
is allowed, blocked, or must be approved is the Policy Engine's call (Phase 4).
All findings use the closed :class:`EvidenceCategory.EXTERNAL_DATA_TRANSFER`
category (docs/DECISIONS.md D-0002); the specific rule id distinguishes the
cases.
"""

from __future__ import annotations

import ipaddress
from enum import StrEnum
from urllib.parse import urlsplit

from contextfence.analysis.redaction import fingerprint
from contextfence.core.models.enums import (
    ActionType,
    DataClassification,
    EvidenceCategory,
    EvidenceSource,
    Severity,
)
from contextfence.core.models.event import SecurityEvent
from contextfence.core.models.evidence import Evidence

__all__ = ["DestinationDetector"]

_NAMESPACE = "DESTINATION"

_SENSITIVE = frozenset(
    {
        DataClassification.PERSONAL_DATA,
        DataClassification.CREDENTIAL,
        DataClassification.SECRET,
        DataClassification.REGULATED,
    }
)
_LOCAL_SCHEMES = frozenset({"", "file"})
_NETWORK_SCHEMES = frozenset(
    {"http", "https", "ftp", "ftps", "ws", "wss", "ssh", "sftp", "smtp", "smtps"}
)


class _Kind(StrEnum):
    LOCAL = "LOCAL"
    EXTERNAL = "EXTERNAL"
    MALFORMED = "MALFORMED"


def _looks_like_path(raw: str) -> bool:
    return (
        raw.startswith(("/", "./", "../", "~/", "\\\\"))
        or raw in (".", "..", "~")
        or bool(len(raw) >= 3 and raw[1] == ":" and raw[2] in "\\/")  # C:\ or C:/
    )


def _host_is_local(host: str) -> bool:
    host = host.strip("[]").lower()
    if not host:
        return False  # empty host is unknown, not local
    if host == "localhost" or host.endswith((".localhost", ".local")):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_unspecified


def _classify(raw: str) -> tuple[_Kind, str, str]:
    """Return ``(kind, scheme, host_kind)`` for a non-empty destination string."""

    text = raw.strip()
    if not text or any(ord(c) < 32 for c in text):
        return _Kind.MALFORMED, "none", "malformed"
    if "://" not in text and _looks_like_path(text):
        return _Kind.LOCAL, "path", "filesystem-path"

    if "://" in text:
        parts = urlsplit(text)
        scheme = parts.scheme.lower()
        try:
            host = parts.hostname or ""
        except ValueError:
            return _Kind.MALFORMED, scheme or "none", "malformed"
    else:
        scheme = ""
        host = text.split("/", 1)[0].split(":", 1)[0]

    if scheme and scheme not in _LOCAL_SCHEMES and scheme not in _NETWORK_SCHEMES:
        return _Kind.MALFORMED, scheme, "unsupported-scheme"
    if scheme == "file":
        return _Kind.LOCAL, "file", "filesystem-path"
    if _host_is_local(host):
        return _Kind.LOCAL, scheme or "none", "local-host"
    if not host:
        return _Kind.MALFORMED, scheme or "none", "missing-host"

    try:
        ipaddress.ip_address(host.strip("[]"))
        host_kind = "ip-literal"
    except ValueError:
        host_kind = "domain"
    return _Kind.EXTERNAL, scheme or "none", host_kind


def _external_severity(classification: DataClassification) -> Severity:
    if classification in (DataClassification.CREDENTIAL, DataClassification.SECRET):
        return Severity.CRITICAL
    if classification in (
        DataClassification.PERSONAL_DATA,
        DataClassification.REGULATED,
    ):
        return Severity.HIGH
    if classification is DataClassification.INTERNAL:
        return Severity.MEDIUM
    return Severity.LOW


class DestinationDetector:
    """Deterministic destination-classification evidence producer."""

    namespace: str = _NAMESPACE
    source: EvidenceSource = EvidenceSource.DESTINATION_CLASSIFIER
    primary_category: EvidenceCategory = EvidenceCategory.EXTERNAL_DATA_TRANSFER

    def analyze(self, event: SecurityEvent) -> tuple[Evidence, ...]:
        classification = event.data_classification
        is_send = event.action is ActionType.NETWORK_SEND

        if event.destination is None:
            if is_send:
                severity = (
                    Severity.HIGH if classification in _SENSITIVE else Severity.MEDIUM
                )
                return (
                    self._evidence(
                        rule_id="DESTINATION.UNSPECIFIED_EGRESS",
                        severity=severity,
                        confidence=0.4,
                        metadata={
                            "action": event.action.value,
                            "data_classification": classification.value,
                            "destination_kind": "absent",
                        },
                    ),
                )
            return ()

        kind, scheme, host_kind = _classify(event.destination)
        base_meta = {
            "action": event.action.value,
            "data_classification": classification.value,
            "destination_kind": kind.value,
            "destination_scheme": scheme,
            "destination_host_kind": host_kind,
            "destination_fingerprint": fingerprint(event.destination),
            "destination_length": str(len(event.destination)),
        }

        if kind is _Kind.LOCAL:
            return ()

        findings: list[Evidence] = []
        if kind is _Kind.MALFORMED:
            findings.append(
                self._evidence(
                    rule_id="DESTINATION.MALFORMED_FORM",
                    severity=Severity.MEDIUM,
                    confidence=0.5,
                    metadata=base_meta,
                )
            )
        else:  # EXTERNAL
            findings.append(
                self._evidence(
                    rule_id="DESTINATION.EXTERNAL",
                    severity=_external_severity(classification),
                    confidence=0.8,
                    metadata=base_meta,
                )
            )

        if is_send and classification in _SENSITIVE:
            findings.append(
                self._evidence(
                    rule_id="DESTINATION.SENSITIVE_EGRESS",
                    severity=_external_severity(classification),
                    confidence=0.85,
                    metadata=base_meta,
                )
            )
        return tuple(findings)

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
