"""The immutable audit record model (Phase 6).

Audit is a **sink**. It records what already happened -- the Policy Engine
:class:`Decision`, the :class:`EnforcementResult`, approval state, sanitization
state -- as *security-relevant metadata*, never the protected payload
(SECURITY.md §5; ARCHITECTURE.md §3.8; PROJECT_SPEC.md §12). Nothing here
authorizes, re-interprets, or influences a decision.

An :class:`AuditRecordBody` is an explicit, typed, closed set of fields. There
is no free-form dictionary and no free text: every field is an enum value, a
count, a boolean, an ISO-8601 UTC timestamp, or a non-reversible
``sha256:`` fingerprint. Raw resources, destinations, actors, payloads, secrets,
PII, prompts and detector excerpts never reach it.

An :class:`AuditRecord` wraps a body with the append-only hash-chain fields
(``sequence_number``, ``record_id``, ``prev_hash``, ``record_hash``). Structural
validation happens here; hash-chain *correctness* is verified separately by
:mod:`contextfence.audit.integrity` (so a deliberately corrupt record can still
be constructed for tests and for a file that was tampered with).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC
from enum import StrEnum

from contextfence.analysis.redaction import fingerprint
from contextfence.core.models.decision import Decision
from contextfence.core.models.enums import (
    ActionType,
    DataClassification,
    DecisionOutcome,
    EvidenceCategory,
    ResourceType,
    Severity,
)
from contextfence.core.models.event import SecurityEvent
from contextfence.core.models.risk import RiskView
from contextfence.enforcement.approval import ApprovalResponse, ApprovalResponseKind
from contextfence.enforcement.results import (
    EnforcementErrorKind,
    EnforcementOutcome,
    EnforcementResult,
)

__all__ = [
    "AUDIT_SCHEMA_VERSION",
    "ApprovalState",
    "AuditRecord",
    "AuditRecordBody",
    "DestinationCategory",
    "SanitizationState",
    "build_audit_body",
]

AUDIT_SCHEMA_VERSION = 1

_FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{12}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_CONFIDENCE_RE = re.compile(r"^\d\.\d{2}$")
_PROVIDER_KEY_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
_PROVIDER_VALUE_MAX = 128


class DestinationCategory(StrEnum):
    """Structural fact about ``event.destination`` -- never its value."""

    ABSENT = "ABSENT"
    PRESENT = "PRESENT"


class ApprovalState(StrEnum):
    NOT_REQUIRED = "NOT_REQUIRED"
    REQUIRED = "REQUIRED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    INVALID = "INVALID"


class SanitizationState(StrEnum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    PERFORMED = "PERFORMED"
    FAILED = "FAILED"


def _one_of(value: str, allowed: frozenset[str], *, field_name: str) -> None:
    if value not in allowed:
        raise ValueError(f"{field_name} has an unrecognised value")


_DECISION_OUTCOMES = frozenset(o.value for o in DecisionOutcome)
_ENFORCEMENT_OUTCOMES = frozenset(o.value for o in EnforcementOutcome)
_ENFORCEMENT_ERRORS = frozenset(o.value for o in EnforcementErrorKind)
_ACTIONS = frozenset(o.value for o in ActionType)
_RESOURCE_TYPES = frozenset(o.value for o in ResourceType)
_CLASSIFICATIONS = frozenset(o.value for o in DataClassification)
_SEVERITIES = frozenset(o.value for o in Severity)
_EVIDENCE_CATEGORIES = frozenset(o.value for o in EvidenceCategory)
_DESTINATION_CATEGORIES = frozenset(o.value for o in DestinationCategory)
_APPROVAL_STATES = frozenset(o.value for o in ApprovalState)
_SANITIZATION_STATES = frozenset(o.value for o in SanitizationState)


@dataclass(frozen=True, slots=True)
class AuditRecordBody:
    """The canonical, privacy-preserving content of one audit record."""

    schema_version: int
    event_id: str
    occurred_at: str
    application: str
    actor_fingerprint: str
    action: str
    resource_type: str
    resource_fingerprint: str
    data_classification: str
    destination_category: str
    highest_severity: str | None
    max_confidence: str | None
    evidence_categories: tuple[str, ...]
    semantic_evidence_available: bool
    evidence_count: int
    decision_outcome: str
    matched_rule_id: str
    enforcement_outcome: str
    enforcement_error_category: str
    approval_state: str
    sanitization_state: str
    sanitized_span_count: int
    destination_fingerprint: str | None = None
    provider_metadata: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.schema_version != AUDIT_SCHEMA_VERSION:
            raise ValueError("unsupported audit schema_version")
        for name in ("event_id", "application", "matched_rule_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if not isinstance(self.occurred_at, str) or "T" not in self.occurred_at:
            raise ValueError("occurred_at must be an ISO-8601 string")

        _require_fingerprint(self.actor_fingerprint, "actor_fingerprint")
        _require_fingerprint(self.resource_fingerprint, "resource_fingerprint")
        if self.destination_fingerprint is not None:
            _require_fingerprint(
                self.destination_fingerprint, "destination_fingerprint"
            )

        _one_of(self.action, _ACTIONS, field_name="action")
        _one_of(self.resource_type, _RESOURCE_TYPES, field_name="resource_type")
        _one_of(
            self.data_classification, _CLASSIFICATIONS, field_name="data_classification"
        )
        _one_of(
            self.destination_category,
            _DESTINATION_CATEGORIES,
            field_name="destination_category",
        )
        _one_of(
            self.decision_outcome, _DECISION_OUTCOMES, field_name="decision_outcome"
        )
        _one_of(
            self.enforcement_outcome,
            _ENFORCEMENT_OUTCOMES,
            field_name="enforcement_outcome",
        )
        _one_of(
            self.enforcement_error_category,
            _ENFORCEMENT_ERRORS,
            field_name="enforcement_error_category",
        )
        _one_of(self.approval_state, _APPROVAL_STATES, field_name="approval_state")
        _one_of(
            self.sanitization_state,
            _SANITIZATION_STATES,
            field_name="sanitization_state",
        )

        if self.highest_severity is not None:
            _one_of(self.highest_severity, _SEVERITIES, field_name="highest_severity")
        if self.max_confidence is not None and not _CONFIDENCE_RE.match(
            self.max_confidence
        ):
            raise ValueError("max_confidence must look like '0.87' or be None")

        if not isinstance(self.evidence_categories, tuple):
            raise ValueError("evidence_categories must be a tuple")
        if list(self.evidence_categories) != sorted(self.evidence_categories):
            raise ValueError("evidence_categories must be sorted")
        for category in self.evidence_categories:
            _one_of(category, _EVIDENCE_CATEGORIES, field_name="evidence_categories")

        for name in ("semantic_evidence_available",):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be a bool")
        for name in ("evidence_count", "sanitized_span_count"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be a non-negative int")

        _validate_provider_metadata(self.provider_metadata)


def _require_fingerprint(value: object, field_name: str) -> None:
    if not isinstance(value, str) or not _FINGERPRINT_RE.match(value):
        raise ValueError(f"{field_name} must be a 'sha256:<12 hex>' fingerprint")


def _validate_provider_metadata(value: object) -> None:
    if not isinstance(value, tuple):
        raise ValueError("provider_metadata must be a tuple of (str, str) pairs")
    seen: set[str] = set()
    last_key = ""
    for pair in value:
        if (
            not isinstance(pair, tuple)
            or len(pair) != 2
            or not all(isinstance(part, str) for part in pair)
        ):
            raise ValueError("provider_metadata entries must be (str, str) pairs")
        key, val = pair
        if not _PROVIDER_KEY_RE.match(key):
            raise ValueError("provider_metadata key has an invalid form")
        if key in seen:
            raise ValueError("provider_metadata keys must be unique")
        if key < last_key:
            raise ValueError("provider_metadata must be sorted by key")
        if len(val) > _PROVIDER_VALUE_MAX or any(c in val for c in "\r\n\x00"):
            raise ValueError("provider_metadata value is too long or has control chars")
        seen.add(key)
        last_key = key


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """A body plus its append-only hash-chain envelope. Immutable."""

    sequence_number: int
    record_id: str
    prev_hash: str
    record_hash: str
    body: AuditRecordBody

    def __post_init__(self) -> None:
        if (
            not isinstance(self.sequence_number, int)
            or isinstance(self.sequence_number, bool)
            or self.sequence_number < 1
        ):
            raise ValueError("sequence_number must be an int >= 1")
        if not isinstance(self.record_id, str) or not self.record_id.strip():
            raise ValueError("record_id must be a non-empty string")
        for name in ("prev_hash", "record_hash"):
            value = getattr(self, name)
            if not isinstance(value, str) or not _HEX64_RE.match(value):
                raise ValueError(f"{name} must be 64 lowercase hex characters")
        if not isinstance(self.body, AuditRecordBody):
            raise ValueError("body must be an AuditRecordBody")


def _confidence(risk_view: RiskView) -> str | None:
    if not risk_view.category_confidence:
        return None
    return f"{max(risk_view.category_confidence.values()):.2f}"


def _approval_state(
    decision: Decision,
    enforcement_result: EnforcementResult,
    approval_response: ApprovalResponse | None,
) -> ApprovalState:
    if approval_response is not None:
        return {
            ApprovalResponseKind.APPROVE: ApprovalState.APPROVED,
            ApprovalResponseKind.REJECT: ApprovalState.REJECTED,
            ApprovalResponseKind.EXPIRED: ApprovalState.EXPIRED,
            ApprovalResponseKind.INVALID: ApprovalState.INVALID,
        }[approval_response.kind]
    if decision.outcome is not DecisionOutcome.ASK:
        return ApprovalState.NOT_REQUIRED
    if enforcement_result.outcome is EnforcementOutcome.ALLOWED:
        return ApprovalState.APPROVED
    if enforcement_result.outcome is EnforcementOutcome.DENIED:
        return ApprovalState.REJECTED
    return ApprovalState.REQUIRED


def _sanitization_state(
    decision: Decision, enforcement_result: EnforcementResult
) -> SanitizationState:
    if decision.outcome is not DecisionOutcome.SANITIZE:
        return SanitizationState.NOT_APPLICABLE
    if enforcement_result.outcome is EnforcementOutcome.SANITIZED:
        return SanitizationState.PERFORMED
    return SanitizationState.FAILED


def build_audit_body(
    *,
    event: SecurityEvent,
    risk_view: RiskView,
    decision: Decision,
    enforcement_result: EnforcementResult,
    approval_response: ApprovalResponse | None = None,
    provider_metadata: Mapping[str, str] | None = None,
) -> AuditRecordBody:
    """Assemble an :class:`AuditRecordBody` from already-produced facts.

    Reads only structural / enum fields and derives non-reversible fingerprints.
    Never reads a raw resource, destination, actor value, payload, rationale
    string, or ``error_detail`` into the body. Mutates nothing.
    """

    metadata_pairs = tuple(
        sorted((str(k), str(v)) for k, v in (provider_metadata or {}).items())
    )
    span_count = (
        enforcement_result.sanitization.sanitized_span_count
        if enforcement_result.sanitization is not None
        else 0
    )

    return AuditRecordBody(
        schema_version=AUDIT_SCHEMA_VERSION,
        event_id=event.event_id,
        occurred_at=event.timestamp.astimezone(UTC).isoformat(),
        application=event.application,
        actor_fingerprint=fingerprint(event.actor),
        action=event.action.value,
        resource_type=event.resource_type.value,
        resource_fingerprint=fingerprint(event.resource),
        data_classification=event.data_classification.value,
        destination_category=(
            DestinationCategory.ABSENT.value
            if event.destination is None
            else DestinationCategory.PRESENT.value
        ),
        destination_fingerprint=(
            None if event.destination is None else fingerprint(event.destination)
        ),
        highest_severity=(
            risk_view.highest_severity.value
            if risk_view.highest_severity is not None
            else None
        ),
        max_confidence=_confidence(risk_view),
        evidence_categories=tuple(sorted(c.value for c in risk_view.categories)),
        semantic_evidence_available=risk_view.semantic_evidence_available,
        evidence_count=risk_view.evidence_count,
        decision_outcome=decision.outcome.value,
        matched_rule_id=decision.matched_rule_id,
        enforcement_outcome=enforcement_result.outcome.value,
        enforcement_error_category=enforcement_result.error_kind.value,
        approval_state=_approval_state(
            decision, enforcement_result, approval_response
        ).value,
        sanitization_state=_sanitization_state(decision, enforcement_result).value,
        sanitized_span_count=span_count,
        provider_metadata=metadata_pairs,
    )
