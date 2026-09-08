"""The canonical :class:`SecurityEvent` model.

Every adapter normalizes its native activity into this representation; the
security core depends only on this shape, never on an adapter's native format
(ARCHITECTURE.md §4, §5). ``SecurityEvent`` is frozen and self-validating: even
when constructed directly (in tests, or by the Policy Engine in a later phase)
it re-checks every invariant. The normal construction path is
:class:`contextfence.core.events.gateway.EventGateway`, which resolves raw
strings to enums, parses/mints the timestamp and id, and rejects anything
malformed.

Field notes with security weight:

* ``destination`` may be ``None`` ("no external destination"). An absent
  destination is preserved as ``None`` -- it is never fabricated into a
  local/allowed value. Treating a missing destination conservatively is the
  Policy Engine's job (ARCHITECTURE.md §5 note).
* ``data_classification`` is required. There is no permissive default; an absent
  classification is a malformed event.
* ``semantic_signals`` is untrusted advisory evidence carried for traceability.
  Its presence here does not make it authoritative; it is routed through the
  Risk Aggregator like any other evidence (ARCHITECTURE.md §3.3, §12). Every
  entry must come from :attr:`EvidenceSource.SEMANTIC_ANALYZER`.
* ``policy_context`` is context, not permission (see
  :mod:`contextfence.core.models.policy_context`).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from contextfence.core.errors import ValidationError
from contextfence.core.models._validation import require_enum_member, require_text
from contextfence.core.models.enums import (
    ActionType,
    DataClassification,
    EvidenceSource,
    ResourceType,
)
from contextfence.core.models.evidence import Evidence
from contextfence.core.models.policy_context import EMPTY_POLICY_CONTEXT, PolicyContext

__all__ = ["SecurityEvent"]


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """A single normalized, validated action observed by an adapter.

    Args:
        event_id: unique id. Canonically a UUID string.
        timestamp: timezone-aware UTC datetime of when the action was observed.
        actor: who/what initiated the action (e.g. ``"claude-code:agent"``).
        application: the integrated application (e.g. ``"claude_code"``).
        action: normalized :class:`ActionType`.
        resource: target identifier (path, url, tool name, ...).
        resource_type: normalized :class:`ResourceType`.
        destination: where data would go, or ``None`` for no external
            destination.
        data_classification: best known :class:`DataClassification` of the data
            involved. Required.
        requested_capabilities: tuple of capability strings the action needs
            (may be empty, but must be supplied explicitly by the adapter).
        semantic_signals: tuple of semantic-analyzer :class:`Evidence` (may be
            empty; empty is the norm when semantic analysis is off/unavailable).
        policy_context: non-authoritative :class:`PolicyContext`.
    """

    event_id: str
    timestamp: datetime
    actor: str
    application: str
    action: ActionType
    resource: str
    resource_type: ResourceType
    data_classification: DataClassification
    destination: str | None = None
    requested_capabilities: tuple[str, ...] = field(default_factory=tuple)
    semantic_signals: tuple[Evidence, ...] = field(default_factory=tuple)
    policy_context: PolicyContext = EMPTY_POLICY_CONTEXT

    def __post_init__(self) -> None:
        require_text(self.event_id, field="event_id")

        if not isinstance(self.timestamp, datetime):
            raise ValidationError("timestamp must be a datetime")
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValidationError("timestamp must be timezone-aware")
        object.__setattr__(self, "timestamp", self.timestamp.astimezone(UTC))

        require_text(self.actor, field="actor")
        require_text(self.application, field="application")
        require_enum_member(self.action, ActionType, field="action")
        require_text(self.resource, field="resource")
        require_enum_member(self.resource_type, ResourceType, field="resource_type")
        require_enum_member(
            self.data_classification, DataClassification, field="data_classification"
        )

        if self.destination is not None:
            require_text(self.destination, field="destination")

        object.__setattr__(
            self,
            "requested_capabilities",
            _validate_capabilities(self.requested_capabilities),
        )
        object.__setattr__(
            self, "semantic_signals", _validate_semantic_signals(self.semantic_signals)
        )

        if not isinstance(self.policy_context, PolicyContext):
            raise ValidationError("policy_context must be a PolicyContext")


def _validate_capabilities(value: object) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise ValidationError("requested_capabilities must be a tuple of strings")
    for entry in value:
        require_text(entry, field="requested_capabilities entry")
    return value


def _validate_semantic_signals(value: object) -> tuple[Evidence, ...]:
    if not isinstance(value, tuple):
        raise ValidationError("semantic_signals must be a tuple of Evidence")
    for entry in value:
        if not isinstance(entry, Evidence):
            raise ValidationError("semantic_signals entries must be Evidence")
        if entry.source is not EvidenceSource.SEMANTIC_ANALYZER:
            raise ValidationError(
                "semantic_signals entries must have source SEMANTIC_ANALYZER"
            )
    return value


def new_event_id() -> str:
    """Return a fresh random UUID4 string for use as an ``event_id``."""

    return str(uuid.uuid4())
