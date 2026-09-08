"""The Event Gateway: the single validated entry point into the security core.

An adapter hands the gateway an *untrusted* raw event (a plain mapping, as would
come from decoded JSON). :meth:`EventGateway.admit` returns a canonical,
validated, immutable :class:`~contextfence.core.models.event.SecurityEvent`, or
raises :class:`~contextfence.core.errors.MalformedEventError`.

Design constraints (ARCHITECTURE.md §3.2, §9; SECURITY.md §2):

* The gateway does not analyze, score, risk-rank, or decide. It only validates
  shape and constructs the canonical event.
* Malformed input is rejected explicitly. Nothing is silently repaired.
* Missing security-critical information is never converted into a permissive
  value. The only fields the gateway will synthesize when absent are
  ``event_id`` and ``timestamp`` (both ingestion metadata, per ARCHITECTURE.md
  §3.2). Every other field must be supplied by the adapter -- in particular an
  absent ``data_classification`` or ``requested_capabilities`` is rejected, not
  defaulted (docs/DECISIONS.md D-0001).
* Unknown top-level keys are rejected rather than ignored, so an adapter (or
  injected content shaping an adapter's output) cannot smuggle an
  authorization-looking field such as ``decision`` or ``authorized`` past the
  boundary.
* ``semantic_signals`` may not be supplied here: it is added later by the
  semantic analyzer, not by adapters.
* Rejection messages name the offending field and problem. A raw value is echoed
  only for closed-enum / type mismatches on non-sensitive fields
  (``action``, ``resource_type``, ``data_classification``).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from enum import Enum
from typing import TypeVar
from uuid import UUID

from contextfence.core.errors import MalformedEventError, ValidationError
from contextfence.core.models.enums import (
    ActionType,
    DataClassification,
    ResourceType,
)
from contextfence.core.models.event import SecurityEvent, new_event_id
from contextfence.core.models.policy_context import EMPTY_POLICY_CONTEXT, PolicyContext

__all__ = ["EventGateway"]

_E = TypeVar("_E", bound=Enum)

_ALLOWED_EVENT_KEYS: frozenset[str] = frozenset(
    {
        "event_id",
        "timestamp",
        "actor",
        "application",
        "action",
        "resource",
        "resource_type",
        "destination",
        "data_classification",
        "requested_capabilities",
        "semantic_signals",
        "policy_context",
    }
)

_ALLOWED_POLICY_CONTEXT_KEYS: frozenset[str] = frozenset(
    {"profile_id", "session_id", "prior_decision_ids", "user_declared_task"}
)


class EventGateway:
    """Validates untrusted raw events into canonical :class:`SecurityEvent`s."""

    def admit(self, raw_event: Mapping[str, object]) -> SecurityEvent:
        """Return a validated :class:`SecurityEvent` for ``raw_event``.

        Raises:
            MalformedEventError: if ``raw_event`` is not a mapping, contains an
                unknown key, is missing a required field, or has a field that
                fails validation.
        """

        if not isinstance(raw_event, Mapping):
            raise MalformedEventError("raw event must be a mapping")

        unknown = {str(k) for k in raw_event} - _ALLOWED_EVENT_KEYS
        if unknown:
            raise MalformedEventError(
                f"unknown event field(s): {', '.join(sorted(unknown))}"
            )

        self._reject_supplied_semantic_signals(raw_event)

        event_id = self._resolve_event_id(raw_event.get("event_id"))
        timestamp = self._resolve_timestamp(raw_event.get("timestamp"))

        action = _resolve_enum(
            _require_present(raw_event, "action"), ActionType, field="action"
        )
        resource_type = _resolve_enum(
            _require_present(raw_event, "resource_type"),
            ResourceType,
            field="resource_type",
        )
        data_classification = _resolve_enum(
            _require_present(raw_event, "data_classification"),
            DataClassification,
            field="data_classification",
        )

        actor = _require_text_field(raw_event, "actor")
        application = _require_text_field(raw_event, "application")
        resource = _require_text_field(raw_event, "resource")

        destination = self._resolve_destination(raw_event.get("destination"))
        requested_capabilities = self._resolve_capabilities(
            _require_present(raw_event, "requested_capabilities")
        )
        policy_context = self._resolve_policy_context(raw_event.get("policy_context"))

        try:
            return SecurityEvent(
                event_id=event_id,
                timestamp=timestamp,
                actor=actor,
                application=application,
                action=action,
                resource=resource,
                resource_type=resource_type,
                data_classification=data_classification,
                destination=destination,
                requested_capabilities=requested_capabilities,
                semantic_signals=(),
                policy_context=policy_context,
            )
        except ValidationError as exc:  # pragma: no cover - defensive re-wrap
            raise MalformedEventError(str(exc)) from exc

    # -- field resolvers ---------------------------------------------------

    @staticmethod
    def _reject_supplied_semantic_signals(raw_event: Mapping[str, object]) -> None:
        signals = raw_event.get("semantic_signals")
        if signals is None:
            return
        if isinstance(signals, (list, tuple)) and len(signals) == 0:
            return
        raise MalformedEventError(
            "semantic_signals is populated by the semantic analyzer, "
            "not supplied by adapters"
        )

    @staticmethod
    def _resolve_event_id(raw: object) -> str:
        if raw is None:
            return new_event_id()
        if not isinstance(raw, str) or not raw.strip():
            raise MalformedEventError("event_id must be a non-empty UUID string")
        try:
            UUID(raw)
        except (ValueError, AttributeError, TypeError) as exc:
            raise MalformedEventError("event_id must be a valid UUID string") from exc
        return raw

    @staticmethod
    def _resolve_timestamp(raw: object) -> datetime:
        if raw is None:
            return datetime.now(UTC)
        parsed: datetime
        if isinstance(raw, datetime):
            parsed = raw
        elif isinstance(raw, str):
            try:
                parsed = datetime.fromisoformat(raw)
            except ValueError as exc:
                raise MalformedEventError("timestamp string must be ISO 8601") from exc
        else:
            raise MalformedEventError("timestamp must be a datetime or ISO 8601 string")
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise MalformedEventError("timestamp must be timezone-aware")
        return parsed.astimezone(UTC)

    @staticmethod
    def _resolve_destination(raw: object) -> str | None:
        if raw is None:
            return None
        if not isinstance(raw, str) or not raw.strip():
            raise MalformedEventError(
                "destination must be a non-empty string when present"
            )
        return raw

    @staticmethod
    def _resolve_capabilities(raw: object) -> tuple[str, ...]:
        if not isinstance(raw, (list, tuple)):
            raise MalformedEventError(
                "requested_capabilities must be a list of strings "
                "(use an empty list, not omission)"
            )
        result: list[str] = []
        for entry in raw:
            if isinstance(entry, (bool, Enum)) or not isinstance(entry, str):
                raise MalformedEventError(
                    "requested_capabilities entries must be plain strings"
                )
            if not entry.strip():
                raise MalformedEventError(
                    "requested_capabilities entries must not be empty"
                )
            result.append(entry)
        return tuple(result)

    @staticmethod
    def _resolve_policy_context(raw: object) -> PolicyContext:
        if raw is None:
            return EMPTY_POLICY_CONTEXT
        if not isinstance(raw, Mapping):
            raise MalformedEventError("policy_context must be a mapping")
        unknown = {str(k) for k in raw} - _ALLOWED_POLICY_CONTEXT_KEYS
        if unknown:
            raise MalformedEventError(
                f"unknown policy_context field(s): {', '.join(sorted(unknown))}"
            )

        prior_raw = raw.get("prior_decision_ids")
        if prior_raw is None:
            prior_ids: tuple[str, ...] = ()
        elif isinstance(prior_raw, (list, tuple)):
            for entry in prior_raw:
                if isinstance(entry, bool) or not isinstance(entry, str):
                    raise MalformedEventError(
                        "policy_context.prior_decision_ids entries must be id strings"
                    )
            prior_ids = tuple(prior_raw)
        else:
            raise MalformedEventError(
                "policy_context.prior_decision_ids must be a list of id strings"
            )

        try:
            return PolicyContext(
                profile_id=_opt_str(raw.get("profile_id"), "policy_context.profile_id"),
                session_id=_opt_str(raw.get("session_id"), "policy_context.session_id"),
                prior_decision_ids=prior_ids,
                user_declared_task=_opt_str(
                    raw.get("user_declared_task"),
                    "policy_context.user_declared_task",
                ),
            )
        except ValidationError as exc:
            raise MalformedEventError(str(exc)) from exc


# -- module-level helpers ------------------------------------------------------


def _require_present(raw_event: Mapping[str, object], key: str) -> object:
    if key not in raw_event or raw_event[key] is None:
        raise MalformedEventError(f"missing required field: {key}")
    return raw_event[key]


def _require_text_field(raw_event: Mapping[str, object], key: str) -> str:
    value = _require_present(raw_event, key)
    if isinstance(value, (bool, Enum)) or not isinstance(value, str):
        raise MalformedEventError(f"{key} must be a string")
    if not value.strip():
        raise MalformedEventError(f"{key} must not be empty")
    return value


def _resolve_enum(raw: object, enum_cls: type[_E], *, field: str) -> _E:
    if isinstance(raw, enum_cls):
        return raw
    if isinstance(raw, str) and not isinstance(raw, Enum):
        try:
            return enum_cls(raw)
        except ValueError as exc:
            raise MalformedEventError(
                f"{field} has unrecognized value {raw!r}"
            ) from exc
    raise MalformedEventError(f"{field} must be a string value of {enum_cls.__name__}")


def _opt_str(value: object, field: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, (bool, Enum)) or not isinstance(value, str):
        raise MalformedEventError(f"{field} must be a string")
    if not value.strip():
        raise MalformedEventError(f"{field} must not be empty when present")
    return value
