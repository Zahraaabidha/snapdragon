"""Deterministic canonical serialization for audit records (Phase 6).

Every audit body / record is turned into JSON explicitly from its trusted typed
fields -- there is no ``__dict__`` dump, no ``repr``, no ``pickle``, no
arbitrary-object serialization. Output is byte-stable: sorted keys, no
whitespace, ASCII escaping, no floats, ``NaN``/``Inf`` rejected. Two equal
records serialize to identical strings.
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from contextfence.audit.record import AuditRecord, AuditRecordBody
from contextfence.core.errors import ContextFenceError

__all__ = [
    "AuditDeserializationError",
    "body_to_dict",
    "canonical_json",
    "load_chain",
    "record_from_dict",
    "record_to_dict",
    "serialize_chain",
]

JsonValue = str | int | bool | None | list["JsonValue"] | dict[str, "JsonValue"]


class AuditDeserializationError(ContextFenceError):
    """A serialized audit record / chain was structurally malformed."""


_BODY_FIELDS: tuple[str, ...] = (
    "schema_version",
    "event_id",
    "occurred_at",
    "application",
    "actor_fingerprint",
    "action",
    "resource_type",
    "resource_fingerprint",
    "data_classification",
    "destination_category",
    "destination_fingerprint",
    "highest_severity",
    "max_confidence",
    "evidence_categories",
    "semantic_evidence_available",
    "evidence_count",
    "decision_outcome",
    "matched_rule_id",
    "enforcement_outcome",
    "enforcement_error_category",
    "approval_state",
    "sanitization_state",
    "sanitized_span_count",
    "provider_metadata",
)
_RECORD_FIELDS: frozenset[str] = frozenset(
    {"sequence_number", "record_id", "prev_hash", "record_hash", "body"}
)


def canonical_json(value: JsonValue) -> str:
    """Serialize a constrained JSON value deterministically."""

    _assert_jsonable(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _assert_jsonable(value: JsonValue, *, depth: int = 0) -> None:
    if depth > 8:
        raise AuditDeserializationError("nested structure is too deep to serialize")
    if value is None or isinstance(value, (str, int)):  # bool is an int subclass
        return
    if isinstance(value, list):
        for item in value:
            _assert_jsonable(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise AuditDeserializationError("dict keys must be strings")
            _assert_jsonable(item, depth=depth + 1)
        return
    raise AuditDeserializationError(
        "canonical serialization accepts only str/int/bool/None/list/dict"
    )


def body_to_dict(body: AuditRecordBody) -> dict[str, JsonValue]:
    """Explicit body -> JSON-compatible dict. The single mapping site."""

    return {
        "schema_version": body.schema_version,
        "event_id": body.event_id,
        "occurred_at": body.occurred_at,
        "application": body.application,
        "actor_fingerprint": body.actor_fingerprint,
        "action": body.action,
        "resource_type": body.resource_type,
        "resource_fingerprint": body.resource_fingerprint,
        "data_classification": body.data_classification,
        "destination_category": body.destination_category,
        "destination_fingerprint": body.destination_fingerprint,
        "highest_severity": body.highest_severity,
        "max_confidence": body.max_confidence,
        "evidence_categories": list(body.evidence_categories),
        "semantic_evidence_available": body.semantic_evidence_available,
        "evidence_count": body.evidence_count,
        "decision_outcome": body.decision_outcome,
        "matched_rule_id": body.matched_rule_id,
        "enforcement_outcome": body.enforcement_outcome,
        "enforcement_error_category": body.enforcement_error_category,
        "approval_state": body.approval_state,
        "sanitization_state": body.sanitization_state,
        "sanitized_span_count": body.sanitized_span_count,
        "provider_metadata": [list(pair) for pair in body.provider_metadata],
    }


def record_to_dict(record: AuditRecord) -> dict[str, JsonValue]:
    return {
        "sequence_number": record.sequence_number,
        "record_id": record.record_id,
        "prev_hash": record.prev_hash,
        "record_hash": record.record_hash,
        "body": body_to_dict(record.body),
    }


def _body_from_dict(raw: object) -> AuditRecordBody:
    if not isinstance(raw, dict):
        raise AuditDeserializationError("body must be an object")
    unknown = set(raw) - set(_BODY_FIELDS)
    if unknown:
        raise AuditDeserializationError("body has unknown field(s)")
    missing = set(_BODY_FIELDS) - set(raw)
    if missing - {"destination_fingerprint", "provider_metadata"}:
        raise AuditDeserializationError("body is missing required field(s)")
    try:
        categories = raw.get("evidence_categories", [])
        metadata = raw.get("provider_metadata", [])
        return AuditRecordBody(
            schema_version=_as_int(raw["schema_version"]),
            event_id=_as_str(raw["event_id"]),
            occurred_at=_as_str(raw["occurred_at"]),
            application=_as_str(raw["application"]),
            actor_fingerprint=_as_str(raw["actor_fingerprint"]),
            action=_as_str(raw["action"]),
            resource_type=_as_str(raw["resource_type"]),
            resource_fingerprint=_as_str(raw["resource_fingerprint"]),
            data_classification=_as_str(raw["data_classification"]),
            destination_category=_as_str(raw["destination_category"]),
            destination_fingerprint=_as_opt_str(raw.get("destination_fingerprint")),
            highest_severity=_as_opt_str(raw["highest_severity"]),
            max_confidence=_as_opt_str(raw["max_confidence"]),
            evidence_categories=tuple(_as_str(c) for c in _as_list(categories)),
            semantic_evidence_available=_as_bool(raw["semantic_evidence_available"]),
            evidence_count=_as_int(raw["evidence_count"]),
            decision_outcome=_as_str(raw["decision_outcome"]),
            matched_rule_id=_as_str(raw["matched_rule_id"]),
            enforcement_outcome=_as_str(raw["enforcement_outcome"]),
            enforcement_error_category=_as_str(raw["enforcement_error_category"]),
            approval_state=_as_str(raw["approval_state"]),
            sanitization_state=_as_str(raw["sanitization_state"]),
            sanitized_span_count=_as_int(raw["sanitized_span_count"]),
            provider_metadata=tuple(
                (_as_str(p[0]), _as_str(p[1]))
                for p in _as_list(metadata)
                if isinstance(p, list) and len(p) == 2
            ),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise AuditDeserializationError("body failed validation") from exc


def record_from_dict(raw: object) -> AuditRecord:
    if not isinstance(raw, dict):
        raise AuditDeserializationError("record must be an object")
    if set(raw) != _RECORD_FIELDS:
        raise AuditDeserializationError("record has missing or unknown field(s)")
    try:
        return AuditRecord(
            sequence_number=_as_int(raw["sequence_number"]),
            record_id=_as_str(raw["record_id"]),
            prev_hash=_as_str(raw["prev_hash"]),
            record_hash=_as_str(raw["record_hash"]),
            body=_body_from_dict(raw["body"]),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise AuditDeserializationError("record failed validation") from exc


def serialize_chain(records: Sequence[AuditRecord]) -> str:
    """One canonical JSON object per line (JSONL)."""

    return "\n".join(canonical_json(record_to_dict(r)) for r in records)


def load_chain(text: str) -> tuple[AuditRecord, ...]:
    """Parse JSONL back into records. Raises on any malformed line."""

    records: list[AuditRecord] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AuditDeserializationError(
                f"line {line_number} is not valid JSON"
            ) from exc
        records.append(record_from_dict(parsed))
    return tuple(records)


def _as_str(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("expected a string")
    return value


def _as_opt_str(value: object) -> str | None:
    if value is None:
        return None
    return _as_str(value)


def _as_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("expected an int")
    return value


def _as_bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise ValueError("expected a bool")
    return value


def _as_list(value: object) -> list[object]:
    if not isinstance(value, list):
        raise ValueError("expected a list")
    return value
