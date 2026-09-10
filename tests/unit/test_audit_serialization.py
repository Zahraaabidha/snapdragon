"""Phase 6: deterministic canonical serialization."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from contextfence.audit import (
    AuditDeserializationError,
    body_to_dict,
    canonical_json,
    load_chain,
    record_from_dict,
    record_to_dict,
    serialize_chain,
)
from contextfence.audit.serialization import _BODY_FIELDS, JsonValue
from tests.unit.test_audit_record import _valid_body


def _record_dict() -> dict[str, JsonValue]:
    return {
        "sequence_number": 1,
        "record_id": "r1",
        "prev_hash": "0" * 64,
        "record_hash": "a" * 64,
        "body": body_to_dict(_valid_body()),
    }


# --- canonical_json ---------------------------------------------------


def test_canonical_json_is_sorted_compact_ascii() -> None:
    out = canonical_json({"b": 1, "a": [2, {"z": True, "y": None}]})
    assert out == '{"a":[2,{"y":null,"z":true}],"b":1}'


def test_canonical_json_rejects_floats_and_non_json_types() -> None:
    with pytest.raises(AuditDeserializationError):
        canonical_json({"x": 1.5})  # type: ignore[dict-item]
    with pytest.raises(AuditDeserializationError):
        canonical_json({"x": object()})  # type: ignore[dict-item]
    with pytest.raises(AuditDeserializationError):
        canonical_json({1: "int key"})  # type: ignore[dict-item]


def test_canonical_json_is_deterministic_across_key_order() -> None:
    a = canonical_json({"a": 1, "b": 2, "c": [1, 2, 3]})
    b = canonical_json({"c": [1, 2, 3], "b": 2, "a": 1})
    assert a == b


def test_equal_bodies_serialize_identically() -> None:
    one = canonical_json(body_to_dict(_valid_body()))
    two = canonical_json(body_to_dict(_valid_body()))
    assert one == two
    assert "0x" not in one  # no memory addresses / object reprs
    assert "object at" not in one


def test_body_to_dict_has_exactly_the_declared_fields() -> None:
    keys = set(body_to_dict(_valid_body()))
    assert keys == set(_BODY_FIELDS)


# --- round trip -----------------------------------------------------


def test_record_dict_round_trips() -> None:
    original = _record_dict()
    record = record_from_dict(original)
    assert record_to_dict(record) == original


def test_serialize_and_load_chain_round_trips() -> None:
    d1, d2 = _record_dict(), _record_dict()
    d2["sequence_number"] = 2
    d2["record_id"] = "r2"
    d2["prev_hash"] = d1["record_hash"]
    text = "\n".join(canonical_json(d) for d in (d1, d2))
    loaded = load_chain(text)
    assert len(loaded) == 2
    assert serialize_chain(loaded) == text


# --- malformed input -----------------------------------------------


def test_record_from_dict_rejects_unknown_or_missing_fields() -> None:
    bad = _record_dict()
    bad["extra"] = 1
    with pytest.raises(AuditDeserializationError):
        record_from_dict(bad)
    incomplete = _record_dict()
    del incomplete["record_hash"]
    with pytest.raises(AuditDeserializationError):
        record_from_dict(incomplete)


def test_body_from_dict_rejects_unknown_body_field() -> None:
    bad = _record_dict()
    assert isinstance(bad["body"], dict)
    bad["body"]["surprise"] = "value"
    with pytest.raises(AuditDeserializationError):
        record_from_dict(bad)


def test_load_chain_rejects_a_non_json_line() -> None:
    with pytest.raises(AuditDeserializationError):
        load_chain("not json at all")


def test_load_chain_skips_blank_lines() -> None:
    text = canonical_json(_record_dict()) + "\n\n"
    assert len(load_chain(text)) == 1


def test_serialization_never_imports_pickle_or_marshal() -> None:
    import ast

    import contextfence.audit.serialization as mod

    source = mod.__file__
    assert source is not None
    tree = ast.parse(Path(source).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert imported.isdisjoint({"pickle", "marshal", "shelve", "dill"})
    assert "json" in imported


def test_no_wall_clock_or_random_in_serialized_body() -> None:
    # the body's only timestamp is the event's own occurred_at, supplied by the
    # caller -- serialization introduces nothing time- or address-dependent.
    text = canonical_json(body_to_dict(_valid_body()))
    parsed = json.loads(text)
    assert parsed["occurred_at"] == "2026-01-01T12:00:00+00:00"
