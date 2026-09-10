"""Redaction helpers: structural metadata only, never the value."""

from __future__ import annotations

from contextfence.analysis.redaction import (
    character_classes,
    fingerprint,
    span_metadata,
    value_metadata,
)

_SYNTHETIC_SECRET = "AKIAIOSFODNN7EXAMPLE"  # AWS-documented non-functional example


def test_fingerprint_is_deterministic_and_non_reversing() -> None:
    fp = fingerprint(_SYNTHETIC_SECRET)
    assert fp == fingerprint(_SYNTHETIC_SECRET)
    assert fp.startswith("sha256:")
    assert len(fp) == len("sha256:") + 12
    # the value itself never appears in its fingerprint
    assert _SYNTHETIC_SECRET not in fp
    assert _SYNTHETIC_SECRET.lower() not in fp


def test_different_values_get_different_fingerprints() -> None:
    assert fingerprint("synthetic-value-one") != fingerprint("synthetic-value-two")


def test_character_classes_summary_is_stable_and_opaque() -> None:
    assert character_classes("abc123") == "lower+digit"
    assert character_classes("ABC") == "upper"
    assert character_classes("a1B_ ") == "lower+upper+digit+space+symbol"
    assert character_classes("") == "empty"


def test_value_metadata_contains_no_substring_of_the_value() -> None:
    meta = value_metadata(_SYNTHETIC_SECRET, prefix="secret")
    assert set(meta) == {"secret_length", "secret_charset", "secret_fingerprint"}
    assert meta["secret_length"] == str(len(_SYNTHETIC_SECRET))
    for value in meta.values():
        # no run of >=4 characters of the secret leaks into any field
        assert not any(
            _SYNTHETIC_SECRET[i : i + 4] in value
            for i in range(len(_SYNTHETIC_SECRET) - 3)
        )


def test_span_metadata_is_offsets_only() -> None:
    meta = span_metadata(field="resource", start=7, length=20)
    assert meta == {
        "matched_field": "resource",
        "match_offset": "7",
        "match_length": "20",
    }
