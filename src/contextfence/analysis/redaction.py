"""Safe-metadata helpers for the deterministic detectors.

Detectors must never place a raw secret, credential, private key, full sensitive
input, or unnecessary personal data into ``Evidence`` metadata (SECURITY.md §5;
CLAUDE.md §10, §24; THREAT_MODEL.md T7). These helpers produce only *structural*
facts about a matched value:

* a truncated, non-reversible SHA-256 fingerprint (for correlating "the same
  value was seen twice" without storing it),
* its length and character-class makeup,
* the field it was found in and the offset/length of the match.

The fingerprint is deliberately short (48 bits). A keyed / salted fingerprint,
if one is ever wanted, belongs to the audit layer (Phase 6), not here.

Nothing in this module performs I/O.
"""

from __future__ import annotations

import hashlib

__all__ = [
    "FINGERPRINT_HEX_LEN",
    "character_classes",
    "fingerprint",
    "span_metadata",
    "value_metadata",
]

FINGERPRINT_HEX_LEN = 12
"""Hex characters kept from the SHA-256 digest (48 bits)."""


def fingerprint(value: str) -> str:
    """Return a short, non-reversible fingerprint of ``value``.

    ``sha256:<12 hex chars>``. Not a security control on its own; it exists so
    two findings can be recognised as referring to the same underlying value
    without that value ever being stored.
    """

    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
    return f"sha256:{digest[:FINGERPRINT_HEX_LEN]}"


def character_classes(value: str) -> str:
    """Return a compact, non-revealing summary of the character classes used.

    e.g. ``"lower+digit"`` or ``"lower+upper+digit+symbol"``. Order is fixed so
    the output is deterministic.
    """

    present: list[str] = []
    if any(c.islower() for c in value):
        present.append("lower")
    if any(c.isupper() for c in value):
        present.append("upper")
    if any(c.isdigit() for c in value):
        present.append("digit")
    if any(c.isspace() for c in value):
        present.append("space")
    if any((not c.isalnum()) and (not c.isspace()) for c in value):
        present.append("symbol")
    return "+".join(present) if present else "empty"


def value_metadata(value: str, *, prefix: str = "value") -> dict[str, str]:
    """Structural, non-sensitive metadata describing ``value``.

    Never includes the value itself or any substring of it.
    """

    return {
        f"{prefix}_length": str(len(value)),
        f"{prefix}_charset": character_classes(value),
        f"{prefix}_fingerprint": fingerprint(value),
    }


def span_metadata(*, field: str, start: int, length: int) -> dict[str, str]:
    """Metadata locating a match: the field name and offset/length only."""

    return {
        "matched_field": field,
        "match_offset": str(start),
        "match_length": str(length),
    }
