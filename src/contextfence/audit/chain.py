"""Tamper-evident hash chaining for the audit log (Phase 6).

Each record's ``record_hash`` is ``SHA-256( prev_hash + "\\n" + canonical )``
where ``canonical`` is the deterministic JSON of ``{sequence_number, record_id,
body}``. Because ``prev_hash``, the sequence number and the record id all feed
the hash, accidental modification, deletion, insertion, reordering or
renumbering breaks the chain and is detected by
:mod:`contextfence.audit.integrity`.

This is standard library SHA-256 -- no invented cryptography. It provides
*tamper evidence*, not tamper-proof storage: a privileged local attacker who can
rewrite the whole log (including every subsequent hash) is out of scope
(SECURITY.md §9, THREAT_MODEL.md TA5).
"""

from __future__ import annotations

import hashlib

from contextfence.audit.record import AuditRecordBody
from contextfence.audit.serialization import body_to_dict, canonical_json

__all__ = ["GENESIS_PREV_HASH", "compute_record_hash"]

#: The ``prev_hash`` of the first record in a chain: 64 zero hex digits.
GENESIS_PREV_HASH = "0" * 64

_SEPARATOR = "\n"


def compute_record_hash(
    *,
    sequence_number: int,
    record_id: str,
    prev_hash: str,
    body: AuditRecordBody,
) -> str:
    """Return the deterministic hex SHA-256 for a record's chain position."""

    canonical = canonical_json(
        {
            "sequence_number": sequence_number,
            "record_id": record_id,
            "body": body_to_dict(body),
        }
    )
    digest = hashlib.sha256((prev_hash + _SEPARATOR + canonical).encode("utf-8"))
    return digest.hexdigest()
