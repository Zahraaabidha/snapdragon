"""Audit chain integrity verification (Phase 6).

``verify_chain`` walks a sequence of :class:`AuditRecord` and reports every
integrity problem it finds without mutating anything and without exposing record
contents -- an :class:`IntegrityIssue` names only the category, the sequence
number, the record id and a short structural detail.

Detected: modified record body or hash, a broken previous-hash link, a bad
genesis link, deleted / inserted / reordered records, sequence gaps or
duplicates, duplicate record ids, and records that cannot be canonically
serialized.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum

from contextfence.audit.chain import GENESIS_PREV_HASH, compute_record_hash
from contextfence.audit.record import AuditRecord
from contextfence.audit.serialization import (
    AuditDeserializationError,
    load_chain,
)

__all__ = [
    "IntegrityIssue",
    "IntegrityIssueCategory",
    "IntegrityReport",
    "IntegrityStatus",
    "verify_chain",
    "verify_serialized",
]


class IntegrityStatus(StrEnum):
    OK = "OK"
    FAILED = "FAILED"
    EMPTY = "EMPTY"


class IntegrityIssueCategory(StrEnum):
    MALFORMED_RECORD = "MALFORMED_RECORD"
    RECORD_HASH_MISMATCH = "RECORD_HASH_MISMATCH"
    BAD_GENESIS_LINK = "BAD_GENESIS_LINK"
    CHAIN_LINK_BROKEN = "CHAIN_LINK_BROKEN"
    SEQUENCE_GAP = "SEQUENCE_GAP"
    DUPLICATE_SEQUENCE = "DUPLICATE_SEQUENCE"
    DUPLICATE_RECORD_ID = "DUPLICATE_RECORD_ID"


@dataclass(frozen=True, slots=True)
class IntegrityIssue:
    category: IntegrityIssueCategory
    sequence_number: int | None
    record_id: str | None
    detail: str


@dataclass(frozen=True, slots=True)
class IntegrityReport:
    status: IntegrityStatus
    checked_count: int
    issues: tuple[IntegrityIssue, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        return self.status is IntegrityStatus.OK

    def categories(self) -> frozenset[IntegrityIssueCategory]:
        return frozenset(issue.category for issue in self.issues)


def verify_chain(records: Sequence[AuditRecord]) -> IntegrityReport:
    """Verify a chain. Reads only; never mutates the records."""

    if len(records) == 0:
        return IntegrityReport(IntegrityStatus.EMPTY, 0, ())

    issues: list[IntegrityIssue] = []
    seen_ids: set[str] = set()
    seen_seqs: set[int] = set()
    expected_seq = 1
    prev_record_hash = GENESIS_PREV_HASH

    for index, record in enumerate(records):
        if not isinstance(record, AuditRecord):
            issues.append(
                IntegrityIssue(
                    IntegrityIssueCategory.MALFORMED_RECORD,
                    None,
                    None,
                    f"item at position {index} is not an AuditRecord",
                )
            )
            continue

        seq = record.sequence_number
        rid = record.record_id

        recomputed = _safe_hash(record, issues)
        if recomputed is not None and recomputed != record.record_hash:
            issues.append(
                IntegrityIssue(
                    IntegrityIssueCategory.RECORD_HASH_MISMATCH,
                    seq,
                    rid,
                    "recomputed hash does not match the stored record_hash",
                )
            )

        if index == 0:
            if record.prev_hash != GENESIS_PREV_HASH:
                issues.append(
                    IntegrityIssue(
                        IntegrityIssueCategory.BAD_GENESIS_LINK,
                        seq,
                        rid,
                        "first record prev_hash is not the genesis hash",
                    )
                )
        elif record.prev_hash != prev_record_hash:
            issues.append(
                IntegrityIssue(
                    IntegrityIssueCategory.CHAIN_LINK_BROKEN,
                    seq,
                    rid,
                    "prev_hash does not match the previous record's record_hash",
                )
            )

        if seq != expected_seq:
            issues.append(
                IntegrityIssue(
                    IntegrityIssueCategory.SEQUENCE_GAP,
                    seq,
                    rid,
                    f"expected sequence number {expected_seq}",
                )
            )
        if seq in seen_seqs:
            issues.append(
                IntegrityIssue(
                    IntegrityIssueCategory.DUPLICATE_SEQUENCE,
                    seq,
                    rid,
                    "sequence number repeats earlier in the chain",
                )
            )
        if rid in seen_ids:
            issues.append(
                IntegrityIssue(
                    IntegrityIssueCategory.DUPLICATE_RECORD_ID,
                    seq,
                    rid,
                    "record id repeats earlier in the chain",
                )
            )

        seen_seqs.add(seq)
        seen_ids.add(rid)
        expected_seq += 1
        prev_record_hash = record.record_hash

    status = IntegrityStatus.OK if not issues else IntegrityStatus.FAILED
    return IntegrityReport(status, len(records), tuple(issues))


def verify_serialized(text: str) -> IntegrityReport:
    """Load JSONL and verify it. A malformed serialized chain fails closed."""

    try:
        records = load_chain(text)
    except AuditDeserializationError:
        return IntegrityReport(
            IntegrityStatus.FAILED,
            0,
            (
                IntegrityIssue(
                    IntegrityIssueCategory.MALFORMED_RECORD,
                    None,
                    None,
                    "serialized chain could not be parsed",
                ),
            ),
        )
    return verify_chain(records)


def _safe_hash(record: AuditRecord, issues: list[IntegrityIssue]) -> str | None:
    try:
        return compute_record_hash(
            sequence_number=record.sequence_number,
            record_id=record.record_id,
            prev_hash=record.prev_hash,
            body=record.body,
        )
    except Exception:  # surfaced as a structural issue, never re-raised
        issues.append(
            IntegrityIssue(
                IntegrityIssueCategory.MALFORMED_RECORD,
                record.sequence_number,
                record.record_id,
                "record could not be canonically serialized for hashing",
            )
        )
        return None
