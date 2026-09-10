"""Append-only audit sink (Phase 6).

An :class:`AuditSink` accepts an :class:`AuditRecordBody`, wraps it in the next
hash-chain envelope, and stores it. The public surface is deliberately tiny:
``append`` / ``records`` / ``verify`` / ``len``. There is **no** update, delete,
insert, truncate, or "fix history" method -- rewriting the log is not part of
the API (SECURITY.md §1.4; ARCHITECTURE.md §3.8).

Failure semantics (task Part "FAILURE SEMANTICS"): ``append`` never raises and
never silently drops a write. On failure it returns
``AppendResult(ok=False, ...)`` with a structural error category. Audit is a
sink downstream of enforcement: a failed write cannot change a ``Decision`` or
an ``EnforcementResult`` -- those are already final when audit is called.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from contextfence.audit.chain import GENESIS_PREV_HASH, compute_record_hash
from contextfence.audit.integrity import IntegrityReport, verify_chain
from contextfence.audit.record import AuditRecord, AuditRecordBody
from contextfence.core.errors import ContextFenceError

__all__ = [
    "AppendResult",
    "AuditSink",
    "AuditWriteError",
    "AuditWriteErrorKind",
    "InMemoryAuditSink",
    "forge_next_record",
]


class AuditWriteError(ContextFenceError):
    """An audit append failed. Carries only a structural reason."""


class AuditWriteErrorKind(StrEnum):
    NONE = "NONE"
    INVALID_BODY = "INVALID_BODY"
    WRITE_FAILED = "WRITE_FAILED"


@dataclass(frozen=True, slots=True)
class AppendResult:
    """Result of an append. ``ok is False`` means the write did not happen."""

    ok: bool
    record: AuditRecord | None = None
    error_kind: AuditWriteErrorKind = AuditWriteErrorKind.NONE
    error_detail: str = ""

    def __post_init__(self) -> None:
        if self.ok and self.record is None:
            raise ValueError("a successful AppendResult must carry a record")
        if not self.ok and self.error_kind is AuditWriteErrorKind.NONE:
            raise ValueError("a failed AppendResult must carry an error_kind")


def forge_next_record(
    existing: Sequence[AuditRecord], body: AuditRecordBody
) -> AuditRecord:
    """Build the next chained record for ``body`` given the current chain."""

    if not isinstance(body, AuditRecordBody):
        raise AuditWriteError("body must be an AuditRecordBody")
    sequence_number = len(existing) + 1
    prev_hash = existing[-1].record_hash if existing else GENESIS_PREV_HASH
    record_id = str(uuid.uuid4())
    record_hash = compute_record_hash(
        sequence_number=sequence_number,
        record_id=record_id,
        prev_hash=prev_hash,
        body=body,
    )
    return AuditRecord(
        sequence_number=sequence_number,
        record_id=record_id,
        prev_hash=prev_hash,
        record_hash=record_hash,
        body=body,
    )


class AuditSink(Protocol):
    """Minimal append-only sink contract."""

    def append(self, body: AuditRecordBody) -> AppendResult: ...

    def records(self) -> tuple[AuditRecord, ...]: ...

    def verify(self) -> IntegrityReport: ...


class InMemoryAuditSink:
    """A local, append-only, in-memory chain. No persistence, no I/O."""

    __slots__ = ("_records",)

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []

    def append(self, body: AuditRecordBody) -> AppendResult:
        try:
            record = forge_next_record(self._records, body)
        except AuditWriteError as exc:
            return AppendResult(
                ok=False,
                error_kind=AuditWriteErrorKind.INVALID_BODY,
                error_detail=str(exc),
            )
        except Exception as exc:  # never let an audit write raise into a caller
            return AppendResult(
                ok=False,
                error_kind=AuditWriteErrorKind.WRITE_FAILED,
                error_detail=type(exc).__name__,
            )
        self._records.append(record)
        return AppendResult(ok=True, record=record)

    def records(self) -> tuple[AuditRecord, ...]:
        """An immutable snapshot. The internal store is never handed out."""

        return tuple(self._records)

    def verify(self) -> IntegrityReport:
        return verify_chain(self.records())

    def __len__(self) -> int:
        return len(self._records)
