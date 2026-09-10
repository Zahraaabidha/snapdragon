"""ContextFence audit / tamper-evident logging (Phase 6).

Audit is a **sink**: it records already-produced facts (the Policy Engine
``Decision``, the ``EnforcementResult``, approval and sanitization state) as
privacy-preserving, hash-chained records. It never authorizes, never
re-interprets a decision, never invokes inference, never executes anything, and
the decision path never reads it.

* :class:`AuditRecordBody` / :class:`AuditRecord` / :func:`build_audit_body`
* :class:`InMemoryAuditSink` / :class:`AuditSink` / :class:`AppendResult`
* :func:`canonical_json` / :func:`serialize_chain` / :func:`load_chain`
* :func:`compute_record_hash` / :data:`GENESIS_PREV_HASH`
* :func:`verify_chain` / :func:`verify_serialized` / :class:`IntegrityReport`

Nothing here imports the UI, adapters, inference, network clients, subprocess,
a database, ``pickle``, or ``contextfence.policy``; nothing here constructs a
``Decision`` or touches ``PolicyConfig``.
"""

from __future__ import annotations

from contextfence.audit.chain import GENESIS_PREV_HASH, compute_record_hash
from contextfence.audit.integrity import (
    IntegrityIssue,
    IntegrityIssueCategory,
    IntegrityReport,
    IntegrityStatus,
    verify_chain,
    verify_serialized,
)
from contextfence.audit.record import (
    AUDIT_SCHEMA_VERSION,
    ApprovalState,
    AuditRecord,
    AuditRecordBody,
    DestinationCategory,
    SanitizationState,
    build_audit_body,
)
from contextfence.audit.serialization import (
    AuditDeserializationError,
    body_to_dict,
    canonical_json,
    load_chain,
    record_from_dict,
    record_to_dict,
    serialize_chain,
)
from contextfence.audit.sink import (
    AppendResult,
    AuditSink,
    AuditWriteError,
    AuditWriteErrorKind,
    InMemoryAuditSink,
    forge_next_record,
)

__all__ = [
    "AUDIT_SCHEMA_VERSION",
    "GENESIS_PREV_HASH",
    "AppendResult",
    "ApprovalState",
    "AuditDeserializationError",
    "AuditRecord",
    "AuditRecordBody",
    "AuditSink",
    "AuditWriteError",
    "AuditWriteErrorKind",
    "DestinationCategory",
    "InMemoryAuditSink",
    "IntegrityIssue",
    "IntegrityIssueCategory",
    "IntegrityReport",
    "IntegrityStatus",
    "SanitizationState",
    "body_to_dict",
    "build_audit_body",
    "canonical_json",
    "compute_record_hash",
    "forge_next_record",
    "load_chain",
    "record_from_dict",
    "record_to_dict",
    "serialize_chain",
    "verify_chain",
    "verify_serialized",
]
