"""Phase 6: hash chain generation and tamper-evident integrity verification."""

from __future__ import annotations

import dataclasses

from contextfence.audit import (
    GENESIS_PREV_HASH,
    AuditRecord,
    InMemoryAuditSink,
    IntegrityIssueCategory,
    IntegrityStatus,
    compute_record_hash,
    serialize_chain,
    verify_chain,
    verify_serialized,
)
from tests.unit.test_audit_record import _valid_body


def _sink(n: int) -> InMemoryAuditSink:
    sink = InMemoryAuditSink()
    for i in range(n):
        result = sink.append(_valid_body(event_id=f"evt-{i}"))
        assert result.ok
    return sink


def _records(n: int) -> list[AuditRecord]:
    return list(_sink(n).records())


# --- generation ---------------------------------------------------


def test_compute_record_hash_is_deterministic() -> None:
    body = _valid_body()
    a = compute_record_hash(
        sequence_number=1, record_id="r1", prev_hash=GENESIS_PREV_HASH, body=body
    )
    b = compute_record_hash(
        sequence_number=1, record_id="r1", prev_hash=GENESIS_PREV_HASH, body=body
    )
    assert a == b
    assert len(a) == 64 and all(c in "0123456789abcdef" for c in a)


def test_hash_changes_with_prev_hash_seq_or_id() -> None:
    body = _valid_body()
    base = compute_record_hash(
        sequence_number=1, record_id="r1", prev_hash=GENESIS_PREV_HASH, body=body
    )
    assert base != compute_record_hash(
        sequence_number=2, record_id="r1", prev_hash=GENESIS_PREV_HASH, body=body
    )
    assert base != compute_record_hash(
        sequence_number=1, record_id="r2", prev_hash=GENESIS_PREV_HASH, body=body
    )
    assert base != compute_record_hash(
        sequence_number=1, record_id="r1", prev_hash="a" * 64, body=body
    )


def test_first_record_links_to_genesis_and_second_links_to_first() -> None:
    records = _records(2)
    assert records[0].prev_hash == GENESIS_PREV_HASH
    assert records[0].sequence_number == 1
    assert records[1].prev_hash == records[0].record_hash
    assert records[1].sequence_number == 2


def test_multiple_records_verify_ok() -> None:
    report = verify_chain(_records(5))
    assert report.status is IntegrityStatus.OK
    assert report.checked_count == 5
    assert report.issues == ()
    assert report.ok is True


def test_empty_chain_reports_empty() -> None:
    report = verify_chain([])
    assert report.status is IntegrityStatus.EMPTY
    assert report.ok is False


# --- tamper detection ------------------------------------------


def test_modifying_a_record_body_is_detected() -> None:
    records = _records(3)
    records[1] = dataclasses.replace(
        records[1],
        body=dataclasses.replace(records[1].body, decision_outcome="DENY"),
    )
    report = verify_chain(records)
    assert report.status is IntegrityStatus.FAILED
    assert IntegrityIssueCategory.RECORD_HASH_MISMATCH in report.categories()


def test_modifying_current_hash_is_detected() -> None:
    records = _records(3)
    records[2] = dataclasses.replace(records[2], record_hash="f" * 64)
    report = verify_chain(records)
    assert IntegrityIssueCategory.RECORD_HASH_MISMATCH in report.categories()


def test_modifying_previous_hash_is_detected() -> None:
    records = _records(3)
    records[2] = dataclasses.replace(records[2], prev_hash="0" * 64)
    report = verify_chain(records)
    cats = report.categories()
    assert IntegrityIssueCategory.CHAIN_LINK_BROKEN in cats
    assert IntegrityIssueCategory.RECORD_HASH_MISMATCH in cats


def test_bad_genesis_link_is_detected() -> None:
    records = _records(2)
    records[0] = dataclasses.replace(records[0], prev_hash="1" * 64)
    report = verify_chain(records)
    assert IntegrityIssueCategory.BAD_GENESIS_LINK in report.categories()


def test_deleting_a_record_is_detected() -> None:
    records = _records(4)
    del records[2]
    report = verify_chain(records)
    cats = report.categories()
    assert IntegrityIssueCategory.SEQUENCE_GAP in cats
    assert IntegrityIssueCategory.CHAIN_LINK_BROKEN in cats


def test_inserting_a_record_is_detected() -> None:
    records = _records(3)
    forged = dataclasses.replace(
        records[1],
        record_id="forged",
        body=dataclasses.replace(records[1].body, event_id="forged-evt"),
    )
    records.insert(2, forged)
    report = verify_chain(records)
    assert report.status is IntegrityStatus.FAILED
    cats = report.categories()
    assert (
        IntegrityIssueCategory.CHAIN_LINK_BROKEN in cats
        or IntegrityIssueCategory.RECORD_HASH_MISMATCH in cats
    )
    assert IntegrityIssueCategory.DUPLICATE_SEQUENCE in cats


def test_reordering_records_is_detected() -> None:
    records = _records(4)
    records[1], records[2] = records[2], records[1]
    report = verify_chain(records)
    assert report.status is IntegrityStatus.FAILED
    assert IntegrityIssueCategory.SEQUENCE_GAP in report.categories()


def test_sequence_number_modification_is_detected() -> None:
    records = _records(3)
    records[1] = dataclasses.replace(records[1], sequence_number=99)
    report = verify_chain(records)
    cats = report.categories()
    assert IntegrityIssueCategory.RECORD_HASH_MISMATCH in cats
    assert IntegrityIssueCategory.SEQUENCE_GAP in cats


def test_malformed_item_in_chain_is_detected() -> None:
    records: list[object] = list(_records(2))
    records.append("not a record")
    report = verify_chain(records)  # type: ignore[arg-type]
    assert IntegrityIssueCategory.MALFORMED_RECORD in report.categories()


def test_verify_serialized_flags_malformed_text() -> None:
    report = verify_serialized("{ this is not valid json")
    assert report.status is IntegrityStatus.FAILED
    assert IntegrityIssueCategory.MALFORMED_RECORD in report.categories()


def test_verify_serialized_of_a_good_chain_is_ok() -> None:
    text = serialize_chain(_records(3))
    assert verify_serialized(text).status is IntegrityStatus.OK


# --- verification does not mutate ---------------------------


def test_verification_does_not_mutate_records() -> None:
    records = _records(4)
    before = [repr(r) for r in records]
    verify_chain(records)
    verify_chain(records)
    assert [repr(r) for r in records] == before


def test_issue_messages_do_not_dump_record_contents() -> None:
    records = _records(2)
    records[1] = dataclasses.replace(
        records[1],
        body=dataclasses.replace(records[1].body, application="secret-app-name"),
    )
    report = verify_chain(records)
    for issue in report.issues:
        assert "secret-app-name" not in issue.detail
        assert issue.sequence_number is not None
        assert issue.record_id is not None
