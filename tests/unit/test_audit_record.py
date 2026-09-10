"""Phase 6: AuditRecordBody / AuditRecord validation, immutability, privacy."""

from __future__ import annotations

import dataclasses

import pytest

from contextfence.audit import (
    AUDIT_SCHEMA_VERSION,
    ApprovalState,
    AuditRecord,
    AuditRecordBody,
    DestinationCategory,
    SanitizationState,
    build_audit_body,
)
from contextfence.audit.record import _FINGERPRINT_RE
from contextfence.core.models.decision import Decision
from contextfence.core.models.enums import (
    ActionType,
    DataClassification,
    DecisionOutcome,
    EvidenceCategory,
    EvidenceSource,
    ResourceType,
    Severity,
)
from contextfence.core.models.evidence import Evidence
from contextfence.core.models.policy_context import PolicyContext
from contextfence.core.risk import aggregate_evidence
from contextfence.enforcement import (
    ApprovalResponse,
    ApprovalResponseKind,
    EnforcementGate,
)
from tests.unit._factories import valid_event

# --- synthetic sensitive values that must NEVER appear in a record ------
FAKE_API_KEY = "AKIAIOSFODNN7EXAMPLE"
FAKE_BEARER = "Bearer synthetic-tok-abcdefghij0123456789"
FAKE_PASSWORD = "hunter2-synthetic-not-real"
FAKE_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.c3ludGhldGlj"
FAKE_EMAIL = "alex.doe@synthetic.invalid"
FAKE_PHONE = "+1 (555) 010-1234"
FAKE_CARD = "4111 1111 1111 1111"
FAKE_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----"
ALL_SECRETS = (
    FAKE_API_KEY,
    FAKE_BEARER,
    FAKE_PASSWORD,
    FAKE_JWT,
    FAKE_EMAIL,
    FAKE_PHONE,
    FAKE_CARD,
    FAKE_PRIVATE_KEY,
)

GATE = EnforcementGate()


def _valid_body(**overrides: object) -> AuditRecordBody:
    base: dict[str, object] = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "event_id": "evt-1",
        "occurred_at": "2026-01-01T12:00:00+00:00",
        "application": "claude_code",
        "actor_fingerprint": "sha256:000000000000",
        "action": ActionType.FILE_READ.value,
        "resource_type": ResourceType.FILE.value,
        "resource_fingerprint": "sha256:0123456789ab",
        "data_classification": DataClassification.NONE.value,
        "destination_category": DestinationCategory.ABSENT.value,
        "highest_severity": None,
        "max_confidence": None,
        "evidence_categories": (),
        "semantic_evidence_available": False,
        "evidence_count": 0,
        "decision_outcome": DecisionOutcome.ALLOW.value,
        "matched_rule_id": "ALLOW.SAFE_LOCAL_READ",
        "enforcement_outcome": "ALLOWED",
        "enforcement_error_category": "NONE",
        "approval_state": ApprovalState.NOT_REQUIRED.value,
        "sanitization_state": SanitizationState.NOT_APPLICABLE.value,
        "sanitized_span_count": 0,
    }
    base.update(overrides)
    return AuditRecordBody(**base)  # type: ignore[arg-type]


# --- validation --------------------------------------------------------


def test_valid_body_constructs() -> None:
    body = _valid_body()
    assert body.schema_version == AUDIT_SCHEMA_VERSION
    assert body.destination_fingerprint is None
    assert body.provider_metadata == ()


@pytest.mark.parametrize(
    "field, value",
    [
        ("schema_version", 999),
        ("event_id", "  "),
        ("occurred_at", "not-a-timestamp"),
        ("actor_fingerprint", "pl://nope"),
        ("resource_fingerprint", "sha256:XYZ"),
        ("action", "file.frobnicate"),
        ("resource_type", "socket"),
        ("data_classification", "TOP_SECRET"),
        ("destination_category", "MAYBE"),
        ("decision_outcome", "MAYBE"),
        ("enforcement_outcome", "MAYBE"),
        ("enforcement_error_category", "KABOOM"),
        ("approval_state", "MAYBE"),
        ("sanitization_state", "MAYBE"),
        ("highest_severity", "SEVERE"),
        ("max_confidence", "0.9"),
        ("max_confidence", "1.234"),
        ("evidence_count", -1),
        ("sanitized_span_count", -2),
        ("semantic_evidence_available", 1),
        ("evidence_categories", ("PERSONAL_DATA", "CREDENTIAL")),  # not sorted
        ("evidence_categories", ("MADE_UP",)),
    ],
)
def test_body_rejects_bad_fields(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        _valid_body(**{field: value})


def test_body_rejects_unknown_provider_metadata_shape() -> None:
    with pytest.raises(ValueError):
        _valid_body(provider_metadata=({"k": "v"},))
    with pytest.raises(ValueError):
        _valid_body(provider_metadata=(("b", "1"), ("a", "2")))  # not sorted
    with pytest.raises(ValueError):
        _valid_body(provider_metadata=(("k", "x" * 200),))  # too long
    with pytest.raises(ValueError):
        _valid_body(provider_metadata=(("k", "line1\nline2"),))  # control char


def test_body_and_record_are_frozen() -> None:
    body = _valid_body()
    with pytest.raises(dataclasses.FrozenInstanceError):
        body.decision_outcome = "DENY"  # type: ignore[misc]
    record = AuditRecord(
        sequence_number=1,
        record_id="r1",
        prev_hash="0" * 64,
        record_hash="a" * 64,
        body=body,
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        record.sequence_number = 2  # type: ignore[misc]


@pytest.mark.parametrize(
    "field, value",
    [
        ("sequence_number", 0),
        ("sequence_number", -1),
        ("record_id", ""),
        ("prev_hash", "0" * 63),
        ("prev_hash", "Z" * 64),
        ("record_hash", "not hex"),
    ],
)
def test_record_rejects_bad_envelope(field: str, value: object) -> None:
    kwargs: dict[str, object] = {
        "sequence_number": 1,
        "record_id": "r1",
        "prev_hash": "0" * 64,
        "record_hash": "a" * 64,
        "body": _valid_body(),
    }
    kwargs[field] = value
    with pytest.raises(ValueError):
        AuditRecord(**kwargs)  # type: ignore[arg-type]


def test_record_does_not_verify_hash_correctness_at_construction() -> None:
    # a structurally valid but cryptographically wrong record is allowed to
    # exist so corruption can be represented and later detected.
    AuditRecord(
        sequence_number=1,
        record_id="r1",
        prev_hash="0" * 64,
        record_hash="f" * 64,
        body=_valid_body(),
    )


# --- build_audit_body: derivation + privacy --------------------------


def _pipeline_body(**event_overrides: object) -> AuditRecordBody:
    event = valid_event(**event_overrides)
    evidence = [
        Evidence(
            source=EvidenceSource.SECRET_DETECTOR,
            category=EvidenceCategory.CREDENTIAL,
            severity=Severity.CRITICAL,
            confidence=0.99,
            metadata={"rule_id": "SECRET.AWS_ACCESS_KEY_ID"},
        )
    ]
    risk_view = aggregate_evidence(evidence)
    decision = Decision(
        outcome=DecisionOutcome.DENY,
        matched_rule_id="DENY.CREDENTIAL_EVIDENCE",
        rationale=(f"a detector found credential material {FAKE_API_KEY}",),
    )
    result = GATE.enforce(decision, event=event, risk_view=risk_view, evidence=evidence)
    return build_audit_body(
        event=event, risk_view=risk_view, decision=decision, enforcement_result=result
    )


def test_build_audit_body_derives_structural_facts() -> None:
    body = _pipeline_body(
        action=ActionType.NETWORK_SEND,
        resource_type=ResourceType.URL,
        data_classification=DataClassification.CREDENTIAL,
        destination="https://api.synthetic.invalid/u",
    )
    assert body.action == "network.send"
    assert body.resource_type == "url"
    assert body.data_classification == "CREDENTIAL"
    assert body.destination_category == "PRESENT"
    assert body.destination_fingerprint is not None
    assert _FINGERPRINT_RE.match(body.destination_fingerprint)
    assert body.highest_severity == "CRITICAL"
    assert body.max_confidence == "0.99"
    assert body.evidence_categories == ("CREDENTIAL",)
    assert body.decision_outcome == "DENY"
    assert body.matched_rule_id == "DENY.CREDENTIAL_EVIDENCE"
    assert body.enforcement_outcome == "DENIED"
    assert body.approval_state == "NOT_REQUIRED"
    assert body.sanitization_state == "NOT_APPLICABLE"


def test_build_audit_body_never_contains_raw_sensitive_values() -> None:
    body = _pipeline_body(
        actor="claude-code:agent",
        resource=f"vault/{FAKE_API_KEY}/{FAKE_EMAIL}/{FAKE_PRIVATE_KEY}",
        resource_type=ResourceType.URL,
        action=ActionType.NETWORK_SEND,
        destination=f"https://user:{FAKE_BEARER}@host.invalid/?jwt={FAKE_JWT}",
        policy_context=PolicyContext(
            user_declared_task=f"send {FAKE_PASSWORD} and card {FAKE_CARD} please"
        ),
    )
    blob = (
        repr(body) + " " + " ".join(str(v) for v in dataclasses.asdict(body).values())
    )
    for secret in ALL_SECRETS:
        assert secret not in blob
        assert secret.lower() not in blob.lower()
    # only fingerprints represent resource / destination / actor
    assert body.resource_fingerprint.startswith("sha256:")
    assert body.actor_fingerprint.startswith("sha256:")
    assert "claude-code:agent" not in blob


def test_build_audit_body_maps_approval_state_from_response() -> None:
    event = valid_event(
        action=ActionType.COMMAND_EXEC, resource_type=ResourceType.COMMAND
    )
    decision = Decision(
        outcome=DecisionOutcome.ASK,
        matched_rule_id="ASK.COMMAND_EXECUTION",
        rationale=("command execution requires review",),
    )
    result = GATE.enforce(decision, event=event, risk_view=aggregate_evidence([]))
    for kind, expected in [
        (ApprovalResponseKind.APPROVE, "APPROVED"),
        (ApprovalResponseKind.REJECT, "REJECTED"),
        (ApprovalResponseKind.EXPIRED, "EXPIRED"),
        (ApprovalResponseKind.INVALID, "INVALID"),
    ]:
        body = build_audit_body(
            event=event,
            risk_view=aggregate_evidence([]),
            decision=decision,
            enforcement_result=result,
            approval_response=ApprovalResponse(
                request_id=result.approval_request.request_id,  # type: ignore[union-attr]
                kind=kind,
            ),
        )
        assert body.approval_state == expected
    # no response -> still REQUIRED, never APPROVED by default
    pending = build_audit_body(
        event=event,
        risk_view=aggregate_evidence([]),
        decision=decision,
        enforcement_result=result,
    )
    assert pending.approval_state == "REQUIRED"


def test_build_audit_body_records_sanitization_state() -> None:
    event = valid_event(
        action=ActionType.NETWORK_SEND,
        resource_type=ResourceType.URL,
        data_classification=DataClassification.INTERNAL,
        destination="https://api.synthetic.invalid/u",
    )
    text = f"mail {FAKE_EMAIL}"
    pii = Evidence(
        source=EvidenceSource.PII_DETECTOR,
        category=EvidenceCategory.PERSONAL_DATA,
        severity=Severity.HIGH,
        confidence=0.9,
        metadata={
            "rule_id": "PII.EMAIL",
            "match_offset": str(text.index(FAKE_EMAIL)),
            "match_length": str(len(FAKE_EMAIL)),
        },
    )
    dest = Evidence(
        source=EvidenceSource.DESTINATION_CLASSIFIER,
        category=EvidenceCategory.EXTERNAL_DATA_TRANSFER,
        severity=Severity.MEDIUM,
        confidence=0.8,
        metadata={"rule_id": "DESTINATION.EXTERNAL"},
    )
    evidence = [pii, dest]
    risk_view = aggregate_evidence(evidence)
    decision = Decision(
        outcome=DecisionOutcome.SANITIZE,
        matched_rule_id="SANITIZE.PII_EXTERNAL_TRANSFER",
        rationale=("pii external transfer",),
    )
    result = GATE.enforce(decision, evidence=evidence, payload=text)
    body = build_audit_body(
        event=event, risk_view=risk_view, decision=decision, enforcement_result=result
    )
    assert body.sanitization_state == "PERFORMED"
    assert body.sanitized_span_count == 1
    assert FAKE_EMAIL not in repr(body)


def test_build_audit_body_does_not_mutate_its_inputs() -> None:
    event = valid_event(data_classification=DataClassification.CREDENTIAL)
    evidence = [
        Evidence(
            source=EvidenceSource.SECRET_DETECTOR,
            category=EvidenceCategory.CREDENTIAL,
            severity=Severity.CRITICAL,
            confidence=0.9,
            metadata={"rule_id": "SECRET.X"},
        )
    ]
    risk_view = aggregate_evidence(evidence)
    decision = Decision(
        outcome=DecisionOutcome.DENY, matched_rule_id="DENY.X", rationale=("x",)
    )
    result = GATE.enforce(decision, event=event, risk_view=risk_view, evidence=evidence)
    snap = (
        repr(event),
        [repr(e) for e in evidence],
        repr(risk_view),
        repr(decision),
        repr(result),
    )
    build_audit_body(
        event=event, risk_view=risk_view, decision=decision, enforcement_result=result
    )
    assert (
        repr(event),
        [repr(e) for e in evidence],
        repr(risk_view),
        repr(decision),
        repr(result),
    ) == snap
