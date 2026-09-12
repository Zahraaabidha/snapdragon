"""The generic SecurityPipeline: analysis -> risk -> policy -> enforcement -> audit."""

from __future__ import annotations

import pytest

from contextfence.audit.serialization import canonical_json, record_to_dict
from contextfence.audit.sink import InMemoryAuditSink
from contextfence.core.models.enums import (
    ActionType,
    DataClassification,
    DecisionOutcome,
    ResourceType,
)
from contextfence.enforcement.results import EnforcementOutcome
from contextfence.pipeline import PipelineResult, SecurityPipeline
from contextfence.policy.default_policy import DEFAULT_POLICY
from contextfence.policy.engine import PolicyEngine
from tests.unit._factories import valid_event, valid_raw_event


def _pipeline(sink: InMemoryAuditSink | None = None) -> SecurityPipeline:
    return SecurityPipeline(policy_engine=PolicyEngine(DEFAULT_POLICY), audit_sink=sink)


def test_safe_local_read_is_allowed() -> None:
    event = valid_event(
        action=ActionType.FILE_READ,
        resource_type=ResourceType.FILE,
        data_classification=DataClassification.NONE,
        resource="synthetic/project/readme.md",
    )
    result = _pipeline().process(event)
    assert isinstance(result, PipelineResult)
    assert result.decision_outcome is DecisionOutcome.ALLOW
    assert result.enforcement_outcome is EnforcementOutcome.ALLOWED
    assert result.permitted_to_proceed is True


def test_protected_secret_is_denied() -> None:
    event = valid_event(
        action=ActionType.FILE_READ,
        resource=".env",
        data_classification=DataClassification.CREDENTIAL,
    )
    result = _pipeline().process(event)
    assert result.decision_outcome is DecisionOutcome.DENY
    assert result.enforcement_outcome is EnforcementOutcome.DENIED
    assert result.permitted_to_proceed is False


def test_command_execution_requires_approval() -> None:
    event = valid_event(
        action=ActionType.COMMAND_EXEC,
        resource="pytest -q",
        resource_type=ResourceType.COMMAND,
        data_classification=DataClassification.NONE,
    )
    result = _pipeline().process(event)
    assert result.decision_outcome is DecisionOutcome.ASK
    assert result.enforcement_outcome is EnforcementOutcome.APPROVAL_REQUIRED
    assert result.enforcement.approval_request is not None


def test_pipeline_admits_raw_events_through_the_gateway() -> None:
    result = _pipeline().submit(valid_raw_event())
    assert result.decision_outcome in set(DecisionOutcome)
    assert result.event.event_id


def test_process_rejects_a_non_security_event() -> None:
    with pytest.raises(TypeError):
        _pipeline().process({"not": "an event"})  # type: ignore[arg-type]


def test_audit_is_recorded_when_a_sink_is_present() -> None:
    sink = InMemoryAuditSink()
    result = _pipeline(sink).process(valid_event())
    assert result.audit_recorded is True
    assert len(sink) == 1
    assert sink.verify().ok


def test_audit_is_skipped_without_a_sink() -> None:
    result = _pipeline().process(valid_event())
    assert result.audit_append is None
    assert result.audit_recorded is False


def test_no_raw_secret_or_resource_reaches_the_audit_record() -> None:
    synthetic_secret = "AKIAIOSFODNN7EXAMPLE"
    sink = InMemoryAuditSink()
    event = valid_event(
        action=ActionType.FILE_READ,
        resource=f"config with {synthetic_secret} inside",
        data_classification=DataClassification.INTERNAL,
    )
    _pipeline(sink).process(event)
    serialized = canonical_json(record_to_dict(sink.records()[0]))
    assert synthetic_secret not in serialized
    assert "config with" not in serialized


def test_pipeline_is_deterministic_for_the_same_event() -> None:
    event = valid_event(
        action=ActionType.COMMAND_EXEC,
        resource="pytest -q",
        resource_type=ResourceType.COMMAND,
    )
    a = _pipeline().process(event)
    b = _pipeline().process(event)
    assert a.decision.outcome is b.decision.outcome
    assert a.decision.matched_rule_id == b.decision.matched_rule_id
    assert a.risk_view.categories == b.risk_view.categories
