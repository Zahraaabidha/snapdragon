"""CapabilityDetector: inherently-sensitive capabilities and actions."""

from __future__ import annotations

import pytest

from contextfence.analysis.capability import CapabilityDetector
from contextfence.core.models.decision import Decision
from contextfence.core.models.enums import (
    ActionType,
    DataClassification,
    EvidenceCategory,
    EvidenceSource,
    ResourceType,
    Severity,
)
from contextfence.core.models.evidence import Evidence
from tests.unit._factories import valid_event


def _analyze(**overrides: object) -> tuple[Evidence, ...]:
    return CapabilityDetector().analyze(valid_event(**overrides))


def _rules(findings: tuple[Evidence, ...]) -> set[str]:
    return {e.metadata["rule_id"] for e in findings}


@pytest.mark.parametrize(
    "capability, rule, category, severity",
    [
        (
            "exec",
            "CAPABILITY.COMMAND_EXECUTION",
            EvidenceCategory.EXCESSIVE_CAPABILITY,
            Severity.HIGH,
        ),
        (
            "net.egress",
            "CAPABILITY.NETWORK_EGRESS",
            EvidenceCategory.EXTERNAL_DATA_TRANSFER,
            Severity.HIGH,
        ),
        (
            "secrets.read",
            "CAPABILITY.CREDENTIAL_ACCESS",
            EvidenceCategory.CREDENTIAL,
            Severity.HIGH,
        ),
        (
            "fs.write",
            "CAPABILITY.FILESYSTEM_WRITE",
            EvidenceCategory.EXCESSIVE_CAPABILITY,
            Severity.MEDIUM,
        ),
    ],
)
def test_identifies_supported_sensitive_capabilities(
    capability: str, rule: str, category: EvidenceCategory, severity: Severity
) -> None:
    (evidence,) = _analyze(requested_capabilities=(capability,))
    assert evidence.metadata["rule_id"] == rule
    assert evidence.category is category
    assert evidence.severity is severity
    assert evidence.source is EvidenceSource.CAPABILITY_ANALYZER
    assert evidence.metadata["capability"] == capability


def test_capability_matching_is_case_insensitive() -> None:
    assert "CAPABILITY.COMMAND_EXECUTION" in _rules(
        _analyze(requested_capabilities=("EXEC",))
    )


def test_plain_fs_read_only_flagged_in_sensitive_context() -> None:
    assert _analyze(requested_capabilities=("fs.read",)) == ()
    sensitive = _analyze(
        requested_capabilities=("fs.read",),
        data_classification=DataClassification.SECRET,
    )
    assert "CAPABILITY.SENSITIVE_FILESYSTEM_READ" in _rules(sensitive)


@pytest.mark.parametrize(
    "action, resource_type, rule",
    [
        (
            ActionType.COMMAND_EXEC,
            ResourceType.COMMAND,
            "CAPABILITY.COMMAND_EXECUTION_ACTION",
        ),
        (
            ActionType.FILE_DELETE,
            ResourceType.FILE,
            "CAPABILITY.DESTRUCTIVE_FILE_ACTION",
        ),
        (ActionType.NETWORK_SEND, ResourceType.URL, "CAPABILITY.NETWORK_EGRESS_ACTION"),
    ],
)
def test_sensitive_actions_are_flagged_independently_of_capabilities(
    action: ActionType, resource_type: ResourceType, rule: str
) -> None:
    findings = _analyze(
        action=action, resource_type=resource_type, requested_capabilities=()
    )
    assert rule in _rules(findings)


def test_benign_event_produces_no_capability_evidence() -> None:
    assert _analyze() == ()  # action=file.read, capability=fs.read, class=INTERNAL


def test_returns_evidence_not_decision() -> None:
    for e in _analyze(requested_capabilities=("exec", "net.egress")):
        assert isinstance(e, Evidence)
        assert not isinstance(e, Decision)


def test_severity_and_confidence_are_separate() -> None:
    (evidence,) = _analyze(requested_capabilities=("exec",))
    assert isinstance(evidence.severity, Severity)
    assert isinstance(evidence.confidence, float)
    assert evidence.severity is Severity.HIGH
    assert evidence.confidence == pytest.approx(0.9)


def test_input_event_is_not_mutated() -> None:
    event = valid_event(requested_capabilities=("exec", "net.egress", "secrets.read"))
    snapshot = repr(event)
    CapabilityDetector().analyze(event)
    assert repr(event) == snapshot
    assert event.requested_capabilities == ("exec", "net.egress", "secrets.read")
