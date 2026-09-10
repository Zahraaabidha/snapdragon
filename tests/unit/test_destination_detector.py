"""DestinationDetector: local vs external vs malformed classification evidence."""

from __future__ import annotations

import pytest

from contextfence.analysis.destination import DestinationDetector
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

_EXTERNAL = "https://api.synthetic-collector.invalid/upload"


def _analyze(**overrides: object) -> tuple[Evidence, ...]:
    return DestinationDetector().analyze(valid_event(**overrides))


@pytest.mark.parametrize(
    "destination",
    [
        "http://localhost:8080/x",
        "http://127.0.0.1/health",
        "https://10.1.2.3/internal",
        "http://192.168.0.9:9000",
        "file:///home/user/output.txt",
        "./relative/output.txt",
        "/var/tmp/output.txt",
        "service.local",
    ],
)
def test_local_destinations_produce_no_evidence(destination: str) -> None:
    assert _analyze(destination=destination, resource_type=ResourceType.URL) == ()


def test_external_destination_is_flagged_with_classification_scaled_severity() -> None:
    low = _analyze(destination=_EXTERNAL, data_classification=DataClassification.NONE)
    assert [e.metadata["rule_id"] for e in low] == ["DESTINATION.EXTERNAL"]
    assert low[0].severity is Severity.LOW
    assert low[0].category is EvidenceCategory.EXTERNAL_DATA_TRANSFER
    assert low[0].source is EvidenceSource.DESTINATION_CLASSIFIER

    high = _analyze(
        destination=_EXTERNAL, data_classification=DataClassification.PERSONAL_DATA
    )
    assert high[0].severity is Severity.HIGH


def test_sensitive_egress_adds_a_second_finding() -> None:
    findings = _analyze(
        destination=_EXTERNAL,
        action=ActionType.NETWORK_SEND,
        data_classification=DataClassification.CREDENTIAL,
    )
    rules = [e.metadata["rule_id"] for e in findings]
    assert rules == ["DESTINATION.EXTERNAL", "DESTINATION.SENSITIVE_EGRESS"]
    assert all(e.severity is Severity.CRITICAL for e in findings)


@pytest.mark.parametrize(
    "destination",
    ["weird-scheme://host.invalid/x", "https://exfil\x01.invalid", "::::"],
)
def test_malformed_destination_form_is_flagged(destination: str) -> None:
    findings = _analyze(destination=destination)
    assert [e.metadata["rule_id"] for e in findings] == ["DESTINATION.MALFORMED_FORM"]
    assert findings[0].severity is Severity.MEDIUM


def test_network_send_with_no_destination_is_flagged() -> None:
    findings = _analyze(destination=None, action=ActionType.NETWORK_SEND)
    assert [e.metadata["rule_id"] for e in findings] == [
        "DESTINATION.UNSPECIFIED_EGRESS"
    ]
    assert findings[0].confidence == pytest.approx(0.4)
    # non-egress action with no destination stays silent
    assert _analyze(destination=None, action=ActionType.FILE_READ) == ()


def test_raw_destination_string_is_not_in_metadata() -> None:
    secretish = "https://user:sYnThEtIcT0ken@api.host.invalid/p?key=sYnThEtIcT0ken"
    findings = _analyze(
        destination=secretish, data_classification=DataClassification.SECRET
    )
    assert findings
    for e in findings:
        blob = " ".join(e.metadata.values())
        assert "sYnThEtIcT0ken" not in blob
        assert "api.host.invalid" not in blob


def test_returns_evidence_not_decision() -> None:
    for e in _analyze(destination=_EXTERNAL):
        assert isinstance(e, Evidence)
        assert not isinstance(e, Decision)


def test_input_event_is_not_mutated() -> None:
    event = valid_event(destination=_EXTERNAL, action=ActionType.NETWORK_SEND)
    snapshot = repr(event)
    DestinationDetector().analyze(event)
    assert repr(event) == snapshot
