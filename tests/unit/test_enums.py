"""Enum vocabulary: members, string values, and rejection of unknown values."""

from __future__ import annotations

import pytest

from contextfence.core.models.enums import (
    ActionType,
    DataClassification,
    DecisionOutcome,
    EvidenceCategory,
    EvidenceSource,
    ResourceType,
    Severity,
)


def test_decision_outcome_has_exactly_the_four_documented_outcomes() -> None:
    assert {o.value for o in DecisionOutcome} == {"ALLOW", "ASK", "DENY", "SANITIZE"}


def test_severity_levels_are_the_four_documented_levels() -> None:
    assert {s.value for s in Severity} == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def test_data_classification_has_no_unknown_member() -> None:
    # There is deliberately no UNKNOWN / OTHER: an absent classification is a
    # malformed event, not a silently-permissive default.
    assert "UNKNOWN" not in DataClassification.__members__
    assert "OTHER" not in DataClassification.__members__
    assert DataClassification.NONE.value == "NONE"


def test_action_and_resource_type_use_dotted_string_values() -> None:
    assert ActionType.FILE_READ.value == "file.read"
    assert ActionType.NETWORK_SEND.value == "network.send"
    assert ResourceType.URL.value == "url"


@pytest.mark.parametrize(
    "enum_cls, bad_value",
    [
        (Severity, "severe"),
        (DecisionOutcome, "MAYBE"),
        (DataClassification, "TOP_SECRET"),
        (EvidenceCategory, "SOMETHING_ELSE"),
        (EvidenceSource, "MYSTERY_DETECTOR"),
        (ActionType, "file.frobnicate"),
        (ResourceType, "socket"),
    ],
)
def test_unknown_string_is_rejected_by_enum_lookup(
    enum_cls: type, bad_value: str
) -> None:
    with pytest.raises(ValueError):
        enum_cls(bad_value)


def test_evidence_source_includes_semantic_analyzer() -> None:
    assert EvidenceSource.SEMANTIC_ANALYZER.value == "SEMANTIC_ANALYZER"
