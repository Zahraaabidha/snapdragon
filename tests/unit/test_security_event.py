"""SecurityEvent canonical model: direct construction and self-validation."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timezone

import pytest

from contextfence.core.errors import ValidationError
from contextfence.core.models.enums import (
    ActionType,
    DataClassification,
    EvidenceCategory,
    EvidenceSource,
    ResourceType,
    Severity,
)
from contextfence.core.models.event import SecurityEvent
from contextfence.core.models.evidence import Evidence
from contextfence.core.models.policy_context import PolicyContext
from tests.unit._factories import VALID_TS, VALID_UUID, valid_event


def test_valid_direct_construction() -> None:
    event = valid_event()
    assert event.event_id == VALID_UUID
    assert event.action is ActionType.FILE_READ
    assert event.destination is None
    assert event.requested_capabilities == ("fs.read",)
    assert event.semantic_signals == ()
    assert isinstance(event.policy_context, PolicyContext)


def test_event_is_frozen() -> None:
    event = valid_event()
    with pytest.raises(dataclasses.FrozenInstanceError):
        event.resource = "elsewhere"  # type: ignore[misc]


@pytest.mark.parametrize(
    "field, value",
    [
        ("event_id", ""),
        ("actor", "   "),
        ("application", ""),
        ("resource", ""),
        ("action", "file.read"),
        ("resource_type", "file"),
        ("data_classification", "INTERNAL"),
    ],
)
def test_invalid_or_wrongly_typed_fields_are_rejected(
    field: str, value: object
) -> None:
    with pytest.raises(ValidationError):
        valid_event(**{field: value})


def test_naive_timestamp_is_rejected() -> None:
    with pytest.raises(ValidationError):
        valid_event(timestamp=datetime(2026, 1, 1, 12, 0, 0))


def test_timestamp_is_normalized_to_utc() -> None:
    # A tz-aware non-UTC instant is valid and canonicalized, not rejected.
    from datetime import timedelta

    plus_two = timezone(timedelta(hours=2))
    event = valid_event(timestamp=datetime(2026, 1, 1, 14, 0, 0, tzinfo=plus_two))
    assert event.timestamp == VALID_TS
    assert event.timestamp.tzinfo == UTC


def test_timestamp_must_be_a_datetime() -> None:
    with pytest.raises(ValidationError):
        valid_event(timestamp="2026-01-01T12:00:00+00:00")


def test_destination_none_is_preserved_not_defaulted() -> None:
    event = valid_event(destination=None)
    assert event.destination is None


def test_destination_when_present_must_be_non_empty_string() -> None:
    assert (
        valid_event(destination="synthetic.invalid").destination == "synthetic.invalid"
    )
    with pytest.raises(ValidationError):
        valid_event(destination="")


def test_data_classification_none_only_when_explicitly_set() -> None:
    # NONE is a real, explicit classification -- never an implicit fallback.
    event = valid_event(data_classification=DataClassification.NONE)
    assert event.data_classification is DataClassification.NONE


def test_semantic_signals_must_come_from_semantic_analyzer() -> None:
    semantic = Evidence(
        source=EvidenceSource.SEMANTIC_ANALYZER,
        category=EvidenceCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        confidence=0.55,
    )
    event = valid_event(semantic_signals=(semantic,))
    assert event.semantic_signals == (semantic,)

    non_semantic = Evidence(
        source=EvidenceSource.SECRET_DETECTOR,
        category=EvidenceCategory.CREDENTIAL,
        severity=Severity.CRITICAL,
        confidence=0.99,
    )
    with pytest.raises(ValidationError):
        valid_event(semantic_signals=(non_semantic,))


def test_requested_capabilities_must_be_tuple_of_non_empty_strings() -> None:
    assert valid_event(requested_capabilities=()).requested_capabilities == ()
    with pytest.raises(ValidationError):
        valid_event(requested_capabilities=["fs.read"])
    with pytest.raises(ValidationError):
        valid_event(requested_capabilities=("",))


def test_policy_context_must_be_a_policy_context_instance() -> None:
    with pytest.raises(ValidationError):
        valid_event(policy_context={"profile_id": "p"})


def test_policy_context_default_is_empty_and_non_authoritative() -> None:
    event = SecurityEvent(
        event_id=VALID_UUID,
        timestamp=VALID_TS,
        actor="synthetic-agent",
        application="synthetic_app",
        action=ActionType.FILE_READ,
        resource="synthetic/notes.txt",
        resource_type=ResourceType.FILE,
        data_classification=DataClassification.INTERNAL,
    )
    assert event.policy_context.profile_id is None
    assert event.policy_context.prior_decision_ids == ()
