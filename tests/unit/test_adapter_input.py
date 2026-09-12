"""AdapterInput: the typed, untrusted translation boundary (task Part B)."""

from __future__ import annotations

from typing import Any

import pytest

from contextfence.adapters.errors import AdapterInputError
from contextfence.adapters.input import AUTHORIZATION_SHAPED_KEYS, AdapterInput
from contextfence.core.events import EventGateway
from contextfence.core.models.enums import ActionType, DataClassification, ResourceType
from contextfence.core.models.event import SecurityEvent


def _valid_kwargs(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "application": "claude_code",
        "actor": "claude_code:agent",
        "action": ActionType.FILE_READ,
        "resource": "synthetic/project/notes.txt",
        "resource_type": ResourceType.FILE,
        "data_classification": DataClassification.INTERNAL,
    }
    base.update(overrides)
    return base


def test_minimal_valid_input_defaults() -> None:
    ai = AdapterInput(**_valid_kwargs())
    assert ai.destination is None
    assert ai.requested_capabilities == ()
    assert ai.agent_context is None


def test_string_enums_are_resolved() -> None:
    ai = AdapterInput(
        **_valid_kwargs(
            action="file.write",
            resource_type="file",
            data_classification="SECRET",
        )
    )
    assert ai.action is ActionType.FILE_WRITE
    assert ai.resource_type is ResourceType.FILE
    assert ai.data_classification is DataClassification.SECRET


@pytest.mark.parametrize(
    "field, bad",
    [
        ("action", "file.frobnicate"),
        ("resource_type", "socket"),
        ("data_classification", "TOP_SECRET"),
        ("action", 5),
        ("resource_type", True),
    ],
)
def test_unknown_enum_values_are_rejected(field: str, bad: object) -> None:
    with pytest.raises(AdapterInputError):
        AdapterInput(**_valid_kwargs(**{field: bad}))


@pytest.mark.parametrize("field", ["application", "actor", "resource"])
def test_empty_text_fields_are_rejected(field: str) -> None:
    with pytest.raises(AdapterInputError):
        AdapterInput(**_valid_kwargs(**{field: "   "}))
    with pytest.raises(AdapterInputError):
        AdapterInput(**_valid_kwargs(**{field: None}))


def test_enum_instance_cannot_pose_as_text_field() -> None:
    with pytest.raises(AdapterInputError):
        AdapterInput(**_valid_kwargs(application=DataClassification.NONE))


def test_empty_destination_is_rejected_but_none_is_fine() -> None:
    assert AdapterInput(**_valid_kwargs(destination=None)).destination is None
    with pytest.raises(AdapterInputError):
        AdapterInput(**_valid_kwargs(destination="  "))


def test_capabilities_must_be_tuple_of_nonempty_strings() -> None:
    assert AdapterInput(
        **_valid_kwargs(requested_capabilities=("fs.read", "net.egress"))
    ).requested_capabilities == ("fs.read", "net.egress")
    with pytest.raises(AdapterInputError):
        AdapterInput(**_valid_kwargs(requested_capabilities=["fs.read"]))
    with pytest.raises(AdapterInputError):
        AdapterInput(**_valid_kwargs(requested_capabilities=("",)))


def test_frozen() -> None:
    ai = AdapterInput(**_valid_kwargs())
    with pytest.raises(AttributeError):
        ai.resource = "elsewhere"  # type: ignore[misc]


# -- from_mapping: unknown + authorization-shaped keys ---------------------


def test_from_mapping_round_trips_a_valid_mapping() -> None:
    ai = AdapterInput.from_mapping(
        {
            "application": "claude_code",
            "actor": "claude_code:agent",
            "action": "file.read",
            "resource": "notes.txt",
            "resource_type": "file",
            "data_classification": "INTERNAL",
            "requested_capabilities": ["fs.read"],
            "agent_context": "read the notes",
        }
    )
    assert ai.action is ActionType.FILE_READ
    assert ai.agent_context == "read the notes"


@pytest.mark.parametrize("key", sorted(AUTHORIZATION_SHAPED_KEYS))
def test_from_mapping_rejects_every_authorization_shaped_key(key: str) -> None:
    mapping = {
        "application": "claude_code",
        "actor": "claude_code:agent",
        "action": "file.read",
        "resource": "notes.txt",
        "resource_type": "file",
        "data_classification": "INTERNAL",
        key: True,
    }
    with pytest.raises(AdapterInputError) as excinfo:
        AdapterInput.from_mapping(mapping)
    assert "authorization-shaped" in str(excinfo.value)


def test_from_mapping_rejects_other_unknown_keys() -> None:
    with pytest.raises(AdapterInputError):
        AdapterInput.from_mapping(
            {
                "application": "claude_code",
                "actor": "a",
                "action": "file.read",
                "resource": "n",
                "resource_type": "file",
                "data_classification": "INTERNAL",
                "cwd": "/somewhere",
            }
        )


def test_from_mapping_rejects_non_mapping() -> None:
    with pytest.raises(AdapterInputError):
        AdapterInput.from_mapping(["not", "a", "map"])  # type: ignore[arg-type]


def test_from_mapping_reports_missing_required_field() -> None:
    with pytest.raises(AdapterInputError):
        AdapterInput.from_mapping(
            {"application": "claude_code", "actor": "a", "action": "file.read"}
        )


# -- to_raw_event feeds the Event Gateway unchanged ----------------------


def test_to_raw_event_is_admitted_by_the_gateway() -> None:
    ai = AdapterInput(
        **_valid_kwargs(
            action=ActionType.NETWORK_SEND,
            resource="https://example.invalid/x",
            resource_type=ResourceType.URL,
            destination="example.invalid",
            requested_capabilities=("net.egress",),
            agent_context="send the report",
        )
    )
    raw = ai.to_raw_event()
    assert "event_id" not in raw
    assert "timestamp" not in raw
    assert "semantic_signals" not in raw

    event = EventGateway().admit(raw)
    assert isinstance(event, SecurityEvent)
    assert event.application == "claude_code"
    assert event.action is ActionType.NETWORK_SEND
    assert event.destination == "example.invalid"
    assert event.policy_context.user_declared_task == "send the report"
    # agent context lands only in the non-authoritative context slot
    assert not hasattr(event, "approved")
