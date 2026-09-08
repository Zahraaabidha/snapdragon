"""Event Gateway: the validation boundary."""

from __future__ import annotations

from datetime import UTC, datetime, timezone

import pytest

from contextfence.core.errors import MalformedEventError
from contextfence.core.events import EventGateway
from contextfence.core.models.enums import (
    ActionType,
    DataClassification,
    ResourceType,
)
from contextfence.core.models.event import SecurityEvent
from tests.unit._factories import VALID_UUID, valid_raw_event


@pytest.fixture()
def gateway() -> EventGateway:
    return EventGateway()


def test_admits_a_well_formed_event(gateway: EventGateway) -> None:
    event = gateway.admit(valid_raw_event())
    assert isinstance(event, SecurityEvent)
    assert event.event_id == VALID_UUID
    assert event.action is ActionType.FILE_READ
    assert event.resource_type is ResourceType.FILE
    assert event.data_classification is DataClassification.INTERNAL
    assert event.timestamp == datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    assert event.destination is None
    assert event.semantic_signals == ()


@pytest.mark.parametrize("bad", [None, 42, "a string", ["a", "list"], object()])
def test_non_mapping_input_is_rejected(gateway: EventGateway, bad: object) -> None:
    with pytest.raises(MalformedEventError):
        gateway.admit(bad)  # type: ignore[arg-type]


def test_unknown_top_level_key_is_rejected(gateway: EventGateway) -> None:
    with pytest.raises(MalformedEventError):
        gateway.admit(valid_raw_event(decision="ALLOW"))
    with pytest.raises(MalformedEventError):
        gateway.admit(valid_raw_event(authorized=True))


@pytest.mark.parametrize(
    "missing",
    [
        "actor",
        "application",
        "action",
        "resource",
        "resource_type",
        "data_classification",
        "requested_capabilities",
    ],
)
def test_missing_required_field_is_rejected(
    gateway: EventGateway, missing: str
) -> None:
    raw = valid_raw_event()
    del raw[missing]
    with pytest.raises(MalformedEventError):
        gateway.admit(raw)


@pytest.mark.parametrize(
    "missing",
    [
        "actor",
        "application",
        "action",
        "resource",
        "resource_type",
        "data_classification",
        "requested_capabilities",
    ],
)
def test_explicit_none_for_required_field_is_rejected(
    gateway: EventGateway, missing: str
) -> None:
    with pytest.raises(MalformedEventError):
        gateway.admit(valid_raw_event(**{missing: None}))


@pytest.mark.parametrize(
    "field, bad_value",
    [
        ("action", "file.frobnicate"),
        ("resource_type", "socket"),
        ("data_classification", "TOP_SECRET"),
        ("action", 5),
        ("resource_type", True),
    ],
)
def test_invalid_enum_values_are_rejected(
    gateway: EventGateway, field: str, bad_value: object
) -> None:
    with pytest.raises(MalformedEventError):
        gateway.admit(valid_raw_event(**{field: bad_value}))


# -- event_id handling ------------------------------------------------------


def test_event_id_is_minted_when_absent(gateway: EventGateway) -> None:
    raw = valid_raw_event()
    del raw["event_id"]
    event = gateway.admit(raw)
    # A syntactically valid UUID string was assigned.
    from uuid import UUID

    assert str(UUID(event.event_id)) == event.event_id


def test_event_id_is_minted_when_none(gateway: EventGateway) -> None:
    event = gateway.admit(valid_raw_event(event_id=None))
    assert event.event_id and event.event_id != ""


def test_valid_event_id_is_preserved(gateway: EventGateway) -> None:
    assert gateway.admit(valid_raw_event()).event_id == VALID_UUID


@pytest.mark.parametrize("bad", ["not-a-uuid", "1234", "", "   ", 12345])
def test_malformed_event_id_is_rejected(gateway: EventGateway, bad: object) -> None:
    with pytest.raises(MalformedEventError):
        gateway.admit(valid_raw_event(event_id=bad))


# -- timestamp handling ---------------------------------------------------


def test_timestamp_is_assigned_when_absent(gateway: EventGateway) -> None:
    raw = valid_raw_event()
    del raw["timestamp"]
    before = datetime.now(UTC)
    event = gateway.admit(raw)
    after = datetime.now(UTC)
    assert before <= event.timestamp <= after


def test_iso_string_timestamp_is_parsed(gateway: EventGateway) -> None:
    event = gateway.admit(valid_raw_event(timestamp="2026-03-04T05:06:07+00:00"))
    assert event.timestamp == datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)


def test_aware_datetime_timestamp_is_accepted_and_utc_normalized(
    gateway: EventGateway,
) -> None:
    from datetime import timedelta

    aware = datetime(2026, 1, 1, 14, 0, 0, tzinfo=timezone(timedelta(hours=2)))
    event = gateway.admit(valid_raw_event(timestamp=aware))
    assert event.timestamp == datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    "bad",
    [
        "2026-01-01T12:00:00",  # naive ISO string
        "not a date",
        datetime(2026, 1, 1, 12, 0, 0),  # naive datetime
        1735732800,  # epoch int -- not accepted, must be explicit
    ],
)
def test_malformed_or_naive_timestamp_is_rejected(
    gateway: EventGateway, bad: object
) -> None:
    with pytest.raises(MalformedEventError):
        gateway.admit(valid_raw_event(timestamp=bad))


# -- destination: no permissive default ---------------------------------


def test_absent_destination_stays_none(gateway: EventGateway) -> None:
    raw = valid_raw_event(action="network.send", resource_type="url")
    assert "destination" not in raw
    event = gateway.admit(raw)
    assert event.destination is None


def test_explicit_null_destination_stays_none(gateway: EventGateway) -> None:
    event = gateway.admit(valid_raw_event(destination=None))
    assert event.destination is None


def test_empty_destination_string_is_rejected(gateway: EventGateway) -> None:
    with pytest.raises(MalformedEventError):
        gateway.admit(valid_raw_event(destination="  "))


# -- requested_capabilities --------------------------------------------


def test_empty_capabilities_list_is_allowed(gateway: EventGateway) -> None:
    assert (
        gateway.admit(valid_raw_event(requested_capabilities=[])).requested_capabilities
        == ()
    )


@pytest.mark.parametrize("bad", ["fs.read", [""], [1], [True], "not-a-list"])
def test_malformed_capabilities_are_rejected(
    gateway: EventGateway, bad: object
) -> None:
    with pytest.raises(MalformedEventError):
        gateway.admit(valid_raw_event(requested_capabilities=bad))


# -- semantic_signals: not adapter-supplied ---------------------------


def test_absent_or_empty_semantic_signals_is_fine(gateway: EventGateway) -> None:
    assert gateway.admit(valid_raw_event()).semantic_signals == ()
    assert gateway.admit(valid_raw_event(semantic_signals=[])).semantic_signals == ()


def test_adapter_supplied_semantic_signals_are_rejected(
    gateway: EventGateway,
) -> None:
    with pytest.raises(MalformedEventError):
        gateway.admit(
            valid_raw_event(semantic_signals=[{"source": "SEMANTIC_ANALYZER"}])
        )


# -- policy_context: parsed, closed, non-authoritative ----------------


def test_absent_policy_context_becomes_empty(gateway: EventGateway) -> None:
    raw = valid_raw_event()
    del raw["policy_context"]
    event = gateway.admit(raw)
    assert event.policy_context.profile_id is None
    assert event.policy_context.prior_decision_ids == ()


def test_policy_context_known_fields_are_carried(gateway: EventGateway) -> None:
    event = gateway.admit(
        valid_raw_event(
            policy_context={
                "profile_id": "default",
                "session_id": "sess-1",
                "prior_decision_ids": ["d-1", "d-2"],
                "user_declared_task": "refactor the parser",
            }
        )
    )
    assert event.policy_context.profile_id == "default"
    assert event.policy_context.prior_decision_ids == ("d-1", "d-2")
    assert event.policy_context.user_declared_task == "refactor the parser"


@pytest.mark.parametrize(
    "ctx",
    [
        {"outcome": "ALLOW"},
        {"decision": "ALLOW"},
        {"authorized": True},
        {"profile_id": "p", "approved": True},
    ],
)
def test_authorization_shaped_keys_in_policy_context_are_rejected(
    gateway: EventGateway, ctx: dict[str, object]
) -> None:
    with pytest.raises(MalformedEventError):
        gateway.admit(valid_raw_event(policy_context=ctx))


def test_policy_context_prior_decision_ids_must_be_strings(
    gateway: EventGateway,
) -> None:
    with pytest.raises(MalformedEventError):
        gateway.admit(
            valid_raw_event(policy_context={"prior_decision_ids": [{"nested": 1}]})
        )


def test_policy_context_must_be_a_mapping(gateway: EventGateway) -> None:
    with pytest.raises(MalformedEventError):
        gateway.admit(valid_raw_event(policy_context=["not", "a", "map"]))


def test_gateway_does_not_attach_any_decision(gateway: EventGateway) -> None:
    # The gateway only validates + constructs. It never produces an outcome.
    event = gateway.admit(valid_raw_event())
    assert not hasattr(event, "decision")
    assert not hasattr(event, "outcome")
