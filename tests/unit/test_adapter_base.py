"""The generic AIAdapter contract: translation only, never authorization."""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from contextfence.adapters.base import AIAdapter
from contextfence.adapters.errors import AdapterInputError
from contextfence.adapters.identity import AdapterId
from contextfence.adapters.input import AdapterInput
from contextfence.core.errors import MalformedEventError
from contextfence.core.events import EventGateway
from contextfence.core.models.decision import Decision
from contextfence.core.models.enums import ActionType, DataClassification, ResourceType
from contextfence.core.models.event import SecurityEvent


class _StubAdapter(AIAdapter):
    """Minimal adapter that echoes a fixed AdapterInput, for contract tests."""

    adapter_id = AdapterId("stub_adapter")

    def __init__(self, *, override: AdapterInput | object | None = None) -> None:
        super().__init__()
        self._override = override

    def translate(self, native_event: Mapping[str, object]) -> AdapterInput:
        if self._override is not None:
            return self._override  # type: ignore[return-value]
        return AdapterInput(
            application=self.adapter_id.value,
            actor="stub:agent",
            action=ActionType.FILE_READ,
            resource=str(native_event.get("resource", "synthetic/notes.txt")),
            resource_type=ResourceType.FILE,
            data_classification=DataClassification.INTERNAL,
            requested_capabilities=("fs.read",),
        )


def test_normalize_produces_a_validated_security_event() -> None:
    event = _StubAdapter().normalize({"resource": "synthetic/a.txt"})
    assert isinstance(event, SecurityEvent)
    assert event.application == "stub_adapter"
    assert event.action is ActionType.FILE_READ
    # gateway minted ingestion metadata the adapter never supplied
    assert event.event_id
    assert event.timestamp is not None


def test_normalize_return_type_is_never_a_decision() -> None:
    event = _StubAdapter().normalize({})
    assert not isinstance(event, Decision)
    assert not hasattr(event, "outcome")
    assert not hasattr(event, "decision")


def test_normalize_routes_through_the_gateway() -> None:
    calls: list[Mapping[str, object]] = []

    class _SpyGateway(EventGateway):
        def admit(self, raw_event: Mapping[str, object]) -> SecurityEvent:
            calls.append(raw_event)
            return super().admit(raw_event)

    _StubAdapter().normalize({}, gateway=_SpyGateway())
    assert len(calls) == 1
    # the adapter handed the gateway a raw mapping, not a pre-built event
    assert isinstance(calls[0], Mapping)
    assert "event_id" not in calls[0]


def test_translate_returning_non_adapter_input_is_rejected() -> None:
    adapter = _StubAdapter(override={"application": "stub_adapter"})
    with pytest.raises(AdapterInputError):
        adapter.normalize({})


def test_identity_mismatch_between_input_and_adapter_id_is_rejected() -> None:
    spoofed = AdapterInput(
        application="claude_code",  # not this adapter's id
        actor="stub:agent",
        action=ActionType.FILE_READ,
        resource="synthetic/notes.txt",
        resource_type=ResourceType.FILE,
        data_classification=DataClassification.INTERNAL,
    )
    with pytest.raises(AdapterInputError):
        _StubAdapter(override=spoofed).normalize({})


def test_malformed_event_from_gateway_propagates() -> None:
    # A buggy adapter that mutates its AdapterInput after validation still cannot
    # sneak a bad event past the gateway -- the gateway re-validates every field.
    class _TamperingAdapter(_StubAdapter):
        def translate(self, native_event: Mapping[str, object]) -> AdapterInput:
            ai = super().translate(native_event)
            object.__setattr__(ai, "resource", "")  # empty after validation
            return ai

    with pytest.raises(MalformedEventError):
        _TamperingAdapter().normalize({})


def test_normalization_is_deterministic_apart_from_ingestion_metadata() -> None:
    adapter = _StubAdapter()
    a = adapter.normalize({"resource": "synthetic/x.txt"})
    b = adapter.normalize({"resource": "synthetic/x.txt"})
    assert (
        a.application,
        a.action,
        a.resource,
        a.resource_type,
        a.data_classification,
        a.requested_capabilities,
    ) == (
        b.application,
        b.action,
        b.resource,
        b.resource_type,
        b.data_classification,
        b.requested_capabilities,
    )


def test_adapter_cannot_be_used_to_construct_policy_config() -> None:
    adapter = _StubAdapter()
    assert not hasattr(adapter, "policy")
    assert not hasattr(adapter, "evaluate")
    assert not hasattr(adapter, "enforce")
