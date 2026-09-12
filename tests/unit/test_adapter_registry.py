"""AdapterRegistry: local, deterministic discovery by id (task Part E)."""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from contextfence.adapters.base import AIAdapter
from contextfence.adapters.claude_code import ClaudeCodeAdapter
from contextfence.adapters.errors import (
    AdapterInputError,
    AdapterRegistryError,
    DuplicateAdapterError,
    UnknownAdapterError,
)
from contextfence.adapters.identity import AdapterId
from contextfence.adapters.input import AdapterInput
from contextfence.adapters.registry import AdapterRegistry
from contextfence.adapters.synthetic import SyntheticAgentAdapter
from contextfence.core.models.enums import ActionType, DataClassification, ResourceType


class _OkAdapter(AIAdapter):
    adapter_id = AdapterId("ok_adapter")

    def translate(self, native_event: Mapping[str, object]) -> AdapterInput:
        return AdapterInput(
            application=self.adapter_id.value,
            actor="x",
            action=ActionType.TOOL_CALL,
            resource="t",
            resource_type=ResourceType.TOOL,
            data_classification=DataClassification.INTERNAL,
        )


class _NoIdAdapter(AIAdapter):
    # deliberately missing adapter_id
    def translate(self, native_event: Mapping[str, object]) -> AdapterInput:
        raise NotImplementedError  # pragma: no cover


def test_register_and_get_round_trip() -> None:
    reg = AdapterRegistry()
    cc = ClaudeCodeAdapter()
    returned = reg.register(cc)
    assert returned == AdapterId("claude_code")
    assert reg.get("claude_code") is cc
    assert reg.get(AdapterId("claude_code")) is cc
    assert reg.is_registered("claude_code")
    assert len(reg) == 1


def test_two_distinct_adapters_coexist() -> None:
    reg = AdapterRegistry()
    reg.register(ClaudeCodeAdapter())
    reg.register(SyntheticAgentAdapter())
    assert reg.adapter_ids() == ("claude_code", "synthetic_agent")


def test_duplicate_id_is_rejected() -> None:
    reg = AdapterRegistry()
    reg.register(ClaudeCodeAdapter())
    with pytest.raises(DuplicateAdapterError):
        reg.register(ClaudeCodeAdapter())


def test_unknown_id_raises() -> None:
    reg = AdapterRegistry()
    with pytest.raises(UnknownAdapterError):
        reg.get("never_registered")
    assert not reg.is_registered("never_registered")


@pytest.mark.parametrize("bad", [object(), "not-an-adapter", 123, None])
def test_non_adapter_is_rejected(bad: object) -> None:
    reg = AdapterRegistry()
    with pytest.raises(AdapterRegistryError):
        reg.register(bad)  # type: ignore[arg-type]


def test_adapter_without_adapter_id_cannot_be_constructed_or_registered() -> None:
    # The base __init__ guard rejects a subclass that never set adapter_id.
    with pytest.raises(AdapterInputError):
        _NoIdAdapter()


def test_adapter_with_non_adapterid_identity_is_rejected() -> None:
    reg = AdapterRegistry()
    adapter = _OkAdapter()
    object.__setattr__(adapter, "adapter_id", "claude_code")  # wrong type at instance
    with pytest.raises(AdapterRegistryError):
        reg.register(adapter)


def test_get_with_bad_key_type_is_rejected() -> None:
    reg = AdapterRegistry()
    with pytest.raises(AdapterRegistryError):
        reg.get(123)  # type: ignore[arg-type]


def test_adapter_ids_snapshot_is_sorted_and_stable() -> None:
    reg = AdapterRegistry()
    reg.register(SyntheticAgentAdapter())
    reg.register(ClaudeCodeAdapter())
    assert reg.adapter_ids() == ("claude_code", "synthetic_agent")
    assert reg.adapter_ids() == reg.adapter_ids()
