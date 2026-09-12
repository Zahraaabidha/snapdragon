"""SyntheticAgentAdapter: proves the contract is not coupled to Claude Code."""

from __future__ import annotations

from typing import Any

import pytest

from contextfence.adapters.errors import AdapterInputError
from contextfence.adapters.synthetic import (
    SYNTHETIC_AGENT_ADAPTER_ID,
    SyntheticAgentAdapter,
)
from contextfence.core.models.enums import ActionType, DataClassification, ResourceType
from contextfence.core.models.event import SecurityEvent


@pytest.fixture()
def adapter() -> SyntheticAgentAdapter:
    return SyntheticAgentAdapter()


def _event(adapter: SyntheticAgentAdapter, **native: Any) -> SecurityEvent:
    return adapter.normalize(native)


def test_adapter_id() -> None:
    assert SyntheticAgentAdapter().adapter_id == SYNTHETIC_AGENT_ADAPTER_ID
    assert SYNTHETIC_AGENT_ADAPTER_ID.value == "synthetic_agent"


@pytest.mark.parametrize(
    "op, action, resource_type, caps",
    [
        ("read_file", ActionType.FILE_READ, ResourceType.FILE, ("fs.read",)),
        ("write_file", ActionType.FILE_WRITE, ResourceType.FILE, ("fs.write",)),
        ("delete_file", ActionType.FILE_DELETE, ResourceType.FILE, ("fs.write",)),
        ("run_shell", ActionType.COMMAND_EXEC, ResourceType.COMMAND, ("exec",)),
        ("invoke_tool", ActionType.TOOL_CALL, ResourceType.TOOL, ("tool.invoke",)),
    ],
)
def test_op_mappings(
    adapter: SyntheticAgentAdapter,
    op: str,
    action: ActionType,
    resource_type: ResourceType,
    caps: tuple[str, ...],
) -> None:
    event = _event(adapter, op=op, target="synthetic/thing")
    assert event.application == "synthetic_agent"
    assert event.action is action
    assert event.resource_type is resource_type
    assert event.resource == "synthetic/thing"
    assert event.requested_capabilities == caps
    assert event.data_classification is DataClassification.INTERNAL


def test_http_request_derives_destination_from_endpoint(
    adapter: SyntheticAgentAdapter,
) -> None:
    event = _event(
        adapter,
        op="http_request",
        target="https://api.invalid/v1/send",
        endpoint="api.invalid",
    )
    assert event.action is ActionType.NETWORK_SEND
    assert event.destination == "api.invalid"


def test_http_request_falls_back_to_target_host(
    adapter: SyntheticAgentAdapter,
) -> None:
    event = _event(adapter, op="http_request", target="https://fallback.invalid/x")
    assert event.destination == "fallback.invalid"


def test_principal_and_note_pass_through(adapter: SyntheticAgentAdapter) -> None:
    event = _event(
        adapter,
        op="read_file",
        target="synthetic/notes.txt",
        principal="synthetic_agent:job-7",
        note="collect the notes",
    )
    assert event.actor == "synthetic_agent:job-7"
    assert event.policy_context.user_declared_task == "collect the notes"


def test_sensitivity_hint_is_honoured(adapter: SyntheticAgentAdapter) -> None:
    event = _event(adapter, op="read_file", target="x", sensitivity="REGULATED")
    assert event.data_classification is DataClassification.REGULATED


@pytest.mark.parametrize(
    "native",
    [
        {},
        {"op": "read_file"},  # no target
        {"op": "teleport", "target": "x"},  # unknown op
        {"op": "read_file", "target": ""},
        {"op": "read_file", "target": "x", "sensitivity": "NOPE"},
    ],
)
def test_malformed_native_input_is_rejected(
    adapter: SyntheticAgentAdapter, native: dict[str, Any]
) -> None:
    with pytest.raises(AdapterInputError):
        adapter.normalize(native)
