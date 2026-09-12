"""The Claude Code reference adapter: native tool events -> SecurityEvent."""

from __future__ import annotations

from typing import Any

import pytest

from contextfence.adapters.claude_code import CLAUDE_CODE_ADAPTER_ID, ClaudeCodeAdapter
from contextfence.adapters.errors import AdapterInputError
from contextfence.analysis import DEFAULT_DETECTORS
from contextfence.analysis.detector import run_detectors
from contextfence.core.models.enums import (
    ActionType,
    DataClassification,
    EvidenceCategory,
    ResourceType,
)
from contextfence.core.models.event import SecurityEvent


@pytest.fixture()
def adapter() -> ClaudeCodeAdapter:
    return ClaudeCodeAdapter()


def _event(adapter: ClaudeCodeAdapter, **native: Any) -> SecurityEvent:
    return adapter.normalize(native)


def test_adapter_id() -> None:
    assert ClaudeCodeAdapter().adapter_id == CLAUDE_CODE_ADAPTER_ID
    assert CLAUDE_CODE_ADAPTER_ID.value == "claude_code"


def test_file_read_mapping(adapter: ClaudeCodeAdapter) -> None:
    event = _event(
        adapter, tool_name="Read", tool_input={"file_path": "src/app/main.py"}
    )
    assert event.application == "claude_code"
    assert event.action is ActionType.FILE_READ
    assert event.resource_type is ResourceType.FILE
    assert event.resource == "src/app/main.py"
    assert event.destination is None
    assert event.requested_capabilities == ("fs.read",)
    assert event.data_classification is DataClassification.INTERNAL


@pytest.mark.parametrize("tool_name", ["Write", "Edit", "MultiEdit"])
def test_file_write_mapping(adapter: ClaudeCodeAdapter, tool_name: str) -> None:
    event = _event(
        adapter, tool_name=tool_name, tool_input={"file_path": "src/app/x.py"}
    )
    assert event.action is ActionType.FILE_WRITE
    assert event.resource_type is ResourceType.FILE
    assert event.requested_capabilities == ("fs.write",)


def test_notebook_edit_uses_notebook_path(adapter: ClaudeCodeAdapter) -> None:
    event = _event(
        adapter, tool_name="NotebookEdit", tool_input={"notebook_path": "nb.ipynb"}
    )
    assert event.action is ActionType.FILE_WRITE
    assert event.resource == "nb.ipynb"


def test_command_execution_mapping(adapter: ClaudeCodeAdapter) -> None:
    event = _event(adapter, tool_name="Bash", tool_input={"command": "pytest -q"})
    assert event.action is ActionType.COMMAND_EXEC
    assert event.resource_type is ResourceType.COMMAND
    assert event.resource == "pytest -q"
    assert event.requested_capabilities == ("exec",)


@pytest.mark.parametrize(
    "command",
    ["rm -rf build", "rmdir ./tmp", "/usr/bin/rm file.txt", "unlink cache"],
)
def test_destructive_file_action_mapping(
    adapter: ClaudeCodeAdapter, command: str
) -> None:
    event = _event(adapter, tool_name="Bash", tool_input={"command": command})
    assert event.action is ActionType.FILE_DELETE


def test_non_destructive_bash_stays_command_exec(adapter: ClaudeCodeAdapter) -> None:
    event = _event(adapter, tool_name="Bash", tool_input={"command": "grep -r rm ."})
    assert event.action is ActionType.COMMAND_EXEC


def test_network_related_mapping_webfetch(adapter: ClaudeCodeAdapter) -> None:
    event = _event(
        adapter,
        tool_name="WebFetch",
        tool_input={"url": "https://service.invalid/api", "prompt": "summarize"},
    )
    assert event.action is ActionType.NETWORK_SEND
    assert event.resource_type is ResourceType.URL
    assert event.resource == "https://service.invalid/api"
    assert event.destination == "service.invalid"
    assert event.requested_capabilities == ("net.egress",)


def test_network_related_mapping_websearch(adapter: ClaudeCodeAdapter) -> None:
    event = _event(adapter, tool_name="WebSearch", tool_input={"query": "python news"})
    assert event.action is ActionType.NETWORK_SEND
    assert event.requested_capabilities == ("net.egress",)


@pytest.mark.parametrize("tool_name", ["Glob", "Grep", "LS"])
def test_directory_read_mapping(adapter: ClaudeCodeAdapter, tool_name: str) -> None:
    event = _event(adapter, tool_name=tool_name, tool_input={"path": "src/"})
    assert event.action is ActionType.FILE_READ
    assert event.resource_type is ResourceType.DIRECTORY
    assert event.resource == "src/"


@pytest.mark.parametrize(
    "tool_name",
    ["mcp__server__do_thing", "Task", "TodoWrite", "SomeCustomTool"],
)
def test_tool_invocation_mapping(adapter: ClaudeCodeAdapter, tool_name: str) -> None:
    event = _event(adapter, tool_name=tool_name, tool_input={"any": "payload"})
    assert event.action is ActionType.TOOL_CALL
    assert event.resource_type is ResourceType.TOOL
    assert event.resource == tool_name
    assert event.requested_capabilities == ("tool.invoke",)


def test_actor_and_agent_context_pass_through(adapter: ClaudeCodeAdapter) -> None:
    event = _event(
        adapter,
        tool_name="Read",
        tool_input={"file_path": "notes.txt"},
        actor="claude_code:subagent",
        user_declared_task="review the release notes",
    )
    assert event.actor == "claude_code:subagent"
    assert event.policy_context.user_declared_task == "review the release notes"


def test_classification_hint_is_honoured(adapter: ClaudeCodeAdapter) -> None:
    event = _event(
        adapter,
        tool_name="Read",
        tool_input={"file_path": "customers.csv"},
        data_classification="PERSONAL_DATA",
    )
    assert event.data_classification is DataClassification.PERSONAL_DATA


# -- malformed native input --------------------------------------------------


@pytest.mark.parametrize(
    "native",
    [
        {},
        {"tool_name": "Read"},  # no tool_input
        {"tool_name": "Read", "tool_input": "not-a-mapping"},
        {"tool_name": "Read", "tool_input": {}},  # missing file_path
        {"tool_name": "Bash", "tool_input": {}},  # missing command
        {"tool_name": "WebFetch", "tool_input": {"prompt": "x"}},  # missing url
        {"tool_name": "", "tool_input": {}},
        {"tool_name": "Read", "tool_input": {"file_path": ""}},
        {
            "tool_name": "Read",
            "tool_input": {"file_path": "n"},
            "data_classification": "NOPE",
        },
    ],
)
def test_malformed_native_input_is_rejected(
    adapter: ClaudeCodeAdapter, native: dict[str, Any]
) -> None:
    with pytest.raises(AdapterInputError):
        adapter.normalize(native)


def test_non_mapping_native_input_is_rejected(adapter: ClaudeCodeAdapter) -> None:
    with pytest.raises(AdapterInputError):
        adapter.normalize(["not", "a", "map"])  # type: ignore[arg-type]


# -- the adapter does NOT do detection: it passes content through ----------


def test_synthetic_secret_in_resource_reaches_the_secret_detector(
    adapter: ClaudeCodeAdapter,
) -> None:
    # obviously synthetic, non-routable material
    synthetic_secret = "AKIAIOSFODNN7EXAMPLE"
    event = _event(
        adapter,
        tool_name="Bash",
        tool_input={"command": f"echo {synthetic_secret} >> .env"},
    )
    # the adapter itself made no security claim
    assert event.data_classification is DataClassification.INTERNAL
    evidence = run_detectors(event, DEFAULT_DETECTORS)
    assert any(e.category is EvidenceCategory.CREDENTIAL for e in evidence)


def test_synthetic_pii_reaches_the_pii_detector(adapter: ClaudeCodeAdapter) -> None:
    # synthetic address on the reserved .invalid TLD; no classification hint,
    # so the finding comes purely from the detector reading the resource.
    event = _event(
        adapter,
        tool_name="WebFetch",
        tool_input={"url": "https://sink.invalid/u?to=alex.doe@synthetic.invalid"},
    )
    assert event.data_classification is DataClassification.INTERNAL
    evidence = run_detectors(event, DEFAULT_DETECTORS)
    assert any(e.category is EvidenceCategory.PERSONAL_DATA for e in evidence)
