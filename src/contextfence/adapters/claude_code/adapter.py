"""The Claude Code reference adapter (Phase 7, task Part F).

Claude Code is the **first** concrete adapter, used to prove the generic
architecture. This module contains *only* Claude-Code-specific normalization:
it maps Claude Code's native tool-call vocabulary onto the core
:class:`~contextfence.core.models.enums.ActionType` /
:class:`~contextfence.core.models.enums.ResourceType` vocabulary and a set of
requested-capability strings. It contains no secret detection, PII detection,
risk logic, policy rules, authorization, enforcement, audit, or inference --
those are downstream of the :class:`AdapterInput` this produces.

**Scope of this integration (be precise, do not overstate).** ContextFence does
*not* currently intercept live Claude Code activity. There is no documented,
in-repo hook by which Claude Code streams its tool calls to ContextFence. This
adapter therefore defines a **structured native-event boundary**: a caller (a
harness, a test, or a future real integration point) supplies a mapping shaped
like a Claude Code tool invocation, and the adapter translates it. The mapping
schema is:

``{"tool_name": str, "tool_input": mapping, "actor"?: str,
   "user_declared_task"?: str, "data_classification"?: str}``

``tool_name`` recognises the common built-in tools (``Read``, ``Write``,
``Edit``, ``MultiEdit``, ``NotebookEdit``, ``Glob``, ``Grep``, ``LS``,
``Bash``, ``WebFetch``, ``WebSearch``). Anything else -- including
``mcp__*`` server tools and agent tools such as ``Task`` -- normalizes to a
generic ``TOOL_CALL``. Recognising a leading ``rm`` / ``rmdir`` / ``unlink``
token in a ``Bash`` command as a destructive :class:`ActionType.FILE_DELETE` is
*native-shape recognition*, not risk analysis: the adapter names the action, it
never decides what to do about it.

``data_classification`` defaults to ``INTERNAL`` -- a conservative baseline, not
a guess of ``NONE`` (docs/DECISIONS.md D-0001). A caller that genuinely knows
better may pass a hint; detectors refine it regardless.
"""

from __future__ import annotations

import shlex
from collections.abc import Mapping
from urllib.parse import urlparse

from contextfence.adapters.base import AIAdapter
from contextfence.adapters.errors import AdapterInputError
from contextfence.adapters.identity import AdapterId
from contextfence.adapters.input import AdapterInput
from contextfence.core.models.enums import ActionType, DataClassification, ResourceType

__all__ = ["CLAUDE_CODE_ADAPTER_ID", "ClaudeCodeAdapter"]

CLAUDE_CODE_ADAPTER_ID = AdapterId("claude_code")

_DEFAULT_ACTOR = "claude_code:agent"

#: Leading argv[0] tokens in a ``Bash`` command that make it a destructive file
#: action rather than a generic command execution.
_DESTRUCTIVE_ARGV0: frozenset[str] = frozenset({"rm", "rmdir", "unlink"})


class ClaudeCodeAdapter(AIAdapter):
    """Translate Claude Code native tool events into :class:`AdapterInput`."""

    adapter_id = CLAUDE_CODE_ADAPTER_ID

    def translate(self, native_event: Mapping[str, object]) -> AdapterInput:
        if not isinstance(native_event, Mapping):
            raise AdapterInputError("native event must be a mapping")

        tool_name = _req_str(native_event, "tool_name")
        tool_input = native_event.get("tool_input")
        if not isinstance(tool_input, Mapping):
            raise AdapterInputError("native event 'tool_input' must be a mapping")

        actor = native_event.get("actor", _DEFAULT_ACTOR)
        agent_context = native_event.get("user_declared_task")
        classification = _resolve_classification(
            native_event.get("data_classification")
        )

        action, resource_type, resource, destination, capabilities = _map_tool(
            tool_name, tool_input
        )

        return AdapterInput(
            application=self.adapter_id.value,
            actor=actor,  # type: ignore[arg-type]  # validated by AdapterInput
            action=action,
            resource=resource,
            resource_type=resource_type,
            data_classification=classification,
            destination=destination,
            requested_capabilities=capabilities,
            agent_context=agent_context,  # type: ignore[arg-type]
        )


def _map_tool(
    tool_name: str, tool_input: Mapping[str, object]
) -> tuple[ActionType, ResourceType, str, str | None, tuple[str, ...]]:
    """Return ``(action, resource_type, resource, destination, capabilities)``."""

    if tool_name in ("Read",):
        return (
            ActionType.FILE_READ,
            ResourceType.FILE,
            _req_str(tool_input, "file_path"),
            None,
            ("fs.read",),
        )
    if tool_name in ("Write",):
        return (
            ActionType.FILE_WRITE,
            ResourceType.FILE,
            _req_str(tool_input, "file_path"),
            None,
            ("fs.write",),
        )
    if tool_name in ("Edit", "MultiEdit", "NotebookEdit"):
        key = "notebook_path" if tool_name == "NotebookEdit" else "file_path"
        return (
            ActionType.FILE_WRITE,
            ResourceType.FILE,
            _req_str(tool_input, key),
            None,
            ("fs.write",),
        )
    if tool_name in ("Glob", "Grep", "LS"):
        resource = _first_str(tool_input, ("path", "pattern"))
        return (
            ActionType.FILE_READ,
            ResourceType.DIRECTORY,
            resource,
            None,
            ("fs.read",),
        )
    if tool_name == "Bash":
        return _map_bash(_req_str(tool_input, "command"))
    if tool_name == "WebFetch":
        url = _req_str(tool_input, "url")
        return (
            ActionType.NETWORK_SEND,
            ResourceType.URL,
            url,
            _host_of(url),
            ("net.egress",),
        )
    if tool_name == "WebSearch":
        return (
            ActionType.NETWORK_SEND,
            ResourceType.URL,
            _req_str(tool_input, "query"),
            None,
            ("net.egress",),
        )

    # Everything else -- mcp__* server tools, Task, TodoWrite, custom tools --
    # is a generic tool invocation.
    return (
        ActionType.TOOL_CALL,
        ResourceType.TOOL,
        tool_name,
        None,
        ("tool.invoke",),
    )


def _map_bash(
    command: str,
) -> tuple[ActionType, ResourceType, str, str | None, tuple[str, ...]]:
    try:
        argv = shlex.split(command)
    except ValueError:
        argv = []
    argv0 = argv[0].rsplit("/", 1)[-1] if argv else ""
    if argv0 in _DESTRUCTIVE_ARGV0:
        return (
            ActionType.FILE_DELETE,
            ResourceType.COMMAND,
            command,
            None,
            ("exec",),
        )
    return (ActionType.COMMAND_EXEC, ResourceType.COMMAND, command, None, ("exec",))


def _resolve_classification(hint: object) -> DataClassification:
    if hint is None:
        return DataClassification.INTERNAL
    if isinstance(hint, DataClassification):
        return hint
    if isinstance(hint, str) and not isinstance(hint, bool):
        try:
            return DataClassification(hint)
        except ValueError as exc:
            raise AdapterInputError(
                f"data_classification hint {hint!r} is not a DataClassification"
            ) from exc
    raise AdapterInputError("data_classification hint must be a string or omitted")


def _req_str(mapping: Mapping[str, object], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or isinstance(value, bool) or not value.strip():
        raise AdapterInputError(f"expected non-empty string field {key!r}")
    return value


def _first_str(mapping: Mapping[str, object], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and not isinstance(value, bool) and value.strip():
            return value
    raise AdapterInputError(f"expected a non-empty string in one of fields {keys}")


def _host_of(url: str) -> str | None:
    host = urlparse(url).hostname
    return host or None
