"""A synthetic second adapter (Phase 7, task Part G).

``SyntheticAgentAdapter`` exists **only to prove the adapter architecture is not
coupled to Claude Code**. It normalizes a small, deliberately different native
vocabulary (an imaginary agent that emits ``{"op": ...}`` records) into the same
canonical :class:`~contextfence.core.models.event.SecurityEvent`, through the
same :class:`~contextfence.adapters.base.AIAdapter` contract and the same Event
Gateway.

It is **not** a real integration with any product. Do not register it in a
production configuration. It ships in ``src/`` (rather than ``tests/``) so that
architectural tests can demonstrate a two-adapter registry and a
provider-independent pipeline without test-only import paths.

Native schema:
``{"op": str, "target": str, "principal"?: str, "note"?: str,
   "sensitivity"?: str, "endpoint"?: str}``
where ``op`` is one of ``read_file``, ``write_file``, ``delete_file``,
``run_shell``, ``http_request``, ``invoke_tool``.
"""

from __future__ import annotations

from collections.abc import Mapping
from urllib.parse import urlparse

from contextfence.adapters.base import AIAdapter
from contextfence.adapters.errors import AdapterInputError
from contextfence.adapters.identity import AdapterId
from contextfence.adapters.input import AdapterInput
from contextfence.core.models.enums import ActionType, DataClassification, ResourceType

__all__ = ["SYNTHETIC_AGENT_ADAPTER_ID", "SyntheticAgentAdapter"]

SYNTHETIC_AGENT_ADAPTER_ID = AdapterId("synthetic_agent")

_DEFAULT_ACTOR = "synthetic_agent:worker"

_OP_MAP: dict[str, tuple[ActionType, ResourceType, tuple[str, ...]]] = {
    "read_file": (ActionType.FILE_READ, ResourceType.FILE, ("fs.read",)),
    "write_file": (ActionType.FILE_WRITE, ResourceType.FILE, ("fs.write",)),
    "delete_file": (ActionType.FILE_DELETE, ResourceType.FILE, ("fs.write",)),
    "run_shell": (ActionType.COMMAND_EXEC, ResourceType.COMMAND, ("exec",)),
    "http_request": (ActionType.NETWORK_SEND, ResourceType.URL, ("net.egress",)),
    "invoke_tool": (ActionType.TOOL_CALL, ResourceType.TOOL, ("tool.invoke",)),
}


class SyntheticAgentAdapter(AIAdapter):
    """Translate the imaginary synthetic-agent vocabulary into ``AdapterInput``."""

    adapter_id = SYNTHETIC_AGENT_ADAPTER_ID

    def translate(self, native_event: Mapping[str, object]) -> AdapterInput:
        if not isinstance(native_event, Mapping):
            raise AdapterInputError("native event must be a mapping")

        op = native_event.get("op")
        if not isinstance(op, str) or op not in _OP_MAP:
            raise AdapterInputError(
                f"unknown synthetic-agent op {op!r}; expected one of "
                + ", ".join(sorted(_OP_MAP))
            )
        action, resource_type, capabilities = _OP_MAP[op]

        target = native_event.get("target")
        if not isinstance(target, str) or not target.strip():
            raise AdapterInputError("native event 'target' must be a non-empty string")

        destination: str | None = None
        if action is ActionType.NETWORK_SEND:
            endpoint = native_event.get("endpoint")
            if isinstance(endpoint, str) and endpoint.strip():
                destination = endpoint
            else:
                destination = urlparse(target).hostname or None

        principal = native_event.get("principal", _DEFAULT_ACTOR)
        note = native_event.get("note")
        classification = _resolve_classification(native_event.get("sensitivity"))

        return AdapterInput(
            application=self.adapter_id.value,
            actor=principal,  # type: ignore[arg-type]  # validated by AdapterInput
            action=action,
            resource=target,
            resource_type=resource_type,
            data_classification=classification,
            destination=destination,
            requested_capabilities=capabilities,
            agent_context=note,  # type: ignore[arg-type]
        )


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
                f"sensitivity hint {hint!r} is not a DataClassification"
            ) from exc
    raise AdapterInputError("sensitivity hint must be a string or omitted")
