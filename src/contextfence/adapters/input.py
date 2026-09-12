"""The typed adapter-input boundary (Phase 7, task Part B).

An :class:`AdapterInput` is the strongly typed, **untrusted** representation an
adapter produces from one native AI-application event. It carries only the
security-relevant information needed to build a canonical
:class:`~contextfence.core.models.event.SecurityEvent`, and nothing else.

Why a separate model at all, rather than letting adapters build a raw mapping
for the Event Gateway directly (task Part B "create only the minimal
adapter-specific boundary required"):

* it gives the adapter contract a typed return value, so ``translate`` is
  checkable and cannot accidentally emit a decision;
* it is the single place that rejects *authorization-shaped* keys
  (``approved``, ``authorized``, ``allow``, ``deny``, ...). A native event may
  contain such keys; they are dropped here and can never reach policy
  evaluation (task Part B, SECURITY.md §1.5, §2).

What is intentionally **not** here: ``event_id`` and ``timestamp`` (ingestion
metadata the Event Gateway mints), ``semantic_signals`` (added later by the
semantic analyzer, never by an adapter), and the operator-controlled
``policy_context`` fields ``profile_id`` / ``session_id`` / ``prior_decision_ids``.
The one untrusted context field an adapter may pass through is
:attr:`agent_context`, which becomes ``policy_context.user_declared_task`` --
free text that is useful for display and rule *selection* heuristics but can
never authorize anything (:mod:`contextfence.core.models.policy_context`).

``AdapterInput`` performs *translation-shape* validation only. It never runs a
detector, scores risk, or decides. The Event Gateway re-validates every field
when :meth:`AdapterInput.to_raw_event` is admitted, so this model is a
convenience boundary, not a second trust boundary.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum

from contextfence.adapters.errors import AdapterInputError
from contextfence.core.models.enums import (
    ActionType,
    DataClassification,
    ResourceType,
)

__all__ = ["ADAPTER_INPUT_FIELDS", "AUTHORIZATION_SHAPED_KEYS", "AdapterInput"]

#: Keys an adapter (or injected content shaping an adapter's output) must never
#: be able to present as trusted authorization facts (task Part B). If any of
#: these appears in a mapping handed to :meth:`AdapterInput.from_mapping` it is
#: rejected explicitly, with a message that names it as authorization-shaped
#: rather than a generic "unknown field".
AUTHORIZATION_SHAPED_KEYS: frozenset[str] = frozenset(
    {
        "approved",
        "authorized",
        "trusted",
        "safe",
        "permission_granted",
        "policy_override",
        "admin",
        "allow",
        "deny",
        "decision",
        "outcome",
    }
)

#: The complete, closed set of keys :meth:`AdapterInput.from_mapping` accepts.
ADAPTER_INPUT_FIELDS: frozenset[str] = frozenset(
    {
        "application",
        "actor",
        "action",
        "resource",
        "resource_type",
        "destination",
        "data_classification",
        "requested_capabilities",
        "agent_context",
    }
)


def _require_plain_str(value: object, *, field_name: str) -> str:
    if isinstance(value, (bool, Enum)) or not isinstance(value, str):
        raise AdapterInputError(f"{field_name} must be a plain string")
    if not value.strip():
        raise AdapterInputError(f"{field_name} must not be empty")
    return value


def _require_enum(value: object, enum_cls: type[Enum], *, field_name: str) -> Enum:
    """Accept an already-resolved member or a plain string naming one.

    Adapters are expected to translate native vocabulary into these enums
    themselves; a bare string is accepted for ergonomics and resolved here the
    same way the Event Gateway would. An unrecognised value is rejected, never
    mapped to a catch-all.
    """

    if isinstance(value, enum_cls):
        return value
    if isinstance(value, str) and not isinstance(value, Enum):
        try:
            return enum_cls(value)
        except ValueError as exc:
            raise AdapterInputError(
                f"{field_name} has unrecognised value {value!r}"
            ) from exc
    raise AdapterInputError(
        f"{field_name} must be a {enum_cls.__name__} member or its string value"
    )


@dataclass(frozen=True, slots=True)
class AdapterInput:
    """One native AI-application event, translated to typed security facts.

    Frozen and self-validating. Construct it directly from an adapter's
    ``translate`` method, or from an untrusted mapping via
    :meth:`from_mapping` (which additionally rejects unknown and
    authorization-shaped keys).

    Args:
        application: the producing adapter's identity string. Must equal the
            adapter's :class:`~contextfence.adapters.identity.AdapterId` value;
            :meth:`AIAdapter.normalize` enforces that.
        actor: who/what initiated the native action (e.g.
            ``"claude_code:agent"``).
        action: normalized :class:`ActionType` (or its string value).
        resource: target identifier (path, url, tool name, command string).
        resource_type: normalized :class:`ResourceType` (or its string value).
        data_classification: the adapter's best-effort
            :class:`DataClassification`. Adapters that cannot tell should pass a
            conservative baseline such as ``INTERNAL`` -- never ``NONE`` as a
            guess (docs/DECISIONS.md D-0001). Detectors refine it downstream.
        destination: where data would go, or ``None`` for no external
            destination. Never fabricated into a local/allowed value.
        requested_capabilities: capability strings the native action needs
            (may be empty; must be explicit).
        agent_context: optional untrusted free text describing the task, mapped
            to ``policy_context.user_declared_task``. Never authorization.
    """

    application: str
    actor: str
    action: ActionType
    resource: str
    resource_type: ResourceType
    data_classification: DataClassification
    destination: str | None = None
    requested_capabilities: tuple[str, ...] = field(default_factory=tuple)
    agent_context: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "application",
            _require_plain_str(self.application, field_name="application"),
        )
        object.__setattr__(
            self, "actor", _require_plain_str(self.actor, field_name="actor")
        )
        object.__setattr__(
            self,
            "action",
            _require_enum(self.action, ActionType, field_name="action"),
        )
        object.__setattr__(
            self,
            "resource",
            _require_plain_str(self.resource, field_name="resource"),
        )
        object.__setattr__(
            self,
            "resource_type",
            _require_enum(self.resource_type, ResourceType, field_name="resource_type"),
        )
        object.__setattr__(
            self,
            "data_classification",
            _require_enum(
                self.data_classification,
                DataClassification,
                field_name="data_classification",
            ),
        )

        if self.destination is not None:
            object.__setattr__(
                self,
                "destination",
                _require_plain_str(self.destination, field_name="destination"),
            )

        object.__setattr__(
            self,
            "requested_capabilities",
            _validate_capabilities(self.requested_capabilities),
        )

        if self.agent_context is not None:
            object.__setattr__(
                self,
                "agent_context",
                _require_plain_str(self.agent_context, field_name="agent_context"),
            )

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, object]) -> AdapterInput:
        """Build an :class:`AdapterInput` from an untrusted mapping.

        Rejects: a non-mapping, any authorization-shaped key
        (:data:`AUTHORIZATION_SHAPED_KEYS`), and any other unknown key. Missing
        optional keys take their defaults; missing required keys are rejected by
        ``__post_init__`` via a ``TypeError`` re-wrapped as
        :class:`AdapterInputError`.
        """

        if not isinstance(mapping, Mapping):
            raise AdapterInputError("adapter input must be a mapping")

        keys = {str(k) for k in mapping}
        auth_shaped = sorted(keys & AUTHORIZATION_SHAPED_KEYS)
        if auth_shaped:
            raise AdapterInputError(
                "adapter input must not carry authorization-shaped field(s): "
                + ", ".join(auth_shaped)
            )
        unknown = sorted(keys - ADAPTER_INPUT_FIELDS)
        if unknown:
            raise AdapterInputError(
                "unknown adapter input field(s): " + ", ".join(unknown)
            )

        raw_caps = mapping.get("requested_capabilities", ())
        caps = tuple(raw_caps) if isinstance(raw_caps, (list, tuple)) else raw_caps

        try:
            return cls(
                application=mapping["application"],  # type: ignore[arg-type]
                actor=mapping["actor"],  # type: ignore[arg-type]
                action=mapping["action"],  # type: ignore[arg-type]
                resource=mapping["resource"],  # type: ignore[arg-type]
                resource_type=mapping["resource_type"],  # type: ignore[arg-type]
                data_classification=mapping[  # type: ignore[arg-type]
                    "data_classification"
                ],
                destination=mapping.get("destination"),  # type: ignore[arg-type]
                requested_capabilities=caps,  # type: ignore[arg-type]
                agent_context=mapping.get("agent_context"),  # type: ignore[arg-type]
            )
        except KeyError as exc:
            raise AdapterInputError(
                f"missing required adapter input field: {exc.args[0]}"
            ) from exc

    def to_raw_event(self) -> dict[str, object]:
        """Render the raw-event mapping the Event Gateway admits.

        Emits only fields an adapter is allowed to supply: no ``event_id`` or
        ``timestamp`` (the gateway mints them), no ``semantic_signals``. The
        gateway re-validates everything here.
        """

        raw: dict[str, object] = {
            "application": self.application,
            "actor": self.actor,
            "action": self.action.value,
            "resource": self.resource,
            "resource_type": self.resource_type.value,
            "data_classification": self.data_classification.value,
            "destination": self.destination,
            "requested_capabilities": list(self.requested_capabilities),
        }
        if self.agent_context is not None:
            raw["policy_context"] = {"user_declared_task": self.agent_context}
        return raw


def _validate_capabilities(value: object) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise AdapterInputError("requested_capabilities must be a tuple of strings")
    for entry in value:
        _require_plain_str(entry, field_name="requested_capabilities entry")
    return value
