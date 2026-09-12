"""Error types for the AI-adapter boundary (Phase 7).

Adapters sit at the edge of the system and are **untrusted** with respect to the
security core (ARCHITECTURE.md §3.1, §4; SECURITY.md §1.12). Failures here are
explicit: a malformed native event, a malformed :class:`AdapterInput`, or a
malformed adapter is rejected -- never silently repaired and never downgraded to
a permissive value.

``AdapterInputError`` deliberately subclasses
:class:`~contextfence.core.errors.ValidationError` so the "reject, don't repair"
contract is the same one the core already uses at the Event Gateway. The
registry errors subclass a plain :class:`AdapterError` because they describe a
wiring mistake by the operator, not an untrusted-input problem.
"""

from __future__ import annotations

from contextfence.core.errors import ContextFenceError, ValidationError

__all__ = [
    "AdapterError",
    "AdapterInputError",
    "AdapterRegistryError",
    "DuplicateAdapterError",
    "UnknownAdapterError",
]


class AdapterError(ContextFenceError):
    """Base class for every error raised by the adapter boundary."""


class AdapterInputError(ValidationError):
    """A native event or an :class:`AdapterInput` failed validation.

    Raised by :class:`~contextfence.adapters.identity.AdapterId`,
    :class:`~contextfence.adapters.input.AdapterInput`, and by an adapter's
    ``translate`` boundary. The offending event is not normalized into a
    :class:`~contextfence.core.models.event.SecurityEvent`; no analysis, policy
    evaluation, or enforcement occurs for it.
    """


class AdapterRegistryError(AdapterError):
    """A registry operation was rejected (bad wiring, not untrusted input)."""


class DuplicateAdapterError(AdapterRegistryError):
    """An adapter id was registered twice."""


class UnknownAdapterError(AdapterRegistryError):
    """No adapter is registered under the requested id."""
