"""Error types for the ContextFence security core.

Security assumption (see SECURITY.md, ARCHITECTURE.md §9): validation failures in
the core are *explicit*. A malformed or under-specified event is rejected by
raising one of these errors -- it is never silently repaired and never
downgraded to a permissive value. Callers must not convert these exceptions into
an ALLOW outcome.

These types deliberately carry only a short, human-readable message. Callers are
responsible for not placing sensitive field values (file contents, secrets,
destinations, free-text task descriptions) into the message. Helpers in this
package that build messages follow that rule: they name the offending *field*
and the *problem*, and echo a value only for closed enum / type mismatches on
non-sensitive fields.
"""

from __future__ import annotations

__all__ = [
    "ContextFenceError",
    "MalformedEventError",
    "ValidationError",
]


class ContextFenceError(Exception):
    """Base class for every error raised by the ContextFence core."""


class ValidationError(ContextFenceError):
    """A typed model failed its own construction-time validation.

    Raised by the ``__post_init__`` validators of the core data models when a
    field violates an invariant (wrong type, out-of-range value, inconsistent
    combination of fields).
    """


class MalformedEventError(ValidationError):
    """The Event Gateway rejected an untrusted raw event.

    Raised only by :class:`contextfence.core.events.gateway.EventGateway`. It
    signals that the supplied raw event was not well-formed enough to become a
    canonical :class:`~contextfence.core.models.event.SecurityEvent`. The event
    is not admitted to the pipeline; no analysis, risk aggregation, policy
    evaluation, or enforcement occurs for it.
    """
