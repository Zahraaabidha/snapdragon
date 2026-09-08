"""The :class:`PolicyContext` model.

``policy_context`` rides on every :class:`~contextfence.core.models.event.SecurityEvent`
to carry *non-authoritative* context that helps the Policy Engine select and
explain a rule: which policy profile is active, a session id for correlation,
references to prior decisions, and the user's own description of the task.

It is context, never permission (ARCHITECTURE.md §5 note; SECURITY.md §1). This
type is a closed set of typed fields -- there is no free-form mapping -- so an
outcome, grant, or "approved" flag cannot be smuggled in. String fields
additionally reject enum instances, so a
:class:`~contextfence.core.models.enums.DecisionOutcome` cannot be parked in a
text field. ``prior_decision_ids`` holds opaque id *strings*, not
:class:`~contextfence.core.models.decision.Decision` objects.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from contextfence.core.errors import ValidationError
from contextfence.core.models._validation import reject_enum_value, require_text

__all__ = ["PolicyContext"]


@dataclass(frozen=True, slots=True)
class PolicyContext:
    """Non-authoritative context attached to a security event.

    Args:
        profile_id: id of the active policy profile, if the adapter knows it.
        session_id: opaque correlation id for the originating session.
        prior_decision_ids: ordered tuple of earlier decision id strings this
            event relates to (references only -- not decision objects, not
            outcomes).
        user_declared_task: the user's own statement of what they are trying to
            do. Untrusted free text: useful for display and for rule selection
            heuristics, but it can never authorize anything.
    """

    profile_id: str | None = None
    session_id: str | None = None
    prior_decision_ids: tuple[str, ...] = field(default_factory=tuple)
    user_declared_task: str | None = None

    def __post_init__(self) -> None:
        for name in ("profile_id", "session_id", "user_declared_task"):
            value = getattr(self, name)
            if value is None:
                continue
            reject_enum_value(value, field=name)
            require_text(value, field=name, allow_empty=False)

        if not isinstance(self.prior_decision_ids, tuple):
            raise ValidationError("prior_decision_ids must be a tuple of id strings")
        for entry in self.prior_decision_ids:
            reject_enum_value(entry, field="prior_decision_ids entry")
            require_text(entry, field="prior_decision_ids entry", allow_empty=False)


EMPTY_POLICY_CONTEXT: PolicyContext = PolicyContext()
"""Shared immutable empty context, used when an adapter supplies none."""
