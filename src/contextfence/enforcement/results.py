"""Enforcement result / outcome models (Phase 5).

The enforcement layer *applies* a Policy Engine :class:`Decision`; it never
produces one. An :class:`EnforcementResult` is the immutable record of what
applying a decision meant. It echoes the source decision's outcome and matched
rule id as read-only facts -- it is not itself an authorization and is never a
:class:`~contextfence.core.models.decision.Decision`.

Fail-closed contract (SECURITY.md; ARCHITECTURE.md §3.6, §9):

* ``permitted_to_proceed`` is ``True`` only for ``ALLOWED`` and ``SANITIZED``.
* ``DENIED``, ``APPROVAL_REQUIRED`` and ``INTERNAL_ERROR`` never permit the
  action to proceed -- an error can never turn a block into an allow.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from contextfence.core.models.enums import DecisionOutcome

if TYPE_CHECKING:
    from contextfence.enforcement.approval import ApprovalRequest
    from contextfence.enforcement.sanitizer import SanitizationSummary

__all__ = [
    "EnforcementErrorKind",
    "EnforcementOutcome",
    "EnforcementResult",
]


class EnforcementOutcome(StrEnum):
    """What applying a :class:`Decision` resulted in."""

    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    SANITIZED = "SANITIZED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class EnforcementErrorKind(StrEnum):
    """Why enforcement failed closed, when it did. ``NONE`` otherwise."""

    NONE = "NONE"
    MISSING_DECISION = "MISSING_DECISION"
    UNSUPPORTED_OUTCOME = "UNSUPPORTED_OUTCOME"
    MISSING_PAYLOAD = "MISSING_PAYLOAD"
    SANITIZATION_FAILED = "SANITIZATION_FAILED"
    MALFORMED_APPROVAL_REQUEST = "MALFORMED_APPROVAL_REQUEST"
    MALFORMED_APPROVAL_RESPONSE = "MALFORMED_APPROVAL_RESPONSE"
    INVALID_APPROVAL_STATE = "INVALID_APPROVAL_STATE"
    INTERNAL_EXCEPTION = "INTERNAL_EXCEPTION"


_PERMITTED_OUTCOMES = frozenset(
    {EnforcementOutcome.ALLOWED, EnforcementOutcome.SANITIZED}
)


@dataclass(frozen=True, slots=True)
class EnforcementResult:
    """Immutable record of applying one :class:`Decision`.

    Args:
        outcome: the enforcement outcome.
        decision_outcome: a read-only echo of the source ``Decision.outcome``
            (``None`` only when no valid decision was supplied).
        matched_rule_id: a read-only echo of ``Decision.matched_rule_id``.
        rationale: trusted, structured reason strings -- the decision's own
            rationale plus enforcement notes. Never agent-supplied text, never a
            raw resource / destination / payload / secret.
        error_kind: set when ``outcome`` is ``INTERNAL_ERROR`` (or a blocked
            approval/sanitize failure); ``NONE`` otherwise.
        error_detail: a short, safe description. Never a sensitive value.
        approval_request: present iff ``outcome`` is ``APPROVAL_REQUIRED``.
        sanitized_payload: the sanitized **copy**, present iff ``outcome`` is
            ``SANITIZED``. Never the original payload.
        sanitization: structural summary of what sanitization did (no values).
    """

    outcome: EnforcementOutcome
    decision_outcome: DecisionOutcome | None
    matched_rule_id: str | None
    rationale: tuple[str, ...]
    error_kind: EnforcementErrorKind = EnforcementErrorKind.NONE
    error_detail: str = ""
    approval_request: ApprovalRequest | None = None
    sanitized_payload: str | None = None
    sanitization: SanitizationSummary | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, EnforcementOutcome):
            raise ValueError("outcome must be an EnforcementOutcome")
        if self.decision_outcome is not None and not isinstance(
            self.decision_outcome, DecisionOutcome
        ):
            raise ValueError("decision_outcome must be a DecisionOutcome or None")
        if not isinstance(self.rationale, tuple) or not self.rationale:
            raise ValueError("rationale must be a non-empty tuple of strings")
        for entry in self.rationale:
            if not isinstance(entry, str) or not entry.strip():
                raise ValueError("rationale entries must be non-empty strings")
        if not isinstance(self.error_kind, EnforcementErrorKind):
            raise ValueError("error_kind must be an EnforcementErrorKind")
        if self.outcome is EnforcementOutcome.APPROVAL_REQUIRED and (
            self.approval_request is None
        ):
            raise ValueError("APPROVAL_REQUIRED result must carry an approval_request")
        if self.outcome is EnforcementOutcome.SANITIZED and (
            self.sanitized_payload is None
        ):
            raise ValueError("SANITIZED result must carry a sanitized_payload")
        if self.outcome is EnforcementOutcome.INTERNAL_ERROR and (
            self.error_kind is EnforcementErrorKind.NONE
        ):
            raise ValueError("INTERNAL_ERROR result must carry an error_kind")

    @property
    def permitted_to_proceed(self) -> bool:
        """``True`` only for ``ALLOWED`` / ``SANITIZED``. Derived, never stored."""

        return self.outcome in _PERMITTED_OUTCOMES

    @property
    def blocked(self) -> bool:
        return not self.permitted_to_proceed
