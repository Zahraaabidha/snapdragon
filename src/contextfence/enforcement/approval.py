"""ASK approval workflow primitives (Phase 5).

No UI. These types represent the *request* ContextFence would show an operator,
the *response* the operator gives, and the resolution of an existing
``APPROVAL_REQUIRED`` enforcement state.

Security (task Part B; ARCHITECTURE.md §3.7, §11; SECURITY.md §6):

* An :class:`ApprovalRequest` carries only trusted, structured facts produced by
  ContextFence -- enum values, ids, counts, a fingerprint. It carries **no** raw
  resource / destination string. Any agent-authored text appears only in
  :attr:`ApprovalRequest.unverified_agent_context`, explicitly labelled, and is
  read by nothing.
* An :class:`ApprovalResponse` resolves an ASK; it does **not** create a
  :class:`Decision` and cannot change policy configuration.
* ``APPROVE`` on a matching request lets enforcement report the ASK as
  satisfied. ``REJECT`` / ``EXPIRED`` / ``INVALID`` (and any mismatch or wrong
  state) keep enforcement blocked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from contextfence.analysis.redaction import fingerprint
from contextfence.core.models.decision import Decision
from contextfence.core.models.enums import DecisionOutcome, EvidenceCategory
from contextfence.core.models.event import SecurityEvent
from contextfence.core.models.risk import RiskView
from contextfence.enforcement.results import (
    EnforcementErrorKind,
    EnforcementOutcome,
    EnforcementResult,
)

__all__ = [
    "ApprovalRequest",
    "ApprovalResponse",
    "ApprovalResponseKind",
    "build_approval_request",
    "resolve_approval",
]

#: The safe/recommended response is always REJECT; approval must be deliberate.
RECOMMENDED_RESPONSE = "REJECT"


class ApprovalResponseKind(StrEnum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    EXPIRED = "EXPIRED"
    INVALID = "INVALID"


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    """Structured, trusted facts for an operator decision. Immutable."""

    request_id: str
    matched_rule_id: str
    recommendation: str
    rationale: tuple[str, ...]
    application: str | None = None
    action: str | None = None
    resource_type: str | None = None
    resource_fingerprint: str | None = None
    classification: str | None = None
    destination_present: bool | None = None
    external_transfer: bool | None = None
    severity: str | None = None
    max_confidence: str | None = None
    evidence_categories: tuple[str, ...] = field(default_factory=tuple)
    unverified_agent_context: str | None = None

    def __post_init__(self) -> None:
        for name in ("request_id", "matched_rule_id", "recommendation"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if self.recommendation != RECOMMENDED_RESPONSE:
            raise ValueError("recommendation must be REJECT (the safe default)")
        if not isinstance(self.rationale, tuple) or not self.rationale:
            raise ValueError("rationale must be a non-empty tuple of strings")
        for entry in self.rationale:
            if not isinstance(entry, str) or not entry.strip():
                raise ValueError("rationale entries must be non-empty strings")
        if not isinstance(self.evidence_categories, tuple):
            raise ValueError("evidence_categories must be a tuple")
        if self.unverified_agent_context is not None and not isinstance(
            self.unverified_agent_context, str
        ):
            raise ValueError("unverified_agent_context must be a string or None")


@dataclass(frozen=True, slots=True)
class ApprovalResponse:
    """An operator response to an :class:`ApprovalRequest`. Immutable.

    Deliberately has no free-text authorization field -- only the kind, the id
    of the request being answered, and an optional opaque responder id.
    """

    request_id: str
    kind: ApprovalResponseKind
    responder_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, str) or not self.request_id.strip():
            raise ValueError("request_id must be a non-empty string")
        if not isinstance(self.kind, ApprovalResponseKind):
            raise ValueError("kind must be an ApprovalResponseKind")
        if self.responder_id is not None and not isinstance(self.responder_id, str):
            raise ValueError("responder_id must be a string or None")


def build_approval_request(
    decision: Decision,
    *,
    request_id: str,
    event: SecurityEvent | None = None,
    risk_view: RiskView | None = None,
    include_agent_context: bool = False,
) -> ApprovalRequest:
    """Build the request for an ``ASK`` decision from trusted facts only.

    Raises ``ValueError`` if ``decision`` is not an ``ASK`` decision -- an
    approval request exists only to resolve an ASK.
    """

    if not isinstance(decision, Decision):
        raise ValueError("decision must be a Decision")
    if decision.outcome is not DecisionOutcome.ASK:
        raise ValueError("an approval request is only built for an ASK decision")

    application = action = resource_type = classification = None
    resource_fp: str | None = None
    destination_present: bool | None = None
    agent_context: str | None = None
    if event is not None:
        application = event.application
        action = event.action.value
        resource_type = event.resource_type.value
        classification = event.data_classification.value
        resource_fp = fingerprint(event.resource)
        destination_present = event.destination is not None
        if include_agent_context:
            agent_context = event.policy_context.user_declared_task

    severity: str | None = None
    max_confidence: str | None = None
    external_transfer: bool | None = None
    categories: tuple[str, ...] = ()
    if risk_view is not None:
        severity = (
            risk_view.highest_severity.value
            if risk_view.highest_severity is not None
            else None
        )
        if risk_view.category_confidence:
            max_confidence = f"{max(risk_view.category_confidence.values()):.2f}"
        external_transfer = (
            EvidenceCategory.EXTERNAL_DATA_TRANSFER in risk_view.categories
        )
        categories = tuple(sorted(c.value for c in risk_view.categories))

    return ApprovalRequest(
        request_id=request_id,
        matched_rule_id=decision.matched_rule_id,
        recommendation=RECOMMENDED_RESPONSE,
        rationale=decision.rationale,
        application=application,
        action=action,
        resource_type=resource_type,
        resource_fingerprint=resource_fp,
        classification=classification,
        destination_present=destination_present,
        external_transfer=external_transfer,
        severity=severity,
        max_confidence=max_confidence,
        evidence_categories=categories,
        unverified_agent_context=agent_context,
    )


def resolve_approval(
    pending: EnforcementResult, response: ApprovalResponse
) -> EnforcementResult:
    """Resolve an ``APPROVAL_REQUIRED`` result with an operator response.

    Fail-closed: anything other than a well-formed ``APPROVE`` for the matching
    request keeps enforcement blocked. Never returns a :class:`Decision`.
    """

    if (
        not isinstance(pending, EnforcementResult)
        or pending.outcome is not EnforcementOutcome.APPROVAL_REQUIRED
        or not isinstance(pending.approval_request, ApprovalRequest)
    ):
        return EnforcementResult(
            outcome=EnforcementOutcome.INTERNAL_ERROR,
            decision_outcome=getattr(pending, "decision_outcome", None),
            matched_rule_id=getattr(pending, "matched_rule_id", None),
            rationale=("approval can only resolve an APPROVAL_REQUIRED result",),
            error_kind=EnforcementErrorKind.INVALID_APPROVAL_STATE,
            error_detail="not an APPROVAL_REQUIRED result",
        )

    request = pending.approval_request
    base_rationale = pending.rationale

    if not isinstance(response, ApprovalResponse):
        return _blocked(
            pending,
            EnforcementErrorKind.MALFORMED_APPROVAL_RESPONSE,
            "approval response was malformed",
        )
    if response.request_id != request.request_id:
        return _blocked(
            pending,
            EnforcementErrorKind.MALFORMED_APPROVAL_RESPONSE,
            "approval response did not match the pending request",
        )

    if response.kind is ApprovalResponseKind.APPROVE:
        return EnforcementResult(
            outcome=EnforcementOutcome.ALLOWED,
            decision_outcome=pending.decision_outcome,
            matched_rule_id=pending.matched_rule_id,
            rationale=(
                *base_rationale,
                "enforcement: operator APPROVED the ASK workflow; "
                "the already-authorized ASK may proceed",
            ),
        )

    reason = {
        ApprovalResponseKind.REJECT: "operator REJECTED the ASK",
        ApprovalResponseKind.EXPIRED: "approval EXPIRED / timed out",
        ApprovalResponseKind.INVALID: "approval response was INVALID",
    }[response.kind]
    clean = response.kind in (ApprovalResponseKind.REJECT, ApprovalResponseKind.EXPIRED)
    return EnforcementResult(
        outcome=EnforcementOutcome.DENIED,
        decision_outcome=pending.decision_outcome,
        matched_rule_id=pending.matched_rule_id,
        rationale=(
            *base_rationale,
            f"enforcement: {reason}; enforcement stays blocked",
        ),
        error_kind=(
            EnforcementErrorKind.NONE
            if clean
            else EnforcementErrorKind.MALFORMED_APPROVAL_RESPONSE
        ),
    )


def _blocked(
    pending: EnforcementResult, kind: EnforcementErrorKind, detail: str
) -> EnforcementResult:
    return EnforcementResult(
        outcome=EnforcementOutcome.DENIED,
        decision_outcome=pending.decision_outcome,
        matched_rule_id=pending.matched_rule_id,
        rationale=(
            *pending.rationale,
            f"enforcement: {detail}; enforcement stays blocked",
        ),
        error_kind=kind,
        error_detail=detail,
    )
