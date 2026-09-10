"""The enforcement gate (Phase 5).

``EnforcementGate.enforce(decision, ...)`` applies a Policy Engine
:class:`Decision` and returns an immutable :class:`EnforcementResult`. It is a
security *gate*, not an executor: it never runs a command, touches the network
or filesystem, mutates the decision / event / evidence, re-evaluates policy, or
constructs a :class:`Decision`.

Mapping:

* ``ALLOW``    -> ``ALLOWED``            (permitted to proceed; the gate does not
                                          perform the action)
* ``DENY``     -> ``DENIED``             (blocked)
* ``ASK``      -> ``APPROVAL_REQUIRED``  (carries an :class:`ApprovalRequest`;
                                          never auto-approved)
* ``SANITIZE`` -> ``SANITIZED``          (carries a sanitized **copy**) or, if a
                                          safe sanitized copy cannot be
                                          established, ``DENIED`` / fail closed
* anything missing / unknown / raising -> ``INTERNAL_ERROR`` (blocked)

No error path yields ``ALLOWED``.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Sequence

from contextfence.core.models.decision import Decision
from contextfence.core.models.enums import DecisionOutcome
from contextfence.core.models.event import SecurityEvent
from contextfence.core.models.evidence import Evidence
from contextfence.core.models.risk import RiskView
from contextfence.enforcement.approval import build_approval_request
from contextfence.enforcement.results import (
    EnforcementErrorKind,
    EnforcementOutcome,
    EnforcementResult,
)
from contextfence.enforcement.sanitizer import findings_from_evidence, sanitize_text

__all__ = ["DEFAULT_GATE", "EnforcementGate"]

_log = logging.getLogger("contextfence.enforcement")


class EnforcementGate:
    """Stateless gate: a :class:`Decision` in, an :class:`EnforcementResult` out."""

    __slots__ = ()

    def enforce(
        self,
        decision: Decision | None,
        *,
        event: SecurityEvent | None = None,
        risk_view: RiskView | None = None,
        evidence: Sequence[Evidence] = (),
        payload: str | None = None,
        include_agent_context: bool = False,
    ) -> EnforcementResult:
        """Apply ``decision``. Never raises; fails closed to a blocked result."""

        try:
            return self._enforce(
                decision,
                event=event,
                risk_view=risk_view,
                evidence=evidence,
                payload=payload,
                include_agent_context=include_agent_context,
            )
        except Exception as exc:  # deliberate top-level fail-safe (ARCHITECTURE.md §9)
            _log.error("enforcement_failed", extra={"error_type": type(exc).__name__})
            return _error(
                EnforcementErrorKind.INTERNAL_EXCEPTION,
                detail=type(exc).__name__,
                decision=decision,
                note="enforcement failed internally; blocking",
            )

    def _enforce(
        self,
        decision: Decision | None,
        *,
        event: SecurityEvent | None,
        risk_view: RiskView | None,
        evidence: Sequence[Evidence],
        payload: str | None,
        include_agent_context: bool,
    ) -> EnforcementResult:
        if not isinstance(decision, Decision):
            return _error(
                EnforcementErrorKind.MISSING_DECISION,
                detail="no valid Decision supplied",
                decision=None,
                note="enforcement requires a Policy Engine Decision; blocking",
            )

        outcome = decision.outcome
        if outcome is DecisionOutcome.ALLOW:
            return EnforcementResult(
                outcome=EnforcementOutcome.ALLOWED,
                decision_outcome=outcome,
                matched_rule_id=decision.matched_rule_id,
                rationale=(
                    *decision.rationale,
                    "enforcement: permitted to proceed; the gate does not "
                    "perform the action",
                ),
            )

        if outcome is DecisionOutcome.DENY:
            return EnforcementResult(
                outcome=EnforcementOutcome.DENIED,
                decision_outcome=outcome,
                matched_rule_id=decision.matched_rule_id,
                rationale=(*decision.rationale, "enforcement: blocked"),
            )

        if outcome is DecisionOutcome.ASK:
            request = build_approval_request(
                decision,
                request_id=_new_request_id(),
                event=event,
                risk_view=risk_view,
                include_agent_context=include_agent_context,
            )
            return EnforcementResult(
                outcome=EnforcementOutcome.APPROVAL_REQUIRED,
                decision_outcome=outcome,
                matched_rule_id=decision.matched_rule_id,
                rationale=(
                    *decision.rationale,
                    "enforcement: explicit operator approval required; "
                    "not auto-approved",
                ),
                approval_request=request,
            )

        if outcome is DecisionOutcome.SANITIZE:
            return self._enforce_sanitize(decision, evidence, payload)

        return _error(
            EnforcementErrorKind.UNSUPPORTED_OUTCOME,
            detail=str(outcome),
            decision=decision,
            note="unsupported decision outcome; blocking",
        )

    def _enforce_sanitize(
        self,
        decision: Decision,
        evidence: Sequence[Evidence],
        payload: str | None,
    ) -> EnforcementResult:
        if payload is None:
            return _error(
                EnforcementErrorKind.MISSING_PAYLOAD,
                detail="SANITIZE decision but no payload supplied",
                decision=decision,
                note="cannot sanitize without a payload; blocking",
            )

        findings = findings_from_evidence(evidence)
        result = sanitize_text(payload, findings)
        if not result.ok or result.sanitized_text is None:
            return EnforcementResult(
                outcome=EnforcementOutcome.DENIED,
                decision_outcome=decision.outcome,
                matched_rule_id=decision.matched_rule_id,
                rationale=(
                    *decision.rationale,
                    "enforcement: a safe sanitized copy could not be "
                    "established; failing closed to a block",
                ),
                error_kind=EnforcementErrorKind.SANITIZATION_FAILED,
                error_detail=result.failure_reason,
                sanitization=result.summary,
            )

        return EnforcementResult(
            outcome=EnforcementOutcome.SANITIZED,
            decision_outcome=decision.outcome,
            matched_rule_id=decision.matched_rule_id,
            rationale=(
                *decision.rationale,
                f"enforcement: sanitized {result.summary.sanitized_span_count} "
                "span(s); the action may proceed with the modified copy only",
            ),
            sanitized_payload=result.sanitized_text,
            sanitization=result.summary,
        )


def _new_request_id() -> str:
    return f"approval-{uuid.uuid4()}"


def _error(
    kind: EnforcementErrorKind,
    *,
    detail: str,
    decision: Decision | None,
    note: str,
) -> EnforcementResult:
    return EnforcementResult(
        outcome=EnforcementOutcome.INTERNAL_ERROR,
        decision_outcome=decision.outcome if isinstance(decision, Decision) else None,
        matched_rule_id=(
            decision.matched_rule_id if isinstance(decision, Decision) else None
        ),
        rationale=(note,),
        error_kind=kind,
        error_detail=detail,
    )


# a thin, importable singleton for callers that need no configuration
DEFAULT_GATE: EnforcementGate = EnforcementGate()
