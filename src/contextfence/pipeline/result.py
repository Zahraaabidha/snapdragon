"""The immutable result of one security-pipeline run (Phase 7, task Part H).

A :class:`PipelineResult` bundles the artefacts every stage already produced --
the validated event, the detector evidence, the aggregated risk view, the Policy
Engine :class:`Decision`, the :class:`EnforcementResult`, and the audit
append result. It is a *report*, not an authorization: it constructs no
``Decision``, and the ``permitted_to_proceed`` convenience simply echoes the
:class:`EnforcementResult` (SECURITY.md §1.9).
"""

from __future__ import annotations

from dataclasses import dataclass

from contextfence.audit.sink import AppendResult
from contextfence.core.models.decision import Decision
from contextfence.core.models.enums import DecisionOutcome
from contextfence.core.models.event import SecurityEvent
from contextfence.core.models.evidence import Evidence
from contextfence.core.models.risk import RiskView
from contextfence.enforcement.results import EnforcementOutcome, EnforcementResult

__all__ = ["PipelineResult"]


@dataclass(frozen=True, slots=True)
class PipelineResult:
    """Everything one :meth:`SecurityPipeline.process` call produced.

    Args:
        event: the validated :class:`SecurityEvent` that was processed.
        evidence: detector evidence, in detector order (never aggregated here).
        risk_view: the Phase 3 :class:`RiskView` built from ``evidence``.
        decision: the authoritative Policy Engine :class:`Decision`.
        enforcement: the :class:`EnforcementResult` of applying ``decision``.
        audit_append: the audit :class:`AppendResult`, or ``None`` if the
            pipeline was constructed without an audit sink or the audit body
            could not be built (never a reason to change the decision).
    """

    event: SecurityEvent
    evidence: tuple[Evidence, ...]
    risk_view: RiskView
    decision: Decision
    enforcement: EnforcementResult
    audit_append: AppendResult | None

    @property
    def decision_outcome(self) -> DecisionOutcome:
        return self.decision.outcome

    @property
    def enforcement_outcome(self) -> EnforcementOutcome:
        return self.enforcement.outcome

    @property
    def permitted_to_proceed(self) -> bool:
        """Echoes :attr:`EnforcementResult.permitted_to_proceed`. Derived."""

        return self.enforcement.permitted_to_proceed

    @property
    def audit_recorded(self) -> bool:
        return self.audit_append is not None and self.audit_append.ok
