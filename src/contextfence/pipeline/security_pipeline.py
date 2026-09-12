"""The generic, provider-independent security pipeline (Phase 7, task Part H).

``SecurityPipeline`` wires the Phase 1-6 components together in the one order the
architecture mandates::

    SecurityEvent -> analysis -> risk -> policy -> enforcement -> audit

It knows nothing about any AI application. It does not import
:mod:`contextfence.adapters`, has no ``ClaudeCodeAdapter`` reference, and
contains no ``if adapter == ...`` branch. Its input is a canonical
:class:`~contextfence.core.models.event.SecurityEvent` (or an untrusted raw
mapping, which it admits through the :class:`EventGateway` first). Whichever
adapter produced the event, the pipeline behaves identically.

Every stage here already fails closed on its own (``run_detectors`` emits an
analysis-error marker instead of swallowing a detector fault; the Policy Engine
returns a fail-closed ``DENY`` on any internal error; the Enforcement Gate
returns a blocked ``INTERNAL_ERROR`` on any internal error). The pipeline adds no
new fail-open path. Audit is strictly downstream: a failure to build or append an
audit record is logged and surfaced as ``audit_append is None`` -- it never
alters the decision or the enforcement result (SECURITY.md §1.9; ARCHITECTURE.md
§3.8).
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence

from contextfence.analysis import DEFAULT_DETECTORS
from contextfence.analysis.detector import Detector, run_detectors
from contextfence.audit.record import build_audit_body
from contextfence.audit.sink import AppendResult, AuditSink
from contextfence.core.events.gateway import EventGateway
from contextfence.core.models.decision import Decision
from contextfence.core.models.event import SecurityEvent
from contextfence.core.models.risk import RiskView
from contextfence.core.risk.aggregator import aggregate_evidence
from contextfence.enforcement.approval import ApprovalResponse
from contextfence.enforcement.gate import DEFAULT_GATE, EnforcementGate
from contextfence.enforcement.results import EnforcementResult
from contextfence.pipeline.result import PipelineResult
from contextfence.policy.engine import PolicyEngine

__all__ = ["SecurityPipeline"]

_log = logging.getLogger("contextfence.pipeline")


class SecurityPipeline:
    """Deterministic orchestration: analysis, risk, policy, enforcement, audit."""

    __slots__ = ("_audit_sink", "_detectors", "_gate", "_gateway", "_policy_engine")

    def __init__(
        self,
        *,
        policy_engine: PolicyEngine,
        detectors: Sequence[Detector] = DEFAULT_DETECTORS,
        enforcement_gate: EnforcementGate = DEFAULT_GATE,
        audit_sink: AuditSink | None = None,
        event_gateway: EventGateway | None = None,
    ) -> None:
        if not isinstance(policy_engine, PolicyEngine):
            raise TypeError("policy_engine must be a PolicyEngine")
        if not isinstance(enforcement_gate, EnforcementGate):
            raise TypeError("enforcement_gate must be an EnforcementGate")
        self._policy_engine = policy_engine
        self._detectors = tuple(detectors)
        self._gate = enforcement_gate
        self._audit_sink = audit_sink
        self._gateway = event_gateway if event_gateway is not None else EventGateway()

    def admit(self, raw_event: Mapping[str, object]) -> SecurityEvent:
        """Validate an untrusted raw event into a :class:`SecurityEvent`.

        A thin pass-through to the :class:`EventGateway`; raises
        :class:`~contextfence.core.errors.MalformedEventError` on bad input.
        """

        return self._gateway.admit(raw_event)

    def submit(
        self,
        raw_event: Mapping[str, object],
        *,
        payload: str | None = None,
        approval_response: ApprovalResponse | None = None,
        include_agent_context: bool = False,
        provider_metadata: Mapping[str, str] | None = None,
    ) -> PipelineResult:
        """Admit ``raw_event``, then process it (``admit`` + ``process``)."""

        event = self.admit(raw_event)
        return self.process(
            event,
            payload=payload,
            approval_response=approval_response,
            include_agent_context=include_agent_context,
            provider_metadata=provider_metadata,
        )

    def process(
        self,
        event: SecurityEvent,
        *,
        payload: str | None = None,
        approval_response: ApprovalResponse | None = None,
        include_agent_context: bool = False,
        provider_metadata: Mapping[str, str] | None = None,
    ) -> PipelineResult:
        """Run one validated event through the whole pipeline.

        Args:
            event: a canonical, already-validated :class:`SecurityEvent`.
            payload: the text a ``SANITIZE`` outcome would operate on. Required
                only when the decision is ``SANITIZE``; otherwise ignored.
            approval_response: an operator response to fold into the audit
                ``approval_state`` (does not re-run enforcement).
            include_agent_context: pass the untrusted ``user_declared_task`` into
                the approval request's clearly-labelled unverified section.
            provider_metadata: small structural key/value pairs for the audit
                body (e.g. adapter id). Never secrets.

        Never raises for a security reason; each stage fails closed on its own.
        """

        if not isinstance(event, SecurityEvent):
            raise TypeError("process() requires a canonical SecurityEvent")

        evidence = run_detectors(event, self._detectors)
        risk_view = aggregate_evidence(evidence)
        decision = self._policy_engine.evaluate(event, evidence, risk_view)
        enforcement = self._gate.enforce(
            decision,
            event=event,
            risk_view=risk_view,
            evidence=evidence,
            payload=payload,
            include_agent_context=include_agent_context,
        )

        audit_append = self._record_audit(
            event=event,
            risk_view=risk_view,
            decision=decision,
            enforcement=enforcement,
            approval_response=approval_response,
            provider_metadata=provider_metadata,
        )

        return PipelineResult(
            event=event,
            evidence=evidence,
            risk_view=risk_view,
            decision=decision,
            enforcement=enforcement,
            audit_append=audit_append,
        )

    def _record_audit(
        self,
        *,
        event: SecurityEvent,
        risk_view: RiskView,
        decision: Decision,
        enforcement: EnforcementResult,
        approval_response: ApprovalResponse | None,
        provider_metadata: Mapping[str, str] | None,
    ) -> AppendResult | None:
        if self._audit_sink is None:
            return None
        try:
            body = build_audit_body(
                event=event,
                risk_view=risk_view,
                decision=decision,
                enforcement_result=enforcement,
                approval_response=approval_response,
                provider_metadata=provider_metadata,
            )
            return self._audit_sink.append(body)
        except Exception as exc:  # audit is downstream; never change the decision
            _log.error(
                "pipeline_audit_record_failed",
                extra={"error_type": type(exc).__name__},
            )
            return None
