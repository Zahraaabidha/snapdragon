"""The ContextFence Policy Engine (Phase 4).

The Policy Engine is the **only** component that turns validated security
context into an authorization :class:`~contextfence.core.models.decision.Decision`
(SECURITY.md §1.1; ARCHITECTURE.md §3.5, §8, §12). It is deterministic, local,
and side-effect free:

* no LLM / semantic-model call, no inference backend, no network, no I/O;
* it never enforces, executes, sanitizes, or audits anything -- it only returns
  a ``Decision``;
* it never mutates the ``SecurityEvent``, the ``Evidence``, or the ``RiskView``
  it is given;
* it never reads ``policy_context`` to select or alter policy. The engine
  evaluates against the single :class:`~contextfence.policy.config.PolicyConfig`
  it was constructed with. ``profile_id``, ``session_id``,
  ``user_declared_task`` and ``prior_decision_ids`` are ignored by evaluation,
  so an AI agent cannot grant itself authorization through event-controlled
  fields (task rules 20-25).

Inputs
------

``evaluate(event, evidence, risk_view)``:

* ``risk_view`` -- the Phase 3 aggregation. Authoritative for
  ``highest_severity``, ``categories`` and ``semantic_evidence_available``.
* ``evidence`` -- the flat detector evidence (plus ``event.semantic_signals``).
  Read **only** to detect the Phase 2 analysis-error marker, a signal the
  ``RiskView`` does not expose.
* ``event`` -- read only for ``action``, ``resource_type`` and
  ``data_classification``. No free-text field (``resource``, ``destination``,
  ``user_declared_task``) is read for the decision or placed in the rationale.

Rule precedence
---------------

1. Outcome tiers: ``DENY`` > ``SANITIZE`` > ``ASK`` > ``ALLOW``.
   :class:`PolicyConfig` rejects a rule list not ordered by these tiers, so a
   ``DENY`` rule always pre-empts a lower-tier rule that would also match.
2. Within evaluation the ordered ``rules`` are tried top to bottom; the first
   rule whose :class:`~contextfence.policy.config.RuleMatch` matches wins
   (documented, deterministic first-match over an explicitly tier-ordered list).
3. If no rule matches, ``config.default_rule`` applies (its ``outcome`` is
   ``ASK`` or ``DENY`` -- never a silent ALLOW).
4. Any internal evaluation error yields ``DENY`` with rule id
   :data:`POLICY_INTERNAL_ERROR_RULE_ID` and is logged. Failures are never
   hidden and never become ALLOW.

Fail-safe behaviour
-------------------

* ``semantic_evidence_available is False`` for a high-impact event resolves to
  ``ASK`` (or a stricter matching rule) -- never a silent ALLOW (task rule 29).
* An analysis-error marker resolves to ``ASK`` (or stricter) -- never ALLOW
  (task rule 20 / Phase 2 contract).
* An unmatched event uses the conservative default, not a permissive fallback.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass

from contextfence.core.models.decision import Decision
from contextfence.core.models.enums import (
    ActionType,
    DataClassification,
    DecisionOutcome,
    EvidenceCategory,
    ResourceType,
    Severity,
    severity_rank,
)
from contextfence.core.models.event import SecurityEvent
from contextfence.core.models.evidence import Evidence
from contextfence.core.models.risk import RiskView
from contextfence.policy.config import (
    PolicyConfig,
    PolicyConfigError,
    PolicyRule,
    RuleMatch,
)

__all__ = ["POLICY_INTERNAL_ERROR_RULE_ID", "PolicyEngine"]

_log = logging.getLogger("contextfence.policy")

#: rule id stamped on the fail-closed decision returned if evaluation raises.
POLICY_INTERNAL_ERROR_RULE_ID = "POLICY.INTERNAL_ERROR"

#: Mirrors ``contextfence.analysis.detector.ANALYSIS_ERROR_RULE_SUFFIX``. Kept a
#: local copy so the policy package need not import the analysis package; a test
#: asserts the two stay equal.
_ANALYSIS_ERROR_RULE_SUFFIX = "ANALYSIS_ERROR"


@dataclass(frozen=True, slots=True)
class _EvalFacts:
    """Trusted, derived facts about one event. Built once, never mutated."""

    action: ActionType
    resource_type: ResourceType
    classification: DataClassification
    categories: frozenset[EvidenceCategory]
    highest_severity: Severity | None
    analysis_error_present: bool
    semantic_evidence_available: bool
    evidence_count: int


def _is_analysis_error(evidence: Evidence) -> bool:
    """True if ``evidence`` is a Phase 2 detector-failure marker.

    Primary signal: a ``rule_id`` ending ``.ANALYSIS_ERROR``. Defensive
    fallback: the marker's fixed shape (``HIGH`` severity with ``0.0``
    confidence), so a marker missing its rule id is still not read as safe.
    """

    rule_id = evidence.metadata.get("rule_id", "")
    if rule_id.endswith(_ANALYSIS_ERROR_RULE_SUFFIX):
        return True
    return evidence.severity is Severity.HIGH and evidence.confidence == 0.0


def _derive_facts(
    event: SecurityEvent, evidence: Iterable[Evidence], risk_view: RiskView
) -> _EvalFacts:
    all_evidence = (*evidence, *event.semantic_signals)
    return _EvalFacts(
        action=event.action,
        resource_type=event.resource_type,
        classification=event.data_classification,
        categories=risk_view.categories,
        highest_severity=risk_view.highest_severity,
        analysis_error_present=any(_is_analysis_error(item) for item in all_evidence),
        semantic_evidence_available=risk_view.semantic_evidence_available,
        evidence_count=risk_view.evidence_count,
    )


def _severity_at_least(current: Severity | None, threshold: Severity) -> bool:
    return current is not None and severity_rank(current) >= severity_rank(threshold)


def _severity_at_most(current: Severity | None, threshold: Severity) -> bool:
    return current is None or severity_rank(current) <= severity_rank(threshold)


def _matches(match: RuleMatch, facts: _EvalFacts) -> bool:
    if match.match_all:
        return True
    if match.require_analysis_error and not facts.analysis_error_present:
        return False
    if match.require_semantic_unavailable and facts.semantic_evidence_available:
        return False
    if match.any_category and not (match.any_category & facts.categories):
        return False
    if match.all_categories and not (match.all_categories <= facts.categories):
        return False
    if match.forbid_categories and (match.forbid_categories & facts.categories):
        return False
    if match.min_severity is not None and not _severity_at_least(
        facts.highest_severity, match.min_severity
    ):
        return False
    if match.max_severity is not None and not _severity_at_most(
        facts.highest_severity, match.max_severity
    ):
        return False
    if match.classifications and facts.classification not in match.classifications:
        return False
    if match.actions and facts.action not in match.actions:
        return False
    return not (
        match.resource_types and facts.resource_type not in match.resource_types
    )


def _rationale(rule: PolicyRule, facts: _EvalFacts) -> tuple[str, ...]:
    """Build the decision rationale from trusted facts only (never agent text)."""

    lines = list(rule.rationale)
    lines.append(f"matched_rule={rule.rule_id}")
    lines.append(f"outcome={rule.outcome.value}")
    severity = (
        facts.highest_severity.value if facts.highest_severity is not None else "none"
    )
    lines.append(f"highest_severity={severity}")
    if facts.categories:
        lines.append(
            "evidence_categories="
            + ",".join(sorted(category.value for category in facts.categories))
        )
    lines.append(f"data_classification={facts.classification.value}")
    lines.append(f"action={facts.action.value}")
    lines.append(f"evidence_count={facts.evidence_count}")
    if facts.analysis_error_present:
        lines.append("analysis_error_present=true")
    if not facts.semantic_evidence_available:
        lines.append("semantic_evidence_available=false")
    return tuple(lines)


class PolicyEngine:
    """Deterministic evaluator: (event, evidence, risk_view) -> Decision."""

    __slots__ = ("_config",)

    def __init__(self, config: PolicyConfig) -> None:
        if not isinstance(config, PolicyConfig):
            raise PolicyConfigError(
                "PolicyEngine requires a validated PolicyConfig instance"
            )
        self._config = config

    @property
    def config(self) -> PolicyConfig:
        """The immutable policy this engine evaluates against (read-only)."""

        return self._config

    def evaluate(
        self,
        event: SecurityEvent,
        evidence: Iterable[Evidence],
        risk_view: RiskView,
    ) -> Decision:
        """Return the authoritative :class:`Decision` for one event.

        Deterministic and side-effect free. On any internal error, returns a
        fail-closed ``DENY`` (never raises, never ALLOW).
        """

        try:
            return self._evaluate(event, tuple(evidence), risk_view)
        except Exception as exc:  # deliberate top-level fail-safe (ARCHITECTURE.md §9)
            _log.error(
                "policy_evaluation_failed",
                extra={"error_type": type(exc).__name__},
            )
            return Decision(
                outcome=DecisionOutcome.DENY,
                matched_rule_id=POLICY_INTERNAL_ERROR_RULE_ID,
                rationale=(
                    "policy evaluation raised an internal error; failing closed",
                    f"error_type={type(exc).__name__}",
                ),
            )

    def _evaluate(
        self,
        event: SecurityEvent,
        evidence: tuple[Evidence, ...],
        risk_view: RiskView,
    ) -> Decision:
        if not isinstance(event, SecurityEvent):
            raise TypeError("event must be a SecurityEvent")
        if not isinstance(risk_view, RiskView):
            raise TypeError("risk_view must be a RiskView")

        facts = _derive_facts(event, evidence, risk_view)

        for rule in self._config.rules:
            if _matches(rule.match, facts):
                return Decision(
                    outcome=rule.outcome,
                    matched_rule_id=rule.rule_id,
                    rationale=_rationale(rule, facts),
                )

        default_rule = self._config.default_rule
        return Decision(
            outcome=default_rule.outcome,
            matched_rule_id=default_rule.rule_id,
            rationale=_rationale(default_rule, facts),
        )
