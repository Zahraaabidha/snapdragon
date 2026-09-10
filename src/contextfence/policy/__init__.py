"""ContextFence Policy Engine (Phase 4).

The Policy Engine is the sole authority for turning validated security context
(a ``SecurityEvent``, its ``Evidence``, and the aggregated ``RiskView``) into an
authorization ``Decision`` (ALLOW / ASK / DENY / SANITIZE). It is deterministic
and local: no LLM or semantic model, no enforcement, no audit, no I/O.

Public API:

* :class:`PolicyEngine` -- ``evaluate(event, evidence, risk_view) -> Decision``
* :class:`PolicyConfig`, :class:`PolicyRule`, :class:`RuleMatch` -- the typed,
  immutable, validated policy representation
* :data:`DEFAULT_POLICY` -- the shipped conservative default
* :class:`PolicyConfigError` -- raised when configuration fails validation
* :data:`POLICY_INTERNAL_ERROR_RULE_ID` -- rule id on the fail-closed decision

Nothing here imports enforcement, audit, UI, adapters, inference, or vendor
code, and ``Decision`` is constructed only inside
:mod:`contextfence.policy.engine`.
"""

from __future__ import annotations

from contextfence.policy.config import (
    OUTCOME_PRECEDENCE,
    PolicyConfig,
    PolicyConfigError,
    PolicyRule,
    RuleMatch,
)
from contextfence.policy.default_policy import DEFAULT_POLICY
from contextfence.policy.engine import POLICY_INTERNAL_ERROR_RULE_ID, PolicyEngine

__all__ = [
    "DEFAULT_POLICY",
    "OUTCOME_PRECEDENCE",
    "POLICY_INTERNAL_ERROR_RULE_ID",
    "PolicyConfig",
    "PolicyConfigError",
    "PolicyEngine",
    "PolicyRule",
    "RuleMatch",
]
