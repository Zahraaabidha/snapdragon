"""The :class:`Decision` model.

A ``Decision`` is the authoritative output of the Policy Engine (Phase 4). It is
the *only* value in the system that represents an authorization outcome.

Security invariants enforced by the shape of this type (SECURITY.md §1.1;
ARCHITECTURE.md §3.5, §8, §12):

* It is frozen -- once produced it cannot be mutated by any later stage.
* Its constructor accepts only a :class:`DecisionOutcome` enum member plus
  provenance strings (a matched rule id and a structured rationale). It accepts
  no :class:`~contextfence.core.models.evidence.Evidence`, no
  :class:`~contextfence.core.models.risk.RiskView`, and no model handle, so
  there is no path by which analyzer or model output *is* a decision. Evidence
  influences a decision only indirectly, by the Policy Engine reading a
  ``RiskView`` and applying deterministic rules.
* This module must never be imported by anything under ``analysis/`` or
  ``inference/``.
"""

from __future__ import annotations

from dataclasses import dataclass

from contextfence.core.errors import ValidationError
from contextfence.core.models._validation import require_enum_member, require_text
from contextfence.core.models.enums import DecisionOutcome

__all__ = ["Decision"]


@dataclass(frozen=True, slots=True)
class Decision:
    """An authoritative security decision.

    Args:
        outcome: one of ALLOW / ASK / DENY / SANITIZE.
        matched_rule_id: identifier of the policy rule that produced this
            outcome. Required and non-empty -- every decision is traceable to an
            inspectable rule (there is no anonymous or default-constructed
            decision).
        rationale: an ordered, non-empty tuple of short human-readable reason
            strings. "Structured" means discrete factors, not one opaque blob;
            it is built by the Policy Engine from trusted facts, never from
            agent-supplied natural language (ARCHITECTURE.md §11).
    """

    outcome: DecisionOutcome
    matched_rule_id: str
    rationale: tuple[str, ...]

    def __post_init__(self) -> None:
        require_enum_member(self.outcome, DecisionOutcome, field="outcome")
        require_text(self.matched_rule_id, field="matched_rule_id")
        if not isinstance(self.rationale, tuple):
            raise ValidationError("rationale must be a tuple of strings")
        if not self.rationale:
            raise ValidationError("rationale must contain at least one entry")
        for entry in self.rationale:
            require_text(entry, field="rationale entry")
