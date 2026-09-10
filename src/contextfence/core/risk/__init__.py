"""Risk aggregation (Phase 3).

``aggregate_evidence(evidence) -> RiskView`` turns detector evidence into the
existing :class:`~contextfence.core.models.risk.RiskView`. It summarises; it
does not decide. Nothing here imports the Policy Engine, enforcement, audit, the
UI, adapters, or inference code, and nothing here produces a ``Decision`` or
``DecisionOutcome``.
"""

from __future__ import annotations

from contextfence.core.risk.aggregator import aggregate_evidence

__all__ = ["aggregate_evidence"]
