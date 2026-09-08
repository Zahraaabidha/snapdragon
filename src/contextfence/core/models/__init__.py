"""Shared typed data models for the ContextFence security core.

These are the foundational contracts every later phase builds on: the canonical
event, the evidence analyzers emit, the aggregated risk view the Policy Engine
reads, and the decision it returns. All are frozen and self-validating.

Nothing in this package imports the UI, an adapter, or an inference backend.
"""

from __future__ import annotations

from contextfence.core.models.decision import Decision
from contextfence.core.models.enums import (
    ActionType,
    DataClassification,
    DecisionOutcome,
    EvidenceCategory,
    EvidenceSource,
    ResourceType,
    Severity,
)
from contextfence.core.models.event import SecurityEvent
from contextfence.core.models.evidence import Evidence
from contextfence.core.models.policy_context import PolicyContext
from contextfence.core.models.risk import RiskView

__all__ = [
    "ActionType",
    "DataClassification",
    "Decision",
    "DecisionOutcome",
    "Evidence",
    "EvidenceCategory",
    "EvidenceSource",
    "PolicyContext",
    "ResourceType",
    "RiskView",
    "SecurityEvent",
    "Severity",
]
