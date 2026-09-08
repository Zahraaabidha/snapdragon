"""The :class:`Evidence` model.

Security analysis (deterministic detectors and the optional semantic analyzer)
produces ``Evidence`` and nothing else. Evidence never enforces and never
authorizes; it is consumed by the Risk Aggregator and the Policy Engine
(ARCHITECTURE.md §6, §12).

``Evidence`` is frozen. It carries two independent axes -- ``severity`` (impact,
an enum) and ``confidence`` (analyzer certainty, a float in ``[0.0, 1.0]``) --
which are never merged or substituted (SECURITY.md §4).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from contextfence.core.errors import ValidationError
from contextfence.core.models._validation import (
    require_confidence,
    require_enum_member,
    require_text,
)
from contextfence.core.models.enums import EvidenceCategory, EvidenceSource, Severity

__all__ = ["Evidence"]

_EMPTY_METADATA: Mapping[str, str] = MappingProxyType({})


def _empty_metadata() -> Mapping[str, str]:
    return _EMPTY_METADATA


@dataclass(frozen=True, slots=True)
class Evidence:
    """A single finding from one analyzer.

    Args:
        source: which analyzer produced the finding.
        category: the kind of finding.
        severity: potential impact if the finding is real.
        confidence: analyzer certainty, a float in ``[0.0, 1.0]``.
        metadata: optional string->string supporting detail (match offsets,
            fingerprints, model id, rule id). Must not contain raw secrets or
            other sensitive content; this constraint is enforced by review and
            by audit-layer tests (Phase 6), not structurally here.
    """

    source: EvidenceSource
    category: EvidenceCategory
    severity: Severity
    confidence: float
    metadata: Mapping[str, str] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        require_enum_member(self.source, EvidenceSource, field="source")
        require_enum_member(self.category, EvidenceCategory, field="category")
        require_enum_member(self.severity, Severity, field="severity")
        # Store confidence normalized to float, rejecting bool / NaN / range.
        object.__setattr__(
            self, "confidence", require_confidence(self.confidence, field="confidence")
        )
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


def _freeze_metadata(value: object) -> Mapping[str, str]:
    if isinstance(value, (MappingProxyType, dict)):
        items = dict(value)
    else:
        raise ValidationError("metadata must be a mapping of str to str")
    for key, val in items.items():
        require_text(key, field="metadata key", allow_empty=False)
        require_text(val, field="metadata value", allow_empty=True)
    return MappingProxyType(items)
