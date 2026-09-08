"""The :class:`RiskView` model.

The Risk Aggregator (Phase 3) consumes all :class:`Evidence` for one event and
produces exactly one ``RiskView`` -- a structured summary the Policy Engine
reads. Phase 1 provides only the immutable container and its validation; the
aggregation logic that builds one from evidence is Phase 3.

``RiskView`` deliberately has **no single scalar "risk score"**. Severity and
confidence are kept as separate structured fields so that "high impact but low
confidence" stays visible to policy instead of being averaged away
(ARCHITECTURE.md §3.4, §7; SECURITY.md §4).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from contextfence.core.errors import ValidationError
from contextfence.core.models._validation import require_confidence, require_enum_member
from contextfence.core.models.enums import EvidenceCategory, Severity

__all__ = ["RiskView"]

_EMPTY_CONFIDENCE: Mapping[EvidenceCategory, float] = MappingProxyType({})


def _empty_confidence() -> Mapping[EvidenceCategory, float]:
    return _EMPTY_CONFIDENCE


@dataclass(frozen=True, slots=True)
class RiskView:
    """Structured, deterministic summary of the evidence for one event.

    Args:
        highest_severity: the most severe :class:`Severity` present across all
            evidence, or ``None`` when there is no evidence at all.
        categories: the set of triggered :class:`EvidenceCategory` values.
        category_confidence: per-category confidence in ``[0.0, 1.0]``. Every key
            must also appear in ``categories``.
        semantic_evidence_available: whether semantic analysis contributed
            evidence to this view. ``False`` means the semantic analyzer was
            disabled, unavailable, or errored -- which the Policy Engine treats
            as a reason to escalate high-impact actions, never to fail open
            (ARCHITECTURE.md §9, §12).
        evidence_count: how many individual :class:`Evidence` items were
            aggregated.
    """

    highest_severity: Severity | None
    categories: frozenset[EvidenceCategory] = field(default_factory=frozenset)
    category_confidence: Mapping[EvidenceCategory, float] = field(
        default_factory=_empty_confidence
    )
    semantic_evidence_available: bool = False
    evidence_count: int = 0

    def __post_init__(self) -> None:
        if self.highest_severity is not None:
            require_enum_member(
                self.highest_severity, Severity, field="highest_severity"
            )

        categories = _freeze_categories(self.categories)
        object.__setattr__(self, "categories", categories)

        object.__setattr__(
            self,
            "category_confidence",
            _freeze_category_confidence(self.category_confidence, categories),
        )

        if not isinstance(self.semantic_evidence_available, bool):
            raise ValidationError("semantic_evidence_available must be a bool")

        if not isinstance(self.evidence_count, int) or isinstance(
            self.evidence_count, bool
        ):
            raise ValidationError("evidence_count must be an int")
        if self.evidence_count < 0:
            raise ValidationError("evidence_count must not be negative")

        if categories and self.highest_severity is None:
            raise ValidationError(
                "highest_severity must be set when categories are present"
            )
        if self.evidence_count == 0 and categories:
            raise ValidationError(
                "evidence_count must be positive when categories are present"
            )


def _freeze_categories(value: object) -> frozenset[EvidenceCategory]:
    if not isinstance(value, (set, frozenset)):
        raise ValidationError("categories must be a set of EvidenceCategory")
    for member in value:
        require_enum_member(member, EvidenceCategory, field="categories member")
    return frozenset(value)


def _freeze_category_confidence(
    value: object, categories: frozenset[EvidenceCategory]
) -> Mapping[EvidenceCategory, float]:
    if isinstance(value, (MappingProxyType, dict)):
        items = dict(value)
    else:
        raise ValidationError(
            "category_confidence must be a mapping of EvidenceCategory to float"
        )
    frozen: dict[EvidenceCategory, float] = {}
    for key, conf in items.items():
        require_enum_member(key, EvidenceCategory, field="category_confidence key")
        if key not in categories:
            raise ValidationError(
                "category_confidence keys must be a subset of categories"
            )
        frozen[key] = require_confidence(conf, field="category_confidence value")
    return MappingProxyType(frozen)
