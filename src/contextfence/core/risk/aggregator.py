"""Deterministic risk aggregation (Phase 3).

Converts the flat list of :class:`~contextfence.core.models.evidence.Evidence`
produced by the deterministic detectors (Phase 2) into exactly one
:class:`~contextfence.core.models.risk.RiskView`, the structured summary the
Policy Engine (Phase 4) reads.

This layer summarises evidence. It does **not** decide anything: it never
returns or imports :class:`~contextfence.core.models.decision.Decision` /
``DecisionOutcome``, never calls the Policy Engine, and performs no enforcement,
audit, network, or other I/O.

Aggregation semantics
---------------------

Given ``evidence`` (any iterable of ``Evidence``), :func:`aggregate_evidence`
builds a ``RiskView`` as follows:

* **evidence_count** -- the number of evidence items supplied, counted verbatim.
  Duplicates and analysis-error markers are counted like any other item.

* **highest_severity** -- the single most severe :class:`Severity` present,
  chosen with :data:`_SEVERITY_ORDER` (an ordinal ranking of ``Severity``'s own
  documented impact order ``LOW < MEDIUM < HIGH < CRITICAL``). This is *not* a
  risk score: nothing is summed or weighted, no number is stored for severity,
  and the result is always a ``Severity`` enum member. ``None`` only when there
  is no evidence at all.

* **categories** -- the set of distinct :class:`EvidenceCategory` values across
  the evidence. A category appearing on many items appears once.

* **category_confidence** -- for each category, the **maximum** ``confidence``
  observed on any evidence item in that category. Highest-observed is used (not
  an average) so a single strong finding is not diluted by weak ones and a weak
  finding never inflates a strong one. Confidence is copied through unchanged;
  it is never combined with severity.

* **semantic_evidence_available** -- ``True`` iff at least one evidence item has
  ``source is EvidenceSource.SEMANTIC_ANALYZER``. Determined purely from
  provenance -- never inferred from severity or confidence.

* **empty input** -- yields ``RiskView(highest_severity=None)`` with empty
  categories, empty ``category_confidence``, ``semantic_evidence_available``
  ``False`` and ``evidence_count`` ``0`` (the model's valid empty form).

Severity and confidence stay separate throughout: severity selection uses only
:data:`_SEVERITY_ORDER`; confidence aggregation uses only ``max`` over floats;
the two are never mixed. There is deliberately no scalar "risk score" field
(ARCHITECTURE.md §3.4, §7; SECURITY.md §4).

Analysis-error evidence
-----------------------

Phase 2 emits an ``Evidence`` marker (``severity=HIGH``, ``confidence=0.0``,
``rule_id`` ending ``ANALYSIS_ERROR``) when a detector fails, instead of
returning nothing. This function treats that marker as ordinary evidence: it
contributes its category, it is counted, and its ``HIGH`` severity participates
in ``highest_severity`` selection. Its ``0.0`` confidence is carried through as
the category confidence when it is the only item in its category -- it is never
read as "safe" and never dropped. Detectors have already run; this layer never
catches detector exceptions.

Determinism
-----------

The result depends only on the multiset of evidence supplied. It uses no clock,
randomness, environment, or I/O. Output collections do not depend on Python set
iteration order: ``categories`` is a ``frozenset`` (compared by content) and
``category_confidence`` is built with categories in a stable sorted order.
Reordering the input yields an equal ``RiskView``.
"""

from __future__ import annotations

from collections.abc import Iterable

from contextfence.core.models.enums import EvidenceCategory, EvidenceSource, Severity
from contextfence.core.models.evidence import Evidence
from contextfence.core.models.risk import RiskView

__all__ = ["aggregate_evidence"]

#: ``Severity`` in ascending order of impact. Source of truth for "which
#: severity is highest"; encodes the order documented on the ``Severity`` enum.
#: Not a weight and not a score -- only an ordering over enum members.
_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)
_SEVERITY_RANK: dict[Severity, int] = {
    severity: index for index, severity in enumerate(_SEVERITY_ORDER)
}


def aggregate_evidence(evidence: Iterable[Evidence]) -> RiskView:
    """Summarise ``evidence`` into a single :class:`RiskView`.

    Deterministic and side-effect free. See the module docstring for the exact
    semantics of each ``RiskView`` field. Returns the model's empty form when
    ``evidence`` is empty. Never returns or constructs a decision.
    """

    items = tuple(evidence)

    if not items:
        return RiskView(highest_severity=None)

    categories = frozenset(item.category for item in items)

    highest_severity = max(
        (item.severity for item in items), key=_SEVERITY_RANK.__getitem__
    )

    category_confidence: dict[EvidenceCategory, float] = {
        category: max(item.confidence for item in items if item.category is category)
        for category in sorted(categories, key=lambda category: category.value)
    }

    semantic_evidence_available = any(
        item.source is EvidenceSource.SEMANTIC_ANALYZER for item in items
    )

    return RiskView(
        highest_severity=highest_severity,
        categories=categories,
        category_confidence=category_confidence,
        semantic_evidence_available=semantic_evidence_available,
        evidence_count=len(items),
    )
