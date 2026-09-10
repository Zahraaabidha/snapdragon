"""The deterministic detector contract and a safe runner.

Phase 2 scope (ARCHITECTURE.md §3.3): the deterministic analysis layer consumes
a validated :class:`~contextfence.core.models.event.SecurityEvent` and produces
:class:`~contextfence.core.models.evidence.Evidence`. It does nothing else -- no
scoring, no risk aggregation, no policy, no enforcement, no I/O.

A detector is any object with an ``analyze`` method matching :class:`Detector`.
New deterministic detectors can be added by implementing the protocol and adding
an instance to the tuple passed to :func:`run_detectors`; the Policy Engine and
every other layer are untouched.

Failure behaviour (ARCHITECTURE.md §9; SECURITY.md §2; task rule 11): if a
detector raises, :func:`run_detectors` does **not** swallow the error and return
"no evidence" (which downstream could read as "nothing found -> safe"). It emits
an explicit *analysis-error marker* -- ``Evidence`` with the detector's primary
category, ``severity=HIGH`` (the category could not be cleared) and
``confidence=0.0`` (no actual finding) -- and continues with the other
detectors. Severity and confidence stay separate; the marker forces downstream
policy (Phase 4) to escalate rather than fail open.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from contextfence.core.models.enums import EvidenceCategory, EvidenceSource, Severity
from contextfence.core.models.event import SecurityEvent
from contextfence.core.models.evidence import Evidence

__all__ = ["Detector", "iter_text_fields", "run_detectors"]

_log = logging.getLogger("contextfence.analysis")

ANALYSIS_ERROR_RULE_SUFFIX = "ANALYSIS_ERROR"


@runtime_checkable
class Detector(Protocol):
    """A deterministic, local, side-effect-free evidence producer.

    Implementations must be pure with respect to the event: read fields, return
    evidence, never mutate the event or perform I/O.
    """

    #: short stable namespace used to prefix this detector's rule ids
    namespace: str
    #: analyzer identity stamped onto every Evidence this detector emits
    source: EvidenceSource
    #: the category used for this detector's analysis-error marker
    primary_category: EvidenceCategory

    def analyze(self, event: SecurityEvent) -> tuple[Evidence, ...]:
        """Return zero or more findings for ``event`` (never a decision)."""
        ...


def run_detectors(
    event: SecurityEvent,
    detectors: Sequence[Detector],
) -> tuple[Evidence, ...]:
    """Run every detector over ``event`` and return the concatenated evidence.

    This is evidence *collection*, not aggregation: findings are returned in
    detector order with no scoring, deduplication, or ranking (that is Phase 3).
    A detector that raises or returns a non-``Evidence`` item yields an
    analysis-error marker instead of aborting the run.
    """

    findings: list[Evidence] = []
    for detector in detectors:
        try:
            produced = detector.analyze(event)
            _require_evidence_sequence(produced)
        except Exception as exc:  # re-surfaced as an evidence marker, never swallowed
            _log.warning(
                "detector_failed",
                extra={
                    "detector_namespace": getattr(detector, "namespace", "?"),
                    "error_type": type(exc).__name__,
                },
            )
            findings.append(_analysis_error_marker(detector, exc))
            continue
        findings.extend(produced)
    return tuple(findings)


#: Event fields that carry free-ish text a content detector (secrets, PII) may
#: scan. All are ``str`` or ``str | None`` on a frozen model, so reading them
#: cannot mutate the event.
_TEXT_FIELD_NAMES = ("resource", "destination", "actor")


def iter_text_fields(event: SecurityEvent) -> tuple[tuple[str, str], ...]:
    """Yield ``(field_name, text)`` for each non-empty text field of ``event``.

    Used by content detectors so they scan a single, documented set of fields
    rather than reaching into the event ad hoc. ``application`` is excluded on
    purpose (it is a fixed adapter identifier, not user/agent content).
    """

    pairs: list[tuple[str, str]] = []
    for name in _TEXT_FIELD_NAMES:
        value = getattr(event, name, None)
        if isinstance(value, str) and value:
            pairs.append((name, value))
    task = event.policy_context.user_declared_task
    if isinstance(task, str) and task:
        pairs.append(("policy_context.user_declared_task", task))
    return tuple(pairs)


def _require_evidence_sequence(value: object) -> None:
    if not isinstance(value, tuple):
        raise TypeError("detector.analyze must return a tuple")
    for item in value:
        if not isinstance(item, Evidence):
            raise TypeError("detector.analyze must return only Evidence items")


def _analysis_error_marker(detector: Detector, exc: Exception) -> Evidence:
    namespace = getattr(detector, "namespace", "DETECTOR")
    source = getattr(detector, "source", EvidenceSource.SECRET_DETECTOR)
    category = getattr(detector, "primary_category", EvidenceCategory.CREDENTIAL)
    return Evidence(
        source=source,
        category=category,
        severity=Severity.HIGH,
        confidence=0.0,
        metadata={
            "rule_id": f"{namespace}.{ANALYSIS_ERROR_RULE_SUFFIX}",
            "error_type": type(exc).__name__,
            "note": "detector raised; this category was not cleared",
        },
    )
