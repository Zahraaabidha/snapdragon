"""The semantic security analyzer (Phase 8).

``SemanticAnalyzer`` is *evidence generation only*, exactly like the Phase 2
deterministic detectors (:mod:`contextfence.analysis.detector`): it consumes a
validated :class:`~contextfence.core.models.event.SecurityEvent` and produces
:class:`~contextfence.core.models.evidence.Evidence`. It never scores risk,
evaluates policy, enforces, audits, or authorizes (task Part "SEMANTIC
ANALYZER"; SECURITY.md §1.1).

It satisfies the same :class:`~contextfence.analysis.detector.Detector`
protocol the deterministic detectors do (``namespace`` / ``source`` /
``primary_category`` / ``analyze``), so it can run through
:func:`~contextfence.analysis.detector.run_detectors` unchanged -- the existing
per-detector analysis-error-marker mechanism becomes this layer's own safety net
for free, with no new marker-construction code (docs/DECISIONS.md D-0004).

Failure discipline (task Part 4): if the provider is unavailable, raises, or
returns a malformed result, :meth:`analyze` does **not** catch the error and
return "no findings" -- it lets the exception propagate. ``run_detectors``
already turns that into an explicit ``SEMANTIC.ANALYSIS_ERROR`` evidence marker
(``source=SEMANTIC_ANALYZER``, ``severity=HIGH``, ``confidence=0.0``), which the
existing ``ASK.ANALYSIS_ERROR`` policy rule escalates unconditionally -- the
same fail-closed path every other detector failure already takes.
"""

from __future__ import annotations

from contextfence.analysis.detector import iter_text_fields
from contextfence.core.models.enums import EvidenceCategory, EvidenceSource
from contextfence.core.models.event import SecurityEvent
from contextfence.core.models.evidence import Evidence
from contextfence.inference.errors import SemanticAnalysisError
from contextfence.inference.provider import (
    InferenceProvider,
    InferenceRequest,
    InferenceResult,
    SemanticFinding,
)

__all__ = ["SemanticAnalyzer"]

_NAMESPACE = "SEMANTIC"


class SemanticAnalyzer:
    """Turns one :class:`InferenceProvider` result into semantic ``Evidence``.

    Args:
        provider: the swappable inference backend. Any object satisfying
            :class:`InferenceProvider` (Phase 8 ships no concrete provider --
            see Phase 9/10).
    """

    namespace: str = _NAMESPACE
    source: EvidenceSource = EvidenceSource.SEMANTIC_ANALYZER
    #: Category stamped on this analyzer's own analysis-error marker. Prompt
    #: injection is the headline threat semantic analysis exists to catch
    #: (ARCHITECTURE.md, SECURITY.md), so "the semantic layer could not run" is
    #: conservatively treated the same as "prompt injection could not be ruled
    #: out". This does not limit which categories individual findings may
    #: carry -- only the failure marker's category.
    primary_category: EvidenceCategory = EvidenceCategory.PROMPT_INJECTION

    __slots__ = ("_provider",)

    def __init__(self, provider: InferenceProvider) -> None:
        if not isinstance(provider, InferenceProvider):
            raise SemanticAnalysisError(
                "provider must implement the InferenceProvider protocol "
                "(provider_id attribute + infer(request) method)"
            )
        self._provider = provider

    def analyze(self, event: SecurityEvent) -> tuple[Evidence, ...]:
        """Return zero or more semantic findings for ``event`` (never a decision).

        Raises whatever the provider raises, or :class:`SemanticAnalysisError`
        if the provider returns something other than a valid
        :class:`InferenceResult`. Never caught here -- see module docstring.
        """

        request = InferenceRequest(
            action=event.action,
            resource_type=event.resource_type,
            data_classification=event.data_classification,
            requested_capabilities=event.requested_capabilities,
            text_fields=iter_text_fields(event),
        )

        result = self._provider.infer(request)
        if not isinstance(result, InferenceResult):
            raise SemanticAnalysisError(
                "InferenceProvider.infer() must return an InferenceResult"
            )

        return tuple(self._to_evidence(finding, result) for finding in result.findings)

    def _to_evidence(
        self, finding: SemanticFinding, result: InferenceResult
    ) -> Evidence:
        metadata = dict(finding.metadata)
        metadata.setdefault("provider_id", result.provider_id)
        metadata.setdefault("schema_version", str(result.schema_version))
        return Evidence(
            source=self.source,
            category=finding.category,
            severity=finding.severity,
            confidence=finding.confidence,
            metadata=metadata,
        )
