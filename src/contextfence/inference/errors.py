"""Error types for the model-independent inference boundary (Phase 8).

Mirrors the "reject, don't repair" contract used everywhere else in the core
(``contextfence.core.errors``, ``contextfence.adapters.errors``): a malformed
provider result or an unusable provider is rejected explicitly, never silently
converted into "no findings" (CLAUDE.md §9, §23; SECURITY.md §1.6).
"""

from __future__ import annotations

from contextfence.core.errors import ValidationError

__all__ = ["SemanticAnalysisError", "SemanticProviderUnavailableError"]


class SemanticAnalysisError(ValidationError):
    """Semantic analysis could not be completed or produced an invalid result.

    Raised for a malformed :class:`~contextfence.inference.provider.InferenceResult`
    / :class:`~contextfence.inference.provider.SemanticFinding` (unknown category,
    out-of-range or non-finite confidence, an unexpected field, a provider that
    returned the wrong type, ...). Caught generically by
    :func:`contextfence.analysis.detector.run_detectors` like any other detector
    failure -- it never becomes "no evidence found".
    """


class SemanticProviderUnavailableError(SemanticAnalysisError):
    """The configured :class:`~contextfence.inference.provider.InferenceProvider`
    could not perform inference at all (not loaded, disabled, out of scope for
    this event, ...), as distinct from a provider that ran and returned a
    malformed result. A provider raises this deliberately; other exceptions
    raised by a provider are treated the same way by the caller either way.
    """
