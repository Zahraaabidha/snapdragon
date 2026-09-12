"""Semantic security analysis (Phase 8).

Optional. Consumes a validated
:class:`~contextfence.core.models.event.SecurityEvent` and produces
:class:`~contextfence.core.models.evidence.Evidence` via a swappable
:class:`~contextfence.inference.provider.InferenceProvider`. Exactly like the
Phase 2 deterministic detectors, it never scores risk, evaluates policy,
enforces, or audits, and it never returns a
:class:`~contextfence.core.models.decision.Decision`.

This is the *only* subpackage under ``contextfence.analysis`` that imports
:mod:`contextfence.inference` -- the deterministic detectors
(:mod:`contextfence.analysis.secrets`, ``.pii``, ``.destination``,
``.capability``) do not, and neither does ``contextfence.core``, ``.policy``,
``.enforcement``, or ``.audit`` (docs/DECISIONS.md D-0004).

Not included in :data:`contextfence.analysis.DEFAULT_DETECTORS` -- there is no
safe default :class:`~contextfence.inference.provider.InferenceProvider` yet
(Phase 9/10). A caller that wants semantic analysis constructs a
:class:`SemanticAnalyzer` explicitly with a provider and passes it to
:class:`~contextfence.pipeline.SecurityPipeline`.
"""

from __future__ import annotations

from contextfence.analysis.semantic.analyzer import SemanticAnalyzer

__all__ = ["SemanticAnalyzer"]
