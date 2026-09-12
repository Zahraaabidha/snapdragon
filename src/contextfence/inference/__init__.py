"""Model-independent inference boundary (Phase 8).

Exposes only the :class:`~contextfence.inference.provider.InferenceProvider`
Protocol and its strictly validated request/result schema. No concrete backend
lives here yet:

* Phase 9 adds ``contextfence.inference.cpu`` -- a local/CPU provider.
* Phase 10 adds ``contextfence.inference.snapdragon`` -- an NPU-accelerated
  provider, isolated so the rest of the tree never imports Qualcomm-specific
  code.

Nothing here performs network I/O, executes a tool/command, reads an arbitrary
file, or depends on a specific AI provider/vendor SDK. The Policy Engine,
enforcement, audit, and the generic pipeline do not import this package;
:mod:`contextfence.analysis.semantic` is the sole bridge between analysis and
inference (docs/DECISIONS.md D-0004).
"""

from __future__ import annotations

from contextfence.inference.errors import (
    SemanticAnalysisError,
    SemanticProviderUnavailableError,
)
from contextfence.inference.provider import (
    SEMANTIC_SCHEMA_VERSION,
    InferenceProvider,
    InferenceRequest,
    InferenceResult,
    SemanticFinding,
)

__all__ = [
    "SEMANTIC_SCHEMA_VERSION",
    "InferenceProvider",
    "InferenceRequest",
    "InferenceResult",
    "SemanticAnalysisError",
    "SemanticFinding",
    "SemanticProviderUnavailableError",
]
