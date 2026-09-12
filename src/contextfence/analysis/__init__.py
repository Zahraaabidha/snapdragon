"""Deterministic security analysis (Phase 2), plus optional semantic analysis
(Phase 8, :mod:`contextfence.analysis.semantic`).

This package consumes a validated
:class:`~contextfence.core.models.event.SecurityEvent` and produces
:class:`~contextfence.core.models.evidence.Evidence`. It is *evidence generation
only*: no risk aggregation (Phase 3), no policy evaluation (Phase 4), no
enforcement, no audit, and no I/O.

The deterministic detectors exported below (and this module itself) import
neither the Policy Engine, enforcement, audit, adapters, the UI, nor any
inference / vendor code -- and nothing here returns a
:class:`~contextfence.core.models.decision.Decision`. The one deliberate
exception is the :mod:`contextfence.analysis.semantic` subpackage: it is the
sole bridge to :mod:`contextfence.inference` (the model-independent
``InferenceProvider`` abstraction), imported explicitly and never bundled into
:data:`DEFAULT_DETECTORS` (docs/DECISIONS.md D-0004).
"""

from __future__ import annotations

from contextfence.analysis.capability import CapabilityDetector
from contextfence.analysis.destination import DestinationDetector
from contextfence.analysis.detector import Detector, iter_text_fields, run_detectors
from contextfence.analysis.pii import PiiDetector
from contextfence.analysis.secrets import SecretDetector

__all__ = [
    "DEFAULT_DETECTORS",
    "CapabilityDetector",
    "DestinationDetector",
    "Detector",
    "PiiDetector",
    "SecretDetector",
    "iter_text_fields",
    "run_detectors",
]

#: The deterministic detectors that always run, in order (ARCHITECTURE.md §3.3).
DEFAULT_DETECTORS: tuple[Detector, ...] = (
    SecretDetector(),
    PiiDetector(),
    DestinationDetector(),
    CapabilityDetector(),
)
