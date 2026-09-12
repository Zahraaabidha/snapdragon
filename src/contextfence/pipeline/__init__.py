"""The generic ContextFence security pipeline (Phase 7).

A provider-independent orchestration boundary that feeds a canonical
:class:`~contextfence.core.models.event.SecurityEvent` through the existing
Phase 1-6 components in order: analysis -> risk -> policy -> enforcement ->
audit.

Nothing here imports :mod:`contextfence.adapters` or any concrete adapter, the
UI, or an inference backend. Any adapter's event runs through this same
pipeline with identical behaviour.
"""

from __future__ import annotations

from contextfence.pipeline.result import PipelineResult
from contextfence.pipeline.security_pipeline import SecurityPipeline

__all__ = ["PipelineResult", "SecurityPipeline"]
