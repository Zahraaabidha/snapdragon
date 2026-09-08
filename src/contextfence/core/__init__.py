"""ContextFence security core.

Framework-agnostic, UI-agnostic, inference-vendor-agnostic. Phase 1 contains the
data contracts (:mod:`contextfence.core.models`) and the validated entry point
(:mod:`contextfence.core.events`). Later phases add risk aggregation, the Policy
Engine, enforcement, and audit under this package.
"""

from __future__ import annotations

from contextfence.core.errors import (
    ContextFenceError,
    MalformedEventError,
    ValidationError,
)

__all__ = [
    "ContextFenceError",
    "MalformedEventError",
    "ValidationError",
]
