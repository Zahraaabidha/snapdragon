"""ContextFence — a privacy-first, on-device security boundary for AI-enabled PCs.

This package is the framework-agnostic security core. Phase 1 is implemented:
the data contracts (:mod:`contextfence.core.models`) and the validated entry
point (:mod:`contextfence.core.events`). Risk aggregation, the Policy Engine,
enforcement, audit, adapters, inference, and the UI are not implemented yet.
See the top-level documents (ARCHITECTURE.md, PROJECT_SPEC.md, THREAT_MODEL.md,
DEVELOPMENT.md, SECURITY.md) and CLAUDE.md for the engineering contract, and
DEVELOPMENT.md §3 for the phased build order.

Design rules that bind every future module in this package:

* The deterministic Policy Engine is the only component that returns a decision.
* AI / semantic model output is evidence, never authority.
* Nothing here may import the UI layer or any inference-vendor SDK.
"""

__version__ = "0.0.0"
