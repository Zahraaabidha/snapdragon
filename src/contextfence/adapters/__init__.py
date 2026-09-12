"""AI-application adapters: the provider-independent edge of ContextFence (Phase 7).

ContextFence is **not** a Claude Code security product. It is an AI-agnostic,
privacy-first, on-device security boundary. An adapter connects one AI
application or agent to the security core by translating that application's
native events into the canonical
:class:`~contextfence.core.models.event.SecurityEvent`. Claude Code is only the
*first reference adapter* used to prove the architecture.

This package exposes the **generic contract only**:

* :class:`~contextfence.adapters.identity.AdapterId` -- validated adapter identity
* :class:`~contextfence.adapters.input.AdapterInput` -- typed, untrusted input model
* :class:`~contextfence.adapters.base.AIAdapter` -- the ``translate`` / ``normalize``
  contract (routes through the Event Gateway; never produces a decision)
* :class:`~contextfence.adapters.registry.AdapterRegistry` -- local, deterministic
  discovery by id
* the adapter error hierarchy

Concrete adapters live in their own subpackages and are imported explicitly
(``from contextfence.adapters.claude_code import ClaudeCodeAdapter``). Nothing in
this package imports a concrete adapter, and nothing in ``core/``, ``policy/``,
``enforcement/``, ``audit/`` or :mod:`contextfence.pipeline` imports this package.
"""

from __future__ import annotations

from contextfence.adapters.base import AIAdapter
from contextfence.adapters.errors import (
    AdapterError,
    AdapterInputError,
    AdapterRegistryError,
    DuplicateAdapterError,
    UnknownAdapterError,
)
from contextfence.adapters.identity import AdapterId
from contextfence.adapters.input import (
    ADAPTER_INPUT_FIELDS,
    AUTHORIZATION_SHAPED_KEYS,
    AdapterInput,
)
from contextfence.adapters.registry import AdapterRegistry

__all__ = [
    "ADAPTER_INPUT_FIELDS",
    "AUTHORIZATION_SHAPED_KEYS",
    "AIAdapter",
    "AdapterError",
    "AdapterId",
    "AdapterInput",
    "AdapterInputError",
    "AdapterRegistry",
    "AdapterRegistryError",
    "DuplicateAdapterError",
    "UnknownAdapterError",
]
