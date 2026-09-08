"""Event ingestion boundary for the ContextFence security core.

Exposes the :class:`~contextfence.core.events.gateway.EventGateway`, the single
validated entry point that turns an untrusted raw event into a canonical
:class:`~contextfence.core.models.event.SecurityEvent`.
"""

from __future__ import annotations

from contextfence.core.events.gateway import EventGateway

__all__ = ["EventGateway"]
