"""Synthetic builders for Phase 1 unit tests.

All values here are obviously synthetic. No real credentials, real personal
data, real hostnames, or routable destinations are used anywhere in the test
suite (SECURITY.md §7). Destination-like strings use the reserved ``.invalid``
TLD (RFC 2606) so they can never resolve.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from contextfence.core.models.enums import (
    ActionType,
    DataClassification,
    ResourceType,
)
from contextfence.core.models.event import SecurityEvent
from contextfence.core.models.policy_context import PolicyContext

# A fixed, valid UUID4 string for deterministic tests.
VALID_UUID = "12345678-1234-4234-8234-123456789abc"

# A fixed timezone-aware instant.
VALID_TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def valid_raw_event(**overrides: Any) -> dict[str, Any]:
    """Return a minimal well-formed raw event mapping for the Event Gateway."""

    base: dict[str, Any] = {
        "event_id": VALID_UUID,
        "timestamp": "2026-01-01T12:00:00+00:00",
        "actor": "synthetic-agent",
        "application": "synthetic_app",
        "action": "file.read",
        "resource": "synthetic/project/notes.txt",
        "resource_type": "file",
        "data_classification": "INTERNAL",
        "requested_capabilities": ["fs.read"],
        "policy_context": {},
    }
    base.update(overrides)
    return base


def valid_event(**overrides: Any) -> SecurityEvent:
    """Return a valid canonical :class:`SecurityEvent` built directly."""

    params: dict[str, Any] = {
        "event_id": VALID_UUID,
        "timestamp": VALID_TS,
        "actor": "synthetic-agent",
        "application": "synthetic_app",
        "action": ActionType.FILE_READ,
        "resource": "synthetic/project/notes.txt",
        "resource_type": ResourceType.FILE,
        "data_classification": DataClassification.INTERNAL,
        "destination": None,
        "requested_capabilities": ("fs.read",),
        "semantic_signals": (),
        "policy_context": PolicyContext(),
    }
    params.update(overrides)
    return SecurityEvent(**params)
