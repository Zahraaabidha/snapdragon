"""Small shared validators used by the core data models.

These helpers raise :class:`~contextfence.core.errors.ValidationError` on bad
input. They never coerce a bad value into a "safe-looking" one -- an invalid
field is rejected, not repaired (SECURITY.md §2, ARCHITECTURE.md §9).

Message discipline: helpers echo a value only for closed enum / numeric / type
mismatches. Free-text and path-like fields (``actor``, ``resource``,
``destination``, ``user_declared_task``) are referred to by name only, because
their values may be sensitive.
"""

from __future__ import annotations

import math
from enum import Enum
from typing import TypeVar

from contextfence.core.errors import ValidationError

__all__ = [
    "reject_enum_value",
    "require_confidence",
    "require_enum_member",
    "require_text",
]

_E = TypeVar("_E", bound=Enum)


def require_text(value: object, *, field: str, allow_empty: bool = False) -> str:
    """Return ``value`` if it is a non-empty ``str`` (after stripping).

    ``bool`` and enum instances are rejected even though some are ``str``
    subclasses, so an authorization-looking token (e.g. ``DecisionOutcome.ALLOW``)
    can never masquerade as free text.
    """

    if isinstance(value, (bool, Enum)):
        raise ValidationError(f"{field} must be a plain string")
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a string")
    if not allow_empty and not value.strip():
        raise ValidationError(f"{field} must not be empty")
    return value


def require_confidence(value: object, *, field: str = "confidence") -> float:
    """Return ``value`` as a ``float`` in the closed interval ``[0.0, 1.0]``.

    Rejects ``bool`` (it is an ``int`` subclass), non-numbers, and non-finite
    values. Confidence is the analyzer-certainty axis and must stay independent
    of :class:`~contextfence.core.models.enums.Severity` (SECURITY.md §4).
    """

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"{field} must be a real number in [0.0, 1.0]")
    number = float(value)
    if not math.isfinite(number):
        raise ValidationError(f"{field} must be finite")
    if number < 0.0 or number > 1.0:
        raise ValidationError(f"{field} must be within [0.0, 1.0], got {number!r}")
    return number


def require_enum_member(value: object, enum_cls: type[_E], *, field: str) -> _E:
    """Return ``value`` if it is already a member of ``enum_cls``.

    The gateway is responsible for resolving raw strings to enum members; the
    models themselves accept only real members, so a stray string cannot reach
    policy evaluation as an unknown value.
    """

    if not isinstance(value, enum_cls):
        raise ValidationError(
            f"{field} must be a {enum_cls.__name__} member, not {type(value).__name__}"
        )
    return value


def reject_enum_value(value: object, *, field: str) -> None:
    """Raise if ``value`` is any :class:`enum.Enum` instance.

    Used by :class:`~contextfence.core.models.policy_context.PolicyContext` to
    guarantee that a decision-like token cannot be smuggled into a context
    field (SECURITY.md §1, ARCHITECTURE.md §5 note: ``policy_context`` is context,
    never permission).
    """

    if isinstance(value, Enum):
        raise ValidationError(f"{field} must not be an enum value")
