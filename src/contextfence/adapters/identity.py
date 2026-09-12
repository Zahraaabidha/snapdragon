"""Controlled AI-application identity (Phase 7, task Part D).

Every event that enters the core must say *which* AI application produced it. The
architecture must be able to tell Claude Code apart from a future adapter
**without the core enum vocabulary changing** -- a future adapter registers
itself, it does not edit the security core (task Part D, Part E).

:class:`AdapterId` is therefore a validated *value object*, not an enum: a small
frozen wrapper around a constrained string. "Controlled" means the form is
validated (a short lowercase ``snake_case`` slug), not that the set is closed.
The value becomes :attr:`SecurityEvent.application`, which the core already
treats as untrusted data -- the id never carries authorization weight.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from contextfence.adapters.errors import AdapterInputError

__all__ = ["AdapterId"]

#: A short, lowercase ``snake_case`` slug: a leading letter then 1-63 more
#: ``[a-z0-9_]`` characters. No dots, no separators an audit/policy field could
#: misread, no room for an arbitrary sentence.
_ADAPTER_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")


@dataclass(frozen=True, slots=True)
class AdapterId:
    """A validated, immutable identifier for one AI-application adapter.

    Args:
        value: the slug, e.g. ``"claude_code"``. Validated against
            :data:`_ADAPTER_ID_RE`. ``bool`` and :class:`enum.Enum` values are
            rejected even though some are ``str`` subclasses, so a
            decision-shaped token can never masquerade as an id.
    """

    value: str

    def __post_init__(self) -> None:
        if isinstance(self.value, (bool, Enum)) or not isinstance(self.value, str):
            raise AdapterInputError("adapter id must be a plain string")
        if not _ADAPTER_ID_RE.match(self.value):
            raise AdapterInputError(
                "adapter id must be a lowercase snake_case slug matching "
                f"{_ADAPTER_ID_RE.pattern!r}"
            )

    def __str__(self) -> str:
        return self.value
