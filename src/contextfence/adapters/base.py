"""The provider-independent AI-adapter contract (Phase 7, task Part A).

An adapter connects one AI application or agent to ContextFence. Its **only**
job is translation: native event in, canonical
:class:`~contextfence.core.models.event.SecurityEvent` out (task Part C). It does
no security analysis, no risk scoring, no policy evaluation, no enforcement, no
audit, and no inference.

This module contains nothing Claude-specific, Cursor-specific, Copilot-specific,
Gemini-specific, or vendor-SDK-specific. Concrete adapters live in their own
subpackages (e.g. :mod:`contextfence.adapters.claude_code`) and depend on this
contract -- never the other way around.

Design: :class:`AIAdapter` is an abstract base class with a *template method*.
Subclasses implement only :meth:`AIAdapter.translate` (native mapping ->
:class:`~contextfence.adapters.input.AdapterInput`). The concrete
:meth:`AIAdapter.normalize` then:

1. calls the subclass ``translate``;
2. checks the result is an :class:`AdapterInput` whose ``application`` equals
   this adapter's :class:`~contextfence.adapters.identity.AdapterId`
   (identity binding -- an adapter cannot label its events as another
   application);
3. hands the rendered raw event to the :class:`EventGateway`.

Step 3 means an adapter can never bypass the Event Gateway and can never return
anything other than a validated ``SecurityEvent`` -- there is no code path from
an adapter to a :class:`~contextfence.core.models.decision.Decision`
(SECURITY.md §1.1, §1.12; ARCHITECTURE.md §3.1).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping

from contextfence.adapters.errors import AdapterInputError
from contextfence.adapters.identity import AdapterId
from contextfence.adapters.input import AdapterInput
from contextfence.core.events.gateway import EventGateway
from contextfence.core.models.event import SecurityEvent

__all__ = ["AIAdapter"]


class AIAdapter(ABC):
    """Abstract base for every AI-application adapter.

    Subclasses set the class attribute :attr:`adapter_id` and implement
    :meth:`translate`. They must not override :meth:`normalize`.
    """

    #: Stable identity for this adapter. Set by every concrete subclass.
    adapter_id: AdapterId

    def __init__(self) -> None:
        if not isinstance(getattr(type(self), "adapter_id", None), AdapterId):
            raise AdapterInputError(
                f"{type(self).__name__} must set a class attribute "
                "'adapter_id' of type AdapterId"
            )

    @abstractmethod
    def translate(self, native_event: Mapping[str, object]) -> AdapterInput:
        """Translate one native event into a typed :class:`AdapterInput`.

        Implementations map native vocabulary onto the core
        :class:`~contextfence.core.models.enums.ActionType` /
        :class:`~contextfence.core.models.enums.ResourceType` /
        :class:`~contextfence.core.models.enums.DataClassification` and
        capability strings. They must not detect secrets or PII, score risk,
        decide, or enforce. On a malformed native event they raise
        :class:`AdapterInputError`.
        """
        raise NotImplementedError

    def normalize(
        self,
        native_event: Mapping[str, object],
        *,
        gateway: EventGateway | None = None,
    ) -> SecurityEvent:
        """Normalize one native event into a canonical :class:`SecurityEvent`.

        Always routes through the :class:`EventGateway`; never returns anything
        else. Raises :class:`AdapterInputError` if ``translate`` returns a
        non-:class:`AdapterInput` or one whose ``application`` does not match
        :attr:`adapter_id`. A :class:`~contextfence.core.errors.MalformedEventError`
        from the gateway propagates unchanged.
        """

        adapter_input = self.translate(native_event)
        if not isinstance(adapter_input, AdapterInput):
            raise AdapterInputError(
                f"{type(self).__name__}.translate must return an AdapterInput"
            )
        if adapter_input.application != self.adapter_id.value:
            raise AdapterInputError(
                "adapter input 'application' must equal this adapter's id "
                f"({self.adapter_id.value!r})"
            )

        gw = gateway if gateway is not None else EventGateway()
        return gw.admit(adapter_input.to_raw_event())
