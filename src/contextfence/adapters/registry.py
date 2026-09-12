"""A small, local, deterministic adapter registry (Phase 7, task Part E).

The registry lets a process discover adapters by their stable
:class:`~contextfence.adapters.identity.AdapterId` without the security core
knowing any adapter by name. A future AI application registers its adapter
here; nothing in ``core/``, ``policy/``, ``enforcement/``, ``audit/``, or the
generic pipeline changes.

Deliberately **not** a plugin marketplace: no dynamic import, no entry-point
scanning, no package installation, no arbitrary code execution, no network. The
caller constructs adapter instances and hands them in. It is an in-memory dict
with validation.

There is no module-level singleton -- callers own their registry instance
(CLAUDE.md §25, "no global mutable state").
"""

from __future__ import annotations

from contextfence.adapters.base import AIAdapter
from contextfence.adapters.errors import (
    AdapterRegistryError,
    DuplicateAdapterError,
    UnknownAdapterError,
)
from contextfence.adapters.identity import AdapterId

__all__ = ["AdapterRegistry"]


class AdapterRegistry:
    """An in-memory map of :class:`AdapterId` -> :class:`AIAdapter` instance."""

    __slots__ = ("_adapters",)

    def __init__(self) -> None:
        self._adapters: dict[str, AIAdapter] = {}

    def register(self, adapter: AIAdapter) -> AdapterId:
        """Register ``adapter`` and return its :class:`AdapterId`.

        Raises:
            AdapterRegistryError: ``adapter`` is not an :class:`AIAdapter`, or
                its ``adapter_id`` is not an :class:`AdapterId`, or its
                ``normalize``/``translate`` attributes are not callable.
            DuplicateAdapterError: an adapter with the same id is already
                registered.
        """

        if not isinstance(adapter, AIAdapter):
            raise AdapterRegistryError("registered object must be an AIAdapter")
        adapter_id = getattr(adapter, "adapter_id", None)
        if not isinstance(adapter_id, AdapterId):
            raise AdapterRegistryError(
                "adapter.adapter_id must be an AdapterId instance"
            )
        if not callable(getattr(adapter, "normalize", None)) or not callable(
            getattr(adapter, "translate", None)
        ):
            raise AdapterRegistryError(
                "adapter must expose callable 'translate' and 'normalize'"
            )
        if adapter_id.value in self._adapters:
            raise DuplicateAdapterError(
                f"an adapter is already registered for id {adapter_id.value!r}"
            )
        self._adapters[adapter_id.value] = adapter
        return adapter_id

    def get(self, adapter_id: AdapterId | str) -> AIAdapter:
        """Return the adapter registered under ``adapter_id``.

        Raises:
            UnknownAdapterError: nothing is registered under that id.
            AdapterRegistryError: ``adapter_id`` is neither an
                :class:`AdapterId` nor a string.
        """

        key = self._key(adapter_id)
        try:
            return self._adapters[key]
        except KeyError as exc:
            raise UnknownAdapterError(f"no adapter registered for id {key!r}") from exc

    def is_registered(self, adapter_id: AdapterId | str) -> bool:
        return self._key(adapter_id) in self._adapters

    def adapter_ids(self) -> tuple[str, ...]:
        """Registered ids, sorted -- a stable, deterministic snapshot."""

        return tuple(sorted(self._adapters))

    def __len__(self) -> int:
        return len(self._adapters)

    @staticmethod
    def _key(adapter_id: AdapterId | str) -> str:
        if isinstance(adapter_id, AdapterId):
            return adapter_id.value
        if isinstance(adapter_id, str) and not isinstance(adapter_id, bool):
            return adapter_id
        raise AdapterRegistryError("adapter_id must be an AdapterId or a string")
