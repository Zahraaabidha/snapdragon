"""Deterministic, synthetic-only test doubles for the semantic layer (Phase 8).

Mirrors ``tests/unit/_factories.py``: no real credentials, no real PII, no real
hostnames. Purely local Python objects -- no I/O, no network, no model.
"""

from __future__ import annotations

from contextfence.inference.provider import InferenceRequest, InferenceResult

__all__ = ["RaisingProvider", "StaticProvider"]


class StaticProvider:
    """Always returns the same, pre-built :class:`InferenceResult`."""

    def __init__(
        self, result: InferenceResult, *, provider_id: str = "static-test-provider"
    ) -> None:
        self.provider_id = provider_id
        self._result = result
        self.calls: list[InferenceRequest] = []

    def infer(self, request: InferenceRequest) -> InferenceResult:
        self.calls.append(request)
        return self._result


class RaisingProvider:
    """Always raises a configured exception -- for failure-path tests."""

    def __init__(
        self, exc: BaseException, *, provider_id: str = "raising-test-provider"
    ) -> None:
        self.provider_id = provider_id
        self._exc = exc

    def infer(self, request: InferenceRequest) -> InferenceResult:
        raise self._exc
