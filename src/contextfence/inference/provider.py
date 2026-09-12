"""The model-independent inference boundary (Phase 8, task Parts 2-3).

``InferenceProvider`` is the seam between the analyzer and a model/runtime::

    SemanticAnalyzer
          |
    InferenceProvider   <- this module
          |
      model/runtime

Nothing here imports PyTorch, ONNX Runtime, a Qualcomm SDK/QNN, Qualcomm AI Hub,
or any cloud API (CLAUDE.md §12, §13; ARCHITECTURE.md §13). A concrete provider
is added in a later phase (Phase 9: CPU/local; Phase 10: Snapdragon/NPU) by
implementing this Protocol -- :class:`~contextfence.analysis.semantic.SemanticAnalyzer`
and the Policy Engine are not touched when that happens.

Both directions of this boundary are strictly validated, immutable, and closed:

* :class:`InferenceRequest` is the *only* context a provider receives. It is
  built by the analyzer from an already-validated
  :class:`~contextfence.core.models.event.SecurityEvent` using the same bounded
  text surface the deterministic detectors scan
  (:func:`~contextfence.analysis.detector.iter_text_fields`) -- never raw
  credentials, never arbitrary event/adapter internals.
* :class:`InferenceResult` / :class:`SemanticFinding` are the *only* shape a
  provider may return. Confidence must be a finite float in ``[0.0, 1.0]``;
  severity and category must be real enum members; metadata keys are a small
  closed allowlist with bounded values. A malformed result is rejected at
  construction time (raises :class:`SemanticAnalysisError`) -- it can never
  reach the Risk Aggregator or Policy Engine as "trusted" data.

Deliberately absent from :class:`SemanticFinding`: a ``source`` field. Every
``Evidence`` this eventually becomes is stamped ``source=SEMANTIC_ANALYZER`` by
the analyzer itself (never by provider-controlled data), so a compromised or
buggy provider cannot claim to be a different, more trusted analyzer
(SECURITY.md §1.1, §1.5; task Part 6). Also absent: anything authorization-
shaped -- there is no field a provider could set to "approve", "allow", or
otherwise construct a :class:`~contextfence.core.models.decision.Decision`.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Protocol, runtime_checkable

from contextfence.core.errors import ValidationError
from contextfence.core.models._validation import require_confidence, require_text
from contextfence.core.models.enums import (
    ActionType,
    DataClassification,
    EvidenceCategory,
    ResourceType,
    Severity,
)
from contextfence.inference.errors import SemanticAnalysisError

__all__ = [
    "SEMANTIC_SCHEMA_VERSION",
    "InferenceProvider",
    "InferenceRequest",
    "InferenceResult",
    "SemanticFinding",
]

#: Current structured-result schema version. A provider result carrying a
#: different value is rejected rather than guessed-at (mirrors
#: ``audit.record.AUDIT_SCHEMA_VERSION``).
SEMANTIC_SCHEMA_VERSION = 1

#: The only metadata keys a :class:`SemanticFinding` may carry. Closed and
#: small on purpose: a provider (or content shaping a provider's output)
#: cannot smuggle an arbitrary key -- e.g. an authorization-shaped one -- into
#: evidence metadata (task Parts 3 and 6).
_ALLOWED_METADATA_KEYS: frozenset[str] = frozenset({"signal", "note", "matched_field"})
_METADATA_VALUE_MAX = 256
_PROVIDER_ID_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")

_EMPTY_METADATA: Mapping[str, str] = MappingProxyType({})


def _empty_metadata() -> Mapping[str, str]:
    return _EMPTY_METADATA


def _require_enum(value: object, enum_cls: type[Enum], *, field_name: str) -> Enum:
    """Accept an already-resolved member or its string value; reject anything else.

    Mirrors :func:`contextfence.adapters.input._require_enum` (kept as a local
    copy rather than a cross-package import -- ``inference`` has no reason to
    depend on ``adapters``, and vice versa; a test asserts the two behave
    identically). Raises :class:`SemanticAnalysisError` specifically, the same
    way every other rejection at this boundary does.
    """

    if isinstance(value, enum_cls):
        return value
    if isinstance(value, str) and not isinstance(value, Enum):
        try:
            return enum_cls(value)
        except ValueError as exc:
            raise SemanticAnalysisError(
                f"{field_name} has unrecognised value {value!r}"
            ) from exc
    raise SemanticAnalysisError(
        f"{field_name} must be a {enum_cls.__name__} member or its string value"
    )


def _require_confidence(value: object, *, field_name: str = "confidence") -> float:
    """As :func:`contextfence.core.models._validation.require_confidence`, but
    raises :class:`SemanticAnalysisError` -- the boundary's own error type,
    consistently, rather than a bare core ``ValidationError``."""

    try:
        return require_confidence(value, field=field_name)
    except ValidationError as exc:
        raise SemanticAnalysisError(str(exc)) from exc


def _require_text(value: object, *, field_name: str, allow_empty: bool = False) -> str:
    """As :func:`contextfence.core.models._validation.require_text`, but raises
    :class:`SemanticAnalysisError`."""

    try:
        return require_text(value, field=field_name, allow_empty=allow_empty)
    except ValidationError as exc:
        raise SemanticAnalysisError(str(exc)) from exc


def _freeze_finding_metadata(value: object) -> Mapping[str, str]:
    if isinstance(value, (MappingProxyType, dict)):
        items = dict(value)
    else:
        raise SemanticAnalysisError("metadata must be a mapping of str to str")
    unknown = sorted(set(items) - _ALLOWED_METADATA_KEYS)
    if unknown:
        raise SemanticAnalysisError(
            "unknown SemanticFinding metadata field(s): " + ", ".join(unknown)
        )
    for key, val in items.items():
        if not isinstance(val, str):
            raise SemanticAnalysisError(f"metadata[{key!r}] must be a string")
        if len(val) > _METADATA_VALUE_MAX or any(c in val for c in "\r\n\x00"):
            raise SemanticAnalysisError(
                f"metadata[{key!r}] is too long or contains control characters"
            )
    return MappingProxyType(items)


@dataclass(frozen=True, slots=True)
class SemanticFinding:
    """One strictly validated semantic finding. Never a decision.

    Args:
        category: the kind of finding -- a real
            :class:`~contextfence.core.models.enums.EvidenceCategory` member (or
            its string value). Unknown values are rejected, not coerced.
        confidence: analyzer certainty, a finite float in ``[0.0, 1.0]``. NaN,
            infinity, and out-of-range values are rejected.
        severity: potential impact if the finding is real -- independent of
            ``confidence`` and never derived from it (SECURITY.md §4).
        metadata: bounded, closed-key structural detail only (``signal``,
            ``note``, ``matched_field``). Never a raw excerpt of the analyzed
            text and never an authorization-shaped key.
    """

    category: EvidenceCategory
    confidence: float
    severity: Severity
    metadata: Mapping[str, str] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "category",
            _require_enum(self.category, EvidenceCategory, field_name="category"),
        )
        object.__setattr__(self, "confidence", _require_confidence(self.confidence))
        object.__setattr__(
            self,
            "severity",
            _require_enum(self.severity, Severity, field_name="severity"),
        )
        object.__setattr__(self, "metadata", _freeze_finding_metadata(self.metadata))


@dataclass(frozen=True, slots=True)
class InferenceResult:
    """The complete, validated output of one :meth:`InferenceProvider.infer` call.

    Args:
        findings: zero or more :class:`SemanticFinding`. Empty means "the
            provider ran and found nothing" -- distinct from a provider that
            could not run at all, which must raise instead of returning an
            empty result (task Part 4).
        provider_id: short identifier for the provider/model that produced
            this result (e.g. ``"static-test-provider"``). Safe to record --
            never a path, credential, or endpoint.
        schema_version: must equal :data:`SEMANTIC_SCHEMA_VERSION`.
    """

    findings: tuple[SemanticFinding, ...] = ()
    provider_id: str = "unknown"
    schema_version: int = SEMANTIC_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.findings, tuple):
            raise SemanticAnalysisError("findings must be a tuple of SemanticFinding")
        for item in self.findings:
            if not isinstance(item, SemanticFinding):
                raise SemanticAnalysisError(
                    "findings entries must be SemanticFinding instances"
                )
        provider_id = _require_text(self.provider_id, field_name="provider_id")
        if not _PROVIDER_ID_RE.match(provider_id):
            raise SemanticAnalysisError("provider_id has an invalid form")
        if (
            isinstance(self.schema_version, bool)
            or not isinstance(self.schema_version, int)
            or self.schema_version != SEMANTIC_SCHEMA_VERSION
        ):
            raise SemanticAnalysisError(
                f"schema_version must equal {SEMANTIC_SCHEMA_VERSION}"
            )


@dataclass(frozen=True, slots=True)
class InferenceRequest:
    """The only context handed to a provider. Bounded, immutable, validated.

    Args:
        action: the event's normalized action.
        resource_type: the event's normalized resource type.
        data_classification: the event's best-known data classification.
        requested_capabilities: capability strings the action needs.
        text_fields: ``(field_name, text)`` pairs -- exactly
            :func:`~contextfence.analysis.detector.iter_text_fields` for the
            event. The same bounded text surface the deterministic detectors
            see; nothing wider.
    """

    action: ActionType
    resource_type: ResourceType
    data_classification: DataClassification
    requested_capabilities: tuple[str, ...] = ()
    text_fields: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "action", _require_enum(self.action, ActionType, field_name="action")
        )
        object.__setattr__(
            self,
            "resource_type",
            _require_enum(self.resource_type, ResourceType, field_name="resource_type"),
        )
        object.__setattr__(
            self,
            "data_classification",
            _require_enum(
                self.data_classification,
                DataClassification,
                field_name="data_classification",
            ),
        )
        if not isinstance(self.requested_capabilities, tuple):
            raise SemanticAnalysisError("requested_capabilities must be a tuple")
        for entry in self.requested_capabilities:
            _require_text(entry, field_name="requested_capabilities entry")
        if not isinstance(self.text_fields, tuple):
            raise SemanticAnalysisError("text_fields must be a tuple")
        for pair in self.text_fields:
            if (
                not isinstance(pair, tuple)
                or len(pair) != 2
                or not all(isinstance(part, str) for part in pair)
            ):
                raise SemanticAnalysisError(
                    "text_fields entries must be (field_name, text) string pairs"
                )


@runtime_checkable
class InferenceProvider(Protocol):
    """A swappable inference backend. CPU (Phase 9) and Snapdragon/NPU (Phase 10)
    implement this same Protocol; nothing above this line changes when they do.
    """

    #: short, stable identifier for this provider (e.g. ``"cpu-onnx-v1"``).
    provider_id: str

    def infer(self, request: InferenceRequest) -> InferenceResult:
        """Run inference for ``request`` and return a validated result.

        Must not perform network I/O, execute tools/commands, read arbitrary
        files, or access credentials. Raise (any exception; prefer
        :class:`~contextfence.inference.errors.SemanticProviderUnavailableError`
        when the provider simply cannot run) rather than returning a result
        that pretends nothing is wrong.
        """
        ...
