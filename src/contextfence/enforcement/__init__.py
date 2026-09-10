"""ContextFence enforcement + sanitization (Phase 5).

Consumes a Policy Engine :class:`~contextfence.core.models.decision.Decision`
and represents applying it. It is a local, deterministic, fail-closed security
gate -- not an executor, not a second Policy Engine, not a UI.

* :class:`EnforcementGate` / :data:`DEFAULT_GATE` --
  ``enforce(decision, ...) -> EnforcementResult``
* :class:`EnforcementResult`, :class:`EnforcementOutcome`,
  :class:`EnforcementErrorKind`
* Approval: :class:`ApprovalRequest`, :class:`ApprovalResponse`,
  :class:`ApprovalResponseKind`, :func:`build_approval_request`,
  :func:`resolve_approval`
* Sanitization: :func:`sanitize_text`, :func:`findings_from_evidence`,
  :class:`SanitizationResult`, :class:`SanitizationSummary`,
  :class:`SanitizeFinding`, :class:`SanitizedSpan`, :data:`SUPPORTED_RULE_IDS`

Nothing here imports the UI, adapters, inference providers, network clients,
subprocess, or a database, and no ``Decision`` is constructed anywhere in this
package.
"""

from __future__ import annotations

from contextfence.enforcement.approval import (
    ApprovalRequest,
    ApprovalResponse,
    ApprovalResponseKind,
    build_approval_request,
    resolve_approval,
)
from contextfence.enforcement.gate import DEFAULT_GATE, EnforcementGate
from contextfence.enforcement.results import (
    EnforcementErrorKind,
    EnforcementOutcome,
    EnforcementResult,
)
from contextfence.enforcement.sanitizer import (
    SUPPORTED_RULE_IDS,
    SanitizationResult,
    SanitizationSummary,
    SanitizedSpan,
    SanitizeFinding,
    findings_from_evidence,
    sanitize_text,
)

__all__ = [
    "DEFAULT_GATE",
    "SUPPORTED_RULE_IDS",
    "ApprovalRequest",
    "ApprovalResponse",
    "ApprovalResponseKind",
    "EnforcementErrorKind",
    "EnforcementGate",
    "EnforcementOutcome",
    "EnforcementResult",
    "SanitizationResult",
    "SanitizationSummary",
    "SanitizeFinding",
    "SanitizedSpan",
    "build_approval_request",
    "findings_from_evidence",
    "resolve_approval",
    "sanitize_text",
]
