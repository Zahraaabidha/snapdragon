"""Security-critical categorical vocabulary for the ContextFence core.

Every value in this module is a closed, typed enum rather than a free string
(CLAUDE.md §25, DEVELOPMENT.md §4: "no magic strings for security decisions").
Using enums means an unrecognised value raises ``ValueError`` at the boundary
instead of flowing into policy evaluation as an unknown string.

Scope note: these enums are expected to *grow* in later phases (new normalized
actions, new evidence categories as detectors are added in Phase 2, new analyzer
sources). Adding a member is a deliberate, reviewed change to the security core.
Removing or renaming a member is a breaking change to the event contract.

None of these types encode an authorization. In particular :class:`Severity` is
*impact*, never *confidence*, and :class:`DecisionOutcome` is produced only by
the Policy Engine (Phase 4), never by an analyzer or a model.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = [
    "SEVERITY_ORDER",
    "ActionType",
    "DataClassification",
    "DecisionOutcome",
    "EvidenceCategory",
    "EvidenceSource",
    "ResourceType",
    "Severity",
    "severity_rank",
]


class Severity(StrEnum):
    """Potential security impact if a finding is real.

    This is one of the two independent axes of a finding. It answers "how bad is
    it if this is true", *not* "how sure are we" -- that second axis is the
    numeric confidence carried alongside it (see
    :class:`contextfence.core.models.evidence.Evidence`). Severity and confidence
    are never substituted for one another (SECURITY.md §4, ARCHITECTURE.md §7).
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)
"""``Severity`` members in ascending order of impact -- the single source of
truth for "which severity is higher".

This is an *ordering over enum members*, not a numeric risk score: the positions
are never summed, weighted, averaged, or combined with confidence. Consumers use
it only to pick the more/most severe member (Risk Aggregator, Phase 3; Policy
Engine, Phase 4)."""

_SEVERITY_RANK: dict[Severity, int] = {
    severity: index for index, severity in enumerate(SEVERITY_ORDER)
}


def severity_rank(severity: Severity) -> int:
    """Return the ordinal position of ``severity`` in :data:`SEVERITY_ORDER`.

    ``LOW`` -> 0 .. ``CRITICAL`` -> 3. Use only for comparing two severities,
    never as a score.
    """

    return _SEVERITY_RANK[severity]


class DecisionOutcome(StrEnum):
    """The four authoritative outcomes the Policy Engine may return.

    Only the Policy Engine (Phase 4) constructs a
    :class:`contextfence.core.models.decision.Decision`. No analyzer, semantic
    model, adapter, or piece of agent-controlled text may create or change one
    (SECURITY.md §1.1, ARCHITECTURE.md §3.5, §12).
    """

    ALLOW = "ALLOW"
    ASK = "ASK"
    DENY = "DENY"
    SANITIZE = "SANITIZE"


class DataClassification(StrEnum):
    """Best known classification of the data involved in an action.

    Supplied by the adapter as its best assessment and later refined by
    deterministic detectors (Phase 2). There is intentionally no ``UNKNOWN``
    member: an absent classification is treated as a malformed event by the
    Event Gateway rather than being silently downgraded to ``NONE``
    (ARCHITECTURE.md §5 note, DEVELOPMENT.md §9; ratified in docs/DECISIONS.md
    D-0001).
    """

    NONE = "NONE"
    INTERNAL = "INTERNAL"
    PERSONAL_DATA = "PERSONAL_DATA"
    CREDENTIAL = "CREDENTIAL"
    SECRET = "SECRET"
    REGULATED = "REGULATED"


class EvidenceCategory(StrEnum):
    """The kind of finding a piece of :class:`Evidence` represents.

    Grows as detectors and the semantic analyzer are implemented (Phases 2 and
    8). The initial set matches the categories named in ARCHITECTURE.md §6. Kept
    a closed enum for now (docs/DECISIONS.md D-0002).
    """

    CREDENTIAL = "CREDENTIAL"
    PERSONAL_DATA = "PERSONAL_DATA"
    EXTERNAL_DATA_TRANSFER = "EXTERNAL_DATA_TRANSFER"
    EXCESSIVE_CAPABILITY = "EXCESSIVE_CAPABILITY"
    PROMPT_INJECTION = "PROMPT_INJECTION"


class EvidenceSource(StrEnum):
    """Which trusted analyzer produced a piece of :class:`Evidence`.

    Provenance is security-relevant: the Risk Aggregator and Policy Engine treat
    ``SEMANTIC_ANALYZER`` output as advisory/untrusted evidence and never as
    authority (ARCHITECTURE.md §3.3, §12). Deterministic detector sources are
    added in Phase 2. Kept a closed enum for now (docs/DECISIONS.md D-0002).
    """

    SECRET_DETECTOR = "SECRET_DETECTOR"
    PII_DETECTOR = "PII_DETECTOR"
    DESTINATION_CLASSIFIER = "DESTINATION_CLASSIFIER"
    CAPABILITY_ANALYZER = "CAPABILITY_ANALYZER"
    SEMANTIC_ANALYZER = "SEMANTIC_ANALYZER"


class ActionType(StrEnum):
    """Normalized action an adapter observed.

    Adapters translate their native events into one of these values
    (ARCHITECTURE.md §5). An unrecognised action is rejected by the Event
    Gateway -- it is not mapped to a catch-all "other" that policy might treat
    permissively.
    """

    FILE_READ = "file.read"
    FILE_WRITE = "file.write"
    FILE_DELETE = "file.delete"
    NETWORK_SEND = "network.send"
    TOOL_CALL = "tool.call"
    COMMAND_EXEC = "command.exec"


class ResourceType(StrEnum):
    """The kind of resource an action targets (ARCHITECTURE.md §5)."""

    FILE = "file"
    DIRECTORY = "directory"
    URL = "url"
    TOOL = "tool"
    COMMAND = "command"
    CLIPBOARD = "clipboard"
