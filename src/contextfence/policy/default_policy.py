"""The shipped conservative default policy (Phase 4).

A small, readable, rule-based policy consistent with PROJECT_SPEC.md,
ARCHITECTURE.md, SECURITY.md and THREAT_MODEL.md. It is *data* -- an immutable
:class:`~contextfence.policy.config.PolicyConfig` built once at import and
validated by that type's ``__post_init__`` (a mistake here fails import).

Design intent: **block credential/secret exposure outright, require human review
for anything else non-trivial, and allow only safe local read-only activity.**
Projects that need a different posture construct their own ``PolicyConfig``.

Rules are grouped by precedence tier (``DENY`` > ``SANITIZE`` > ``ASK`` >
``ALLOW``); the first matching rule in list order wins. ``default_rule`` (ASK)
covers everything unmatched -- e.g. a non-sensitive local file *write*, which is
deliberately not in the "safe" (read-only) allow-list.
"""

from __future__ import annotations

from contextfence.core.models.enums import (
    ActionType,
    DataClassification,
    DecisionOutcome,
    EvidenceCategory,
    ResourceType,
    Severity,
)
from contextfence.policy.config import PolicyConfig, PolicyRule, RuleMatch

__all__ = ["DEFAULT_POLICY"]

_SENSITIVE_CLASSIFICATIONS = frozenset(
    {
        DataClassification.PERSONAL_DATA,
        DataClassification.REGULATED,
        DataClassification.CREDENTIAL,
        DataClassification.SECRET,
    }
)
_ALL_EVIDENCE_CATEGORIES = frozenset(EvidenceCategory)
_DANGEROUS_ACTIONS = frozenset(
    {ActionType.COMMAND_EXEC, ActionType.FILE_DELETE, ActionType.NETWORK_SEND}
)


_DENY_RULES: tuple[PolicyRule, ...] = (
    PolicyRule(
        rule_id="DENY.SECRET_CLASSIFICATION",
        outcome=DecisionOutcome.DENY,
        match=RuleMatch(
            classifications=frozenset(
                {DataClassification.CREDENTIAL, DataClassification.SECRET}
            )
        ),
        rationale=(
            "the action involves data classified CREDENTIAL or SECRET; the "
            "default policy denies credential/secret exposure or access",
        ),
    ),
    PolicyRule(
        rule_id="DENY.CREDENTIAL_EVIDENCE",
        outcome=DecisionOutcome.DENY,
        match=RuleMatch(any_category=frozenset({EvidenceCategory.CREDENTIAL})),
        rationale=(
            "a deterministic detector found credential/secret material; the "
            "default policy denies rather than risk exposure",
        ),
    ),
)

_SANITIZE_RULES: tuple[PolicyRule, ...] = (
    PolicyRule(
        rule_id="SANITIZE.PII_EXTERNAL_TRANSFER",
        outcome=DecisionOutcome.SANITIZE,
        match=RuleMatch(
            all_categories=frozenset(
                {
                    EvidenceCategory.PERSONAL_DATA,
                    EvidenceCategory.EXTERNAL_DATA_TRANSFER,
                }
            )
        ),
        rationale=(
            "personal data is present and the action would transfer data "
            "externally; the payload must be sanitized before it may proceed",
        ),
    ),
)

_ASK_RULES: tuple[PolicyRule, ...] = (
    # Incomplete analysis is surfaced first: when a detector failed, "the
    # security picture is incomplete" is the most important reason to show a
    # human, even if a specific concern also matched (both appear in the
    # rationale).
    PolicyRule(
        rule_id="ASK.ANALYSIS_ERROR",
        outcome=DecisionOutcome.ASK,
        match=RuleMatch(require_analysis_error=True),
        rationale=(
            "a deterministic detector failed to run; the security picture is "
            "incomplete, so the action is not allowed automatically",
        ),
    ),
    PolicyRule(
        rule_id="ASK.SENSITIVE_CLASSIFICATION_EXTERNAL_TRANSFER",
        outcome=DecisionOutcome.ASK,
        match=RuleMatch(
            classifications=frozenset(
                {DataClassification.PERSONAL_DATA, DataClassification.REGULATED}
            ),
            any_category=frozenset({EvidenceCategory.EXTERNAL_DATA_TRANSFER}),
        ),
        rationale=(
            "personal/regulated data would be transferred externally; the "
            "default policy does not permit this automatically",
        ),
    ),
    PolicyRule(
        rule_id="ASK.PERSONAL_DATA_DETECTED",
        outcome=DecisionOutcome.ASK,
        match=RuleMatch(any_category=frozenset({EvidenceCategory.PERSONAL_DATA})),
        rationale=("personal data was detected in the action; a human must review",),
    ),
    PolicyRule(
        rule_id="ASK.EXTERNAL_DATA_TRANSFER",
        outcome=DecisionOutcome.ASK,
        match=RuleMatch(
            any_category=frozenset({EvidenceCategory.EXTERNAL_DATA_TRANSFER})
        ),
        rationale=("the action would transfer data to an external destination",),
    ),
    PolicyRule(
        rule_id="ASK.COMMAND_EXECUTION",
        outcome=DecisionOutcome.ASK,
        match=RuleMatch(actions=frozenset({ActionType.COMMAND_EXEC})),
        rationale=("command execution requires human review under the default policy",),
    ),
    PolicyRule(
        rule_id="ASK.DESTRUCTIVE_FILE_ACTION",
        outcome=DecisionOutcome.ASK,
        match=RuleMatch(actions=frozenset({ActionType.FILE_DELETE})),
        rationale=("a destructive file action requires human confirmation",),
    ),
    PolicyRule(
        rule_id="ASK.EXCESSIVE_CAPABILITY",
        outcome=DecisionOutcome.ASK,
        match=RuleMatch(
            any_category=frozenset({EvidenceCategory.EXCESSIVE_CAPABILITY})
        ),
        rationale=(
            "the action requests a security-sensitive capability (exec, egress, "
            "credential access, sensitive filesystem access)",
        ),
    ),
    PolicyRule(
        rule_id="ASK.SENSITIVE_FILE_ACCESS",
        outcome=DecisionOutcome.ASK,
        match=RuleMatch(
            actions=frozenset({ActionType.FILE_READ, ActionType.FILE_WRITE}),
            classifications=frozenset(
                {DataClassification.PERSONAL_DATA, DataClassification.REGULATED}
            ),
        ),
        rationale=("filesystem access to personal/regulated data requires review",),
    ),
    PolicyRule(
        rule_id="ASK.PROMPT_INJECTION_SUSPECTED",
        outcome=DecisionOutcome.ASK,
        match=RuleMatch(any_category=frozenset({EvidenceCategory.PROMPT_INJECTION})),
        rationale=("analysis flagged possible prompt-injection content",),
    ),
    # Backstops: guarantee a high-impact event never falls through to a silent
    # allow when semantic analysis did not contribute. These overlap the
    # specific rules above under the default set; they matter if those are ever
    # narrowed.
    PolicyRule(
        rule_id="ASK.SEMANTIC_UNAVAILABLE_HIGH_IMPACT",
        outcome=DecisionOutcome.ASK,
        match=RuleMatch(require_semantic_unavailable=True, min_severity=Severity.HIGH),
        rationale=(
            "semantic analysis did not contribute and the aggregated severity "
            "is HIGH or above; escalate rather than fail open",
        ),
    ),
    PolicyRule(
        rule_id="ASK.SEMANTIC_UNAVAILABLE_SENSITIVE_DATA",
        outcome=DecisionOutcome.ASK,
        match=RuleMatch(
            require_semantic_unavailable=True,
            classifications=_SENSITIVE_CLASSIFICATIONS,
        ),
        rationale=(
            "semantic analysis did not contribute and the data is sensitive; "
            "escalate rather than fail open",
        ),
    ),
    PolicyRule(
        rule_id="ASK.SEMANTIC_UNAVAILABLE_DANGEROUS_ACTION",
        outcome=DecisionOutcome.ASK,
        match=RuleMatch(require_semantic_unavailable=True, actions=_DANGEROUS_ACTIONS),
        rationale=(
            "semantic analysis did not contribute and the action is high-impact "
            "(exec / delete / network send); escalate rather than fail open",
        ),
    ),
)

_ALLOW_RULES: tuple[PolicyRule, ...] = (
    PolicyRule(
        rule_id="ALLOW.SAFE_LOCAL_READ",
        outcome=DecisionOutcome.ALLOW,
        match=RuleMatch(
            actions=frozenset({ActionType.FILE_READ}),
            resource_types=frozenset({ResourceType.FILE, ResourceType.DIRECTORY}),
            classifications=frozenset(
                {DataClassification.NONE, DataClassification.INTERNAL}
            ),
            forbid_categories=_ALL_EVIDENCE_CATEGORIES,
            max_severity=Severity.LOW,
        ),
        rationale=(
            "local read of a non-sensitive file/directory with no concerning "
            "evidence and no severe finding",
        ),
    ),
    PolicyRule(
        rule_id="ALLOW.SAFE_LOCAL_TOOL_CALL",
        outcome=DecisionOutcome.ALLOW,
        match=RuleMatch(
            actions=frozenset({ActionType.TOOL_CALL}),
            classifications=frozenset(
                {DataClassification.NONE, DataClassification.INTERNAL}
            ),
            forbid_categories=_ALL_EVIDENCE_CATEGORIES,
            max_severity=Severity.LOW,
        ),
        rationale=(
            "tool call on non-sensitive data with no concerning evidence and "
            "no severe finding",
        ),
    ),
)

DEFAULT_POLICY: PolicyConfig = PolicyConfig(
    rules=(*_DENY_RULES, *_SANITIZE_RULES, *_ASK_RULES, *_ALLOW_RULES),
    default_rule=PolicyRule(
        rule_id="DEFAULT.CONSERVATIVE_ASK",
        outcome=DecisionOutcome.ASK,
        match=RuleMatch(match_all=True),
        rationale=(
            "no explicit policy rule matched; the conservative default requires "
            "human review before the action may proceed",
        ),
    ),
)
