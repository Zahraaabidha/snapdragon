"""Typed, validated, immutable policy configuration (Phase 4).

A :class:`PolicyConfig` is an ordered list of :class:`PolicyRule` plus one
mandatory conservative ``default_rule``. Each rule pairs a declarative
:class:`RuleMatch` (a flat AND of optional conditions) with a
:class:`~contextfence.core.models.enums.DecisionOutcome` and a human-readable
rationale.

Security properties (SECURITY.md §1.14, §2; ARCHITECTURE.md §3.5, §10;
task rules 20-28):

* **Not agent-reachable.** A ``PolicyConfig`` is constructed by an operator /
  the process that builds the :class:`~contextfence.policy.engine.PolicyEngine`.
  Nothing here reads a :class:`~contextfence.core.models.event.SecurityEvent` or
  ``policy_context``; there is no code path from an event to a config mutation.
* **Immutable after validation.** Every type here is a frozen dataclass holding
  only frozensets / tuples / enums, so a validated config is deeply immutable.
* **Fail closed.** Invalid configuration raises :class:`PolicyConfigError` and is
  never silently replaced with something permissive. The ``default_rule`` may
  only be ``ASK`` or ``DENY`` -- an "allow everything" default is rejected.
* **Explicit precedence.** ``rules`` must be ordered by outcome tier
  (``DENY`` > ``SANITIZE`` > ``ASK`` > ``ALLOW``); a mis-ordered list is
  rejected. See :mod:`contextfence.policy.engine` for how the order is used.

This module constructs no :class:`~contextfence.core.models.decision.Decision`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TypeVar

from contextfence.core.errors import ContextFenceError
from contextfence.core.models.enums import (
    ActionType,
    DataClassification,
    DecisionOutcome,
    EvidenceCategory,
    ResourceType,
    Severity,
)

_E = TypeVar("_E", bound=Enum)

__all__ = [
    "OUTCOME_PRECEDENCE",
    "PolicyConfig",
    "PolicyConfigError",
    "PolicyRule",
    "RuleMatch",
]


class PolicyConfigError(ContextFenceError):
    """Raised when policy configuration fails validation. Fail closed."""


#: Lower number == higher precedence. ``DENY`` pre-empts ``SANITIZE`` pre-empts
#: ``ASK`` pre-empts ``ALLOW`` (ARCHITECTURE.md §8; task "RULE EVALUATION").
OUTCOME_PRECEDENCE: dict[DecisionOutcome, int] = {
    DecisionOutcome.DENY: 0,
    DecisionOutcome.SANITIZE: 1,
    DecisionOutcome.ASK: 2,
    DecisionOutcome.ALLOW: 3,
}


def _frozen_enum_set(
    value: object, enum_cls: type[_E], *, field_name: str
) -> frozenset[_E]:
    if not isinstance(value, (set, frozenset)):
        raise PolicyConfigError(f"{field_name} must be a set/frozenset")
    validated: set[_E] = set()
    for member in value:
        if not isinstance(member, enum_cls):
            raise PolicyConfigError(
                f"{field_name} entries must be {enum_cls.__name__} members"
            )
        validated.add(member)
    return frozenset(validated)


@dataclass(frozen=True, slots=True)
class RuleMatch:
    """A flat AND of optional match conditions over the evaluation facts.

    An empty condition means "don't care". A rule with no conditions at all is
    rejected unless ``match_all`` is set, so a rule cannot match everything by
    accident. ``match_all`` is the explicit catch-all and must be used alone.

    Conditions:

    * ``any_category`` -- at least one of these evidence categories is present.
    * ``all_categories`` -- every one of these categories is present.
    * ``forbid_categories`` -- none of these categories may be present.
    * ``min_severity`` -- ``highest_severity`` is present and at least this.
    * ``max_severity`` -- ``highest_severity`` is absent or at most this.
    * ``classifications`` -- the event ``data_classification`` is one of these.
    * ``actions`` -- the event ``action`` is one of these.
    * ``resource_types`` -- the event ``resource_type`` is one of these.
    * ``require_analysis_error`` -- an analysis-error marker is present.
    * ``require_semantic_unavailable`` -- semantic analysis did not contribute.
    """

    any_category: frozenset[EvidenceCategory] = field(default_factory=frozenset)
    all_categories: frozenset[EvidenceCategory] = field(default_factory=frozenset)
    forbid_categories: frozenset[EvidenceCategory] = field(default_factory=frozenset)
    min_severity: Severity | None = None
    max_severity: Severity | None = None
    classifications: frozenset[DataClassification] = field(default_factory=frozenset)
    actions: frozenset[ActionType] = field(default_factory=frozenset)
    resource_types: frozenset[ResourceType] = field(default_factory=frozenset)
    require_analysis_error: bool = False
    require_semantic_unavailable: bool = False
    match_all: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "any_category",
            _frozen_enum_set(
                self.any_category, EvidenceCategory, field_name="any_category"
            ),
        )
        object.__setattr__(
            self,
            "all_categories",
            _frozen_enum_set(
                self.all_categories, EvidenceCategory, field_name="all_categories"
            ),
        )
        object.__setattr__(
            self,
            "forbid_categories",
            _frozen_enum_set(
                self.forbid_categories, EvidenceCategory, field_name="forbid_categories"
            ),
        )
        object.__setattr__(
            self,
            "classifications",
            _frozen_enum_set(
                self.classifications, DataClassification, field_name="classifications"
            ),
        )
        object.__setattr__(
            self,
            "actions",
            _frozen_enum_set(self.actions, ActionType, field_name="actions"),
        )
        object.__setattr__(
            self,
            "resource_types",
            _frozen_enum_set(
                self.resource_types, ResourceType, field_name="resource_types"
            ),
        )

        for name in ("min_severity", "max_severity"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, Severity):
                raise PolicyConfigError(f"{name} must be a Severity or None")
        for name in (
            "require_analysis_error",
            "require_semantic_unavailable",
            "match_all",
        ):
            if not isinstance(getattr(self, name), bool):
                raise PolicyConfigError(f"{name} must be a bool")

        if self.match_all and self._has_any_condition():
            raise PolicyConfigError(
                "match_all rules must not also set other conditions"
            )
        if not self.match_all and not self._has_any_condition():
            raise PolicyConfigError(
                "a rule must set at least one condition, or match_all"
            )

    def _has_any_condition(self) -> bool:
        return bool(
            self.any_category
            or self.all_categories
            or self.forbid_categories
            or self.min_severity is not None
            or self.max_severity is not None
            or self.classifications
            or self.actions
            or self.resource_types
            or self.require_analysis_error
            or self.require_semantic_unavailable
        )


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """One inspectable policy rule: conditions -> outcome, with a rationale."""

    rule_id: str
    outcome: DecisionOutcome
    match: RuleMatch
    rationale: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.rule_id, str) or not self.rule_id.strip():
            raise PolicyConfigError("rule_id must be a non-empty string")
        if not isinstance(self.outcome, DecisionOutcome):
            raise PolicyConfigError("outcome must be a DecisionOutcome member")
        if not isinstance(self.match, RuleMatch):
            raise PolicyConfigError("match must be a RuleMatch")
        if not isinstance(self.rationale, tuple) or not self.rationale:
            raise PolicyConfigError("rationale must be a non-empty tuple of strings")
        for entry in self.rationale:
            if not isinstance(entry, str) or not entry.strip():
                raise PolicyConfigError("rationale entries must be non-empty strings")


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    """An immutable, validated policy: ordered rules + a conservative default."""

    rules: tuple[PolicyRule, ...]
    default_rule: PolicyRule

    def __post_init__(self) -> None:
        if not isinstance(self.rules, tuple):
            raise PolicyConfigError("rules must be a tuple of PolicyRule")
        for rule in self.rules:
            if not isinstance(rule, PolicyRule):
                raise PolicyConfigError("every rule must be a PolicyRule")
        if not isinstance(self.default_rule, PolicyRule):
            raise PolicyConfigError("default_rule must be a PolicyRule")

        ids = [rule.rule_id for rule in self.rules] + [self.default_rule.rule_id]
        if len(ids) != len(set(ids)):
            raise PolicyConfigError("rule_id values must be unique across the config")

        tiers = [OUTCOME_PRECEDENCE[rule.outcome] for rule in self.rules]
        if tiers != sorted(tiers):
            raise PolicyConfigError(
                "rules must be ordered by outcome precedence: "
                "DENY, then SANITIZE, then ASK, then ALLOW"
            )

        if self.default_rule.outcome not in (DecisionOutcome.ASK, DecisionOutcome.DENY):
            raise PolicyConfigError(
                "default_rule.outcome must be ASK or DENY (an ALLOW/SANITIZE "
                "default is not fail-safe)"
            )
        if not self.default_rule.match.match_all:
            raise PolicyConfigError("default_rule.match must be match_all")

    def all_rules(self) -> tuple[PolicyRule, ...]:
        """Every rule including the default, for inspection/testing."""

        return (*self.rules, self.default_rule)
