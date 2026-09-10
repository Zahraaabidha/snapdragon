"""Phase 4: policy configuration is typed, validated, immutable, fail-closed."""

from __future__ import annotations

import dataclasses

import pytest

from contextfence.core.models.enums import (
    ActionType,
    DecisionOutcome,
    EvidenceCategory,
    Severity,
)
from contextfence.policy.config import (
    OUTCOME_PRECEDENCE,
    PolicyConfig,
    PolicyConfigError,
    PolicyRule,
    RuleMatch,
)
from contextfence.policy.default_policy import DEFAULT_POLICY


def _rule(rule_id: str, outcome: DecisionOutcome, match: RuleMatch) -> PolicyRule:
    return PolicyRule(rule_id=rule_id, outcome=outcome, match=match, rationale=("r",))


_MATCH_ALL = RuleMatch(match_all=True)
_DEFAULT = _rule("DEFAULT.X", DecisionOutcome.ASK, _MATCH_ALL)


# --- RuleMatch validation ------------------------------------------------


def test_rule_match_requires_a_condition_or_match_all() -> None:
    with pytest.raises(PolicyConfigError):
        RuleMatch()


def test_match_all_must_be_used_alone() -> None:
    with pytest.raises(PolicyConfigError):
        RuleMatch(match_all=True, actions=frozenset({ActionType.FILE_READ}))


def test_rule_match_rejects_wrong_enum_types() -> None:
    with pytest.raises(PolicyConfigError):
        RuleMatch(any_category=frozenset({ActionType.FILE_READ}))  # type: ignore[arg-type]
    with pytest.raises(PolicyConfigError):
        RuleMatch(classifications=frozenset({EvidenceCategory.CREDENTIAL}))  # type: ignore[arg-type]
    with pytest.raises(PolicyConfigError):
        RuleMatch(min_severity="HIGH")  # type: ignore[arg-type]


def test_rule_match_is_frozen() -> None:
    match = RuleMatch(actions=frozenset({ActionType.FILE_READ}))
    with pytest.raises(dataclasses.FrozenInstanceError):
        match.match_all = True  # type: ignore[misc]


# --- PolicyRule validation ---------------------------------------------


def test_policy_rule_rejects_empty_id_and_rationale() -> None:
    with pytest.raises(PolicyConfigError):
        PolicyRule(
            rule_id="  ",
            outcome=DecisionOutcome.ASK,
            match=_MATCH_ALL,
            rationale=("r",),
        )
    with pytest.raises(PolicyConfigError):
        PolicyRule(
            rule_id="R", outcome=DecisionOutcome.ASK, match=_MATCH_ALL, rationale=()
        )
    with pytest.raises(PolicyConfigError):
        PolicyRule(
            rule_id="R", outcome=DecisionOutcome.ASK, match=_MATCH_ALL, rationale=("",)
        )


def test_policy_rule_rejects_non_enum_outcome() -> None:
    with pytest.raises(PolicyConfigError):
        PolicyRule(rule_id="R", outcome="ALLOW", match=_MATCH_ALL, rationale=("r",))  # type: ignore[arg-type]


def test_policy_rule_is_frozen() -> None:
    rule = _rule("R", DecisionOutcome.ASK, _MATCH_ALL)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rule.outcome = DecisionOutcome.ALLOW  # type: ignore[misc]


# --- PolicyConfig validation -----------------------------------------


def test_config_rejects_duplicate_rule_ids() -> None:
    with pytest.raises(PolicyConfigError):
        PolicyConfig(
            rules=(
                _rule(
                    "DUP", DecisionOutcome.DENY, RuleMatch(min_severity=Severity.LOW)
                ),
                _rule("DUP", DecisionOutcome.ASK, RuleMatch(min_severity=Severity.LOW)),
            ),
            default_rule=_DEFAULT,
        )


def test_config_rejects_rules_not_ordered_by_precedence_tier() -> None:
    allow = _rule(
        "A", DecisionOutcome.ALLOW, RuleMatch(actions=frozenset({ActionType.FILE_READ}))
    )
    deny = _rule(
        "D",
        DecisionOutcome.DENY,
        RuleMatch(actions=frozenset({ActionType.FILE_DELETE})),
    )
    with pytest.raises(PolicyConfigError):
        PolicyConfig(rules=(allow, deny), default_rule=_DEFAULT)
    # correct order is accepted
    PolicyConfig(rules=(deny, allow), default_rule=_DEFAULT)


def test_config_rejects_non_conservative_default() -> None:
    for bad in (DecisionOutcome.ALLOW, DecisionOutcome.SANITIZE):
        with pytest.raises(PolicyConfigError):
            PolicyConfig(rules=(), default_rule=_rule("DEF", bad, _MATCH_ALL))


def test_config_default_rule_must_be_match_all() -> None:
    with pytest.raises(PolicyConfigError):
        PolicyConfig(
            rules=(),
            default_rule=_rule(
                "DEF",
                DecisionOutcome.ASK,
                RuleMatch(actions=frozenset({ActionType.FILE_READ})),
            ),
        )


def test_config_is_frozen_and_deeply_immutable() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        DEFAULT_POLICY.rules = ()  # type: ignore[misc]
    # nested structures are tuples / frozensets
    assert isinstance(DEFAULT_POLICY.rules, tuple)
    for rule in DEFAULT_POLICY.all_rules():
        assert isinstance(rule.match.any_category, frozenset)
        assert isinstance(rule.rationale, tuple)


# --- the shipped default policy -------------------------------------


def test_default_policy_validates_and_is_tier_ordered() -> None:
    tiers = [OUTCOME_PRECEDENCE[r.outcome] for r in DEFAULT_POLICY.rules]
    assert tiers == sorted(tiers)


def test_default_policy_covers_all_four_outcomes_in_its_rules() -> None:
    outcomes = {r.outcome for r in DEFAULT_POLICY.rules}
    assert outcomes == {
        DecisionOutcome.DENY,
        DecisionOutcome.SANITIZE,
        DecisionOutcome.ASK,
        DecisionOutcome.ALLOW,
    }


def test_default_policy_default_rule_is_ask() -> None:
    assert DEFAULT_POLICY.default_rule.outcome is DecisionOutcome.ASK
    assert DEFAULT_POLICY.default_rule.rule_id == "DEFAULT.CONSERVATIVE_ASK"


def test_default_policy_rule_ids_are_all_specific() -> None:
    for rule in DEFAULT_POLICY.all_rules():
        assert rule.rule_id.strip()
        assert rule.rule_id not in {"unknown", "default", "rule", ""}
