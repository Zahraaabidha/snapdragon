"""PolicyContext: context only, never authorization."""

from __future__ import annotations

import dataclasses

import pytest

from contextfence.core.errors import ValidationError
from contextfence.core.models.decision import Decision
from contextfence.core.models.enums import DecisionOutcome
from contextfence.core.models.policy_context import EMPTY_POLICY_CONTEXT, PolicyContext


def test_empty_context_is_valid_and_carries_nothing() -> None:
    ctx = PolicyContext()
    assert ctx.profile_id is None
    assert ctx.session_id is None
    assert ctx.prior_decision_ids == ()
    assert ctx.user_declared_task is None


def test_shared_empty_singleton_is_a_policy_context() -> None:
    assert isinstance(EMPTY_POLICY_CONTEXT, PolicyContext)


def test_context_is_frozen() -> None:
    ctx = PolicyContext()
    with pytest.raises(dataclasses.FrozenInstanceError):
        ctx.profile_id = "x"  # type: ignore[misc]


def test_fields_are_only_context_never_authorization() -> None:
    names = {f.name for f in dataclasses.fields(PolicyContext)}
    assert names == {
        "profile_id",
        "session_id",
        "prior_decision_ids",
        "user_declared_task",
    }
    for forbidden in (
        "decision",
        "outcome",
        "authorized",
        "approved",
        "allow",
        "permission",
        "grant",
        "override",
    ):
        assert forbidden not in names


def test_decision_outcome_cannot_be_parked_in_a_text_field() -> None:
    # DecisionOutcome is a str subclass, so static typing does NOT catch this;
    # the runtime reject_enum_value guard is what keeps a decision token out of
    # a context field.
    with pytest.raises(ValidationError):
        PolicyContext(user_declared_task=DecisionOutcome.ALLOW)
    with pytest.raises(ValidationError):
        PolicyContext(profile_id=DecisionOutcome.ALLOW)


def test_prior_decision_ids_are_strings_not_decision_objects() -> None:
    d = Decision(outcome=DecisionOutcome.DENY, matched_rule_id="R", rationale=("x",))
    with pytest.raises(ValidationError):
        PolicyContext(prior_decision_ids=(d,))  # type: ignore[arg-type]

    ok = PolicyContext(prior_decision_ids=("decision-1", "decision-2"))
    assert ok.prior_decision_ids == ("decision-1", "decision-2")


def test_text_fields_reject_blank_and_non_string() -> None:
    with pytest.raises(ValidationError):
        PolicyContext(profile_id="  ")
    with pytest.raises(ValidationError):
        PolicyContext(session_id=123)  # type: ignore[arg-type]


def test_prior_decision_ids_must_be_tuple_of_non_empty_strings() -> None:
    with pytest.raises(ValidationError):
        PolicyContext(prior_decision_ids=["a"])  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        PolicyContext(prior_decision_ids=("",))
