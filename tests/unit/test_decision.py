"""Decision model: the four outcomes, provenance fields, immutability."""

from __future__ import annotations

import dataclasses

import pytest

from contextfence.core.errors import ValidationError
from contextfence.core.models.decision import Decision
from contextfence.core.models.enums import DecisionOutcome


@pytest.mark.parametrize("outcome", list(DecisionOutcome))
def test_all_four_outcomes_construct(outcome: DecisionOutcome) -> None:
    d = Decision(
        outcome=outcome,
        matched_rule_id="SYNTHETIC_RULE",
        rationale=("synthetic rationale line",),
    )
    assert d.outcome is outcome
    assert d.matched_rule_id == "SYNTHETIC_RULE"
    assert d.rationale == ("synthetic rationale line",)


def test_decision_is_frozen() -> None:
    d = Decision(
        outcome=DecisionOutcome.DENY,
        matched_rule_id="R",
        rationale=("x",),
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        d.outcome = DecisionOutcome.ALLOW  # type: ignore[misc]


def test_outcome_must_be_enum_member() -> None:
    with pytest.raises(ValidationError):
        Decision(outcome="ALLOW", matched_rule_id="R", rationale=("x",))  # type: ignore[arg-type]


def test_matched_rule_id_required_non_empty() -> None:
    with pytest.raises(ValidationError):
        Decision(outcome=DecisionOutcome.ALLOW, matched_rule_id="", rationale=("x",))
    with pytest.raises(ValidationError):
        Decision(outcome=DecisionOutcome.ALLOW, matched_rule_id="   ", rationale=("x",))


def test_rationale_must_be_non_empty_tuple_of_strings() -> None:
    with pytest.raises(ValidationError):
        Decision(outcome=DecisionOutcome.ALLOW, matched_rule_id="R", rationale=())
    with pytest.raises(ValidationError):
        Decision(
            outcome=DecisionOutcome.ALLOW,
            matched_rule_id="R",
            rationale=["x"],  # type: ignore[arg-type]
        )
    with pytest.raises(ValidationError):
        Decision(
            outcome=DecisionOutcome.ALLOW,
            matched_rule_id="R",
            rationale=("ok", 5),  # type: ignore[arg-type]
        )


def test_decision_constructor_takes_no_evidence_or_risk_view() -> None:
    # Structural guard for SECURITY.md §1.1: a Decision is provenance strings +
    # an outcome enum. It cannot be *built from* analyzer/model output.
    fields = {f.name for f in dataclasses.fields(Decision)}
    assert fields == {"outcome", "matched_rule_id", "rationale"}
