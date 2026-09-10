"""Phase 3 Risk Aggregator: aggregate_evidence(evidence) -> RiskView.

Covers aggregation semantics, severity/confidence separation, analysis-error
preservation, determinism, immutability, and architectural boundaries.
"""

from __future__ import annotations

import ast
import dataclasses
import importlib
import pkgutil
import random
from collections.abc import Iterator
from pathlib import Path

import pytest

import contextfence.core.risk as risk_pkg
from contextfence.core.models.decision import Decision
from contextfence.core.models.enums import (
    DecisionOutcome,
    EvidenceCategory,
    EvidenceSource,
    Severity,
)
from contextfence.core.models.evidence import Evidence
from contextfence.core.models.risk import RiskView
from contextfence.core.risk import aggregate_evidence
from contextfence.core.risk.aggregator import _SEVERITY_ORDER

_RISK_DIR = Path(risk_pkg.__file__).parent

_FORBIDDEN_IMPORT_FRAGMENTS = (
    "PySide6",
    "onnxruntime",
    "qnn",
    "qai_hub",
    "qualcomm",
    "torch",
    "snapdragon",
    "contextfence.core.models.decision",
    "contextfence.policy",
    "contextfence.enforcement",
    "contextfence.audit",
    "contextfence.ui",
    "contextfence.adapters",
    "contextfence.inference",
)
_NETWORK_MODULES = frozenset(
    {
        "socket",
        "urllib.request",
        "http.client",
        "httplib",
        "requests",
        "ftplib",
        "asyncio",
    }
)


def ev(
    *,
    source: EvidenceSource = EvidenceSource.SECRET_DETECTOR,
    category: EvidenceCategory = EvidenceCategory.CREDENTIAL,
    severity: Severity = Severity.HIGH,
    confidence: float = 0.5,
    rule_id: str = "TEST.RULE",
) -> Evidence:
    return Evidence(
        source=source,
        category=category,
        severity=severity,
        confidence=confidence,
        metadata={"rule_id": rule_id},
    )


def analysis_error_marker(
    *,
    source: EvidenceSource = EvidenceSource.SECRET_DETECTOR,
    category: EvidenceCategory = EvidenceCategory.CREDENTIAL,
) -> Evidence:
    """A faithful copy of the Phase 2 detector-failure marker shape."""

    return Evidence(
        source=source,
        category=category,
        severity=Severity.HIGH,
        confidence=0.0,
        metadata={"rule_id": "SECRET.ANALYSIS_ERROR", "error_type": "RuntimeError"},
    )


# --- 1. empty input --------------------------------------------------------


def test_empty_evidence_produces_the_empty_risk_view() -> None:
    rv = aggregate_evidence([])
    assert rv == RiskView(highest_severity=None)
    assert rv.highest_severity is None
    assert rv.categories == frozenset()
    assert dict(rv.category_confidence) == {}
    assert rv.semantic_evidence_available is False
    assert rv.evidence_count == 0


def _gen(*items: Evidence) -> Iterator[Evidence]:
    yield from items


def test_accepts_a_single_pass_generator() -> None:
    assert aggregate_evidence(_gen()) == RiskView(highest_severity=None)
    rv = aggregate_evidence(_gen(ev(), ev(category=EvidenceCategory.PERSONAL_DATA)))
    assert rv.evidence_count == 2


# --- 2-4. highest severity + ordering -----------------------------------


def test_single_item_sets_its_severity_as_highest() -> None:
    for severity in Severity:
        rv = aggregate_evidence([ev(severity=severity)])
        assert rv.highest_severity is severity


def test_multiple_severities_select_the_most_severe() -> None:
    rv = aggregate_evidence(
        [
            ev(severity=Severity.LOW, category=EvidenceCategory.PERSONAL_DATA),
            ev(severity=Severity.CRITICAL, category=EvidenceCategory.CREDENTIAL),
            ev(
                severity=Severity.MEDIUM, category=EvidenceCategory.EXCESSIVE_CAPABILITY
            ),
        ]
    )
    assert rv.highest_severity is Severity.CRITICAL


def test_severity_order_constant_covers_every_member_ascending() -> None:
    assert set(_SEVERITY_ORDER) == set(Severity)
    assert _SEVERITY_ORDER == (
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    )


@pytest.mark.parametrize(
    "lower, higher",
    [
        (Severity.LOW, Severity.MEDIUM),
        (Severity.MEDIUM, Severity.HIGH),
        (Severity.HIGH, Severity.CRITICAL),
        (Severity.LOW, Severity.CRITICAL),
    ],
)
def test_pairwise_severity_selection_follows_the_contract(
    lower: Severity, higher: Severity
) -> None:
    rv = aggregate_evidence([ev(severity=lower), ev(severity=higher)])
    assert rv.highest_severity is higher


# --- 5-6. categories -----------------------------------------------------


def test_categories_are_collected() -> None:
    rv = aggregate_evidence(
        [
            ev(category=EvidenceCategory.CREDENTIAL),
            ev(category=EvidenceCategory.PERSONAL_DATA),
            ev(category=EvidenceCategory.EXTERNAL_DATA_TRANSFER),
        ]
    )
    assert rv.categories == {
        EvidenceCategory.CREDENTIAL,
        EvidenceCategory.PERSONAL_DATA,
        EvidenceCategory.EXTERNAL_DATA_TRANSFER,
    }


def test_duplicate_categories_collapse_but_are_still_counted() -> None:
    rv = aggregate_evidence(
        [
            ev(category=EvidenceCategory.CREDENTIAL, confidence=0.2),
            ev(category=EvidenceCategory.CREDENTIAL, confidence=0.4),
            ev(category=EvidenceCategory.CREDENTIAL, confidence=0.1),
        ]
    )
    assert rv.categories == {EvidenceCategory.CREDENTIAL}
    assert rv.evidence_count == 3


# --- 7-8. per-category confidence (max) --------------------------------


def test_per_category_confidence_uses_the_maximum_observed() -> None:
    rv = aggregate_evidence(
        [
            ev(category=EvidenceCategory.CREDENTIAL, confidence=0.30),
            ev(category=EvidenceCategory.CREDENTIAL, confidence=0.90),
            ev(category=EvidenceCategory.CREDENTIAL, confidence=0.50),
            ev(category=EvidenceCategory.PERSONAL_DATA, confidence=0.10),
        ]
    )
    assert rv.category_confidence[EvidenceCategory.CREDENTIAL] == pytest.approx(0.90)
    assert rv.category_confidence[EvidenceCategory.PERSONAL_DATA] == pytest.approx(0.10)


def test_every_category_has_a_confidence_entry() -> None:
    rv = aggregate_evidence(
        [
            ev(category=EvidenceCategory.CREDENTIAL),
            ev(category=EvidenceCategory.EXCESSIVE_CAPABILITY),
        ]
    )
    assert set(rv.category_confidence) == rv.categories


# --- 9-11. severity and confidence stay separate ---------------------


def test_confidence_is_never_derived_from_severity() -> None:
    rv = aggregate_evidence([ev(severity=Severity.CRITICAL, confidence=0.05)])
    assert rv.highest_severity is Severity.CRITICAL
    assert rv.category_confidence[EvidenceCategory.CREDENTIAL] == pytest.approx(0.05)


def test_critical_with_low_confidence_stays_critical_with_its_confidence() -> None:
    rv = aggregate_evidence(
        [
            ev(
                severity=Severity.CRITICAL,
                confidence=0.01,
                category=EvidenceCategory.CREDENTIAL,
            )
        ]
    )
    assert rv.highest_severity is Severity.CRITICAL
    assert rv.category_confidence[EvidenceCategory.CREDENTIAL] == pytest.approx(0.01)


def test_low_severity_with_high_confidence_stays_low_with_high_confidence() -> None:
    rv = aggregate_evidence(
        [
            ev(
                severity=Severity.LOW,
                confidence=0.99,
                category=EvidenceCategory.PERSONAL_DATA,
            )
        ]
    )
    assert rv.highest_severity is Severity.LOW
    assert rv.category_confidence[EvidenceCategory.PERSONAL_DATA] == pytest.approx(0.99)


def test_high_impact_low_confidence_and_low_impact_high_confidence_coexist() -> None:
    rv = aggregate_evidence(
        [
            ev(
                severity=Severity.CRITICAL,
                confidence=0.10,
                category=EvidenceCategory.CREDENTIAL,
            ),
            ev(
                severity=Severity.LOW,
                confidence=0.95,
                category=EvidenceCategory.PERSONAL_DATA,
            ),
        ]
    )
    assert rv.highest_severity is Severity.CRITICAL
    assert rv.category_confidence[EvidenceCategory.CREDENTIAL] == pytest.approx(0.10)
    assert rv.category_confidence[EvidenceCategory.PERSONAL_DATA] == pytest.approx(0.95)


# --- 12-13. semantic evidence availability (provenance only) --------


def test_semantic_source_sets_semantic_evidence_available() -> None:
    rv = aggregate_evidence(
        [
            ev(),
            ev(
                source=EvidenceSource.SEMANTIC_ANALYZER,
                category=EvidenceCategory.PROMPT_INJECTION,
                severity=Severity.MEDIUM,
                confidence=0.4,
            ),
        ]
    )
    assert rv.semantic_evidence_available is True


def test_no_semantic_source_leaves_semantic_evidence_available_false() -> None:
    rv = aggregate_evidence([ev(), ev(category=EvidenceCategory.PERSONAL_DATA)])
    assert rv.semantic_evidence_available is False


def test_semantic_availability_is_not_inferred_from_severity_or_confidence() -> None:
    rv = aggregate_evidence(
        [
            ev(
                severity=Severity.CRITICAL,
                confidence=1.0,
                source=EvidenceSource.SECRET_DETECTOR,
            )
        ]
    )
    assert rv.semantic_evidence_available is False


# --- 14-15. analysis-error evidence is real evidence --------------


def test_analysis_error_marker_is_preserved_alongside_findings() -> None:
    rv = aggregate_evidence(
        [
            ev(category=EvidenceCategory.PERSONAL_DATA, confidence=0.9),
            analysis_error_marker(category=EvidenceCategory.CREDENTIAL),
        ]
    )
    assert EvidenceCategory.CREDENTIAL in rv.categories
    assert rv.evidence_count == 2
    assert rv.highest_severity is Severity.HIGH


def test_lone_analysis_error_marker_is_not_treated_as_no_risk() -> None:
    rv = aggregate_evidence([analysis_error_marker()])
    assert rv != RiskView(highest_severity=None)
    assert rv.highest_severity is Severity.HIGH
    assert rv.categories == {EvidenceCategory.CREDENTIAL}
    assert rv.category_confidence[EvidenceCategory.CREDENTIAL] == 0.0
    assert rv.evidence_count == 1


def test_zero_confidence_marker_does_not_lower_a_real_finding_in_same_category() -> (
    None
):
    rv = aggregate_evidence(
        [
            ev(category=EvidenceCategory.CREDENTIAL, confidence=0.8),
            analysis_error_marker(category=EvidenceCategory.CREDENTIAL),
        ]
    )
    assert rv.category_confidence[EvidenceCategory.CREDENTIAL] == pytest.approx(0.8)


# --- 16. evidence count ---------------------------------------------


def test_evidence_count_matches_input_length_including_duplicates() -> None:
    items = [ev() for _ in range(5)] + [ev(category=EvidenceCategory.PERSONAL_DATA)]
    assert aggregate_evidence(items).evidence_count == 6


# --- 17-18. immutability -----------------------------------------------


def test_input_evidence_objects_are_not_mutated() -> None:
    items = [
        ev(severity=Severity.CRITICAL, confidence=0.2),
        ev(category=EvidenceCategory.PERSONAL_DATA, confidence=0.7),
        analysis_error_marker(category=EvidenceCategory.EXTERNAL_DATA_TRANSFER),
    ]
    snapshots = [repr(item) for item in items]
    aggregate_evidence(items)
    aggregate_evidence(items)
    assert [repr(item) for item in items] == snapshots


def test_returned_risk_view_is_immutable() -> None:
    rv = aggregate_evidence([ev()])
    with pytest.raises(dataclasses.FrozenInstanceError):
        rv.evidence_count = 99  # type: ignore[misc]
    with pytest.raises(TypeError):
        rv.category_confidence[EvidenceCategory.CREDENTIAL] = 0.0  # type: ignore[index]


# --- 19. determinism / reordering ---------------------------------


def test_reordering_equivalent_evidence_produces_an_equal_risk_view() -> None:
    items = [
        ev(
            severity=Severity.LOW,
            confidence=0.9,
            category=EvidenceCategory.PERSONAL_DATA,
        ),
        ev(
            severity=Severity.CRITICAL,
            confidence=0.2,
            category=EvidenceCategory.CREDENTIAL,
        ),
        ev(
            severity=Severity.MEDIUM,
            confidence=0.5,
            category=EvidenceCategory.CREDENTIAL,
        ),
        analysis_error_marker(category=EvidenceCategory.EXCESSIVE_CAPABILITY),
        ev(
            source=EvidenceSource.SEMANTIC_ANALYZER,
            category=EvidenceCategory.PROMPT_INJECTION,
            severity=Severity.HIGH,
            confidence=0.55,
        ),
    ]
    baseline = aggregate_evidence(items)
    rng = random.Random(1234)
    for _ in range(20):
        shuffled = items[:]
        rng.shuffle(shuffled)
        assert aggregate_evidence(shuffled) == baseline


def test_repeated_calls_on_the_same_input_are_equal() -> None:
    items = [ev(), ev(category=EvidenceCategory.PERSONAL_DATA, confidence=0.3)]
    assert aggregate_evidence(items) == aggregate_evidence(items)


# --- 20-22. no authorization anywhere -----------------------------


def test_result_is_a_risk_view_and_never_a_decision() -> None:
    rv = aggregate_evidence([ev()])
    assert isinstance(rv, RiskView)
    assert not isinstance(rv, Decision)


def test_risk_view_exposes_no_decision_or_outcome_field() -> None:
    rv = aggregate_evidence([ev()])
    for forbidden in (
        "decision",
        "outcome",
        "allow",
        "deny",
        "ask",
        "sanitize",
        "authorized",
    ):
        assert not hasattr(rv, forbidden)


def test_aggregate_evidence_cannot_be_coerced_into_an_outcome() -> None:
    rv = aggregate_evidence([ev(severity=Severity.CRITICAL, confidence=1.0)])
    # the result carries a Severity, never a DecisionOutcome
    assert not isinstance(rv.highest_severity, DecisionOutcome)
    severity_value = rv.highest_severity.value if rv.highest_severity else ""
    assert severity_value not in {outcome.value for outcome in DecisionOutcome}


# --- boundary / import hygiene ------------------------------------


def test_risk_package_modules_import_cleanly() -> None:
    for mod in pkgutil.walk_packages(
        risk_pkg.__path__, prefix="contextfence.core.risk."
    ):
        importlib.import_module(mod.name)


def test_risk_package_has_no_forbidden_imports() -> None:
    offenders: list[str] = []
    for path in _RISK_DIR.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            mods: list[str] = []
            if isinstance(node, ast.Import):
                mods = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods = [node.module]
            for mod in mods:
                if any(frag in mod for frag in _FORBIDDEN_IMPORT_FRAGMENTS):
                    offenders.append(f"{path.name}: {mod}")
                assert mod not in _NETWORK_MODULES, f"{path.name} imports {mod}"
    assert offenders == []


def test_risk_namespace_exposes_no_decision_symbols() -> None:
    for mod in pkgutil.walk_packages(
        risk_pkg.__path__, prefix="contextfence.core.risk."
    ):
        module = importlib.import_module(mod.name)
        assert not hasattr(module, "Decision")
        assert not hasattr(module, "DecisionOutcome")
        assert not hasattr(module, "PolicyEngine")
    assert not hasattr(risk_pkg, "Decision")
    assert not hasattr(risk_pkg, "DecisionOutcome")


def test_no_scalar_risk_score_field_exists_on_the_output() -> None:
    rv = aggregate_evidence([ev(), ev(category=EvidenceCategory.PERSONAL_DATA)])
    field_names = {f.name for f in dataclasses.fields(rv)}
    for banned in (
        "risk_score",
        "score",
        "danger_score",
        "weight",
        "risk_level",
        "total",
    ):
        assert banned not in field_names
    assert field_names == {
        "highest_severity",
        "categories",
        "category_confidence",
        "semantic_evidence_available",
        "evidence_count",
    }
