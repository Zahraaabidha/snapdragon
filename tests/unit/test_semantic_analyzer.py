"""SemanticAnalyzer: provider result -> Evidence, and fail-closed on failure.

Covers task testing sections C (provider failure) and D (security boundary).
"""

from __future__ import annotations

import pytest

from contextfence.analysis.detector import ANALYSIS_ERROR_RULE_SUFFIX, run_detectors
from contextfence.analysis.semantic import SemanticAnalyzer
from contextfence.core.models.decision import Decision
from contextfence.core.models.enums import (
    EvidenceCategory,
    EvidenceSource,
    Severity,
)
from contextfence.core.models.evidence import Evidence
from contextfence.inference.errors import (
    SemanticAnalysisError,
    SemanticProviderUnavailableError,
)
from contextfence.inference.provider import InferenceResult, SemanticFinding
from tests.unit._factories import valid_event
from tests.unit._semantic_fakes import RaisingProvider, StaticProvider


def _finding(**overrides: object) -> SemanticFinding:
    base: dict[str, object] = {
        "category": EvidenceCategory.PROMPT_INJECTION,
        "confidence": 0.8,
        "severity": Severity.HIGH,
        "metadata": {"signal": "prompt_injection_suspected"},
    }
    base.update(overrides)
    return SemanticFinding(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# happy path: provider result -> Evidence
# --------------------------------------------------------------------------


def test_analyzer_converts_findings_to_evidence() -> None:
    finding = _finding()
    provider = StaticProvider(InferenceResult(findings=(finding,), provider_id="p1"))
    analyzer = SemanticAnalyzer(provider)
    evidence = analyzer.analyze(valid_event())
    assert len(evidence) == 1
    item = evidence[0]
    assert isinstance(item, Evidence)
    assert item.source is EvidenceSource.SEMANTIC_ANALYZER
    assert item.category is EvidenceCategory.PROMPT_INJECTION
    assert item.severity is Severity.HIGH
    assert item.confidence == 0.8
    assert item.metadata["provider_id"] == "p1"
    assert item.metadata["schema_version"] == "1"
    assert item.metadata["signal"] == "prompt_injection_suspected"


def test_analyzer_returns_empty_tuple_when_provider_finds_nothing() -> None:
    provider = StaticProvider(InferenceResult(findings=(), provider_id="p1"))
    analyzer = SemanticAnalyzer(provider)
    assert analyzer.analyze(valid_event()) == ()


def test_analyzer_passes_bounded_request_context_to_the_provider() -> None:
    provider = StaticProvider(InferenceResult())
    analyzer = SemanticAnalyzer(provider)
    event = valid_event(resource="synthetic/project/task.md")
    analyzer.analyze(event)
    assert len(provider.calls) == 1
    request = provider.calls[0]
    assert request.action is event.action
    assert request.resource_type is event.resource_type
    assert request.data_classification is event.data_classification
    assert ("resource", "synthetic/project/task.md") in request.text_fields


def test_analyzer_satisfies_the_detector_protocol() -> None:
    analyzer = SemanticAnalyzer(StaticProvider(InferenceResult()))
    assert analyzer.namespace == "SEMANTIC"
    assert analyzer.source is EvidenceSource.SEMANTIC_ANALYZER
    assert isinstance(analyzer.primary_category, EvidenceCategory)
    evidence = run_detectors(valid_event(), (analyzer,))
    assert evidence == ()


# --------------------------------------------------------------------------
# C. provider failure -> explicit, safe failure evidence (never silent)
# --------------------------------------------------------------------------


def test_provider_exception_propagates_from_analyze() -> None:
    analyzer = SemanticAnalyzer(RaisingProvider(RuntimeError("boom")))
    with pytest.raises(RuntimeError):
        analyzer.analyze(valid_event())


def test_provider_unavailable_propagates_from_analyze() -> None:
    analyzer = SemanticAnalyzer(
        RaisingProvider(SemanticProviderUnavailableError("no model loaded"))
    )
    with pytest.raises(SemanticProviderUnavailableError):
        analyzer.analyze(valid_event())


def test_provider_returning_the_wrong_type_is_rejected() -> None:
    class BadProvider:
        provider_id = "bad"

        def infer(self, request: object) -> object:
            return {"findings": []}  # not an InferenceResult

    analyzer = SemanticAnalyzer(BadProvider())  # type: ignore[arg-type]
    with pytest.raises(SemanticAnalysisError):
        analyzer.analyze(valid_event())


@pytest.mark.parametrize(
    "provider",
    [
        RaisingProvider(RuntimeError("boom")),
        RaisingProvider(SemanticProviderUnavailableError("unavailable")),
        RaisingProvider(SemanticAnalysisError("malformed")),
    ],
)
def test_every_failure_mode_becomes_an_explicit_marker_via_run_detectors(
    provider: RaisingProvider,
) -> None:
    analyzer = SemanticAnalyzer(provider)
    evidence = run_detectors(valid_event(), (analyzer,))
    # never silently "no findings": exactly one explicit marker is produced.
    assert len(evidence) == 1
    marker = evidence[0]
    assert marker.source is EvidenceSource.SEMANTIC_ANALYZER
    assert marker.severity is Severity.HIGH
    assert marker.confidence == 0.0
    assert marker.metadata["rule_id"] == f"SEMANTIC.{ANALYSIS_ERROR_RULE_SUFFIX}"


def test_malformed_provider_result_becomes_a_marker_not_silence() -> None:
    class BadProvider:
        provider_id = "bad"

        def infer(self, request: object) -> object:
            return None

    evidence = run_detectors(
        valid_event(),
        (SemanticAnalyzer(BadProvider()),),  # type: ignore[arg-type]
    )
    assert len(evidence) == 1
    assert evidence[0].metadata["rule_id"] == f"SEMANTIC.{ANALYSIS_ERROR_RULE_SUFFIX}"


# --------------------------------------------------------------------------
# D. security boundary
# --------------------------------------------------------------------------


def test_analyzer_construction_rejects_a_non_provider() -> None:
    with pytest.raises(SemanticAnalysisError):
        SemanticAnalyzer(object())  # type: ignore[arg-type]


def test_analyze_never_returns_a_decision() -> None:
    provider = StaticProvider(InferenceResult(findings=(_finding(),), provider_id="p1"))
    result = SemanticAnalyzer(provider).analyze(valid_event())
    for item in result:
        assert not isinstance(item, Decision)
        assert not hasattr(item, "outcome")


def test_analyzer_has_no_decide_enforce_or_policy_surface() -> None:
    analyzer = SemanticAnalyzer(StaticProvider(InferenceResult()))
    assert not hasattr(analyzer, "evaluate")
    assert not hasattr(analyzer, "decide")
    assert not hasattr(analyzer, "enforce")
    assert not hasattr(analyzer, "approve")


def test_finding_source_cannot_be_set_by_the_provider() -> None:
    # SemanticFinding has no 'source' field at all -- the analyzer always
    # stamps SEMANTIC_ANALYZER itself.
    with pytest.raises(TypeError):
        SemanticFinding(  # type: ignore[call-arg]
            category=EvidenceCategory.PROMPT_INJECTION,
            confidence=0.5,
            severity=Severity.LOW,
            source=EvidenceSource.SECRET_DETECTOR,
        )


def test_analyzer_does_not_bypass_the_event_gateway() -> None:
    # the analyzer only ever receives an already-validated SecurityEvent and
    # returns Evidence; it has no admit()/gateway-shaped surface at all.
    analyzer = SemanticAnalyzer(StaticProvider(InferenceResult()))
    assert not hasattr(analyzer, "admit")
    assert not hasattr(analyzer, "gateway")
