"""Semantic analysis wired into the generic SecurityPipeline (Phase 8 Part 7).

Covers task testing sections E (evidence integration), F (policy integration),
and G (provider independence -- a fake deterministic provider only).
"""

from __future__ import annotations

from contextfence.adapters.claude_code import ClaudeCodeAdapter
from contextfence.adapters.synthetic import SyntheticAgentAdapter
from contextfence.analysis.semantic import SemanticAnalyzer
from contextfence.audit.serialization import canonical_json, record_to_dict
from contextfence.audit.sink import InMemoryAuditSink
from contextfence.core.models.enums import (
    ActionType,
    DataClassification,
    DecisionOutcome,
    EvidenceCategory,
    ResourceType,
    Severity,
)
from contextfence.inference.provider import InferenceResult, SemanticFinding
from contextfence.pipeline import SecurityPipeline
from contextfence.policy.default_policy import DEFAULT_POLICY
from contextfence.policy.engine import PolicyEngine
from tests.unit._factories import valid_event
from tests.unit._semantic_fakes import RaisingProvider, StaticProvider


def _pipeline(
    analyzer: SemanticAnalyzer | None, sink: InMemoryAuditSink | None = None
) -> SecurityPipeline:
    return SecurityPipeline(
        policy_engine=PolicyEngine(DEFAULT_POLICY),
        semantic_analyzer=analyzer,
        audit_sink=sink,
    )


def _analyzer(*findings: SemanticFinding) -> SemanticAnalyzer:
    return SemanticAnalyzer(
        StaticProvider(InferenceResult(findings=findings, provider_id="p1"))
    )


# --------------------------------------------------------------------------
# E. evidence integration: semantic findings feed the Risk Aggregator normally
# --------------------------------------------------------------------------


def test_no_semantic_analyzer_matches_phase_7_behaviour_exactly() -> None:
    event = valid_event(
        action=ActionType.FILE_READ,
        resource_type=ResourceType.FILE,
        data_classification=DataClassification.NONE,
        resource="synthetic/readme.md",
    )
    without = _pipeline(None).process(event)
    assert without.decision.outcome is DecisionOutcome.ALLOW
    assert without.event.semantic_signals == ()


def test_semantic_finding_is_aggregated_into_the_risk_view() -> None:
    finding = SemanticFinding(
        category=EvidenceCategory.PROMPT_INJECTION,
        confidence=0.7,
        severity=Severity.HIGH,
    )
    event = valid_event(
        action=ActionType.FILE_READ, data_classification=DataClassification.NONE
    )
    result = _pipeline(_analyzer(finding)).process(event)
    assert EvidenceCategory.PROMPT_INJECTION in result.risk_view.categories
    assert result.risk_view.semantic_evidence_available is True
    assert result.risk_view.highest_severity is Severity.HIGH


def test_semantic_finding_is_carried_on_the_resulting_event() -> None:
    finding = SemanticFinding(
        category=EvidenceCategory.SUSPICIOUS_INTENT,
        confidence=0.6,
        severity=Severity.MEDIUM,
    )
    result = _pipeline(_analyzer(finding)).process(valid_event())
    assert len(result.event.semantic_signals) == 1
    assert (
        result.event.semantic_signals[0].category is EvidenceCategory.SUSPICIOUS_INTENT
    )


# --------------------------------------------------------------------------
# F. policy integration: existing rules fire from semantic evidence
# --------------------------------------------------------------------------


def test_prompt_injection_suspected_rule_fires_from_semantic_evidence() -> None:
    finding = SemanticFinding(
        category=EvidenceCategory.PROMPT_INJECTION,
        confidence=0.9,
        severity=Severity.HIGH,
    )
    event = valid_event(
        action=ActionType.FILE_READ, data_classification=DataClassification.NONE
    )
    result = _pipeline(_analyzer(finding)).process(event)
    assert result.decision.outcome is DecisionOutcome.ASK
    assert result.decision.matched_rule_id == "ASK.PROMPT_INJECTION_SUSPECTED"


def test_suspicious_intent_and_contextual_sensitivity_rules_fire() -> None:
    for category, rule_id in (
        (EvidenceCategory.SUSPICIOUS_INTENT, "ASK.SUSPICIOUS_INTENT_DETECTED"),
        (
            EvidenceCategory.CONTEXTUAL_SENSITIVITY,
            "ASK.CONTEXTUAL_SENSITIVITY_DETECTED",
        ),
    ):
        finding = SemanticFinding(
            category=category, confidence=0.5, severity=Severity.MEDIUM
        )
        event = valid_event(
            action=ActionType.FILE_READ, data_classification=DataClassification.NONE
        )
        result = _pipeline(_analyzer(finding)).process(event)
        assert result.decision.outcome is DecisionOutcome.ASK
        assert result.decision.matched_rule_id == rule_id


def test_semantic_unavailable_equivalent_still_escalates_high_impact() -> None:
    # provider raises -> SEMANTIC.ANALYSIS_ERROR marker -> ASK.ANALYSIS_ERROR,
    # the same fail-closed rule every detector failure uses.
    analyzer = SemanticAnalyzer(RaisingProvider(RuntimeError("provider offline")))
    event = valid_event(
        action=ActionType.COMMAND_EXEC,
        resource="pytest -q",
        resource_type=ResourceType.COMMAND,
        data_classification=DataClassification.INTERNAL,
    )
    result = _pipeline(analyzer).process(event)
    assert result.decision.outcome is not DecisionOutcome.ALLOW
    assert result.decision.outcome is DecisionOutcome.ASK
    assert result.decision.matched_rule_id == "ASK.ANALYSIS_ERROR"


def test_semantic_failure_on_low_impact_action_never_becomes_allow_silently() -> None:
    # even the conservative existing default never silently ALLOWs on failure.
    analyzer = SemanticAnalyzer(RaisingProvider(RuntimeError("boom")))
    event = valid_event(
        action=ActionType.FILE_READ,
        data_classification=DataClassification.NONE,
        resource="synthetic/readme.md",
    )
    result = _pipeline(analyzer).process(event)
    assert result.decision.outcome is not DecisionOutcome.ALLOW


def test_semantic_finding_never_directly_produces_allow_or_deny() -> None:
    # a LOW-severity finding on an otherwise-safe read still requires review
    # under the default policy (no ALLOW rule ignores semantic categories).
    finding = SemanticFinding(
        category=EvidenceCategory.CONTEXTUAL_SENSITIVITY,
        confidence=0.3,
        severity=Severity.LOW,
    )
    event = valid_event(
        action=ActionType.FILE_READ,
        resource_type=ResourceType.FILE,
        data_classification=DataClassification.NONE,
        resource="synthetic/readme.md",
    )
    result = _pipeline(_analyzer(finding)).process(event)
    assert result.decision.outcome is not DecisionOutcome.ALLOW


def test_no_raw_semantic_metadata_leaks_into_audit() -> None:
    finding = SemanticFinding(
        category=EvidenceCategory.SUSPICIOUS_INTENT,
        confidence=0.5,
        severity=Severity.MEDIUM,
        metadata={"note": "synthetic-injection-marker-x9"},
    )
    sink = InMemoryAuditSink()
    result = _pipeline(_analyzer(finding), sink).process(valid_event())
    assert result.audit_recorded is True
    blob = canonical_json(record_to_dict(sink.records()[0]))
    assert "synthetic-injection-marker-x9" not in blob


# --------------------------------------------------------------------------
# G. provider independence: the same pipeline behaves identically regardless
#    of which adapter produced the event
# --------------------------------------------------------------------------


def test_semantic_layer_behaves_identically_for_both_reference_adapters() -> None:
    finding = SemanticFinding(
        category=EvidenceCategory.PROMPT_INJECTION,
        confidence=0.85,
        severity=Severity.HIGH,
    )
    pipeline = _pipeline(_analyzer(finding))

    claude_event = ClaudeCodeAdapter().normalize(
        {"tool_name": "Read", "tool_input": {"file_path": "notes.txt"}}
    )
    synthetic_event = SyntheticAgentAdapter().normalize(
        {"op": "read_file", "target": "notes.txt"}
    )

    claude_result = pipeline.process(claude_event)
    synthetic_result = pipeline.process(synthetic_event)

    assert claude_result.decision.outcome is synthetic_result.decision.outcome
    assert (
        claude_result.decision.matched_rule_id
        == synthetic_result.decision.matched_rule_id
        == "ASK.PROMPT_INJECTION_SUSPECTED"
    )
