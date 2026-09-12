"""The structured semantic result schema: strictly validated, never trusted text.

Covers task Part 3 and testing sections A/B: valid results, and every listed
invalid shape (unknown signal/category, out-of-range confidence, NaN, infinity,
malformed structure, unexpected fields).
"""

from __future__ import annotations

import math

import pytest

from contextfence.core.models.enums import (
    ActionType,
    DataClassification,
    EvidenceCategory,
    ResourceType,
    Severity,
)
from contextfence.inference.errors import SemanticAnalysisError
from contextfence.inference.provider import (
    SEMANTIC_SCHEMA_VERSION,
    InferenceRequest,
    InferenceResult,
    SemanticFinding,
)

# --------------------------------------------------------------------------
# A. valid results
# --------------------------------------------------------------------------


def test_valid_finding_round_trips() -> None:
    finding = SemanticFinding(
        category=EvidenceCategory.PROMPT_INJECTION,
        confidence=0.8,
        severity=Severity.HIGH,
        metadata={"signal": "prompt_injection_suspected"},
    )
    assert finding.category is EvidenceCategory.PROMPT_INJECTION
    assert finding.confidence == 0.8
    assert finding.severity is Severity.HIGH
    assert finding.metadata["signal"] == "prompt_injection_suspected"


def test_finding_accepts_string_category() -> None:
    finding = SemanticFinding(
        category="SUSPICIOUS_INTENT",  # type: ignore[arg-type]
        confidence=0.5,
        severity=Severity.MEDIUM,
    )
    assert finding.category is EvidenceCategory.SUSPICIOUS_INTENT


@pytest.mark.parametrize(
    "category",
    [
        EvidenceCategory.PROMPT_INJECTION,
        EvidenceCategory.SUSPICIOUS_INTENT,
        EvidenceCategory.CONTEXTUAL_SENSITIVITY,
    ],
)
def test_the_three_semantic_categories_are_valid(category: EvidenceCategory) -> None:
    SemanticFinding(category=category, confidence=0.5, severity=Severity.LOW)


def test_valid_metadata_keys_are_accepted() -> None:
    SemanticFinding(
        category=EvidenceCategory.PROMPT_INJECTION,
        confidence=0.5,
        severity=Severity.LOW,
        metadata={"signal": "x", "note": "y", "matched_field": "resource"},
    )


def test_empty_metadata_is_fine() -> None:
    finding = SemanticFinding(
        category=EvidenceCategory.PROMPT_INJECTION,
        confidence=0.0,
        severity=Severity.LOW,
    )
    assert dict(finding.metadata) == {}


def test_valid_inference_result() -> None:
    finding = SemanticFinding(
        category=EvidenceCategory.PROMPT_INJECTION,
        confidence=0.9,
        severity=Severity.HIGH,
    )
    result = InferenceResult(findings=(finding,), provider_id="static-test-provider")
    assert result.findings == (finding,)
    assert result.schema_version == SEMANTIC_SCHEMA_VERSION


def test_empty_findings_is_a_valid_result() -> None:
    result = InferenceResult(findings=(), provider_id="static-test-provider")
    assert result.findings == ()


def test_valid_inference_request() -> None:
    req = InferenceRequest(
        action=ActionType.FILE_READ,
        resource_type=ResourceType.FILE,
        data_classification=DataClassification.INTERNAL,
        requested_capabilities=("fs.read",),
        text_fields=(("resource", "synthetic/notes.txt"),),
    )
    assert req.action is ActionType.FILE_READ
    assert req.text_fields == (("resource", "synthetic/notes.txt"),)


# --------------------------------------------------------------------------
# B. invalid results
# --------------------------------------------------------------------------


def test_unknown_category_is_rejected() -> None:
    with pytest.raises(SemanticAnalysisError):
        SemanticFinding(
            category="NOT_A_CATEGORY",  # type: ignore[arg-type]
            confidence=0.5,
            severity=Severity.LOW,
        )


@pytest.mark.parametrize("bad", [-0.0001, -1.0, 1.0001, 2.0, 100.0])
def test_out_of_range_confidence_is_rejected(bad: float) -> None:
    with pytest.raises(SemanticAnalysisError):
        SemanticFinding(
            category=EvidenceCategory.PROMPT_INJECTION,
            confidence=bad,
            severity=Severity.LOW,
        )


def test_nan_confidence_is_rejected() -> None:
    with pytest.raises(SemanticAnalysisError):
        SemanticFinding(
            category=EvidenceCategory.PROMPT_INJECTION,
            confidence=math.nan,
            severity=Severity.LOW,
        )


@pytest.mark.parametrize("bad", [math.inf, -math.inf])
def test_infinite_confidence_is_rejected(bad: float) -> None:
    with pytest.raises(SemanticAnalysisError):
        SemanticFinding(
            category=EvidenceCategory.PROMPT_INJECTION,
            confidence=bad,
            severity=Severity.LOW,
        )


def test_boolean_confidence_is_rejected() -> None:
    # bool is an int subclass -- must not silently pass as 0.0/1.0.
    with pytest.raises(SemanticAnalysisError):
        SemanticFinding(
            category=EvidenceCategory.PROMPT_INJECTION,
            confidence=True,
            severity=Severity.LOW,
        )


def test_confidence_never_substitutes_for_severity() -> None:
    # high confidence must not silently imply/derive a severity.
    with pytest.raises(TypeError):
        SemanticFinding(category=EvidenceCategory.PROMPT_INJECTION, confidence=0.99)  # type: ignore[call-arg]


def test_unknown_severity_is_rejected() -> None:
    with pytest.raises(SemanticAnalysisError):
        SemanticFinding(
            category=EvidenceCategory.PROMPT_INJECTION,
            confidence=0.5,
            severity="CATASTROPHIC",  # type: ignore[arg-type]
        )


def test_unexpected_metadata_field_is_rejected() -> None:
    with pytest.raises(SemanticAnalysisError):
        SemanticFinding(
            category=EvidenceCategory.PROMPT_INJECTION,
            confidence=0.5,
            severity=Severity.LOW,
            metadata={"approved": "true"},
        )


def test_authorization_shaped_metadata_field_is_rejected() -> None:
    for key in ("decision", "outcome", "allow", "policy_override"):
        with pytest.raises(SemanticAnalysisError):
            SemanticFinding(
                category=EvidenceCategory.PROMPT_INJECTION,
                confidence=0.5,
                severity=Severity.LOW,
                metadata={key: "ALLOW"},
            )


def test_overlong_metadata_value_is_rejected() -> None:
    with pytest.raises(SemanticAnalysisError):
        SemanticFinding(
            category=EvidenceCategory.PROMPT_INJECTION,
            confidence=0.5,
            severity=Severity.LOW,
            metadata={"note": "x" * 300},
        )


def test_control_characters_in_metadata_value_are_rejected() -> None:
    with pytest.raises(SemanticAnalysisError):
        SemanticFinding(
            category=EvidenceCategory.PROMPT_INJECTION,
            confidence=0.5,
            severity=Severity.LOW,
            metadata={"note": "line1\r\nline2"},
        )


def test_malformed_metadata_structure_is_rejected() -> None:
    with pytest.raises(SemanticAnalysisError):
        SemanticFinding(
            category=EvidenceCategory.PROMPT_INJECTION,
            confidence=0.5,
            severity=Severity.LOW,
            metadata="not-a-mapping",  # type: ignore[arg-type]
        )


def test_result_findings_must_be_a_tuple_of_semantic_finding() -> None:
    with pytest.raises(SemanticAnalysisError):
        InferenceResult(findings=[{"category": "PROMPT_INJECTION"}])  # type: ignore[arg-type]
    with pytest.raises(SemanticAnalysisError):
        InferenceResult(findings=("not-a-finding",))  # type: ignore[arg-type]


def test_result_schema_version_must_match() -> None:
    finding = SemanticFinding(
        category=EvidenceCategory.PROMPT_INJECTION,
        confidence=0.5,
        severity=Severity.LOW,
    )
    with pytest.raises(SemanticAnalysisError):
        InferenceResult(findings=(finding,), schema_version=999)


def test_result_provider_id_must_be_well_formed() -> None:
    with pytest.raises(SemanticAnalysisError):
        InferenceResult(provider_id="")
    with pytest.raises(SemanticAnalysisError):
        InferenceResult(provider_id="has a space")


def test_request_rejects_unknown_action_value() -> None:
    with pytest.raises(SemanticAnalysisError):
        InferenceRequest(
            action="file.frobnicate",  # type: ignore[arg-type]
            resource_type=ResourceType.FILE,
            data_classification=DataClassification.INTERNAL,
        )


def test_request_text_fields_must_be_string_pairs() -> None:
    with pytest.raises(SemanticAnalysisError):
        InferenceRequest(
            action=ActionType.FILE_READ,
            resource_type=ResourceType.FILE,
            data_classification=DataClassification.INTERNAL,
            text_fields=(("resource", 123),),  # type: ignore[arg-type]
        )


def test_findings_are_frozen() -> None:
    finding = SemanticFinding(
        category=EvidenceCategory.PROMPT_INJECTION,
        confidence=0.5,
        severity=Severity.LOW,
    )
    with pytest.raises(AttributeError):
        finding.confidence = 0.9  # type: ignore[misc]
