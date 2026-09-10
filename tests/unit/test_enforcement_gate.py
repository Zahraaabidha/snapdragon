"""Phase 5: the enforcement gate turns a Decision into an EnforcementResult."""

from __future__ import annotations

import ast
import dataclasses
import importlib
import pkgutil
from pathlib import Path

import pytest

import contextfence.enforcement as enforcement_pkg
from contextfence.core.models.decision import Decision
from contextfence.core.models.enums import (
    ActionType,
    DataClassification,
    DecisionOutcome,
    EvidenceCategory,
    EvidenceSource,
    ResourceType,
    Severity,
)
from contextfence.core.models.evidence import Evidence
from contextfence.core.risk import aggregate_evidence
from contextfence.enforcement import (
    DEFAULT_GATE,
    EnforcementErrorKind,
    EnforcementGate,
    EnforcementOutcome,
    EnforcementResult,
)
from contextfence.policy import DEFAULT_POLICY, PolicyEngine
from tests.unit._factories import valid_event

GATE = EnforcementGate()

_ENF_DIR = Path(enforcement_pkg.__file__).parent
_FORBIDDEN_IMPORT_FRAGMENTS = (
    "PySide6",
    "onnxruntime",
    "qnn",
    "qai_hub",
    "qualcomm",
    "torch",
    "snapdragon",
    "contextfence.ui",
    "contextfence.adapters",
    "contextfence.inference",
    "contextfence.audit",
)
_FORBIDDEN_MODULES = frozenset(
    {
        "socket",
        "urllib.request",
        "urllib3",
        "http.client",
        "httplib",
        "requests",
        "ftplib",
        "subprocess",
        "sqlite3",
        "asyncio",
        "os.system",
    }
)


def _decision(outcome: DecisionOutcome, rule_id: str = "RULE.X") -> Decision:
    return Decision(
        outcome=outcome, matched_rule_id=rule_id, rationale=("policy rationale line",)
    )


def _pii_evidence(text: str, needle: str, rule_id: str) -> Evidence:
    start = text.index(needle)
    return Evidence(
        source=EvidenceSource.PII_DETECTOR,
        category=EvidenceCategory.PERSONAL_DATA,
        severity=Severity.HIGH,
        confidence=0.9,
        metadata={
            "rule_id": rule_id,
            "match_offset": str(start),
            "match_length": str(len(needle)),
        },
    )


# --- the five outcomes ------------------------------------------------


def test_allow_produces_permitted_result_without_executing() -> None:
    result = GATE.enforce(_decision(DecisionOutcome.ALLOW, "ALLOW.SAFE_LOCAL_READ"))
    assert result.outcome is EnforcementOutcome.ALLOWED
    assert result.permitted_to_proceed is True
    assert result.decision_outcome is DecisionOutcome.ALLOW
    assert result.matched_rule_id == "ALLOW.SAFE_LOCAL_READ"
    # nothing executed: no payload transformation, no side-effect surface
    assert result.sanitized_payload is None


def test_deny_produces_blocked_result() -> None:
    result = GATE.enforce(_decision(DecisionOutcome.DENY, "DENY.CREDENTIAL_EVIDENCE"))
    assert result.outcome is EnforcementOutcome.DENIED
    assert result.permitted_to_proceed is False


def test_ask_produces_approval_required_result_not_auto_approved() -> None:
    result = GATE.enforce(_decision(DecisionOutcome.ASK, "ASK.COMMAND_EXECUTION"))
    assert result.outcome is EnforcementOutcome.APPROVAL_REQUIRED
    assert result.permitted_to_proceed is False
    assert result.approval_request is not None


def test_sanitize_produces_sanitized_copy_result() -> None:
    text = "email alex.doe@synthetic.invalid please"
    evidence = [_pii_evidence(text, "alex.doe@synthetic.invalid", "PII.EMAIL")]
    result = GATE.enforce(
        _decision(DecisionOutcome.SANITIZE, "SANITIZE.PII_EXTERNAL_TRANSFER"),
        evidence=evidence,
        payload=text,
    )
    assert result.outcome is EnforcementOutcome.SANITIZED
    assert result.permitted_to_proceed is True
    assert result.sanitized_payload == "email [REDACTED:PII.EMAIL] please"
    assert "alex.doe@synthetic.invalid" not in (result.sanitized_payload or "")


def test_sanitize_without_payload_fails_closed() -> None:
    result = GATE.enforce(_decision(DecisionOutcome.SANITIZE), evidence=[])
    assert result.outcome is EnforcementOutcome.INTERNAL_ERROR
    assert result.error_kind is EnforcementErrorKind.MISSING_PAYLOAD
    assert result.permitted_to_proceed is False


def test_sanitize_of_a_secret_fails_closed_never_downgraded() -> None:
    text = "key AKIAIOSFODNN7EXAMPLE tail"
    secret_ev = Evidence(
        source=EvidenceSource.SECRET_DETECTOR,
        category=EvidenceCategory.CREDENTIAL,
        severity=Severity.CRITICAL,
        confidence=0.9,
        metadata={
            "rule_id": "SECRET.AWS_ACCESS_KEY_ID",
            "match_offset": str(text.index("AKIAIOSFODNN7EXAMPLE")),
            "match_length": "20",
        },
    )
    result = GATE.enforce(
        _decision(DecisionOutcome.SANITIZE), evidence=[secret_ev], payload=text
    )
    assert result.permitted_to_proceed is False
    assert result.outcome is EnforcementOutcome.DENIED
    assert result.error_kind is EnforcementErrorKind.SANITIZATION_FAILED
    assert "AKIAIOSFODNN7EXAMPLE" not in (result.error_detail or "")
    assert result.sanitized_payload is None


# --- fail-closed on bad input ---------------------------------------


def test_missing_decision_fails_closed() -> None:
    result = GATE.enforce(None)
    assert result.outcome is EnforcementOutcome.INTERNAL_ERROR
    assert result.error_kind is EnforcementErrorKind.MISSING_DECISION
    assert result.permitted_to_proceed is False
    assert result.decision_outcome is None


def test_non_decision_object_fails_closed() -> None:
    result = GATE.enforce("ALLOW")  # type: ignore[arg-type]
    assert result.outcome is EnforcementOutcome.INTERNAL_ERROR
    assert result.permitted_to_proceed is False


def test_internal_exception_fails_closed_to_blocked() -> None:
    class _BoomDecision:
        outcome = DecisionOutcome.SANITIZE
        matched_rule_id = "X"
        rationale = ("x",)

    # not a Decision instance -> caught as MISSING_DECISION, still blocked
    result = GATE.enforce(_BoomDecision())  # type: ignore[arg-type]
    assert result.permitted_to_proceed is False
    assert result.outcome is EnforcementOutcome.INTERNAL_ERROR


def test_error_result_never_reports_permitted() -> None:
    for kind in EnforcementErrorKind:
        if kind is EnforcementErrorKind.NONE:
            continue
        res = EnforcementResult(
            outcome=EnforcementOutcome.INTERNAL_ERROR,
            decision_outcome=None,
            matched_rule_id=None,
            rationale=("blocked",),
            error_kind=kind,
        )
        assert res.permitted_to_proceed is False


# --- enforcement does not create or mutate a Decision --------------


def test_enforcement_does_not_construct_policy_decisions() -> None:
    for path in _ENF_DIR.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert "Decision(" not in source, f"{path.name} constructs a Decision"


def test_enforcement_does_not_mutate_the_supplied_decision() -> None:
    decision = _decision(DecisionOutcome.SANITIZE, "SANITIZE.PII_EXTERNAL_TRANSFER")
    text = "hi alex.doe@synthetic.invalid"
    before = repr(decision)
    GATE.enforce(
        decision,
        evidence=[_pii_evidence(text, "alex.doe@synthetic.invalid", "PII.EMAIL")],
        payload=text,
    )
    assert repr(decision) == before


def test_enforcement_does_not_mutate_event_or_evidence_or_payload() -> None:
    event = valid_event(
        action=ActionType.NETWORK_SEND,
        resource_type=ResourceType.URL,
        data_classification=DataClassification.PERSONAL_DATA,
        destination="https://x.invalid",
    )
    text = "call +1 (555) 010-1234 now and mail alex.doe@synthetic.invalid"
    text_copy = str(text)
    evidence = [
        _pii_evidence(text, "+1 (555) 010-1234", "PII.PHONE_NUMBER"),
        _pii_evidence(text, "alex.doe@synthetic.invalid", "PII.EMAIL"),
    ]
    ev_before = [repr(e) for e in evidence]
    event_before = repr(event)
    risk_view = aggregate_evidence(evidence)
    rv_before = repr(risk_view)
    GATE.enforce(
        _decision(DecisionOutcome.SANITIZE, "SANITIZE.PII_EXTERNAL_TRANSFER"),
        event=event,
        risk_view=risk_view,
        evidence=evidence,
        payload=text,
    )
    assert text == text_copy
    assert [repr(e) for e in evidence] == ev_before
    assert repr(event) == event_before
    assert repr(risk_view) == rv_before


def test_result_is_never_a_decision() -> None:
    result = GATE.enforce(_decision(DecisionOutcome.ALLOW))
    assert isinstance(result, EnforcementResult)
    assert not isinstance(result, Decision)


def test_result_is_immutable() -> None:
    result = GATE.enforce(_decision(DecisionOutcome.ALLOW))
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.outcome = EnforcementOutcome.DENIED  # type: ignore[misc]


def test_enforcement_gate_is_stateless() -> None:
    assert EnforcementGate.__slots__ == ()
    assert DEFAULT_GATE.enforce(_decision(DecisionOutcome.ALLOW)).outcome is (
        EnforcementOutcome.ALLOWED
    )


# --- end to end with the real Policy Engine ----------------------


def test_end_to_end_from_real_policy_decisions() -> None:
    engine = PolicyEngine(DEFAULT_POLICY)

    # ALLOW: safe local read
    allow_event = valid_event(
        action=ActionType.FILE_READ,
        resource_type=ResourceType.FILE,
        data_classification=DataClassification.NONE,
    )
    allow_decision = engine.evaluate(allow_event, [], aggregate_evidence([]))
    assert GATE.enforce(allow_decision).outcome is EnforcementOutcome.ALLOWED

    # DENY: credential classification
    deny_event = valid_event(data_classification=DataClassification.CREDENTIAL)
    deny_decision = engine.evaluate(deny_event, [], aggregate_evidence([]))
    assert GATE.enforce(deny_decision).outcome is EnforcementOutcome.DENIED

    # SANITIZE: located PII + external transfer
    text = "please email alex.doe@synthetic.invalid the summary"
    pii = _pii_evidence(text, "alex.doe@synthetic.invalid", "PII.EMAIL")
    dest = Evidence(
        source=EvidenceSource.DESTINATION_CLASSIFIER,
        category=EvidenceCategory.EXTERNAL_DATA_TRANSFER,
        severity=Severity.MEDIUM,
        confidence=0.8,
        metadata={"rule_id": "DESTINATION.EXTERNAL"},
    )
    san_event = valid_event(
        action=ActionType.NETWORK_SEND,
        resource_type=ResourceType.URL,
        data_classification=DataClassification.INTERNAL,
        destination="https://api.synthetic.invalid/u",
    )
    evidence = [pii, dest]
    san_decision = engine.evaluate(san_event, evidence, aggregate_evidence(evidence))
    assert san_decision.outcome is DecisionOutcome.SANITIZE
    result = GATE.enforce(san_decision, evidence=evidence, payload=text)
    assert result.outcome is EnforcementOutcome.SANITIZED
    assert "alex.doe@synthetic.invalid" not in (result.sanitized_payload or "")


# --- import boundaries --------------------------------------------


def test_enforcement_modules_import_cleanly() -> None:
    for mod in pkgutil.walk_packages(
        enforcement_pkg.__path__, prefix="contextfence.enforcement."
    ):
        importlib.import_module(mod.name)


def test_enforcement_has_no_forbidden_imports() -> None:
    offenders: list[str] = []
    for path in _ENF_DIR.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                if any(frag in name for frag in _FORBIDDEN_IMPORT_FRAGMENTS):
                    offenders.append(f"{path.name}: {name}")
                assert name not in _FORBIDDEN_MODULES, f"{path.name} imports {name}"
                if name.startswith("contextfence.analysis"):
                    assert name == "contextfence.analysis.redaction", (
                        f"{path.name} imports {name}; only redaction is reused"
                    )
    assert offenders == []


def test_enforcement_namespace_exposes_no_executor_or_policy_engine() -> None:
    for mod in pkgutil.walk_packages(
        enforcement_pkg.__path__, prefix="contextfence.enforcement."
    ):
        module = importlib.import_module(mod.name)
        for banned in ("PolicyEngine", "subprocess", "execute", "run_command", "Popen"):
            assert not hasattr(module, banned)
