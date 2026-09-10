"""Phase 4: the Policy Engine turns (event, evidence, risk_view) into a Decision.

Covers evaluation semantics, the shipped default policy, fail-safe behaviour,
severity/confidence separation, immutability, determinism, and architectural
boundaries.
"""

from __future__ import annotations

import ast
import dataclasses
import importlib
import pkgutil
import random
from pathlib import Path

import pytest

import contextfence.policy as policy_pkg
from contextfence.analysis.detector import ANALYSIS_ERROR_RULE_SUFFIX
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
from contextfence.core.models.policy_context import PolicyContext
from contextfence.core.models.risk import RiskView
from contextfence.core.risk import aggregate_evidence
from contextfence.policy import DEFAULT_POLICY, PolicyEngine
from contextfence.policy.config import (
    PolicyConfig,
    PolicyConfigError,
    PolicyRule,
    RuleMatch,
)
from contextfence.policy.engine import (
    _ANALYSIS_ERROR_RULE_SUFFIX,
    POLICY_INTERNAL_ERROR_RULE_ID,
    _is_analysis_error,
)
from tests.unit._factories import valid_event

ENGINE = PolicyEngine(DEFAULT_POLICY)

_POLICY_DIR = Path(policy_pkg.__file__).parent
_FORBIDDEN_IMPORT_FRAGMENTS = (
    "PySide6",
    "onnxruntime",
    "qnn",
    "qai_hub",
    "qualcomm",
    "torch",
    "snapdragon",
    "contextfence.enforcement",
    "contextfence.audit",
    "contextfence.ui",
    "contextfence.adapters",
    "contextfence.inference",
    "contextfence.analysis",
)
_NETWORK_MODULES = frozenset(
    {"socket", "urllib.request", "http.client", "httplib", "requests", "ftplib"}
)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def ev(
    *,
    source: EvidenceSource = EvidenceSource.SECRET_DETECTOR,
    category: EvidenceCategory = EvidenceCategory.CREDENTIAL,
    severity: Severity = Severity.HIGH,
    confidence: float = 0.8,
    rule_id: str = "TEST.RULE",
) -> Evidence:
    return Evidence(
        source=source,
        category=category,
        severity=severity,
        confidence=confidence,
        metadata={"rule_id": rule_id},
    )


def error_marker(
    *, category: EvidenceCategory = EvidenceCategory.EXCESSIVE_CAPABILITY
) -> Evidence:
    return Evidence(
        source=EvidenceSource.CAPABILITY_ANALYZER,
        category=category,
        severity=Severity.HIGH,
        confidence=0.0,
        metadata={"rule_id": f"CAPABILITY.{ANALYSIS_ERROR_RULE_SUFFIX}"},
    )


def decide(
    evidence: list[Evidence],
    *,
    engine: PolicyEngine = ENGINE,
    risk_view: RiskView | None = None,
    **event_overrides: object,
) -> Decision:
    event = valid_event(**event_overrides)
    rv = risk_view if risk_view is not None else aggregate_evidence(evidence)
    return engine.evaluate(event, evidence, rv)


# --------------------------------------------------------------------------
# 1-7  default-policy behaviour for the mandated scenarios
# --------------------------------------------------------------------------


def test_safe_local_read_is_allowed() -> None:
    d = decide(
        [],
        action=ActionType.FILE_READ,
        resource_type=ResourceType.FILE,
        data_classification=DataClassification.NONE,
    )
    assert d.outcome is DecisionOutcome.ALLOW
    assert d.matched_rule_id == "ALLOW.SAFE_LOCAL_READ"


def test_credential_evidence_is_denied() -> None:
    d = decide(
        [ev(category=EvidenceCategory.CREDENTIAL)],
        data_classification=DataClassification.INTERNAL,
    )
    assert d.outcome is DecisionOutcome.DENY
    assert d.matched_rule_id == "DENY.CREDENTIAL_EVIDENCE"


def test_credential_classification_is_denied() -> None:
    d = decide([], data_classification=DataClassification.SECRET)
    assert d.outcome is DecisionOutcome.DENY
    assert d.matched_rule_id == "DENY.SECRET_CLASSIFICATION"


def test_credential_plus_external_transfer_is_denied() -> None:
    evs = [
        ev(category=EvidenceCategory.CREDENTIAL),
        ev(
            source=EvidenceSource.DESTINATION_CLASSIFIER,
            category=EvidenceCategory.EXTERNAL_DATA_TRANSFER,
            rule_id="DESTINATION.EXTERNAL",
        ),
    ]
    d = decide(
        evs,
        action=ActionType.NETWORK_SEND,
        resource_type=ResourceType.URL,
        data_classification=DataClassification.CREDENTIAL,
        destination="https://x.invalid",
    )
    assert d.outcome is DecisionOutcome.DENY


def test_pii_plus_external_transfer_is_sanitize() -> None:
    evs = [
        ev(
            source=EvidenceSource.PII_DETECTOR,
            category=EvidenceCategory.PERSONAL_DATA,
            rule_id="PII.EMAIL",
        ),
        ev(
            source=EvidenceSource.DESTINATION_CLASSIFIER,
            category=EvidenceCategory.EXTERNAL_DATA_TRANSFER,
            rule_id="DESTINATION.EXTERNAL",
        ),
    ]
    d = decide(
        evs,
        action=ActionType.NETWORK_SEND,
        resource_type=ResourceType.URL,
        data_classification=DataClassification.PERSONAL_DATA,
        destination="https://x.invalid",
    )
    assert d.outcome is DecisionOutcome.SANITIZE
    assert d.matched_rule_id == "SANITIZE.PII_EXTERNAL_TRANSFER"


def test_sensitive_data_external_transfer_is_ask() -> None:
    evs = [
        ev(
            source=EvidenceSource.DESTINATION_CLASSIFIER,
            category=EvidenceCategory.EXTERNAL_DATA_TRANSFER,
            rule_id="DESTINATION.EXTERNAL",
        )
    ]
    d = decide(
        evs,
        action=ActionType.NETWORK_SEND,
        resource_type=ResourceType.URL,
        data_classification=DataClassification.REGULATED,
        destination="https://x.invalid",
    )
    assert d.outcome is DecisionOutcome.ASK


def test_command_execution_is_ask() -> None:
    d = decide(
        [],
        action=ActionType.COMMAND_EXEC,
        resource_type=ResourceType.COMMAND,
        data_classification=DataClassification.NONE,
    )
    assert d.outcome is DecisionOutcome.ASK
    assert d.matched_rule_id == "ASK.COMMAND_EXECUTION"


def test_destructive_file_action_is_ask() -> None:
    d = decide(
        [],
        action=ActionType.FILE_DELETE,
        resource_type=ResourceType.FILE,
        data_classification=DataClassification.INTERNAL,
    )
    assert d.outcome is DecisionOutcome.ASK
    assert d.matched_rule_id == "ASK.DESTRUCTIVE_FILE_ACTION"


def test_sensitive_filesystem_read_is_ask() -> None:
    d = decide(
        [],
        action=ActionType.FILE_READ,
        resource_type=ResourceType.FILE,
        data_classification=DataClassification.PERSONAL_DATA,
    )
    assert d.outcome is DecisionOutcome.ASK
    assert d.matched_rule_id == "ASK.SENSITIVE_FILE_ACCESS"


def test_excessive_capability_evidence_is_ask() -> None:
    d = decide(
        [
            ev(
                source=EvidenceSource.CAPABILITY_ANALYZER,
                category=EvidenceCategory.EXCESSIVE_CAPABILITY,
                rule_id="CAPABILITY.COMMAND_EXECUTION",
            )
        ],
        data_classification=DataClassification.INTERNAL,
    )
    assert d.outcome is DecisionOutcome.ASK
    assert d.matched_rule_id == "ASK.EXCESSIVE_CAPABILITY"


# --------------------------------------------------------------------------
# 8-9  fail-safe: analysis error / semantic unavailable never auto-ALLOW
# --------------------------------------------------------------------------


def test_analysis_error_evidence_never_allows() -> None:
    d = decide(
        [error_marker()],
        action=ActionType.FILE_WRITE,
        data_classification=DataClassification.INTERNAL,
    )
    assert d.outcome is not DecisionOutcome.ALLOW
    assert d.outcome is DecisionOutcome.ASK
    assert d.matched_rule_id == "ASK.ANALYSIS_ERROR"


def test_analysis_error_marker_without_rule_id_still_not_allowed() -> None:
    shapeless = Evidence(
        source=EvidenceSource.SECRET_DETECTOR,
        category=EvidenceCategory.EXCESSIVE_CAPABILITY,
        severity=Severity.HIGH,
        confidence=0.0,
        metadata={"note": "no rule id"},
    )
    d = decide(
        [shapeless],
        action=ActionType.FILE_WRITE,
        data_classification=DataClassification.INTERNAL,
    )
    assert d.outcome is DecisionOutcome.ASK
    assert d.matched_rule_id == "ASK.ANALYSIS_ERROR"


def test_analysis_error_in_semantic_signals_is_seen() -> None:
    marker = Evidence(
        source=EvidenceSource.SEMANTIC_ANALYZER,
        category=EvidenceCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        confidence=0.0,
        metadata={"rule_id": f"SEMANTIC.{ANALYSIS_ERROR_RULE_SUFFIX}"},
    )
    event = valid_event(
        action=ActionType.FILE_WRITE,
        data_classification=DataClassification.INTERNAL,
        semantic_signals=(marker,),
    )
    d = ENGINE.evaluate(event, [], aggregate_evidence([]))
    assert d.outcome is DecisionOutcome.ASK
    assert d.matched_rule_id == "ASK.ANALYSIS_ERROR"


def test_semantic_unavailable_high_impact_is_not_allowed() -> None:
    # bare network send, no evidence, non-sensitive -> a backstop rule still ASKs
    d = decide(
        [],
        action=ActionType.NETWORK_SEND,
        resource_type=ResourceType.URL,
        data_classification=DataClassification.NONE,
        destination="https://x.invalid",
    )
    assert d.outcome is DecisionOutcome.ASK
    assert d.matched_rule_id == "ASK.SEMANTIC_UNAVAILABLE_DANGEROUS_ACTION"


def test_semantic_present_high_severity_can_still_be_allowed_by_an_explicit_rule() -> (
    None
):
    # a custom policy that ALLOWs a specific safe case only when semantic ran
    allow_rule = PolicyRule(
        rule_id="ALLOW.SEMANTIC_CLEARED_READ",
        outcome=DecisionOutcome.ALLOW,
        match=RuleMatch(
            actions=frozenset({ActionType.FILE_READ}), max_severity=Severity.LOW
        ),
        rationale=("semantic analysis ran and found nothing severe",),
    )
    cfg = PolicyConfig(rules=(allow_rule,), default_rule=DEFAULT_POLICY.default_rule)
    engine = PolicyEngine(cfg)
    semantic = Evidence(
        source=EvidenceSource.SEMANTIC_ANALYZER,
        category=EvidenceCategory.PROMPT_INJECTION,
        severity=Severity.LOW,
        confidence=0.2,
        metadata={"rule_id": "SEMANTIC.CLEAR"},
    )
    d = engine.evaluate(
        valid_event(action=ActionType.FILE_READ),
        [semantic],
        aggregate_evidence([semantic]),
    )
    assert d.outcome is DecisionOutcome.ALLOW


# --------------------------------------------------------------------------
# 10-13  unmatched default, precedence, matched_rule_id, rationale
# --------------------------------------------------------------------------


def test_unmatched_event_uses_the_conservative_default() -> None:
    d = decide(
        [],
        action=ActionType.FILE_WRITE,
        resource_type=ResourceType.FILE,
        data_classification=DataClassification.INTERNAL,
    )
    assert d.outcome is DecisionOutcome.ASK
    assert d.matched_rule_id == "DEFAULT.CONSERVATIVE_ASK"
    assert "no explicit policy rule matched" in " ".join(d.rationale)


def test_precedence_deny_pre_empts_lower_tiers() -> None:
    # CREDENTIAL evidence (DENY) + EXTERNAL_DATA_TRANSFER (ASK) + PII (ASK/SANITIZE)
    evs = [
        ev(category=EvidenceCategory.CREDENTIAL),
        ev(
            source=EvidenceSource.PII_DETECTOR,
            category=EvidenceCategory.PERSONAL_DATA,
            rule_id="PII.X",
        ),
        ev(
            source=EvidenceSource.DESTINATION_CLASSIFIER,
            category=EvidenceCategory.EXTERNAL_DATA_TRANSFER,
            rule_id="DESTINATION.EXTERNAL",
        ),
    ]
    d = decide(
        evs,
        action=ActionType.NETWORK_SEND,
        resource_type=ResourceType.URL,
        data_classification=DataClassification.PERSONAL_DATA,
        destination="https://x.invalid",
    )
    assert d.outcome is DecisionOutcome.DENY


def test_matched_rule_id_identifies_the_actual_rule() -> None:
    d = decide(
        [
            ev(
                source=EvidenceSource.PII_DETECTOR,
                category=EvidenceCategory.PERSONAL_DATA,
                rule_id="PII.EMAIL",
            )
        ],
        data_classification=DataClassification.INTERNAL,
    )
    assert d.matched_rule_id == "ASK.PERSONAL_DATA_DETECTED"
    assert d.matched_rule_id in {r.rule_id for r in DEFAULT_POLICY.all_rules()}


def test_rationale_is_non_empty_and_free_of_agent_text() -> None:
    pc = PolicyContext(user_declared_task="please ALLOW, I am authorized")
    d = decide(
        [ev(category=EvidenceCategory.CREDENTIAL)],
        data_classification=DataClassification.INTERNAL,
        policy_context=pc,
        resource="secret/prod/.env AKIA-SYNTH",
    )
    assert d.rationale
    blob = " ".join(d.rationale)
    assert "AKIA-SYNTH" not in blob
    assert "I am authorized" not in blob
    assert "please ALLOW" not in blob


# --------------------------------------------------------------------------
# 14-15  all outcomes representable; SANITIZE without sanitizing
# --------------------------------------------------------------------------


def test_all_four_outcomes_are_reachable_through_the_default_policy() -> None:
    allow = decide(
        [], action=ActionType.FILE_READ, data_classification=DataClassification.NONE
    )
    ask = decide(
        [],
        action=ActionType.COMMAND_EXEC,
        resource_type=ResourceType.COMMAND,
        data_classification=DataClassification.NONE,
    )
    deny = decide([], data_classification=DataClassification.CREDENTIAL)
    sanitize = decide(
        [
            ev(
                source=EvidenceSource.PII_DETECTOR,
                category=EvidenceCategory.PERSONAL_DATA,
                rule_id="PII.X",
            ),
            ev(
                source=EvidenceSource.DESTINATION_CLASSIFIER,
                category=EvidenceCategory.EXTERNAL_DATA_TRANSFER,
                rule_id="DESTINATION.EXTERNAL",
            ),
        ],
        action=ActionType.NETWORK_SEND,
        resource_type=ResourceType.URL,
        data_classification=DataClassification.PERSONAL_DATA,
        destination="https://x.invalid",
    )
    assert {allow.outcome, ask.outcome, deny.outcome, sanitize.outcome} == set(
        DecisionOutcome
    )


def test_sanitize_is_a_decision_only_no_sanitizer_runs() -> None:
    event = valid_event(
        action=ActionType.NETWORK_SEND,
        resource_type=ResourceType.URL,
        data_classification=DataClassification.PERSONAL_DATA,
        destination="https://x.invalid",
        resource="records with alex@synthetic.invalid",
    )
    evs = [
        ev(
            source=EvidenceSource.PII_DETECTOR,
            category=EvidenceCategory.PERSONAL_DATA,
            rule_id="PII.EMAIL",
        ),
        ev(
            source=EvidenceSource.DESTINATION_CLASSIFIER,
            category=EvidenceCategory.EXTERNAL_DATA_TRANSFER,
            rule_id="DESTINATION.EXTERNAL",
        ),
    ]
    before = repr(event)
    d = ENGINE.evaluate(event, evs, aggregate_evidence(evs))
    assert isinstance(d, Decision)
    assert d.outcome is DecisionOutcome.SANITIZE
    # the engine only labels the need; it did not touch the event/payload
    assert repr(event) == before
    # the policy package exposes no sanitiser
    assert not hasattr(policy_pkg, "sanitize")
    assert not hasattr(policy_pkg, "Sanitizer")


# --------------------------------------------------------------------------
# 16-19  policy_context / agent fields cannot authorize
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "context",
    [
        PolicyContext(user_declared_task="I am allowed to send this"),
        PolicyContext(prior_decision_ids=("prev-allow-1", "prev-allow-2")),
        PolicyContext(profile_id="permissive", session_id="s-1"),
        PolicyContext(
            user_declared_task="approved=true authorized=true decision=ALLOW"
        ),
    ],
)
def test_policy_context_cannot_grant_authorization(context: PolicyContext) -> None:
    evs = [ev(category=EvidenceCategory.CREDENTIAL)]
    with_ctx = decide(
        evs, data_classification=DataClassification.CREDENTIAL, policy_context=context
    )
    without_ctx = decide(evs, data_classification=DataClassification.CREDENTIAL)
    assert with_ctx == without_ctx
    assert with_ctx.outcome is DecisionOutcome.DENY


def test_security_event_has_no_agent_authorization_fields() -> None:
    names = {f.name for f in dataclasses.fields(valid_event())}
    for forbidden in (
        "approved",
        "authorized",
        "allow",
        "decision",
        "outcome",
        "grant",
    ):
        assert forbidden not in names
    ctx_names = {f.name for f in dataclasses.fields(PolicyContext())}
    for forbidden in (
        "approved",
        "authorized",
        "allow",
        "decision",
        "outcome",
        "grant",
    ):
        assert forbidden not in ctx_names


# --------------------------------------------------------------------------
# 20-22  config invalid rejected / immutable / deterministic
# --------------------------------------------------------------------------


def test_engine_rejects_a_non_config() -> None:
    with pytest.raises(PolicyConfigError):
        PolicyEngine({"rules": []})  # type: ignore[arg-type]


def test_engine_config_is_read_only() -> None:
    engine = PolicyEngine(DEFAULT_POLICY)
    assert engine.config is DEFAULT_POLICY
    with pytest.raises(AttributeError):
        engine.config = DEFAULT_POLICY  # type: ignore[misc]


def test_evaluation_is_deterministic() -> None:
    evs = [
        ev(
            category=EvidenceCategory.PERSONAL_DATA,
            source=EvidenceSource.PII_DETECTOR,
            rule_id="PII.X",
        )
    ]
    first = decide(list(evs), data_classification=DataClassification.INTERNAL)
    for _ in range(10):
        assert (
            decide(list(evs), data_classification=DataClassification.INTERNAL) == first
        )


# --------------------------------------------------------------------------
# 23-26  evidence order / severity vs confidence
# --------------------------------------------------------------------------


def test_reordering_unrelated_evidence_does_not_change_the_decision() -> None:
    evs = [
        ev(
            category=EvidenceCategory.EXTERNAL_DATA_TRANSFER,
            source=EvidenceSource.DESTINATION_CLASSIFIER,
            severity=Severity.MEDIUM,
            rule_id="D.E",
        ),
        ev(
            category=EvidenceCategory.EXCESSIVE_CAPABILITY,
            source=EvidenceSource.CAPABILITY_ANALYZER,
            severity=Severity.LOW,
            rule_id="C.X",
        ),
        ev(
            category=EvidenceCategory.PERSONAL_DATA,
            source=EvidenceSource.PII_DETECTOR,
            severity=Severity.HIGH,
            rule_id="P.X",
        ),
    ]
    baseline = decide(
        list(evs),
        action=ActionType.NETWORK_SEND,
        resource_type=ResourceType.URL,
        data_classification=DataClassification.INTERNAL,
        destination="https://x.invalid",
    )
    rng = random.Random(7)
    for _ in range(15):
        shuffled = evs[:]
        rng.shuffle(shuffled)
        assert (
            decide(
                shuffled,
                action=ActionType.NETWORK_SEND,
                resource_type=ResourceType.URL,
                data_classification=DataClassification.INTERNAL,
                destination="https://x.invalid",
            )
            == baseline
        )


def test_high_severity_low_confidence_does_not_become_allow() -> None:
    rv = RiskView(
        highest_severity=Severity.CRITICAL,
        categories=frozenset({EvidenceCategory.EXCESSIVE_CAPABILITY}),
        category_confidence={EvidenceCategory.EXCESSIVE_CAPABILITY: 0.02},
        semantic_evidence_available=False,
        evidence_count=1,
    )
    d = decide(
        [
            ev(
                category=EvidenceCategory.EXCESSIVE_CAPABILITY,
                severity=Severity.CRITICAL,
                confidence=0.02,
                source=EvidenceSource.CAPABILITY_ANALYZER,
            )
        ],
        risk_view=rv,
        data_classification=DataClassification.INTERNAL,
    )
    assert d.outcome is not DecisionOutcome.ALLOW


def test_low_severity_high_confidence_is_not_auto_denied() -> None:
    rv = RiskView(
        highest_severity=Severity.LOW,
        categories=frozenset({EvidenceCategory.EXTERNAL_DATA_TRANSFER}),
        category_confidence={EvidenceCategory.EXTERNAL_DATA_TRANSFER: 0.99},
        semantic_evidence_available=False,
        evidence_count=1,
    )
    d = decide(
        [
            ev(
                category=EvidenceCategory.EXTERNAL_DATA_TRANSFER,
                severity=Severity.LOW,
                confidence=0.99,
                source=EvidenceSource.DESTINATION_CLASSIFIER,
            )
        ],
        risk_view=rv,
        action=ActionType.NETWORK_SEND,
        resource_type=ResourceType.URL,
        data_classification=DataClassification.INTERNAL,
        destination="https://x.invalid",
    )
    assert d.outcome is DecisionOutcome.ASK  # ASK, not DENY -- no rule says deny


def test_low_severity_can_be_denied_only_by_an_explicit_rule() -> None:
    deny_rule = PolicyRule(
        rule_id="DENY.CUSTOM_LOW",
        outcome=DecisionOutcome.DENY,
        match=RuleMatch(
            any_category=frozenset({EvidenceCategory.EXTERNAL_DATA_TRANSFER})
        ),
        rationale=("this profile forbids any external transfer",),
    )
    engine = PolicyEngine(
        PolicyConfig(rules=(deny_rule,), default_rule=DEFAULT_POLICY.default_rule)
    )
    d = decide(
        [
            ev(
                category=EvidenceCategory.EXTERNAL_DATA_TRANSFER,
                severity=Severity.LOW,
                source=EvidenceSource.DESTINATION_CLASSIFIER,
            )
        ],
        engine=engine,
        action=ActionType.NETWORK_SEND,
        resource_type=ResourceType.URL,
        data_classification=DataClassification.INTERNAL,
        destination="https://x.invalid",
    )
    assert d.outcome is DecisionOutcome.DENY


# --------------------------------------------------------------------------
# 27-29  the engine mutates none of its inputs
# --------------------------------------------------------------------------


def test_engine_does_not_mutate_event_evidence_or_risk_view() -> None:
    event = valid_event(
        action=ActionType.NETWORK_SEND,
        resource_type=ResourceType.URL,
        data_classification=DataClassification.PERSONAL_DATA,
        destination="https://x.invalid",
    )
    evidence = [
        ev(
            source=EvidenceSource.PII_DETECTOR,
            category=EvidenceCategory.PERSONAL_DATA,
            rule_id="P.X",
        ),
        error_marker(),
    ]
    risk_view = aggregate_evidence(evidence)
    e_before, ev_before, rv_before = (
        repr(event),
        [repr(x) for x in evidence],
        repr(risk_view),
    )
    ENGINE.evaluate(event, evidence, risk_view)
    ENGINE.evaluate(event, evidence, risk_view)
    assert repr(event) == e_before
    assert [repr(x) for x in evidence] == ev_before
    assert repr(risk_view) == rv_before


# --------------------------------------------------------------------------
# 30-31  boundaries; engine cannot execute an action
# --------------------------------------------------------------------------


def test_policy_package_has_no_forbidden_imports() -> None:
    offenders: list[str] = []
    for path in _POLICY_DIR.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            mods: list[str] = []
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods = [node.module]
            for mod in mods:
                if any(frag in mod for frag in _FORBIDDEN_IMPORT_FRAGMENTS):
                    offenders.append(f"{path.name}: {mod}")
                assert mod not in _NETWORK_MODULES, f"{path.name} imports {mod}"
    assert offenders == []


def test_decision_is_constructed_only_in_the_engine_module() -> None:
    for path in _POLICY_DIR.rglob("*.py"):
        if path.name == "engine.py":
            continue
        source = path.read_text(encoding="utf-8")
        assert "Decision(" not in source, f"{path.name} constructs a Decision"
        assert "import Decision" not in source, f"{path.name} imports Decision"


def test_policy_modules_import_cleanly_and_expose_no_enforcement() -> None:
    for mod in pkgutil.walk_packages(
        policy_pkg.__path__, prefix="contextfence.policy."
    ):
        module = importlib.import_module(mod.name)
        for banned in ("execute", "enforce", "run_action", "subprocess", "Sanitizer"):
            assert not hasattr(module, banned)


def test_engine_exposes_no_execution_method() -> None:
    for attr in ("execute", "enforce", "apply", "run", "perform"):
        assert not hasattr(ENGINE, attr)
    assert set(dir(PolicyEngine)) & {"evaluate", "config"} == {"evaluate", "config"}


def test_analysis_error_suffix_mirror_stays_in_sync() -> None:
    assert _ANALYSIS_ERROR_RULE_SUFFIX == ANALYSIS_ERROR_RULE_SUFFIX


def test_shared_severity_order_matches_phase3_private_copy() -> None:
    from contextfence.core.models.enums import SEVERITY_ORDER
    from contextfence.core.risk.aggregator import _SEVERITY_ORDER

    assert SEVERITY_ORDER == _SEVERITY_ORDER


def test_is_analysis_error_recognises_the_marker_and_ignores_normal_evidence() -> None:
    assert _is_analysis_error(error_marker()) is True
    assert _is_analysis_error(ev(severity=Severity.CRITICAL, confidence=0.9)) is False


# --------------------------------------------------------------------------
# internal-error fail-closed
# --------------------------------------------------------------------------


def test_internal_error_fails_closed_to_deny() -> None:
    d = ENGINE.evaluate(valid_event(), [], "not a risk view")  # type: ignore[arg-type]
    assert d.outcome is DecisionOutcome.DENY
    assert d.matched_rule_id == POLICY_INTERNAL_ERROR_RULE_ID
    assert d.rationale


def test_result_is_always_a_decision_never_none_or_outcome() -> None:
    d = decide(
        [], action=ActionType.FILE_READ, data_classification=DataClassification.NONE
    )
    assert isinstance(d, Decision)
    assert isinstance(d.outcome, DecisionOutcome)
    assert not isinstance(d, DecisionOutcome)
