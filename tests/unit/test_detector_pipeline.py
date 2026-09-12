"""run_detectors: safe collection, failure handling, and analysis boundaries."""

from __future__ import annotations

import ast
import importlib
import pkgutil
from pathlib import Path

import pytest

import contextfence.analysis as analysis_pkg
from contextfence.analysis import DEFAULT_DETECTORS, run_detectors
from contextfence.analysis.detector import Detector
from contextfence.core.models.decision import Decision
from contextfence.core.models.enums import (
    ActionType,
    DataClassification,
    EvidenceCategory,
    EvidenceSource,
    Severity,
)
from contextfence.core.models.evidence import Evidence
from tests.unit._factories import valid_event

_ANALYSIS_DIR = Path(analysis_pkg.__file__).parent

_FORBIDDEN_IMPORT_FRAGMENTS = (
    "PySide6",
    "onnxruntime",
    "qnn",
    "qai_hub",
    "torch",
    "snapdragon",
    "contextfence.core.models.decision",
    "contextfence.policy",
    "contextfence.enforcement",
    "contextfence.audit",
    "contextfence.ui",
    "contextfence.adapters",
)

#: contextfence.inference is forbidden everywhere in ``analysis/`` *except*
#: ``analysis/semantic/`` (Phase 8): that subpackage is the sole, deliberate
#: bridge to the model-independent InferenceProvider abstraction
#: (docs/DECISIONS.md D-0004). The deterministic detectors this module
#: otherwise covers -- secrets, pii, destination, capability, detector,
#: redaction -- must still never import it.
_INFERENCE_FRAGMENT = "contextfence.inference"
_INFERENCE_ALLOWED_SUBPACKAGE = "semantic"


# --- happy path ----------------------------------------------------------------


def test_benign_event_yields_no_evidence() -> None:
    assert run_detectors(valid_event(), DEFAULT_DETECTORS) == ()


def test_collects_from_every_detector_in_order() -> None:
    event = valid_event(
        action=ActionType.NETWORK_SEND,
        resource="repo/.env",
        destination="https://api.collector.invalid/u?x=1",
        data_classification=DataClassification.CREDENTIAL,
        requested_capabilities=("net.egress", "exec"),
    )
    findings = run_detectors(event, DEFAULT_DETECTORS)
    sources = [e.source for e in findings]
    assert EvidenceSource.SECRET_DETECTOR in sources
    assert EvidenceSource.DESTINATION_CLASSIFIER in sources
    assert EvidenceSource.CAPABILITY_ANALYZER in sources
    # detector order is preserved (secret before destination before capability)
    assert sources == sorted(
        sources,
        key=lambda s: [
            EvidenceSource.SECRET_DETECTOR,
            EvidenceSource.PII_DETECTOR,
            EvidenceSource.DESTINATION_CLASSIFIER,
            EvidenceSource.CAPABILITY_ANALYZER,
        ].index(s),
    )
    assert all(isinstance(e, Evidence) for e in findings)


def test_pipeline_returns_evidence_never_decision() -> None:
    event = valid_event(resource="AKIAIOSFODNN7EXAMPLE")
    for e in run_detectors(event, DEFAULT_DETECTORS):
        assert isinstance(e, Evidence)
        assert not isinstance(e, Decision)


# --- failure handling: no silent fail-open -----------------------------------


class _RaisingDetector:
    namespace = "BOOM"
    source = EvidenceSource.SECRET_DETECTOR
    primary_category = EvidenceCategory.CREDENTIAL

    def analyze(self, event: object) -> tuple[Evidence, ...]:
        raise RuntimeError("kaboom-with-sensitive-substring-AKIAIOSFODNN7EXAMPLE")


class _BadReturnDetector:
    namespace = "BADRET"
    source = EvidenceSource.PII_DETECTOR
    primary_category = EvidenceCategory.PERSONAL_DATA

    def analyze(self, event: object) -> list[int]:
        return [1, 2, 3]


def test_detector_exception_becomes_high_severity_zero_confidence_marker() -> None:
    findings = run_detectors(valid_event(), (_RaisingDetector(),))
    assert len(findings) == 1
    marker = findings[0]
    assert marker.metadata["rule_id"] == "BOOM.ANALYSIS_ERROR"
    assert marker.severity is Severity.HIGH
    assert marker.confidence == 0.0
    assert marker.metadata["error_type"] == "RuntimeError"
    # the exception message (which contains a secret-shaped substring) is not kept
    for value in marker.metadata.values():
        assert "AKIAIOSFODNN7EXAMPLE" not in value
        assert "kaboom" not in value


def test_detector_returning_non_evidence_becomes_a_marker() -> None:
    # _BadReturnDetector deliberately violates the return contract.
    findings = run_detectors(valid_event(), (_BadReturnDetector(),))  # type: ignore[arg-type]
    assert [e.metadata["rule_id"] for e in findings] == ["BADRET.ANALYSIS_ERROR"]
    assert findings[0].confidence == 0.0


def test_one_failing_detector_does_not_stop_the_others() -> None:
    event = valid_event(
        resource="repo/.env", data_classification=DataClassification.SECRET
    )
    findings = run_detectors(event, (_RaisingDetector(), *DEFAULT_DETECTORS))
    rule_ids = {e.metadata["rule_id"] for e in findings}
    assert "BOOM.ANALYSIS_ERROR" in rule_ids
    assert any(r.startswith("SECRET.") and r != "BOOM.ANALYSIS_ERROR" for r in rule_ids)


def test_error_marker_keeps_severity_and_confidence_independent() -> None:
    (marker,) = run_detectors(valid_event(), (_RaisingDetector(),))
    # HIGH impact, but zero certainty -- the two axes are not the same value
    assert marker.severity is Severity.HIGH
    assert marker.confidence == 0.0


# --- architectural boundaries ----------------------------------------------


def test_all_analysis_modules_import_cleanly() -> None:
    for mod in pkgutil.walk_packages(
        analysis_pkg.__path__, prefix="contextfence.analysis."
    ):
        importlib.import_module(mod.name)


def test_analysis_has_no_policy_enforcement_ui_or_vendor_imports() -> None:
    offenders: list[str] = []
    for path in _ANALYSIS_DIR.rglob("*.py"):
        in_semantic = (
            _INFERENCE_ALLOWED_SUBPACKAGE in path.relative_to(_ANALYSIS_DIR).parts
        )
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            mods: list[str] = []
            if isinstance(node, ast.Import):
                mods = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods = [node.module]
            for mod in mods:
                if in_semantic and mod.startswith(_INFERENCE_FRAGMENT):
                    continue
                if mod.startswith(_INFERENCE_FRAGMENT) or any(
                    frag in mod for frag in _FORBIDDEN_IMPORT_FRAGMENTS
                ):
                    offenders.append(f"{path.name}: {mod}")
    assert offenders == []


def test_only_the_semantic_subpackage_imports_inference() -> None:
    offenders: list[str] = []
    for path in _ANALYSIS_DIR.rglob("*.py"):
        if _INFERENCE_ALLOWED_SUBPACKAGE in path.relative_to(_ANALYSIS_DIR).parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            mods: list[str] = []
            if isinstance(node, ast.Import):
                mods = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods = [node.module]
            for mod in mods:
                if mod.startswith(_INFERENCE_FRAGMENT):
                    offenders.append(f"{path.name}: {mod}")
    assert offenders == []


def test_analysis_namespace_exposes_no_decision_symbols() -> None:
    for mod in pkgutil.walk_packages(
        analysis_pkg.__path__, prefix="contextfence.analysis."
    ):
        module = importlib.import_module(mod.name)
        assert not hasattr(module, "Decision")
        assert not hasattr(module, "DecisionOutcome")
        assert not hasattr(module, "PolicyEngine")


def test_default_detectors_satisfy_the_protocol() -> None:
    assert len(DEFAULT_DETECTORS) == 4
    for detector in DEFAULT_DETECTORS:
        assert isinstance(detector, Detector)
        assert isinstance(detector.namespace, str) and detector.namespace
        assert isinstance(detector.source, EvidenceSource)
        assert isinstance(detector.primary_category, EvidenceCategory)


def test_no_network_access_symbols_imported_in_analysis() -> None:
    # deterministic, local-only: sockets / urllib.request / http.client must not
    # be imported anywhere in the analysis package (urllib.parse is fine).
    banned = (
        "socket",
        "urllib.request",
        "http.client",
        "httplib",
        "requests",
        "ftplib",
    )
    for path in _ANALYSIS_DIR.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                assert name not in banned, f"{path.name} imports {name}"


@pytest.mark.parametrize("detector", list(DEFAULT_DETECTORS))
def test_each_detector_leaves_the_event_unmodified(detector: Detector) -> None:
    event = valid_event(
        action=ActionType.NETWORK_SEND,
        resource="repo/.env AKIAIOSFODNN7EXAMPLE alex@synthetic.invalid",
        destination="https://api.collector.invalid/u?tok=sYnThEtIc",
        data_classification=DataClassification.CREDENTIAL,
        requested_capabilities=("net.egress", "exec", "fs.read"),
    )
    snapshot = repr(event)
    detector.analyze(event)
    assert repr(event) == snapshot
