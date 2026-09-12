"""Architectural guards for the Phase 8 semantic / inference boundary.

Lock in the properties that make semantic analysis "evidence, never authority"
structurally, not just by convention:

* the security core (``core``, ``policy``, ``enforcement``, ``audit``) and the
  adapter boundary import nothing from ``contextfence.inference`` or
  ``contextfence.analysis.semantic``;
* ``contextfence.inference`` imports no vendor/ML SDK and performs no network
  or process I/O;
* ``contextfence.analysis.semantic`` is the only place under ``analysis/`` that
  imports ``contextfence.inference`` (also checked from the analysis side in
  ``tests/unit/test_detector_pipeline.py``);
* ``SemanticAnalyzer`` is not part of ``DEFAULT_DETECTORS``;
* the generic pipeline's only semantic-layer dependency is
  ``SemanticAnalyzer`` itself -- it does not import ``contextfence.inference``.
"""

from __future__ import annotations

import ast
from pathlib import Path

import contextfence
import contextfence.analysis as analysis_pkg
import contextfence.inference as inference_pkg
import contextfence.pipeline as pipeline_pkg
from contextfence.analysis import DEFAULT_DETECTORS
from contextfence.analysis.semantic import SemanticAnalyzer

_SRC = Path(contextfence.__file__).parent
_INFERENCE_DIR = Path(inference_pkg.__file__).parent
_SEMANTIC_DIR = Path(analysis_pkg.__file__).parent / "semantic"
_PIPELINE_DIR = Path(pipeline_pkg.__file__).parent

_CORE_PACKAGES = ("core", "policy", "enforcement", "audit", "adapters")


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def _py_files(root: Path) -> list[Path]:
    return sorted(root.rglob("*.py"))


def test_core_packages_do_not_import_inference_or_semantic() -> None:
    offenders: list[str] = []
    for package in _CORE_PACKAGES:
        for path in _py_files(_SRC / package):
            for mod in _imported_modules(path):
                if mod.startswith("contextfence.inference") or mod.startswith(
                    "contextfence.analysis.semantic"
                ):
                    offenders.append(f"{path.relative_to(_SRC)}: {mod}")
    assert offenders == []


def test_inference_package_has_no_vendor_or_cloud_imports() -> None:
    banned = {
        "onnxruntime",
        "qnn",
        "qai_hub",
        "torch",
        "transformers",
        "requests",
        "httpx",
        "urllib.request",
        "http.client",
        "socket",
        "subprocess",
    }
    offenders: list[str] = []
    for path in _py_files(_INFERENCE_DIR):
        hits = {
            m
            for m in _imported_modules(path)
            if any(m == b or m.startswith(b + ".") for b in banned)
        }
        if hits:
            offenders.append(f"{path.name}: {sorted(hits)}")
    assert offenders == []


def test_inference_package_imports_no_other_contextfence_package() -> None:
    # InferenceProvider is a leaf abstraction: it depends only on the core
    # models/enums (for the request/result schema) and its own errors.
    allowed_prefixes = (
        "contextfence.core.models",
        "contextfence.core.errors",
        "contextfence.inference",
    )
    offenders: list[str] = []
    for path in _py_files(_INFERENCE_DIR):
        for mod in _imported_modules(path):
            if mod.startswith("contextfence.") and not mod.startswith(allowed_prefixes):
                offenders.append(f"{path.name}: {mod}")
    assert offenders == []


def test_semantic_analyzer_is_not_a_default_detector() -> None:
    assert not any(isinstance(d, SemanticAnalyzer) for d in DEFAULT_DETECTORS)


def test_generic_pipeline_does_not_import_inference_directly() -> None:
    offenders: list[str] = []
    for path in _py_files(_PIPELINE_DIR):
        for mod in _imported_modules(path):
            if mod.startswith("contextfence.inference"):
                offenders.append(f"{path.name}: {mod}")
    assert offenders == []


def test_generic_pipeline_imports_only_the_semantic_analyzer_type() -> None:
    offenders: list[str] = []
    for path in _py_files(_PIPELINE_DIR):
        for mod in _imported_modules(path):
            if mod.startswith("contextfence.analysis.semantic") and mod != (
                "contextfence.analysis.semantic"
            ):
                offenders.append(f"{path.name}: {mod}")
    assert offenders == []


def test_semantic_module_constructs_no_decision_and_touches_no_policy_config() -> None:
    forbidden = (
        "contextfence.core.models.decision",
        "contextfence.policy",
        "contextfence.enforcement",
        "contextfence.audit",
        "contextfence.adapters",
    )
    offenders: list[str] = []
    for path in _py_files(_SEMANTIC_DIR):
        for mod in _imported_modules(path):
            if mod.startswith(forbidden):
                offenders.append(f"{path.name}: {mod}")
    assert offenders == []
