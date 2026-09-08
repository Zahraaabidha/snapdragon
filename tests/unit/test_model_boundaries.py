"""Architectural guards for the Phase 1 core.

These lock in structural security properties so a later change that quietly
weakens them fails a test:

* the core models import no UI, adapter, or inference-vendor code
  (SECURITY.md §1.11, §1.13; PROJECT_SPEC.md NFR-7);
* nothing that produces evidence imports the Decision type -- evidence can only
  influence a decision indirectly, via the Policy Engine reading a RiskView
  (SECURITY.md §1.1).
"""

from __future__ import annotations

import ast
import importlib
import pkgutil
from pathlib import Path

import contextfence.core as core_pkg

_CORE_DIR = Path(core_pkg.__file__).parent

_FORBIDDEN_IMPORT_FRAGMENTS = (
    "PySide6",
    "onnxruntime",
    "qnn",
    "qai_hub",
    "torch",
    "contextfence.ui",
    "contextfence.adapters",
    "contextfence.inference",
)


def _core_modules() -> list[str]:
    names: list[str] = []
    for mod in pkgutil.walk_packages(core_pkg.__path__, prefix="contextfence.core."):
        names.append(mod.name)
    return names


def test_all_core_modules_import_cleanly() -> None:
    for name in _core_modules():
        importlib.import_module(name)


def test_core_has_no_ui_adapter_or_vendor_imports() -> None:
    offenders: list[str] = []
    for path in _CORE_DIR.rglob("*.py"):
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
    assert offenders == []


def test_evidence_and_risk_modules_do_not_import_decision() -> None:
    for module_name in ("evidence", "risk"):
        path = _CORE_DIR / "models" / f"{module_name}.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imported: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module)
            elif isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
        assert not any("decision" in m for m in imported), (
            f"{module_name}.py must not import the Decision module"
        )


def test_evidence_module_namespace_has_no_decision_symbols() -> None:
    evidence_mod = importlib.import_module("contextfence.core.models.evidence")
    risk_mod = importlib.import_module("contextfence.core.models.risk")
    for mod in (evidence_mod, risk_mod):
        assert not hasattr(mod, "Decision")
        assert not hasattr(mod, "DecisionOutcome")
