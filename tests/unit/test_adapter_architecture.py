"""Architectural guards for the Phase 7 adapter boundary.

These lock in the "ContextFence is AI-provider agnostic" property so a later
change that quietly couples the core to an adapter fails a test:

* the security core, the analysis/policy/enforcement/audit packages, and the
  generic pipeline import **nothing** from ``contextfence.adapters``;
* the generic pipeline imports no concrete adapter and has no
  ``if adapter == "..."`` branch;
* the concrete adapters depend on the generic contract, never the reverse;
* an adapter module constructs no ``Decision`` and never touches ``PolicyConfig``
  or the ``EnforcementGate``;
* no Phase 9+ code exists yet: no concrete inference backend
  (``inference/cpu``, ``inference/snapdragon``) and no UI. Phase 8's semantic
  analyzer and the model-independent ``InferenceProvider`` *contract* do exist
  -- see ``tests/unit/test_semantic_architecture.py`` for their own guards.
"""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path

import contextfence
import contextfence.adapters as adapters_pkg
import contextfence.pipeline as pipeline_pkg

_SRC = Path(contextfence.__file__).parent
_ADAPTERS_DIR = Path(adapters_pkg.__file__).parent
_PIPELINE_DIR = Path(pipeline_pkg.__file__).parent

_PROVIDER_INDEPENDENT_PACKAGES = ("core", "analysis", "policy", "enforcement", "audit")


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


# -- the core / support packages must not import adapters -----------------


def test_provider_independent_packages_do_not_import_adapters() -> None:
    offenders: list[str] = []
    for package in _PROVIDER_INDEPENDENT_PACKAGES:
        for path in _py_files(_SRC / package):
            for mod in _imported_modules(path):
                if mod.startswith("contextfence.adapters"):
                    offenders.append(f"{path.relative_to(_SRC)}: {mod}")
    assert offenders == []


def test_generic_pipeline_does_not_import_adapters_or_a_concrete_adapter() -> None:
    offenders: list[str] = []
    for path in _py_files(_PIPELINE_DIR):
        for mod in _imported_modules(path):
            if mod.startswith("contextfence.adapters") or "claude_code" in mod:
                offenders.append(f"{path.name}: {mod}")
    assert offenders == []


def test_generic_pipeline_has_no_adapter_specific_branch() -> None:
    """No ``if adapter == "claude"`` style dispatch anywhere in pipeline *code*.

    Scans string literals used in comparisons (ignoring docstrings and
    comments, which legitimately mention adapters when describing the boundary).
    """

    banned_fragments = ("claude", "cursor", "copilot", "gemini", "adapter")
    offenders: list[str] = []
    for path in _py_files(_PIPELINE_DIR):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
            operands = [node.left, *node.comparators]
            for operand in operands:
                if isinstance(operand, ast.Constant) and isinstance(operand.value, str):
                    low = operand.value.lower()
                    if any(fragment in low for fragment in banned_fragments):
                        offenders.append(
                            f"{path.name}: compares against {operand.value!r}"
                        )
    assert offenders == []


# -- concrete adapters depend on the generic contract, not vice versa ----


def test_generic_adapter_modules_do_not_import_concrete_adapters() -> None:
    generic = ("base.py", "identity.py", "input.py", "registry.py", "errors.py")
    offenders: list[str] = []
    for name in generic:
        for mod in _imported_modules(_ADAPTERS_DIR / name):
            if "claude_code" in mod or mod.endswith("adapters.synthetic"):
                offenders.append(f"{name}: {mod}")
    assert offenders == []


def test_claude_code_adapter_imports_only_generic_and_core_contracts() -> None:
    mods = _imported_modules(_ADAPTERS_DIR / "claude_code" / "adapter.py")
    cf_mods = {m for m in mods if m.startswith("contextfence.")}
    allowed_prefixes = ("contextfence.adapters", "contextfence.core.models")
    assert cf_mods, "expected the adapter to use the core contracts"
    for mod in cf_mods:
        assert mod.startswith(allowed_prefixes), mod


# -- an adapter cannot decide, enforce, or mutate policy -----------------


def test_no_adapter_module_imports_decision_policy_or_enforcement() -> None:
    forbidden = (
        "contextfence.core.models.decision",
        "contextfence.policy",
        "contextfence.enforcement",
        "contextfence.audit",
    )
    offenders: list[str] = []
    for path in _py_files(_ADAPTERS_DIR):
        for mod in _imported_modules(path):
            if mod.startswith(forbidden):
                offenders.append(f"{path.relative_to(_ADAPTERS_DIR)}: {mod}")
    assert offenders == []


def test_no_adapter_or_pipeline_module_does_process_or_network_io() -> None:
    forbidden = {
        "subprocess",
        "socket",
        "http",
        "http.client",
        "urllib.request",
        "ftplib",
        "asyncio",
        "ctypes",
        "winreg",
    }
    offenders: list[str] = []
    for root in (_ADAPTERS_DIR, _PIPELINE_DIR):
        for path in _py_files(root):
            hits = _imported_modules(path) & forbidden
            if hits:
                offenders.append(f"{path.name}: {sorted(hits)}")
    assert offenders == []


# -- no Phase 9+ implementation exists -----------------------------------


def test_no_ui_or_concrete_inference_backend_packages_exist() -> None:
    """Phase 8 adds the semantic analyzer + ``InferenceProvider`` contract only.

    Concrete inference backends (Phase 9 CPU, Phase 10 Snapdragon/NPU) and the
    desktop UI (Phase 12) must not exist yet.
    """

    for missing in (
        "contextfence.inference.cpu",
        "contextfence.inference.snapdragon",
        "contextfence.ui",
    ):
        assert importlib.util.find_spec(missing) is None, f"unexpected: {missing}"
    assert not (_SRC / "inference" / "cpu").exists()
    assert not (_SRC / "inference" / "snapdragon").exists()
    assert not (_SRC / "ui").exists()


def test_no_vendor_or_npu_imports_anywhere_in_the_package() -> None:
    banned = ("onnxruntime", "qnn", "qai_hub", "torch", "PySide6", "transformers")
    offenders: list[str] = []
    for path in _py_files(_SRC):
        for mod in _imported_modules(path):
            if any(mod == b or mod.startswith(b + ".") for b in banned):
                offenders.append(f"{path.relative_to(_SRC)}: {mod}")
    assert offenders == []
