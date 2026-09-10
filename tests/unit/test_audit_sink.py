"""Phase 6: append-only sink, failure semantics, persistence, boundaries."""

from __future__ import annotations

import ast
import importlib
import pkgutil
from pathlib import Path

import contextfence.audit as audit_pkg
from contextfence.audit import (
    AppendResult,
    AuditWriteErrorKind,
    InMemoryAuditSink,
    IntegrityStatus,
    load_chain,
    serialize_chain,
    verify_serialized,
)
from contextfence.core.models.decision import Decision
from contextfence.core.models.enums import DecisionOutcome
from contextfence.enforcement import EnforcementGate, EnforcementOutcome
from tests.unit.test_audit_record import _valid_body

_AUDIT_DIR = Path(audit_pkg.__file__).parent
_FORBIDDEN_FRAGMENTS = (
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
    "contextfence.policy",
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
        "pickle",
        "asyncio",
    }
)


# --- append-only behaviour ------------------------------------


def test_append_returns_a_chained_record() -> None:
    sink = InMemoryAuditSink()
    r1 = sink.append(_valid_body(event_id="a"))
    r2 = sink.append(_valid_body(event_id="b"))
    assert r1.ok and r2.ok
    assert r1.record is not None and r2.record is not None
    assert r2.record.prev_hash == r1.record.record_hash
    assert len(sink) == 2
    assert sink.verify().status is IntegrityStatus.OK


def test_sink_exposes_no_mutation_methods() -> None:
    forbidden = {
        "update",
        "delete",
        "remove",
        "pop",
        "insert",
        "clear",
        "truncate",
        "rewrite",
        "__setitem__",
        "__delitem__",
    }
    assert forbidden.isdisjoint(dir(InMemoryAuditSink))


def test_records_returns_an_immutable_snapshot() -> None:
    sink = InMemoryAuditSink()
    sink.append(_valid_body())
    snapshot = sink.records()
    assert isinstance(snapshot, tuple)
    # mutating the snapshot cannot affect the sink
    sink.append(_valid_body(event_id="two"))
    assert len(snapshot) == 1
    assert len(sink.records()) == 2


def test_append_result_validates_its_own_shape() -> None:
    import pytest

    with pytest.raises(ValueError):
        AppendResult(ok=True, record=None)
    with pytest.raises(ValueError):
        AppendResult(ok=False, error_kind=AuditWriteErrorKind.NONE)


# --- failure semantics --------------------------------------


def test_invalid_body_append_fails_without_raising() -> None:
    sink = InMemoryAuditSink()
    result = sink.append("not a body")  # type: ignore[arg-type]
    assert result.ok is False
    assert result.error_kind is AuditWriteErrorKind.INVALID_BODY
    assert result.record is None
    assert len(sink) == 0  # nothing was written


def test_audit_failure_does_not_alter_a_prior_enforcement_result() -> None:
    # a DENY enforcement result stays DENIED regardless of what audit does
    gate = EnforcementGate()
    enf = gate.enforce(
        Decision(
            outcome=DecisionOutcome.DENY,
            matched_rule_id="DENY.X",
            rationale=("blocked",),
        )
    )
    assert enf.outcome is EnforcementOutcome.DENIED
    assert enf.permitted_to_proceed is False

    sink = InMemoryAuditSink()
    failed = sink.append("garbage")  # type: ignore[arg-type]
    assert failed.ok is False

    # the enforcement result object is unchanged and still blocking
    assert enf.outcome is EnforcementOutcome.DENIED
    assert enf.permitted_to_proceed is False


# --- persistence via serialization (no file I/O in the module) --


def test_chain_persists_through_a_jsonl_file_round_trip(tmp_path: Path) -> None:
    sink = InMemoryAuditSink()
    for i in range(4):
        sink.append(_valid_body(event_id=f"evt-{i}"))
    path = tmp_path / "audit.jsonl"
    path.write_text(serialize_chain(sink.records()), encoding="utf-8")

    reloaded = load_chain(path.read_text(encoding="utf-8"))
    assert reloaded == sink.records()
    assert verify_serialized(path.read_text(encoding="utf-8")).status is (
        IntegrityStatus.OK
    )

    # tamper with the stored bytes: swap two lines -> reordering is detected
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    path.write_text("\n".join(lines), encoding="utf-8")
    assert verify_serialized(path.read_text(encoding="utf-8")).status is (
        IntegrityStatus.FAILED
    )


# --- architectural boundaries ------------------------------


def test_audit_modules_import_cleanly() -> None:
    for mod in pkgutil.walk_packages(audit_pkg.__path__, prefix="contextfence.audit."):
        importlib.import_module(mod.name)


def test_audit_has_no_forbidden_imports() -> None:
    offenders: list[str] = []
    for path in _AUDIT_DIR.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                if any(frag in name for frag in _FORBIDDEN_FRAGMENTS):
                    offenders.append(f"{path.name}: {name}")
                assert name not in _FORBIDDEN_MODULES, f"{path.name} imports {name}"
                if name.startswith("contextfence.analysis"):
                    assert name == "contextfence.analysis.redaction"
    assert offenders == []


def test_audit_constructs_no_decision_and_exposes_no_policy_engine() -> None:
    for path in _AUDIT_DIR.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert "Decision(" not in source, f"{path.name} constructs a Decision"
        assert "PolicyConfig(" not in source
    for mod in pkgutil.walk_packages(audit_pkg.__path__, prefix="contextfence.audit."):
        module = importlib.import_module(mod.name)
        for banned in ("PolicyEngine", "subprocess", "execute", "Sanitizer"):
            assert not hasattr(module, banned)


def test_audit_does_not_expose_a_decision_producing_symbol() -> None:
    assert not hasattr(audit_pkg, "Decision")
    assert not hasattr(audit_pkg, "DecisionOutcome")
    assert not hasattr(audit_pkg, "PolicyEngine")
