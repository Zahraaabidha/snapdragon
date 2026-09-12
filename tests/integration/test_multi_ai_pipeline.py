"""Multi-AI extensibility (task Part G): two adapters, one security pipeline.

These tests demonstrate that ContextFence is AI-provider agnostic. The Claude
Code adapter and a synthetic second adapter each produce a canonical
``SecurityEvent`` from their own native vocabulary, both feed the *same*
:class:`SecurityPipeline`, and the security behaviour depends only on the
event -- never on which adapter produced it.
"""

from __future__ import annotations

import pytest

from contextfence.adapters import AdapterRegistry
from contextfence.adapters.base import AIAdapter
from contextfence.adapters.claude_code import ClaudeCodeAdapter
from contextfence.adapters.synthetic import SyntheticAgentAdapter
from contextfence.audit.sink import InMemoryAuditSink
from contextfence.core.models.enums import DecisionOutcome
from contextfence.core.models.event import SecurityEvent
from contextfence.pipeline import SecurityPipeline
from contextfence.policy.default_policy import DEFAULT_POLICY
from contextfence.policy.engine import PolicyEngine


@pytest.fixture()
def pipeline() -> SecurityPipeline:
    return SecurityPipeline(
        policy_engine=PolicyEngine(DEFAULT_POLICY), audit_sink=InMemoryAuditSink()
    )


@pytest.fixture()
def registry() -> AdapterRegistry:
    reg = AdapterRegistry()
    reg.register(ClaudeCodeAdapter())
    reg.register(SyntheticAgentAdapter())
    return reg


def test_both_adapters_produce_canonical_security_events(
    registry: AdapterRegistry,
) -> None:
    claude = registry.get("claude_code")
    synthetic = registry.get("synthetic_agent")

    claude_event = claude.normalize(
        {"tool_name": "Read", "tool_input": {"file_path": "notes.txt"}}
    )
    synthetic_event = synthetic.normalize({"op": "read_file", "target": "notes.txt"})

    assert isinstance(claude_event, SecurityEvent)
    assert isinstance(synthetic_event, SecurityEvent)
    assert claude_event.application == "claude_code"
    assert synthetic_event.application == "synthetic_agent"


def test_same_security_input_same_policy_behaviour_regardless_of_adapter(
    registry: AdapterRegistry, pipeline: SecurityPipeline
) -> None:
    """A credential read is denied whether Claude Code or the synthetic agent asked."""

    claude_event = registry.get("claude_code").normalize(
        {
            "tool_name": "Read",
            "tool_input": {"file_path": "project/.env"},
            "data_classification": "CREDENTIAL",
        }
    )
    synthetic_event = registry.get("synthetic_agent").normalize(
        {
            "op": "read_file",
            "target": "project/.env",
            "sensitivity": "CREDENTIAL",
        }
    )

    claude_result = pipeline.process(claude_event)
    synthetic_result = pipeline.process(synthetic_event)

    assert claude_result.decision.outcome is DecisionOutcome.DENY
    assert synthetic_result.decision.outcome is DecisionOutcome.DENY
    assert (
        claude_result.decision.matched_rule_id
        == synthetic_result.decision.matched_rule_id
    )
    assert claude_result.enforcement.outcome == synthetic_result.enforcement.outcome


@pytest.mark.parametrize(
    "claude_native, synthetic_native",
    [
        (
            {"tool_name": "Read", "tool_input": {"file_path": "a/b.md"}},
            {"op": "read_file", "target": "a/b.md"},
        ),
        (
            {"tool_name": "Bash", "tool_input": {"command": "pytest -q"}},
            {"op": "run_shell", "target": "pytest -q"},
        ),
        (
            {
                "tool_name": "WebFetch",
                "tool_input": {"url": "https://x.invalid/p", "prompt": "s"},
            },
            {
                "op": "http_request",
                "target": "https://x.invalid/p",
                "endpoint": "x.invalid",
            },
        ),
    ],
)
def test_equivalent_native_events_yield_equivalent_decisions(
    registry: AdapterRegistry,
    pipeline: SecurityPipeline,
    claude_native: dict[str, object],
    synthetic_native: dict[str, object],
) -> None:
    claude_event = registry.get("claude_code").normalize(claude_native)
    synthetic_event = registry.get("synthetic_agent").normalize(synthetic_native)

    # the two adapters agreed on the canonical action / resource_type
    assert claude_event.action is synthetic_event.action
    assert claude_event.resource_type is synthetic_event.resource_type

    claude_result = pipeline.process(claude_event)
    synthetic_result = pipeline.process(synthetic_event)
    assert claude_result.decision.outcome is synthetic_result.decision.outcome
    assert (
        claude_result.decision.matched_rule_id
        == synthetic_result.decision.matched_rule_id
    )


def test_the_pipeline_never_sees_the_adapter(pipeline: SecurityPipeline) -> None:
    # The pipeline's public surface takes a SecurityEvent (or raw mapping); there
    # is no adapter parameter and no adapter attribute. (Import-level isolation
    # is asserted in tests/unit/test_adapter_architecture.py.)
    assert not hasattr(pipeline, "adapter")
    assert not hasattr(pipeline, "adapter_id")
    import inspect

    signature = inspect.signature(SecurityPipeline.process)
    assert "adapter" not in signature.parameters


def test_a_third_adapter_needs_no_core_or_pipeline_change() -> None:
    """Registering a brand-new adapter is a local operation."""

    from collections.abc import Mapping

    from contextfence.adapters.identity import AdapterId
    from contextfence.adapters.input import AdapterInput
    from contextfence.core.models.enums import (
        ActionType,
        DataClassification,
        ResourceType,
    )

    class ThirdPartyAdapter(AIAdapter):
        adapter_id = AdapterId("third_party_agent")

        def translate(self, native_event: Mapping[str, object]) -> AdapterInput:
            return AdapterInput(
                application=self.adapter_id.value,
                actor="third_party:agent",
                action=ActionType.FILE_READ,
                resource=str(native_event["path"]),
                resource_type=ResourceType.FILE,
                data_classification=DataClassification.INTERNAL,
                requested_capabilities=("fs.read",),
            )

    registry = AdapterRegistry()
    registry.register(ThirdPartyAdapter())
    event = registry.get("third_party_agent").normalize({"path": "synthetic/x.md"})

    pipeline = SecurityPipeline(policy_engine=PolicyEngine(DEFAULT_POLICY))
    result = pipeline.process(event)
    assert result.decision.outcome in set(DecisionOutcome)
