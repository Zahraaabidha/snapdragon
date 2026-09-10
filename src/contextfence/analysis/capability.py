"""Deterministic capability detector.

Flags security-sensitive entries in ``event.requested_capabilities`` and
security-sensitive ``event.action`` values: command execution, external network
egress, credential access, and sensitive / destructive filesystem access.

Scope note: ARCHITECTURE.md §3.3 also envisions comparing requested capabilities
against what an actor is *normally granted*. That baseline lives in policy
configuration, which does not exist until Phase 4, so this Phase 2 detector only
flags capabilities that are inherently sensitive. It produces evidence, never a
decision.
"""

from __future__ import annotations

from dataclasses import dataclass

from contextfence.analysis.secrets import credential_path_rule
from contextfence.core.models.enums import (
    ActionType,
    DataClassification,
    EvidenceCategory,
    EvidenceSource,
    Severity,
)
from contextfence.core.models.event import SecurityEvent
from contextfence.core.models.evidence import Evidence

__all__ = ["CapabilityDetector"]

_NAMESPACE = "CAPABILITY"

_SENSITIVE_CLASS = frozenset(
    {
        DataClassification.PERSONAL_DATA,
        DataClassification.CREDENTIAL,
        DataClassification.SECRET,
        DataClassification.REGULATED,
    }
)


@dataclass(frozen=True)
class _CapRule:
    rule_id: str
    category: EvidenceCategory
    severity: Severity
    confidence: float
    tokens: frozenset[str]
    #: only emit when the event context is already sensitive
    requires_sensitive_context: bool = False


_CAPABILITY_RULES: tuple[_CapRule, ...] = (
    _CapRule(
        "CAPABILITY.COMMAND_EXECUTION",
        EvidenceCategory.EXCESSIVE_CAPABILITY,
        Severity.HIGH,
        0.9,
        frozenset(
            {
                "exec",
                "command.exec",
                "process.exec",
                "process.spawn",
                "shell",
                "shell.exec",
                "subprocess",
            }
        ),
    ),
    _CapRule(
        "CAPABILITY.NETWORK_EGRESS",
        EvidenceCategory.EXTERNAL_DATA_TRANSFER,
        Severity.HIGH,
        0.8,
        frozenset(
            {
                "net.egress",
                "network.egress",
                "network.send",
                "net.outbound",
                "net.connect",
                "http.client",
                "egress",
            }
        ),
    ),
    _CapRule(
        "CAPABILITY.CREDENTIAL_ACCESS",
        EvidenceCategory.CREDENTIAL,
        Severity.HIGH,
        0.8,
        frozenset(
            {
                "credential.read",
                "credentials.read",
                "secret.read",
                "secrets.read",
                "keychain.read",
                "vault.read",
                "env.read",
            }
        ),
    ),
    _CapRule(
        "CAPABILITY.FILESYSTEM_WRITE",
        EvidenceCategory.EXCESSIVE_CAPABILITY,
        Severity.MEDIUM,
        0.6,
        frozenset(
            {"fs.write", "file.write", "filesystem.write", "fs.delete", "file.delete"}
        ),
    ),
    _CapRule(
        "CAPABILITY.SENSITIVE_FILESYSTEM_READ",
        EvidenceCategory.EXCESSIVE_CAPABILITY,
        Severity.MEDIUM,
        0.55,
        frozenset({"fs.read", "file.read", "filesystem.read"}),
        requires_sensitive_context=True,
    ),
)

_ACTION_RULES: dict[ActionType, tuple[str, EvidenceCategory, Severity, float]] = {
    ActionType.COMMAND_EXEC: (
        "CAPABILITY.COMMAND_EXECUTION_ACTION",
        EvidenceCategory.EXCESSIVE_CAPABILITY,
        Severity.HIGH,
        0.9,
    ),
    ActionType.FILE_DELETE: (
        "CAPABILITY.DESTRUCTIVE_FILE_ACTION",
        EvidenceCategory.EXCESSIVE_CAPABILITY,
        Severity.MEDIUM,
        0.8,
    ),
    ActionType.NETWORK_SEND: (
        "CAPABILITY.NETWORK_EGRESS_ACTION",
        EvidenceCategory.EXTERNAL_DATA_TRANSFER,
        Severity.MEDIUM,
        0.7,
    ),
}


class CapabilityDetector:
    """Deterministic sensitive-capability evidence producer."""

    namespace: str = _NAMESPACE
    source: EvidenceSource = EvidenceSource.CAPABILITY_ANALYZER
    primary_category: EvidenceCategory = EvidenceCategory.EXCESSIVE_CAPABILITY

    def analyze(self, event: SecurityEvent) -> tuple[Evidence, ...]:
        action_value = event.action.value
        sensitive_context = (
            event.data_classification in _SENSITIVE_CLASS
            or credential_path_rule(event.resource) is not None
        )

        findings: list[Evidence] = []
        for capability in event.requested_capabilities:
            token = capability.strip().lower()
            for rule in _CAPABILITY_RULES:
                if token not in rule.tokens:
                    continue
                if rule.requires_sensitive_context and not sensitive_context:
                    continue
                findings.append(
                    Evidence(
                        source=self.source,
                        category=rule.category,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        metadata={
                            "rule_id": rule.rule_id,
                            "action": action_value,
                            "capability": capability[:64],
                        },
                    )
                )
                break

        action_entry = _ACTION_RULES.get(event.action)
        if action_entry is not None:
            rule_id, category, severity, confidence = action_entry
            findings.append(
                Evidence(
                    source=self.source,
                    category=category,
                    severity=severity,
                    confidence=confidence,
                    metadata={
                        "rule_id": rule_id,
                        "action": action_value,
                        "signal": f"action={action_value}",
                    },
                )
            )
        return tuple(findings)
