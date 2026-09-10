"""Deterministic local sanitization (Phase 5).

Given a payload string and the located sensitive findings for it, produce a
sanitized **copy** in which supported sensitive spans are replaced by stable
markers. No LLM, no network, no I/O. The caller's original string is never
mutated (Python strings are immutable; this module also never returns it as a
"sanitized" value or leaks it through diagnostics).

Supported categories are **explicit and narrow** (task Part C; SECURITY.md §14):

* only :data:`EvidenceCategory.PERSONAL_DATA` findings whose ``rule_id`` is one
  of :data:`SUPPORTED_RULE_IDS` (``PII.EMAIL`` / ``PII.PHONE_NUMBER`` /
  ``PII.PAYMENT_CARD``) with a valid character span are sanitized;
* a ``CREDENTIAL`` finding (or any ``SECRET.*`` rule id) makes the whole call
  **fail closed** -- a secret is never turned into a "safe" result just because
  a replacement function exists;
* a personal-data finding that cannot be located (e.g.
  ``PII.DECLARED_CLASSIFICATION`` -- a classification signal, not a span) also
  fails closed: a span-replacement copy cannot be certified safe when the
  classification itself asserts the payload is personal data;
* any invalid / out-of-range span fails closed.

Failing closed means ``SanitizationResult.ok is False`` and
``sanitized_text is None``; the enforcement gate then blocks.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from contextfence.analysis.redaction import character_classes, fingerprint
from contextfence.core.models.enums import EvidenceCategory
from contextfence.core.models.evidence import Evidence

__all__ = [
    "SUPPORTED_RULE_IDS",
    "SanitizationResult",
    "SanitizationSummary",
    "SanitizeFinding",
    "SanitizedSpan",
    "findings_from_evidence",
    "sanitize_text",
]

SUPPORTED_RULE_IDS: frozenset[str] = frozenset(
    {"PII.EMAIL", "PII.PHONE_NUMBER", "PII.PAYMENT_CARD"}
)
_SANITIZABLE_CATEGORIES: frozenset[EvidenceCategory] = frozenset(
    {EvidenceCategory.PERSONAL_DATA}
)
#: findings in these categories are never sanitized -- the call fails closed
_HARD_BLOCK_CATEGORIES: frozenset[EvidenceCategory] = frozenset(
    {EvidenceCategory.CREDENTIAL}
)
_SECRET_RULE_PREFIX = "SECRET."
_NON_LOCATABLE = -1


@dataclass(frozen=True, slots=True)
class SanitizeFinding:
    """A sensitive span to sanitize, distilled from an :class:`Evidence` item.

    ``start`` is :data:`_NON_LOCATABLE` (``-1``) when the source evidence carried
    no character span (a classification-level signal).
    """

    rule_id: str
    category: EvidenceCategory
    start: int
    length: int

    @property
    def locatable(self) -> bool:
        return self.start != _NON_LOCATABLE


@dataclass(frozen=True, slots=True)
class SanitizedSpan:
    """Structural record of one replaced span. Holds no original substring."""

    rule_ids: tuple[str, ...]
    start: int
    length: int
    marker: str
    original_length: int
    original_charset: str
    original_fingerprint: str


@dataclass(frozen=True, slots=True)
class SanitizationSummary:
    """What sanitization did, in structural terms only (no values)."""

    total_findings: int
    sanitized_span_count: int
    applied: tuple[SanitizedSpan, ...] = field(default_factory=tuple)
    skipped_reasons: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class SanitizationResult:
    """Outcome of :func:`sanitize_text`. ``ok is False`` means fail closed."""

    ok: bool
    sanitized_text: str | None
    summary: SanitizationSummary
    failure_reason: str = ""


def _fail(
    reason: str, *, total: int, skipped: tuple[str, ...] = ()
) -> SanitizationResult:
    return SanitizationResult(
        ok=False,
        sanitized_text=None,
        summary=SanitizationSummary(
            total_findings=total,
            sanitized_span_count=0,
            applied=(),
            skipped_reasons=skipped,
        ),
        failure_reason=reason,
    )


def findings_from_evidence(evidence: Sequence[Evidence]) -> tuple[SanitizeFinding, ...]:
    """Extract sanitizable/blocking findings from evidence.

    Only ``PERSONAL_DATA`` and ``CREDENTIAL`` evidence produce findings; other
    categories are irrelevant to sanitization and are ignored. Span offsets are
    read from the Phase 2 metadata keys ``match_offset`` / ``match_length``;
    evidence without them yields a non-locatable finding.
    """

    out: list[SanitizeFinding] = []
    for item in evidence:
        if item.category not in _SANITIZABLE_CATEGORIES | _HARD_BLOCK_CATEGORIES:
            continue
        rule_id = item.metadata.get("rule_id", "")
        start, length = _read_span(item)
        out.append(
            SanitizeFinding(
                rule_id=rule_id,
                category=item.category,
                start=start,
                length=length,
            )
        )
    return tuple(out)


def _read_span(item: Evidence) -> tuple[int, int]:
    raw_offset = item.metadata.get("match_offset")
    raw_length = item.metadata.get("match_length")
    if raw_offset is None or raw_length is None:
        return _NON_LOCATABLE, 0
    try:
        return int(raw_offset), int(raw_length)
    except (TypeError, ValueError):
        # a present-but-unparseable span is treated as non-locatable, which
        # forces a fail-closed downstream rather than a silent skip.
        return _NON_LOCATABLE, 0


def sanitize_text(text: str, findings: Sequence[SanitizeFinding]) -> SanitizationResult:
    """Return a sanitized copy of ``text`` or fail closed. Deterministic."""

    if not isinstance(text, str):
        return _fail("payload to sanitize must be a string", total=len(findings))

    total = len(findings)

    for finding in findings:
        if finding.category in _HARD_BLOCK_CATEGORIES or finding.rule_id.startswith(
            _SECRET_RULE_PREFIX
        ):
            return _fail(
                "credential/secret findings are not sanitizable; blocking",
                total=total,
            )

    supported: list[SanitizeFinding] = []
    skipped: list[str] = []
    for finding in findings:
        if not finding.locatable:
            return _fail(
                "a personal-data signal without a locatable span cannot be "
                "span-sanitized; blocking",
                total=total,
            )
        if (
            finding.category not in _SANITIZABLE_CATEGORIES
            or finding.rule_id not in SUPPORTED_RULE_IDS
        ):
            unsupported_id = finding.rule_id or "<no rule id>"
            return _fail(
                f"unsupported sanitization finding: {unsupported_id}",
                total=total,
            )
        if not _span_ok(finding, len(text)):
            return _fail(
                "a finding had an invalid or out-of-range span; blocking",
                total=total,
            )
        supported.append(finding)

    if not supported:
        return _fail(
            "SANITIZE requires at least one locatable finding to establish "
            "that the payload can be made safe",
            total=total,
            skipped=tuple(skipped),
        )

    merged = _merge(text, supported)
    sanitized = _apply(text, merged)
    return SanitizationResult(
        ok=True,
        sanitized_text=sanitized,
        summary=SanitizationSummary(
            total_findings=total,
            sanitized_span_count=len(merged),
            applied=merged,
            skipped_reasons=tuple(skipped),
        ),
    )


def _span_ok(finding: SanitizeFinding, text_len: int) -> bool:
    return (
        isinstance(finding.start, int)
        and isinstance(finding.length, int)
        and finding.start >= 0
        and finding.length > 0
        and finding.start + finding.length <= text_len
    )


def _merge(text: str, findings: Sequence[SanitizeFinding]) -> tuple[SanitizedSpan, ...]:
    """Merge overlapping/adjacent spans into disjoint sanitized spans."""

    ordered = sorted(findings, key=lambda f: (f.start, f.start + f.length))
    groups: list[list[SanitizeFinding]] = []
    for finding in ordered:
        end = finding.start + finding.length
        if groups and finding.start < _group_end(groups[-1]):
            groups[-1].append(finding)
        else:
            groups.append([finding])
    spans: list[SanitizedSpan] = []
    for group in groups:
        start = min(f.start for f in group)
        end = max(f.start + f.length for f in group)
        rule_ids = tuple(sorted({f.rule_id for f in group}))
        original = text[start:end]
        spans.append(
            SanitizedSpan(
                rule_ids=rule_ids,
                start=start,
                length=end - start,
                marker="[REDACTED:" + "+".join(rule_ids) + "]",
                original_length=len(original),
                original_charset=character_classes(original),
                original_fingerprint=fingerprint(original),
            )
        )
    return tuple(spans)


def _group_end(group: Sequence[SanitizeFinding]) -> int:
    return max(f.start + f.length for f in group)


def _apply(text: str, spans: Sequence[SanitizedSpan]) -> str:
    parts: list[str] = []
    cursor = 0
    for span in spans:
        parts.append(text[cursor : span.start])
        parts.append(span.marker)
        cursor = span.start + span.length
    parts.append(text[cursor:])
    return "".join(parts)
