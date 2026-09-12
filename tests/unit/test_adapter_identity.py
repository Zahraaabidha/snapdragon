"""AdapterId: a validated, controlled identity -- not an open string, not an enum."""

from __future__ import annotations

import pytest

from contextfence.adapters.errors import AdapterInputError
from contextfence.adapters.identity import AdapterId


@pytest.mark.parametrize("value", ["claude_code", "synthetic_agent", "a1", "x_9_z"])
def test_valid_ids_are_accepted(value: str) -> None:
    assert AdapterId(value).value == value
    assert str(AdapterId(value)) == value


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "A",  # uppercase
        "Claude_Code",
        "claude-code",  # hyphen
        "claude.code",  # dot
        "claude code",  # space
        "1claude",  # leading digit
        "x",  # too short (needs >= 2 chars)
        "claude_code!",
        "x" * 65,  # too long
    ],
)
def test_malformed_ids_are_rejected(value: str) -> None:
    with pytest.raises(AdapterInputError):
        AdapterId(value)


@pytest.mark.parametrize("value", [None, 123, True, b"claude_code", ("claude_code",)])
def test_non_string_ids_are_rejected(value: object) -> None:
    with pytest.raises(AdapterInputError):
        AdapterId(value)  # type: ignore[arg-type]


def test_adapter_id_is_frozen() -> None:
    adapter_id = AdapterId("claude_code")
    with pytest.raises(AttributeError):
        adapter_id.value = "other"  # type: ignore[misc]


def test_adapter_id_equality_is_by_value() -> None:
    assert AdapterId("claude_code") == AdapterId("claude_code")
    assert AdapterId("claude_code") != AdapterId("synthetic_agent")
