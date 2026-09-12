"""Claude Code adapter -- the first reference adapter (Phase 7).

Imports the generic contract from :mod:`contextfence.adapters`; nothing in the
security core or the generic pipeline imports this subpackage. See
:mod:`contextfence.adapters.claude_code.adapter` for the exact, deliberately
narrow scope of this integration.
"""

from __future__ import annotations

from contextfence.adapters.claude_code.adapter import (
    CLAUDE_CODE_ADAPTER_ID,
    ClaudeCodeAdapter,
)

__all__ = ["CLAUDE_CODE_ADAPTER_ID", "ClaudeCodeAdapter"]
