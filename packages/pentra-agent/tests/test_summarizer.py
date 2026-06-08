"""Tests for Chain Summarizer — Task 15.4"""

import pytest
from unittest.mock import AsyncMock, MagicMock

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from pentra_agent.llm.summarizer import (
    SUMMARIZE_THRESHOLD,
    KEEP_RECENT,
    maybe_summarize,
)


@pytest.mark.asyncio
async def test_summarizer_not_triggered_below_threshold():
    """maybe_summarize harus return original tanpa LLM call jika < SUMMARIZE_THRESHOLD."""
    messages = [AIMessage(content=f"msg {i}") for i in range(SUMMARIZE_THRESHOLD - 5)]
    mock_llm = MagicMock()
    mock_llm.complete = AsyncMock()

    result = await maybe_summarize(messages, mock_llm)

    assert result == messages
    mock_llm.complete.assert_not_called()


@pytest.mark.asyncio
async def test_summarizer_compresses_to_summary_plus_recent():
    """Jika > threshold, hasil harus [SystemMessage(summary)] + KEEP_RECENT pesan terakhir."""
    total = SUMMARIZE_THRESHOLD + 10
    messages = [AIMessage(content=f"msg {i}") for i in range(total)]

    mock_llm = MagicMock()
    mock_llm.complete = AsyncMock(
        return_value=(
            "## Confirmed Findings\n- SQL Injection at /products\n\n"
            "## Current State\n- Recon complete, vuln_hunt in progress"
        )
    )

    result = await maybe_summarize(messages, mock_llm)

    # Should have exactly 1 SystemMessage (the summary) + KEEP_RECENT recent messages
    assert len(result) == 1 + KEEP_RECENT
    assert isinstance(result[0], SystemMessage)
    assert "COMPRESSED SESSION HISTORY" in result[0].content
    # The KEEP_RECENT most recent messages must be preserved verbatim
    assert result[1:] == messages[-KEEP_RECENT:]
    mock_llm.complete.assert_called_once()
