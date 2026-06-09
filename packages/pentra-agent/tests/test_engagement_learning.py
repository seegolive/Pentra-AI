"""Tests for Task 20.6 — EngagementLearning di plan_node."""

from __future__ import annotations

import pytest

from pentra_agent.utils.learning_query import format_learnings_for_llm


def test_format_learnings_empty_returns_empty():
    """No learnings → empty string."""
    assert format_learnings_for_llm([]) == ""
    assert format_learnings_for_llm(None) == ""  # type: ignore[arg-type]


def test_format_learnings_formats_correctly():
    """format_learnings_for_llm should produce a readable LLM block."""
    learnings = [
        {
            "target_pattern": "ASP.NET + IIS + MSSQL",
            "effective_tools": [{"tool": "burp_mcp"}, {"tool": "nuclei"}],
            "effective_techniques": [{"technique": "WAITFOR DELAY time-based SQLi"}],
            "high_value_endpoints": [{"pattern": "/listproducts.aspx?cat="}, {"pattern": "/comment.aspx?id="}],
            "findings_count": 8,
            "high_critical_count": 5,
        }
    ]
    result = format_learnings_for_llm(learnings)
    assert "PRIOR ENGAGEMENT LEARNINGS" in result
    assert "ASP.NET" in result
    assert "findings_count" not in result  # Should be human-readable, not raw
    assert "8" in result   # findings count
    assert "burp_mcp" in result


def test_format_learnings_handles_missing_fields():
    """format_learnings_for_llm should not crash on partial data."""
    learnings = [
        {"findings_count": 3, "high_critical_count": 1},  # missing most fields
    ]
    result = format_learnings_for_llm(learnings)
    assert "PRIOR ENGAGEMENT LEARNINGS" in result
    assert "3" in result


def test_format_learnings_caps_at_3():
    """Should show at most 3 learnings."""
    learnings = [
        {"target_pattern": f"target-{i}", "findings_count": i, "high_critical_count": 0}
        for i in range(6)
    ]
    result = format_learnings_for_llm(learnings)
    # Should only include items 0-2 (first 3)
    assert "target-0" in result
    assert "target-2" in result
    assert "target-3" not in result  # capped at 3


@pytest.mark.asyncio
async def test_query_similar_learnings_returns_empty_without_db():
    """Should return empty list gracefully when DB not available."""
    from pentra_agent.utils.learning_query import query_similar_learnings_standalone

    result = await query_similar_learnings_standalone(
        tech_stack=["iis", "aspnet"],
        db_url="",  # empty URL — should return [] without crashing
    )
    assert result == []


@pytest.mark.asyncio
async def test_query_similar_learnings_empty_tech_stack():
    """Should return empty list when tech_stack is empty."""
    from pentra_agent.utils.learning_query import query_similar_learnings_standalone

    result = await query_similar_learnings_standalone(
        tech_stack=[],
        db_url="postgresql+asyncpg://x:x@localhost/x",
    )
    assert result == []
