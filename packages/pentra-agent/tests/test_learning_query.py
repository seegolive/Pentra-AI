"""Tests for learning_query utility — Task 21.8."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from pentra_agent.utils.learning_query import (
    format_learnings_for_llm,
    query_similar_learnings_standalone,
)


def test_query_similar_learnings_no_db_url():
    """Without db_url, should return empty list (no crash)."""

    async def _run():
        return await query_similar_learnings_standalone(
            tech_stack=["ASP.NET", "IIS"],
            db_url="",
        )

    result = asyncio.run(_run())
    assert result == []


def test_query_similar_learnings_empty_tech_stack():
    """Empty tech_stack should return empty list."""

    async def _run():
        return await query_similar_learnings_standalone(
            tech_stack=[],
            db_url="postgresql+asyncpg://user:pass@localhost/db",
        )

    result = asyncio.run(_run())
    assert result == []


def test_format_learning_context_empty():
    """Empty learnings → empty string."""
    result = format_learnings_for_llm([])
    assert result == ""


def test_format_learning_context_with_data():
    """Learning context must include tech info, findings count, and tools."""
    learning = {
        "target_pattern": "*.vulnapp.com",
        "findings_count": 8,
        "high_critical_count": 3,
        "effective_tools": [
            {"tool": "nuclei"},
            {"tool": "burp"},
        ],
        "effective_techniques": [
            {"technique": "time-based SQLi"},
        ],
        "high_value_endpoints": [
            {"pattern": "/products?id="},
        ],
    }

    result = format_learnings_for_llm([learning])
    assert "vulnapp.com" in result
    assert "8" in result       # findings_count
    assert "nuclei" in result
    assert "/products?id=" in result


def test_format_learning_context_header():
    """Result must include the 'PRIOR ENGAGEMENT LEARNINGS' header."""
    learning = {
        "target_pattern": "test.com",
        "findings_count": 1,
        "high_critical_count": 0,
        "effective_tools": [],
        "effective_techniques": [],
        "high_value_endpoints": [],
    }
    result = format_learnings_for_llm([learning])
    assert "PRIOR ENGAGEMENT LEARNINGS" in result
