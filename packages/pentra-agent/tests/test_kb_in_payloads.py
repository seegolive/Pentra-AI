from __future__ import annotations
import pytest
from unittest.mock import AsyncMock, patch
from pentra_agent.llm.client import LLMClient


@pytest.fixture
def client():
    return LLMClient(model="test-model", base_url="http://localhost:11434")


@pytest.mark.asyncio
async def test_craft_exploit_payloads_accepts_kb_context(client):
    """kb_context kwarg must be accepted without error."""
    with patch.object(client, "complete_json", new=AsyncMock(return_value=[])):
        result = await client.craft_exploit_payloads(
            url="http://t.com/",
            method="GET",
            param_name="q",
            param_location="query",
            original_value="x",
            test_types=["sqli"],
            tech_stack=["php"],
            kb_context=[
                {"vuln_class": "sqli", "key_insight": "Use SLEEP bypass", "technique": "time-based"}
            ],
        )
    assert isinstance(result, list)


@pytest.mark.asyncio
async def test_craft_exploit_payloads_kb_context_injects_into_prompt(client):
    """KB key_insight must appear in the user prompt when kb_context provided."""
    captured: list[str] = []

    async def capture(system, user):
        captured.append(user)
        return []

    with patch.object(client, "complete_json", new=capture):
        await client.craft_exploit_payloads(
            url="http://t.com/",
            method="GET",
            param_name="id",
            param_location="query",
            original_value="1",
            test_types=["sqli"],
            tech_stack=[],
            kb_context=[
                {"vuln_class": "sqli", "key_insight": "UNIQUE_MARKER_XYZ", "technique": "error-based"}
            ],
        )
    assert captured
    assert "UNIQUE_MARKER_XYZ" in captured[0]


@pytest.mark.asyncio
async def test_craft_exploit_payloads_no_kb_context_no_kb_section(client):
    """When kb_context is None, no KB section should appear in the user prompt."""
    captured: list[str] = []

    async def capture(system, user):
        captured.append(user)
        return []

    with patch.object(client, "complete_json", new=capture):
        await client.craft_exploit_payloads(
            url="http://t.com/",
            method="GET",
            param_name="id",
            param_location="query",
            original_value="1",
            test_types=["sqli"],
            tech_stack=[],
            kb_context=None,
        )
    assert captured
    assert "Historical" not in captured[0]
