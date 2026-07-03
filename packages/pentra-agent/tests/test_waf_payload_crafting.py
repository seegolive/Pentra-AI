from __future__ import annotations
import pytest
from unittest.mock import AsyncMock, patch

from pentra_agent.llm.client import LLMClient


@pytest.fixture
def client():
    return LLMClient(model="test-model", base_url="http://localhost:11434")


@pytest.mark.asyncio
async def test_craft_exploit_payloads_accepts_waf_info(client):
    """craft_exploit_payloads must accept waf_info kwarg without error."""
    with patch.object(client, "complete_json", new=AsyncMock(return_value=[])):
        result = await client.craft_exploit_payloads(
            url="http://target.com/search",
            method="GET",
            param_name="q",
            param_location="query",
            original_value="test",
            test_types=["sqli"],
            tech_stack=["php"],
            waf_info={"waf_type": "cloudflare", "is_blocking": True,
                      "bypass_strategies": ["case_variation"], "safe_rps": 5},
        )
    assert isinstance(result, list)


@pytest.mark.asyncio
async def test_craft_exploit_payloads_waf_none_unchanged(client):
    """waf_info=None must not change prompt or behaviour."""
    captured: list[str] = []

    async def capture_complete_json(system, user):
        captured.append(system)
        return []

    with patch.object(client, "complete_json", new=capture_complete_json):
        await client.craft_exploit_payloads(
            url="http://target.com/",
            method="GET",
            param_name="id",
            param_location="query",
            original_value="1",
            test_types=["idor"],
            tech_stack=[],
            waf_info=None,
        )
    assert captured, "complete_json must have been called"
    assert "WAF" not in captured[0] or "No WAF" in captured[0]


@pytest.mark.asyncio
async def test_craft_exploit_payloads_waf_cloudflare_injects_bypass_context(client):
    """When waf_type=cloudflare, system prompt must mention cloudflare bypass."""
    captured: list[str] = []

    async def capture_complete_json(system, user):
        captured.append(system)
        return []

    with patch.object(client, "complete_json", new=capture_complete_json):
        await client.craft_exploit_payloads(
            url="http://target.com/",
            method="POST",
            param_name="username",
            param_location="body",
            original_value="admin",
            test_types=["sqli"],
            tech_stack=["php"],
            waf_info={"waf_type": "cloudflare", "is_blocking": True,
                      "bypass_strategies": [], "safe_rps": 10},
        )
    assert captured
    system_lower = captured[0].lower()
    assert "cloudflare" in system_lower


@pytest.mark.asyncio
async def test_craft_exploit_payloads_blocking_waf_adds_evasion_instruction(client):
    """When is_blocking=True, system prompt must include evasion instruction."""
    captured: list[str] = []

    async def capture_complete_json(system, user):
        captured.append(system)
        return []

    with patch.object(client, "complete_json", new=capture_complete_json):
        await client.craft_exploit_payloads(
            url="http://target.com/",
            method="GET",
            param_name="q",
            param_location="query",
            original_value="x",
            test_types=["xss"],
            tech_stack=[],
            waf_info={"waf_type": "akamai", "is_blocking": True,
                      "bypass_strategies": ["unicode_bypass"], "safe_rps": 5},
        )
    assert captured
    # Must include WAF-specific blocking indicator, not just static RULE 3 text
    assert "ACTIVE WAF BLOCKING" in captured[0] or "akamai" in captured[0].lower()
