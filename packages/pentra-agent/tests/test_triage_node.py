"""Tests for Triage Gate Node — Sprint 16 Task 16.1"""

import pytest
from unittest.mock import AsyncMock, patch


def _make_state(findings: list[dict]) -> dict:
    return {
        "engagement_id": "test-engagement-id",
        "target": {"domain": "target.com"},
        "scope": {"in_scope": ["target.com"], "out_of_scope": []},
        "mode": "semi_auto",
        "llm_model": "qwen2.5:32b",
        "findings": findings,
    }


def _sqli_finding(severity: str = "high") -> dict:
    return {
        "title": "SQL Injection on /api/search",
        "vuln_class": "SQLi",
        "severity": severity,
        "target_url": "https://target.com/api/search?q=1",
        "description": "Error-based SQL injection confirmed via `'` payload.",
        "request_raw": "GET /api/search?q=' HTTP/1.1\nHost: target.com",
        "response_raw": "You have an error in your SQL syntax...",
    }


def _theoretical_finding() -> dict:
    return {
        "title": "Possible SSRF via redirect parameter",
        "vuln_class": "SSRF",
        "severity": "high",
        "target_url": "https://target.com/redirect?url=http://evil.com",
        "description": "The redirect parameter might allow SSRF but no DNS pingback confirmed.",
        "request_raw": "",
        "response_raw": "",
    }


def _overstated_finding() -> dict:
    return {
        "title": "Missing X-Content-Type-Options header",
        "vuln_class": "Misconfiguration",
        "severity": "high",
        "target_url": "https://target.com/",
        "description": "Server does not set X-Content-Type-Options header.",
        "request_raw": "GET / HTTP/1.1",
        "response_raw": "HTTP/1.1 200 OK",
    }


@pytest.mark.asyncio
async def test_triage_pass_verdict_keeps_finding():
    """PASS verdict: finding dengan evidence kuat harus ada di triaged_findings."""
    mock_llm = AsyncMock()
    mock_llm.complete_json = AsyncMock(return_value={
        "verdict": "PASS",
        "final_severity": "high",
        "reason": "Confirmed SQL injection with server error response as evidence.",
        "chain_suggestion": "",
        "downgrade_reason": "",
    })

    with patch("pentra_agent.nodes.triage_node.LLMClient", return_value=mock_llm):
        from pentra_agent.nodes.triage_node import triage_node

        state = _make_state([_sqli_finding()])
        result = await triage_node(state)  # type: ignore[arg-type]

    assert "triaged_findings" in result
    assert len(result["triaged_findings"]) == 1
    assert result["triaged_findings"][0]["triage_verdict"] == "PASS"
    assert result["triaged_findings"][0]["title"] == "SQL Injection on /api/search"
    # Summary message — Two-stage triage
    assert "Two-stage triage done" in result["messages"][0].content


@pytest.mark.asyncio
async def test_triage_kill_verdict_drops_finding():
    """KILL verdict: theoretical-only finding harus di-drop dari triaged_findings."""
    mock_llm = AsyncMock()
    mock_llm.complete_json = AsyncMock(return_value={
        "verdict": "KILL",
        "final_severity": "high",
        "reason": "No DNS pingback or response difference — theoretical only.",
        "chain_suggestion": "",
        "downgrade_reason": "",
    })

    with patch("pentra_agent.nodes.triage_node.LLMClient", return_value=mock_llm):
        from pentra_agent.nodes.triage_node import triage_node

        state = _make_state([_theoretical_finding()])
        result = await triage_node(state)  # type: ignore[arg-type]

    assert "triaged_findings" in result
    assert len(result["triaged_findings"]) == 0
    assert "Two-stage triage done" in result["messages"][0].content


@pytest.mark.asyncio
async def test_triage_downgrade_verdict_lowers_severity():
    """DOWNGRADE verdict: severity harus diturunkan sesuai final_severity dari LLM."""
    mock_llm = AsyncMock()
    mock_llm.complete_json = AsyncMock(return_value={
        "verdict": "DOWNGRADE",
        "final_severity": "info",
        "reason": "Missing header is best-practice, not exploitable impact.",
        "chain_suggestion": "",
        "downgrade_reason": "Header absence alone has no direct exploitable impact.",
    })

    with patch("pentra_agent.nodes.triage_node.LLMClient", return_value=mock_llm):
        from pentra_agent.nodes.triage_node import triage_node

        state = _make_state([_overstated_finding()])
        result = await triage_node(state)  # type: ignore[arg-type]

    assert "triaged_findings" in result
    assert len(result["triaged_findings"]) == 1
    triaged = result["triaged_findings"][0]
    assert triaged["triage_verdict"] == "DOWNGRADE"
    assert triaged["severity"] == "info"      # was "high" → downgraded
    assert "Two-stage triage done" in result["messages"][0].content
