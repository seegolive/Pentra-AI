"""tests/test_graph.py — Graph routing, HITL behaviour, and LLMClient unit tests.

Tests (8 total):
  1.  route_after_recon → vuln_hunt on approve
  2.  route_after_recon → report on skip
  3.  route_after_vuln_hunt → hitl_exploit when high/critical findings present
  4.  route_after_vuln_hunt → report when only medium/low findings
  5.  route_after_vuln_hunt → report when no findings
  6.  hitl_plan_review auto-approves in agentic mode
  7.  hitl_exploit_review interrupts by default
  8.  hitl_exploit_review can auto-approve when explicitly configured
  9.  LLMClient.complete_json strips markdown fences
  10. LLMClient.complete_json handles raw JSON without fences
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from pentra_agent.graph.builder import route_after_recon, route_after_vuln_hunt
from pentra_agent.graph.state import PentraState
from pentra_agent.llm.client import LLMClient


# ── Helpers ───────────────────────────────────────────────────────────────────

def _base_state(**overrides) -> PentraState:
    """Minimal valid PentraState dict for testing."""
    base: dict = {
        "engagement_id": "test-engagement-001",
        "target": {"domain": "example.com", "ip_ranges": [], "base_urls": []},
        "scope": {"in_scope": ["example.com"], "out_of_scope": []},
        "mode": "semi_auto",
        "llm_model": "qwen2.5-coder:7b",
        "opsec_mode": False,
        "request_jitter_ms": 0,
        "scan_sequential": False,
        "auto_approve_exploit_validation": False,
        "current_phase": "planning",
        "phase_history": [],
        "subdomains": [],
        "open_ports": [],
        "tech_stack": [],
        "endpoints": [],
        "findings": [],
        "pentest_plan": "",
        "current_hypothesis": "",
        "knowledge_context": [],
        "awaiting_approval": False,
        "pending_action": None,
        "user_decision": None,
        "messages": [],
        "tool_outputs": [],
        "errors": [],
    }
    base.update(overrides)
    return base  # type: ignore[return-value]


# ── 1. route_after_recon → vuln_hunt ─────────────────────────────────────────

def test_route_after_recon_goes_to_vuln_hunt_on_approve():
    state = _base_state(user_decision="approve")
    assert route_after_recon(state) == "vuln_hunt"


# ── 2. route_after_recon → report on skip ────────────────────────────────────

def test_route_after_recon_goes_to_report_on_skip():
    state = _base_state(user_decision="skip")
    assert route_after_recon(state) == "report"


# ── 3. route_after_vuln_hunt → hitl_exploit on high findings ─────────────────

def test_route_after_vuln_hunt_goes_to_hitl_exploit_when_high_findings():
    findings = [
        {"title": "SQL Injection", "severity": "high", "target_url": "https://example.com/api"},
        {"title": "Reflected XSS", "severity": "medium", "target_url": "https://example.com/search"},
    ]
    state = _base_state(findings=findings)
    assert route_after_vuln_hunt(state) == "hitl_exploit"


# ── 4. route_after_vuln_hunt → report when only medium/low ───────────────────

def test_route_after_vuln_hunt_goes_to_report_when_no_high_findings():
    findings = [
        {"title": "Missing Security Headers", "severity": "low", "target_url": "https://example.com"},
        {"title": "Clickjacking", "severity": "medium", "target_url": "https://example.com"},
    ]
    state = _base_state(findings=findings)
    assert route_after_vuln_hunt(state) == "report"


# ── 5. route_after_vuln_hunt → report when no findings ───────────────────────

def test_route_after_vuln_hunt_goes_to_report_when_no_findings():
    state = _base_state(findings=[])
    assert route_after_vuln_hunt(state) == "report"


# ── 6. hitl_plan_review auto-approves in agentic mode ────────────────────────

@pytest.mark.asyncio
async def test_hitl_plan_review_auto_approves_in_agentic_mode():
    from pentra_agent.nodes.hitl_nodes import hitl_plan_review

    state = _base_state(
        mode="agentic",
        pentest_plan="1. Enumerate subdomains\n2. Scan open ports",
    )

    with patch("pentra_agent.nodes.hitl_nodes.write_audit_log", new_callable=AsyncMock) as mock_audit:
        result = await hitl_plan_review(state)

    assert result["user_decision"] == "approve"
    assert result["awaiting_approval"] is False
    mock_audit.assert_awaited_once()
    call_kwargs = mock_audit.call_args
    assert call_kwargs.kwargs.get("action") == "auto_approved_plan" or \
           call_kwargs.args[2] == "auto_approved_plan"


# ── 7. hitl_exploit_review interrupts by default ─────────────────────────────

@pytest.mark.asyncio
async def test_hitl_exploit_interrupts_by_default():
    """hitl_exploit_review must call interrupt() unless explicitly bypassed."""
    from pentra_agent.nodes.hitl_nodes import hitl_exploit_review

    findings = [
        {"title": "RCE via File Upload", "severity": "critical", "target_url": "https://example.com/upload"},
    ]

    for mode in ("semi_auto", "agentic"):
        state = _base_state(mode=mode, findings=findings)

        interrupt_payload: dict = {}

        def capture_interrupt(payload):
            interrupt_payload.update(payload)
            # Simulate LangGraph interrupt() raising GraphInterrupt — we just capture the payload
            raise _FakeInterrupt(payload)

        with patch("pentra_agent.nodes.hitl_nodes.interrupt", side_effect=capture_interrupt):
            with pytest.raises(_FakeInterrupt):
                await hitl_exploit_review(state)

        assert interrupt_payload.get("type") == "AWAITING_APPROVAL"
        assert interrupt_payload.get("phase") == "exploit_validation"
        assert interrupt_payload.get("engagement_id") == "test-engagement-001"


# ── 8. hitl_exploit_review can auto-approve when configured ─────────────────

@pytest.mark.asyncio
async def test_hitl_exploit_auto_approves_when_explicitly_configured():
    from pentra_agent.nodes.hitl_nodes import hitl_exploit_review

    state = _base_state(
        auto_approve_exploit_validation=True,
        findings=[
            {"title": "RCE via File Upload", "severity": "critical", "target_url": "https://example.com/upload"},
        ],
    )

    with patch("pentra_agent.nodes.hitl_nodes.interrupt") as mock_interrupt:
        with patch("pentra_agent.nodes.hitl_nodes.write_audit_log", new_callable=AsyncMock) as mock_audit:
            result = await hitl_exploit_review(state)

    assert result["user_decision"] == "approve"
    assert result["awaiting_approval"] is False
    mock_interrupt.assert_not_called()
    mock_audit.assert_awaited_once()
    call_kwargs = mock_audit.call_args
    assert call_kwargs.kwargs.get("action") == "auto_approved_exploit_validation" or \
           call_kwargs.args[2] == "auto_approved_exploit_validation"


class _FakeInterrupt(Exception):
    def __init__(self, payload):
        self.payload = payload
        super().__init__(str(payload))


# ── 9. LLMClient.complete_json strips markdown fences ────────────────────────

@pytest.mark.asyncio
async def test_llm_client_complete_json_strips_markdown_fences():
    """complete_json should strip ```json ... ``` fences before parsing."""
    client = LLMClient(base_url="http://localhost:11434/v1", model="test-model")

    fenced_response = '```json\n{"vuln_class": "XSS", "severity": "high"}\n```'

    with patch.object(client, "complete", new_callable=AsyncMock, return_value=fenced_response):
        result = await client.complete_json(system="sys", user="usr")

    assert isinstance(result, dict)
    assert result["vuln_class"] == "XSS"
    assert result["severity"] == "high"


# ── 10. LLMClient.complete_json handles raw JSON without fences ──────────────

@pytest.mark.asyncio
async def test_llm_client_complete_json_handles_raw_json():
    """complete_json should parse raw JSON that has no markdown fences."""
    client = LLMClient(base_url="http://localhost:11434/v1", model="test-model")

    raw_json = '{"hypotheses": ["IDOR", "SSRF"], "summary": "attack surface discovered"}'

    with patch.object(client, "complete", new_callable=AsyncMock, return_value=raw_json):
        result = await client.complete_json(system="sys", user="usr")

    assert isinstance(result, dict)
    assert "IDOR" in result["hypotheses"]
    assert result["summary"] == "attack surface discovered"
