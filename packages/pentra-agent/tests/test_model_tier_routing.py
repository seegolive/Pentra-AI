"""Tests for per-task model tier routing (Sprint 2, Task 2).

Verifies that:
- triage_node uses OLLAMA_MODEL_FAST (fast 7B for binary triage decisions)
- plan_node uses OLLAMA_MODEL_REASONING (deep planning needs best model)
- When env var is unset, both nodes fall back to state["llm_model"]
"""
from __future__ import annotations

import pytest


# ── Shared minimal state factories ───────────────────────────────────────────

def _triage_state(llm_model: str = "user-model:32b") -> dict:
    return {
        "findings": [
            {
                "title": "SQLi",
                "severity": "medium",  # medium skips Stage 2 HTTP re-probe
                "target_url": "http://t.com/",
                "vuln_class": "sqli",
                "evidence": "test evidence",
                "request": "",
                "response": "",
            }
        ],
        "engagement_id": "eng-001",
        "llm_model": llm_model,
        "scope": {"in_scope": ["t.com"], "out_of_scope": []},
    }


def _plan_state(llm_model: str = "user-model:32b") -> dict:
    return {
        "engagement_id": "eng-002",
        "target": {"domain": "example.com", "url": "https://example.com"},
        "scope": {"in_scope": ["example.com"], "out_of_scope": []},
        "llm_model": llm_model,
        "tech_stack": [],
    }


def _make_triage_mock_llm(captured: list) -> type:
    class MockLLMClient:
        def __init__(self, model: str, base_url: str):
            captured.append(model)

        async def complete_json(self, *a, **kw):
            return {
                "verdict": "PASS",
                "final_severity": "medium",
                "reason": "test",
                "chain_suggestion": "",
                "downgrade_reason": "",
            }

    return MockLLMClient


def _make_plan_mock_llm(captured: list) -> type:
    class MockLLMClient:
        def __init__(self, model: str, base_url: str):
            captured.append(model)

        async def plan_engagement(self, *a, **kw) -> str:
            return "Pentest plan: test"

    return MockLLMClient


# ── Test 1: triage_node runtime routing ──────────────────────────────────────

@pytest.mark.asyncio
async def test_triage_node_uses_fast_model_env(monkeypatch):
    """triage_node must instantiate LLMClient with OLLAMA_MODEL_FAST when set."""
    captured: list[str] = []
    monkeypatch.setenv("OLLAMA_MODEL_FAST", "fast-model:7b")
    monkeypatch.setenv("OLLAMA_URL", "http://localhost:11434")
    monkeypatch.setattr(
        "pentra_agent.nodes.triage_node.LLMClient",
        _make_triage_mock_llm(captured),
    )

    from pentra_agent.nodes import triage_node as tn
    await tn.triage_node(_triage_state())

    assert captured, "LLMClient was never instantiated — check triage_node imports"
    assert captured[0] == "fast-model:7b", (
        f"Expected fast-model:7b but got {captured[0]!r} — "
        "triage_node must use OLLAMA_MODEL_FAST, not state['llm_model']"
    )


# ── Test 2: plan_node runtime routing ────────────────────────────────────────

@pytest.mark.asyncio
async def test_plan_node_uses_reasoning_model_env(monkeypatch):
    """plan_node must instantiate LLMClient with OLLAMA_MODEL_REASONING when set."""
    captured: list[str] = []
    monkeypatch.setenv("OLLAMA_MODEL_REASONING", "reasoning-model:32b")
    monkeypatch.setenv("OLLAMA_URL", "http://localhost:11434")
    monkeypatch.setattr(
        "pentra_agent.nodes.plan_node.LLMClient",
        _make_plan_mock_llm(captured),
    )

    from pentra_agent.nodes import plan_node as pn
    await pn.plan_node(_plan_state())

    assert captured, "LLMClient was never instantiated — check plan_node imports"
    assert captured[0] == "reasoning-model:32b", (
        f"Expected reasoning-model:32b but got {captured[0]!r} — "
        "plan_node must use OLLAMA_MODEL_REASONING, not state['llm_model']"
    )


# ── Test 3: unset env fallback ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_triage_node_fallback_when_env_unset(monkeypatch):
    """When OLLAMA_MODEL_FAST is unset, triage_node falls back to state['llm_model']."""
    fallback_model = "user-chosen-model:13b"
    captured: list[str] = []

    monkeypatch.delenv("OLLAMA_MODEL_FAST", raising=False)
    monkeypatch.delenv("OLLAMA_MODEL_REASONING", raising=False)
    monkeypatch.setenv("OLLAMA_URL", "http://localhost:11434")
    monkeypatch.setattr(
        "pentra_agent.nodes.triage_node.LLMClient",
        _make_triage_mock_llm(captured),
    )

    from pentra_agent.nodes import triage_node as tn
    await tn.triage_node(_triage_state(llm_model=fallback_model))

    assert captured, "LLMClient was never instantiated — check triage_node imports"
    assert captured[0] == fallback_model, (
        f"Expected fallback {fallback_model!r} but got {captured[0]!r} — "
        "triage_node must fall back to state['llm_model'] when OLLAMA_MODEL_FAST is unset"
    )


# ── Test 4: plan_node fallback when env unset ─────────────────────────────────

@pytest.mark.asyncio
async def test_plan_node_fallback_when_env_unset(monkeypatch):
    """When OLLAMA_MODEL_REASONING is not set, plan_node falls back to state['llm_model']."""
    fallback_model = "user-chosen-model:13b"
    captured: list[str] = []

    monkeypatch.delenv("OLLAMA_MODEL_REASONING", raising=False)
    monkeypatch.delenv("OLLAMA_MODEL_FAST", raising=False)
    monkeypatch.setenv("OLLAMA_URL", "http://localhost:11434")
    monkeypatch.setattr(
        "pentra_agent.nodes.plan_node.LLMClient",
        _make_plan_mock_llm(captured),
    )

    from pentra_agent.nodes import plan_node as pn
    await pn.plan_node(_plan_state(llm_model=fallback_model))

    assert captured, "LLMClient was never instantiated — check plan_node imports"
    assert captured[0] == fallback_model, (
        f"Expected fallback {fallback_model!r} but got {captured[0]!r} — "
        "plan_node must fall back to state['llm_model'] when OLLAMA_MODEL_REASONING is unset"
    )
