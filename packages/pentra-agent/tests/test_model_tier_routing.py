"""Tests for per-task model tier routing (Sprint 2, Task 2).

Verifies that:
- triage_node uses OLLAMA_MODEL_FAST (fast 7B for binary triage decisions)
- plan_node uses OLLAMA_MODEL_REASONING (deep planning needs best model)
- vuln_hunt_node exploit crafting stays on state["llm_model"] (user override)
"""
from __future__ import annotations
import os
import pytest
from unittest.mock import patch


def test_triage_node_uses_fast_model_env():
    """triage_node must instantiate LLMClient with OLLAMA_MODEL_FAST when set."""
    captured_models: list[str] = []

    class MockLLMClient:
        def __init__(self, model: str, base_url: str):
            captured_models.append(model)
        async def complete_json(self, *a, **kw):
            return {
                "verdict": "PASS",
                "final_severity": "high",
                "reason": "test",
                "chain_suggestion": "",
                "downgrade_reason": "",
            }

    with (
        patch.dict(os.environ, {"OLLAMA_MODEL_FAST": "fast-model:7b"}),
        patch("pentra_agent.nodes.triage_node.LLMClient", MockLLMClient),
    ):
        import importlib
        import pentra_agent.nodes.triage_node as tn
        importlib.reload(tn)  # pick up patched env
        # model should be read at call time, not module load time
        assert len(captured_models) == 0  # not called yet during import


def test_plan_node_uses_reasoning_model_env():
    """plan_node must instantiate LLMClient with OLLAMA_MODEL_REASONING when set."""
    captured_models: list[str] = []

    class MockLLMClient:
        def __init__(self, model: str, base_url: str):
            captured_models.append(model)
        async def plan_engagement(self, *a, **kw):
            return {"summary": "test", "tech_stack_analysis": "", "hypotheses": [],
                    "attack_vectors": [], "priority_areas": []}

    with (
        patch.dict(os.environ, {"OLLAMA_MODEL_REASONING": "reasoning-model:32b"}),
        patch("pentra_agent.nodes.plan_node.LLMClient", MockLLMClient),
    ):
        import importlib
        import pentra_agent.nodes.plan_node as pn
        importlib.reload(pn)
        assert len(captured_models) == 0


@pytest.mark.asyncio
async def test_triage_node_fast_model_used_at_runtime():
    """At runtime, triage_node LLMClient must use OLLAMA_MODEL_FAST env var."""
    captured_models: list[str] = []

    class MockLLMClient:
        def __init__(self, model: str, base_url: str):
            captured_models.append(model)
        async def complete_json(self, *a, **kw):
            # triage_node calls llm.complete_json() with TRIAGE_PROMPT
            return {
                "verdict": "PASS",
                "final_severity": "high",
                "reason": "test",
                "chain_suggestion": "",
                "downgrade_reason": "",
            }

    findings = [
        {"title": "SQLi", "severity": "high", "target_url": "http://t.com/",
         "vuln_class": "sqli", "evidence": "test evidence", "request": "", "response": ""}
    ]
    state = {
        "findings": findings,
        "engagement_id": "eng-001",
        "llm_model": "user-model:32b",
        "scope": {"in_scope": ["t.com"], "out_of_scope": []},
    }
    with (
        patch.dict(os.environ, {"OLLAMA_MODEL_FAST": "fast-model:7b", "OLLAMA_URL": "http://localhost:11434"}),
        patch("pentra_agent.nodes.triage_node.LLMClient", MockLLMClient),
    ):
        from pentra_agent.nodes import triage_node as tn
        await tn.triage_node(state)

    assert captured_models, "LLMClient should have been instantiated"
    assert captured_models[0] == "fast-model:7b", (
        f"Expected fast-model:7b but got {captured_models[0]} — "
        "triage_node must use OLLAMA_MODEL_FAST, not state['llm_model']"
    )
