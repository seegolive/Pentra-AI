"""Plan node — LLM creates a pentest plan from target + scope + KB context.

First node in the graph. Queries knowledge base for similar findings, then
asks the LLM to produce a structured engagement plan.
"""

from __future__ import annotations

import logging
import os

from langchain_core.messages import AIMessage

from pentra_agent.graph.state import PentraState
from pentra_agent.llm.client import LLMClient

log = logging.getLogger(__name__)


async def plan_node(state: PentraState) -> dict:
    """Query KB for context, query past learnings, then LLM-generate a pentest plan."""
    knowledge: list[dict] = []
    learnings: list[dict] = []

    try:
        from pentra_knowledge.services.search import hybrid_search
        from app.db.base import _get_session_factory
        from app.services.learning import query_similar_learnings

        async with _get_session_factory()() as db:
            records = await hybrid_search(
                query=f"pentest techniques for {state['target']['domain']}",
                db=db,
                top_k=5,
                min_quality_score=0.0,
            )
            prior = await query_similar_learnings(
                tech_stack=state.get("tech_stack", []),
                db=db,
                limit=3,
            )

        knowledge = [r.model_dump() for r in records]
        learnings = [
            {
                "target_pattern": p.target_pattern,
                "effective_tools": p.effective_tools,
                "effective_techniques": p.effective_techniques,
                "high_value_endpoints": p.high_value_endpoints,
                "findings_count": p.findings_count,
                "high_critical_count": p.high_critical_count,
            }
            for p in prior
        ]
        if learnings:
            log.info("[plan_node] Loaded %d prior learnings for engagement %s", len(learnings), state["engagement_id"])
    except Exception as exc:
        log.warning("[plan_node] KB / learnings query failed: %s", exc)

    llm = LLMClient(base_url=_ollama_url(), model=state["llm_model"])
    plan = await llm.plan_engagement(
        target=state["target"],
        scope=state["scope"],
        knowledge_hints=knowledge,
        prior_learnings=learnings,
    )

    log.info("[plan_node] Plan generated for engagement %s", state["engagement_id"])

    return {
        "pentest_plan": plan,
        "current_phase": "planning",
        "phase_history": ["planning"],
        "knowledge_context": knowledge,
        "messages": [AIMessage(content=f"**Pentest Plan**\n\n{plan}")],
    }


def _ollama_url() -> str:
    return os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/") + "/v1"
