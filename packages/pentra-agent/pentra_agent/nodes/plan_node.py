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
    """Query KB for context, then LLM-generate a pentest plan."""
    knowledge: list[dict] = []
    try:
        from pentra_knowledge.services.search import hybrid_search
        from app.db.base import _get_session_factory

        async with _get_session_factory()() as db:
            records = await hybrid_search(
                query=f"pentest techniques for {state['target']['domain']}",
                db=db,
                top_k=5,
                min_quality_score=0.4,
            )
        knowledge = [r.model_dump() for r in records]
    except Exception as exc:
        log.warning("[plan_node] KB query failed: %s", exc)

    llm = LLMClient(base_url=_ollama_url(), model=state["llm_model"])
    plan = await llm.plan_engagement(
        target=state["target"],
        scope=state["scope"],
        knowledge_hints=knowledge,
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
