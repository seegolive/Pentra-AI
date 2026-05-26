"""Agent execution Celery tasks.

Bridge between the FastAPI engagement API and the LangGraph agent.
When an engagement is started the API enqueues ``run_engagement``; the
agent graph runs in the worker and publishes events to Redis so the
WebSocket endpoint can forward them to the browser.

Tasks:
  tasks.agent.run_engagement    — start a new engagement
  tasks.agent.resume_engagement — resume after HITL approval
"""

from __future__ import annotations

import asyncio
import json
import logging
import os

from celery import shared_task
from celery.utils.log import get_task_logger

from app.core.config import settings

log: logging.Logger = get_task_logger(__name__)


# ── Celery Tasks ───────────────────────────────────────────────────────────────


@shared_task(
    bind=True,
    name="tasks.agent.run_engagement",
    max_retries=0,          # stateful engagement — do not retry automatically
    acks_late=True,
    queue="agent",
)
def run_engagement(self, engagement_id: str) -> None:
    """Celery entry point: start the full agent graph for an engagement."""
    asyncio.run(_run_async(engagement_id))


@shared_task(
    bind=True,
    name="tasks.agent.resume_engagement",
    max_retries=0,
    acks_late=True,
    queue="agent",
)
def resume_engagement(self, engagement_id: str, user_decision: str) -> None:
    """Celery entry point: resume a paused engagement after HITL decision.

    ``user_decision`` is one of ``"approve"``, ``"skip"``, ``"modify"``.
    """
    asyncio.run(_resume_async(engagement_id, user_decision))


# ── Async implementations ──────────────────────────────────────────────────────


async def _run_async(engagement_id: str) -> None:
    """Run the engagement graph and publish events to Redis."""
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy import select

    engine = create_async_engine(settings.database_url, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # ── 1. Load engagement row ─────────────────────────────────────────────
    async with async_session() as session:
        from app.db.models import EngagementORM  # type: ignore[attr-defined]

        result = await session.execute(
            select(EngagementORM).where(EngagementORM.id == engagement_id)
        )
        engagement = result.scalar_one_or_none()

        if engagement is None:
            log.error("[run_engagement] Engagement %s not found — aborting", engagement_id)
            await engine.dispose()
            return

        # ── 2. Mark engagement as active ──────────────────────────────────
        engagement.status = "active"
        await session.commit()

    await engine.dispose()

    # ── 3. Build initial PentraState ──────────────────────────────────────
    initial_state = _build_initial_state(engagement)

    # ── 4. Publish ENGAGEMENT_STARTED event ───────────────────────────────
    _publish_event(engagement_id, {"type": "ENGAGEMENT_STARTED", "engagement_id": engagement_id})

    # ── 5. Run the graph — stream events to Redis ──────────────────────────
    db_url = settings.database_url.replace("postgresql+asyncpg://", "postgresql://")

    try:
        from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
        from pentra_agent.graph.builder import build_pentra_graph
        from pentra_agent.service import AgentService

        async with await AsyncPostgresSaver.from_conn_string(db_url) as checkpointer:
            await checkpointer.setup()
            graph = build_pentra_graph(checkpointer=checkpointer)
            service = AgentService(graph=graph)

            log.info("[run_engagement] Starting engagement %s", engagement_id)
            async for event in service.stream_events_during_start(engagement_id, initial_state):
                _publish_event(engagement_id, event)

            log.info("[run_engagement] Engagement %s finished / waiting for HITL", engagement_id)

    except Exception as exc:
        log.exception("[run_engagement] Error in engagement %s: %s", engagement_id, exc)
        _publish_event(engagement_id, {"type": "AGENT_ERROR", "error": str(exc)})

        # Mark engagement as failed
        engine2 = create_async_engine(settings.database_url, echo=False)
        async_session2 = sessionmaker(engine2, class_=AsyncSession, expire_on_commit=False)
        async with async_session2() as session:
            from app.db.models import EngagementORM  # type: ignore[attr-defined]
            result = await session.execute(
                select(EngagementORM).where(EngagementORM.id == engagement_id)
            )
            eng = result.scalar_one_or_none()
            if eng:
                eng.status = "failed"
                await session.commit()
        await engine2.dispose()
        raise


async def _resume_async(engagement_id: str, user_decision: str) -> None:
    """Resume an engagement after HITL approval."""
    db_url = settings.database_url.replace("postgresql+asyncpg://", "postgresql://")

    _publish_event(engagement_id, {
        "type": "AGENT_RESUMED",
        "engagement_id": engagement_id,
        "decision": user_decision,
    })

    try:
        from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
        from pentra_agent.graph.builder import build_pentra_graph
        from pentra_agent.service import AgentService

        async with await AsyncPostgresSaver.from_conn_string(db_url) as checkpointer:
            await checkpointer.setup()
            graph = build_pentra_graph(checkpointer=checkpointer)
            service = AgentService(graph=graph)

            log.info("[resume_engagement] Resuming %s with decision=%s", engagement_id, user_decision)
            await service.resume(engagement_id, user_decision)

    except Exception as exc:
        log.exception("[resume_engagement] Error resuming %s: %s", engagement_id, exc)
        _publish_event(engagement_id, {"type": "AGENT_ERROR", "error": str(exc)})
        raise


# ── Helpers ────────────────────────────────────────────────────────────────────


def _publish_event(engagement_id: str, event: dict) -> None:
    """Publish an event to Redis pub/sub for the engagement's WebSocket channel."""
    import redis

    redis_url = os.getenv("REDIS_URL", settings.redis_url if hasattr(settings, "redis_url") else "redis://redis:6379/0")
    channel = f"engagement:{engagement_id}:events"
    try:
        r = redis.from_url(redis_url)
        r.publish(channel, json.dumps(event))
    except Exception as exc:
        log.warning("[_publish_event] Failed to publish to Redis: %s", exc)


def _extract_domain(in_scope: list[str]) -> str:
    """Extract the primary domain from a list of scope entries.

    Prefers bare domain names (e.g. ``shopify.com``) over wildcard or CIDR
    entries.  Returns empty string if nothing suitable is found.
    """
    for entry in in_scope:
        # Skip CIDR blocks
        if "/" in entry and not entry.startswith("http"):
            continue
        # Strip wildcard prefix
        clean = entry.lstrip("*.")
        if clean and "." in clean:
            return clean
    return ""


def _build_initial_state(engagement) -> dict:
    """Convert EngagementORM → PentraState initial dict."""
    in_scope: list[str] = list(engagement.in_scope or [])
    out_of_scope: list[str] = list(engagement.out_of_scope or [])

    domain = _extract_domain(in_scope)
    ip_ranges = [s for s in in_scope if "/" in s and not s.startswith("http")]
    base_urls = [s for s in in_scope if s.startswith("http")]

    mode: str = engagement.mode or "semi_auto"
    llm_model: str = engagement.llm_model or settings.ollama_model_fast
    opsec_mode: bool = bool(engagement.opsec_mode)
    request_jitter_ms: int = int(engagement.request_jitter_ms or 0)

    return {
        "engagement_id": str(engagement.id),
        "target": {
            "domain": domain,
            "ip_ranges": ip_ranges,
            "base_urls": base_urls,
        },
        "scope": {
            "in_scope": in_scope or ([domain] if domain else []),
            "out_of_scope": out_of_scope,
        },
        "mode": mode,
        "llm_model": llm_model,
        "opsec_mode": opsec_mode,
        "request_jitter_ms": request_jitter_ms,
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


