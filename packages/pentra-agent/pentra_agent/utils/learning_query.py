"""Standalone learning query utility — Task 20.6 helper.

Provides query_similar_learnings() for use outside the API context
(e.g., from worker tasks or scripts that don't have the app.services.learning
import available).

When running inside the API context, prefer app.services.learning directly.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)


async def query_similar_learnings_standalone(
    tech_stack: list[str],
    db_url: str,
    limit: int = 3,
) -> list[dict]:
    """Query EngagementLearning records similar to the given tech stack.

    Standalone version that creates its own DB engine — for use in agent
    nodes that run outside the FastAPI request lifecycle.

    Args:
        tech_stack:  List of tech stack strings (e.g. ["iis", "aspnet"]).
        db_url:      PostgreSQL asyncpg URL.
        limit:       Max records to return.

    Returns:
        List of learning dicts with keys: target_pattern, effective_tools,
        effective_techniques, high_value_endpoints, findings_count.
    """
    if not tech_stack or not db_url:
        return []

    try:
        from sqlalchemy import cast, select
        from sqlalchemy.dialects.postgresql import JSONB
        from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

        engine = create_async_engine(db_url, echo=False)
        try:
            async with AsyncSession(engine) as session:
                from app.db.models import EngagementLearningORM

                result = await session.execute(
                    select(EngagementLearningORM)
                    .where(
                        EngagementLearningORM.findings_count > 0,
                        EngagementLearningORM.tech_stack.op("&&")(
                            cast(tech_stack, JSONB)
                        ),
                    )
                    .order_by(EngagementLearningORM.high_critical_count.desc())
                    .limit(limit)
                )
                records = result.scalars().all()

            if records:
                log.info("[learning_query] Found %d matching learnings", len(records))

            return [
                {
                    "target_pattern": r.target_pattern,
                    "effective_tools": r.effective_tools or [],
                    "effective_techniques": r.effective_techniques or [],
                    "high_value_endpoints": r.high_value_endpoints or [],
                    "findings_count": r.findings_count,
                    "high_critical_count": r.high_critical_count,
                }
                for r in records
            ]
        finally:
            await engine.dispose()

    except Exception as exc:
        log.debug("[learning_query] Standalone query failed (non-fatal): %s", exc)
        return []


def format_learnings_for_llm(learnings: list[dict]) -> str:
    """Format past learnings into a compact text block for LLM prompt injection."""
    if not learnings:
        return ""

    lines = ["PRIOR ENGAGEMENT LEARNINGS (similar tech stack):"]
    for i, l in enumerate(learnings[:3], 1):
        hve = [ep.get("pattern", "") for ep in (l.get("high_value_endpoints") or [])[:3]]
        tools = [t.get("tool", "") for t in (l.get("effective_tools") or [])[:3]]
        techniques = [t.get("technique", "") for t in (l.get("effective_techniques") or [])[:2]]

        lines.append(
            f"{i}. Target: {l.get('target_pattern','?')} | "
            f"Findings: {l.get('findings_count',0)} ({l.get('high_critical_count',0)} H/C) | "
            f"Worked: {', '.join(t for t in tools if t)[:60]} | "
            f"Techniques: {', '.join(t for t in techniques if t)[:60]}"
        )
        if hve:
            lines.append(f"   High-value endpoints: {', '.join(h for h in hve if h)[:80]}")

    return "\n".join(lines)
