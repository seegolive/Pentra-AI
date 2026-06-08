"""Engagement learning service — persist and query cross-engagement learnings.

Called at the end of each engagement (report_node) to record what worked,
what failed, and which endpoints were valuable.  The learnings are later
queried by plan_node so the LLM can benefit from prior engagements.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import cast, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import EngagementLearningORM, EngagementORM

log = logging.getLogger(__name__)


async def save_engagement_learning(
    engagement_id: str,
    tech_stack: list[str],
    findings: list[dict],
    db: AsyncSession,
) -> EngagementLearningORM | None:
    """Build and persist an EngagementLearningORM record.

    Args:
        engagement_id: UUID string of the completed engagement.
        tech_stack: Detected tech stack list from agent state.
        findings: Deduplicated findings list from agent state.
        db: Async SQLAlchemy session.

    Returns:
        The persisted ORM record, or None if an error occurred.
    """
    try:
        eng_uuid = UUID(engagement_id)
    except ValueError:
        log.warning("[learning] Invalid engagement_id: %s", engagement_id)
        return None

    # ── Load engagement for timing info ──────────────────────────────────────
    result = await db.execute(select(EngagementORM).where(EngagementORM.id == eng_uuid))
    engagement = result.scalar_one_or_none()
    if engagement is None:
        log.warning("[learning] Engagement %s not found", engagement_id)
        return None

    # ── Derive metrics ────────────────────────────────────────────────────────
    high_critical = sum(
        1 for f in findings
        if (f.get("severity") or "").lower() in ("critical", "high")
    )

    duration_minutes: int | None = None
    if engagement.started_at:
        now = datetime.now(tz=timezone.utc)
        started = engagement.started_at
        if started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        duration_minutes = max(1, int((now - started).total_seconds() / 60))

    # ── Build effective_tools from findings ───────────────────────────────────
    tool_stats: dict[str, dict] = {}
    for f in findings:
        tool = f.get("tool") or f.get("source") or "unknown"
        tags = f.get("tags") or []
        entry = tool_stats.setdefault(tool, {"tool": tool, "tags": [], "findings": 0})
        entry["findings"] += 1
        for tag in tags:
            if tag not in entry["tags"]:
                entry["tags"].append(tag)
    effective_tools = [v for v in tool_stats.values() if v["tool"] != "unknown"]

    # ── Build high_value_endpoints from confirmed findings ────────────────────
    high_value_endpoints = []
    for f in findings:
        url = f.get("target_url") or f.get("url") or ""
        vuln = f.get("vuln_class") or f.get("title") or ""
        if url and vuln and (f.get("confirmed") or f.get("verified")):
            high_value_endpoints.append({"pattern": url, "vuln": vuln, "confirmed": True})

    # ── Derive target_pattern from tech stack ─────────────────────────────────
    target_pattern = " + ".join(sorted(set(tech_stack))) if tech_stack else "unknown"

    # ── Effective techniques: check state for known patterns ──────────────────
    effective_techniques: list[dict] = []
    has_https_fallback = any(
        "http://" in (f.get("target_url") or "") and "https" not in (f.get("target_url") or "")
        for f in findings
    )
    if has_https_fallback:
        effective_techniques.append({
            "technique": "HTTPS→HTTP fallback",
            "impact": f"findings available on HTTP even with HTTPS closed",
        })

    # ── Persist ───────────────────────────────────────────────────────────────
    learning = EngagementLearningORM(
        id=uuid4(),
        engagement_id=eng_uuid,
        tech_stack=list(set(tech_stack)),
        target_pattern=target_pattern,
        effective_tools=effective_tools,
        effective_techniques=effective_techniques,
        failed_tools=[],
        failed_techniques=[],
        high_value_endpoints=high_value_endpoints[:20],  # cap at 20
        findings_count=len(findings),
        high_critical_count=high_critical,
        engagement_duration_minutes=duration_minutes,
    )
    db.add(learning)
    await db.commit()
    await db.refresh(learning)
    log.info(
        "[learning] Saved learning record %s for engagement %s "
        "(findings=%d, high/critical=%d, duration=%s min)",
        learning.id, engagement_id, len(findings), high_critical, duration_minutes,
    )
    return learning


async def query_similar_learnings(
    tech_stack: list[str],
    db: AsyncSession,
    limit: int = 3,
) -> list[EngagementLearningORM]:
    """Return up to *limit* past learnings whose tech_stack overlaps with the query.

    Uses PostgreSQL JSONB array overlap operator (&&) and ranks by
    high_critical_count descending so the most valuable engagements surface first.
    """
    if not tech_stack:
        return []

    try:
        result = await db.execute(
            select(EngagementLearningORM)
            .where(
                EngagementLearningORM.tech_stack.op("&&")(cast(tech_stack, JSONB))
            )
            .order_by(EngagementLearningORM.high_critical_count.desc())
            .limit(limit)
        )
        return list(result.scalars().all())
    except Exception as exc:
        log.warning("[learning] query_similar_learnings failed: %s", exc)
        return []
