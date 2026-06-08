"""Lightweight audit log writer for agent nodes.

Writes directly to the ``audit_logs`` table using the same DATABASE_URL that
the API and worker use. Avoids importing ORM models from ``apps/api`` by using
raw SQL via SQLAlchemy core so that ``pentra-agent`` stays independent.

Usage (from within any node)::

    from pentra_agent.audit import write_audit_log

    await write_audit_log(
        engagement_id="abc-123",
        actor="agent/agentic",
        action="auto_approved_plan",
        detail={"mode": "agentic", "reason": "agentic mode — no HITL required"},
    )
"""

from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

log = logging.getLogger(__name__)

_DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://pentra:pentra@localhost:5432/pentra",
)


async def write_audit_log(
    engagement_id: str,
    actor: str,
    action: str,
    detail: dict[str, Any] | None = None,
) -> None:
    """Insert one row into ``audit_logs`` (append-only, fire-and-forget).

    Failures are swallowed so a DB outage never crashes the agent graph.
    """
    try:
        from sqlalchemy import text
        from sqlalchemy.ext.asyncio import create_async_engine

        engine = create_async_engine(_DATABASE_URL, pool_pre_ping=True)
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO audit_logs (engagement_id, actor, action, detail, created_at) "
                    "VALUES (CAST(:engagement_id AS uuid), :actor, :action, CAST(:detail AS jsonb), :created_at)"
                ),
                {
                    "engagement_id": engagement_id,
                    "actor": actor,
                    "action": action,
                    "detail": json.dumps(detail or {}),
                    "created_at": datetime.now(UTC).replace(tzinfo=None),
                },
            )
        await engine.dispose()
        log.debug("[audit] %s / %s / %s", engagement_id, actor, action)
    except Exception as exc:  # noqa: BLE001
        exc_str = str(exc)
        # FK violation = engagement doesn't exist in DB (e.g. live_scan.py script mode).
        # This is expected when running outside the API — skip silently, no spam.
        if "ForeignKeyViolationError" in exc_str or "foreign key" in exc_str.lower():
            log.debug("[audit] skipping audit_log — engagement %s not in DB (script mode)", engagement_id)
            return
        log.warning("[audit] write_audit_log failed (non-fatal): %s", exc)
