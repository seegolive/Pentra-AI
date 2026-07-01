"""Pentra AI — FastAPI gateway.

Mounts the pentra-knowledge router and adds CORS + health check.
Run with:
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path

# ── Ensure .env is resolved relative to apps/api/ regardless of CWD ──────────
_API_DIR = Path(__file__).parent.parent
os.chdir(str(_API_DIR))

# Load .env into os.environ so os.getenv() calls in agent nodes (pentra-agent
# package) can also read secrets without importing pydantic-settings.
from dotenv import load_dotenv  # noqa: E402
load_dotenv(dotenv_path=str(_API_DIR / ".env"), override=False)

# ── Logging: ensure pentra_agent node logs reach the root logger ──────────────
# Root logger is set to INFO so messages propagate through to both the log file
# (via uvicorn's stderr handler) and the per-engagement live feed handler
# (attached to root by _attach_live_feed_log_handler).
# Per-logger StreamHandlers are NOT added here — they cause duplicate log lines
# because each message is written once by the child handler and again when it
# propagates up the hierarchy to another ancestor with a handler.
import logging as _logging  # noqa: E402
_logging.getLogger().setLevel(_logging.INFO)   # root logger passes INFO upward
for _logger_name in (
    "pentra_agent",
    "pentra_agent.nodes.plan_node",
    "pentra_agent.nodes.recon_node",
    "pentra_agent.nodes.vuln_hunt_node",
    "pentra_agent.nodes.report_node",
    "pentra_agent.llm.client",
    "pentra_tools.burp.client",
):
    _l = _logging.getLogger(_logger_name)
    _l.setLevel(_logging.DEBUG)   # let all levels through; root filters at INFO
    _l.propagate = True           # propagate to root so live feed handler receives them

from fastapi import FastAPI  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402

from app.core.config import get_api_settings  # noqa: E402
from app.core.agent import init_agent_service  # noqa: E402
from app.core.redis_bridge import start_redis_bridge  # noqa: E402
from app.api.auth_router import router as auth_router  # noqa: E402
from app.api.router import router as engagement_router  # noqa: E402
from app.api.report_router import router as report_router  # noqa: E402
from app.api.monitoring_router import router as monitoring_router  # noqa: E402
from app.api.admin_router import router as admin_router  # noqa: E402
from app.api.setup_router import router as setup_router  # noqa: E402
from app.api.h1_router import router as h1_router  # noqa: E402
from app.api.worker_health_router import router as worker_health_router  # noqa: E402
from app.api.internal_router import router as internal_router  # noqa: E402
from app.core.middleware.rate_limit import RateLimitMiddleware  # noqa: E402
from pentra_knowledge.api.router import router as knowledge_router  # noqa: E402


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — startup / shutdown hooks."""
    # Validate environment and service connectivity before accepting traffic
    from app.core.startup import StartupValidator

    validator = StartupValidator()
    await validator.validate_all()

    # Ensure Qdrant collection exists on startup
    from pentra_knowledge.services.search import ensure_collection_exists

    await ensure_collection_exists()

    # Initialise LangGraph agent service with AsyncPostgresSaver (persistent checkpointing)
    from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

    settings = get_api_settings()
    db_url = settings.database_url.replace(
        "postgresql+asyncpg://", "postgresql://"
    )

    async with AsyncPostgresSaver.from_conn_string(db_url) as checkpointer:
        await checkpointer.setup()  # creates langgraph checkpoint tables if needed
        init_agent_service(checkpointer=checkpointer)

        # Recover stale engagements from previous crashes (active but no heartbeat)
        await _recover_stale_engagements()

        # Start Redis → WebSocket bridge as a background task
        bridge_task = asyncio.create_task(start_redis_bridge())

        yield

        # Shutdown: cancel the bridge gracefully
        bridge_task.cancel()
        try:
            await bridge_task
        except asyncio.CancelledError:
            pass


def create_app() -> FastAPI:
    settings = get_api_settings()

    app = FastAPI(
        title="Pentra AI API",
        version="1.0.0",
        description="Self-hosted AI Security Research Platform — Knowledge & Agent API",
        lifespan=lifespan,
        redirect_slashes=False,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.add_middleware(
        RateLimitMiddleware,
        redis_url=settings.redis_url,
        default_limit=200,
        expensive_limit=10,
    )

    # ── Routers ───────────────────────────────────────────────────────────
    app.include_router(auth_router)
    app.include_router(setup_router)
    app.include_router(knowledge_router)
    app.include_router(engagement_router)
    app.include_router(monitoring_router)
    app.include_router(admin_router)
    app.include_router(report_router)
    app.include_router(h1_router)
    app.include_router(worker_health_router)
    app.include_router(internal_router)

    # ── Health check ──────────────────────────────────────────────────────
    @app.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": "1.0.0"}

    @app.get("/api/v1/version", tags=["system"])
    async def version_info() -> dict[str, str]:
        return {
            "version": "1.0.0",
            "phase": "Phase 2 — Agent Engine",
            "build_date": "2026-06-04",
        }

    return app


app = create_app()


async def _recover_stale_engagements() -> None:
    """On startup, mark engagements stuck in 'active' as 'failed'.

    This handles the case where the API process was killed mid-scan leaving
    engagements permanently stuck. Any engagement that has been 'active' for
    more than 4 hours without completing is considered crashed.
    """
    import logging
    from datetime import datetime, timezone, timedelta
    from sqlalchemy import select, update
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
    from app.core.config import get_api_settings
    from app.db.models import EngagementORM

    log = logging.getLogger(__name__)
    settings = get_api_settings()
    _STALE_HOURS = 4

    try:
        engine = create_async_engine(settings.database_url, echo=False, pool_size=1, max_overflow=0)
        async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=_STALE_HOURS)
        async with async_session() as db:
            result = await db.execute(
                select(EngagementORM).where(
                    EngagementORM.status == "active",
                    EngagementORM.started_at < cutoff,
                )
            )
            stale = result.scalars().all()
            if stale:
                for eng in stale:
                    eng.status = "failed"
                    eng.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
                await db.commit()
                log.warning(
                    "[startup_recovery] Marked %d stale engagement(s) as failed: %s",
                    len(stale),
                    [str(e.id) for e in stale],
                )
            else:
                log.info("[startup_recovery] No stale engagements found")

        await engine.dispose()
    except Exception as exc:
        logging.getLogger(__name__).warning("[startup_recovery] Failed (non-fatal): %s", exc)
