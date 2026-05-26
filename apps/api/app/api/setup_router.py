"""Setup wizard endpoints — first-run configuration.

Routes:
  GET  /api/v1/setup/status       — check if platform is configured
  POST /api/v1/setup/initialize   — one-time setup (admin creation + config)

These endpoints are intentionally NOT protected by authentication so they
can be called before any user exists. POST /initialize is guarded by checking
whether an admin already exists — if one does, it returns 403.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.db.base import get_db
from app.db.models import UserORM

router = APIRouter(prefix="/api/v1/setup", tags=["setup"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class SetupStatus(BaseModel):
    is_configured: bool
    requires_setup: bool
    kb_record_count: int
    ollama_reachable: bool


class SetupAdminConfig(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: str = Field(max_length=200)
    password: str = Field(min_length=8, max_length=128)


class SetupInitRequest(BaseModel):
    admin: SetupAdminConfig
    seed_knowledge: bool = False


class SetupInitResponse(BaseModel):
    success: bool
    admin_username: str
    message: str


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _admin_exists(db: AsyncSession) -> bool:
    result = await db.execute(
        select(UserORM.id).where(UserORM.is_admin.is_(True)).limit(1)
    )
    return result.scalar_one_or_none() is not None


async def _kb_record_count(db: AsyncSession) -> int:
    try:
        from pentra_knowledge.db.repository import KnowledgeRepository
        repo = KnowledgeRepository(db)
        return await repo.count_all()
    except Exception:
        return 0


async def _ollama_reachable() -> bool:
    """Quick connectivity check to Ollama."""
    import httpx
    from app.core.config import get_api_settings
    settings = get_api_settings()
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{settings.ollama_url}/api/tags")
            return resp.status_code == 200
    except Exception:
        return False


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/status", response_model=SetupStatus, summary="Setup status", description="Check whether initial setup has been completed (admin account exists). Used by the UI to redirect to /setup on first run.")
async def get_setup_status(db: AsyncSession = Depends(get_db)) -> SetupStatus:
    """Check whether the platform has been set up. No auth required."""
    admin_ok = await _admin_exists(db)
    kb_count = await _kb_record_count(db)
    ollama_ok = await _ollama_reachable()

    return SetupStatus(
        is_configured=admin_ok,
        requires_setup=not admin_ok,
        kb_record_count=kb_count,
        ollama_reachable=ollama_ok,
    )


@router.post("/initialize", response_model=SetupInitResponse, summary="Initialize Pentra AI", description="First-run setup: create the initial admin account. Fails with 409 if setup is already complete.")
async def initialize_platform(
    config: SetupInitRequest,
    db: AsyncSession = Depends(get_db),
) -> SetupInitResponse:
    """
    First-run platform initialisation.
    Creates the admin user and optionally seeds the knowledge base.
    Returns 403 if an admin already exists (idempotency guard).
    """
    if await _admin_exists(db):
        raise HTTPException(
            status_code=403,
            detail="Platform already configured. Use /admin endpoints to manage users.",
        )

    # Check username uniqueness (defensive — shouldn't matter since no users exist)
    existing = await db.execute(
        select(UserORM).where(UserORM.username == config.admin.username)
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="Username already taken")

    admin = UserORM(
        username=config.admin.username,
        email=config.admin.email,
        hashed_password=hash_password(config.admin.password),
        is_admin=True,
        is_active=True,
    )
    db.add(admin)
    await db.commit()

    if config.seed_knowledge:
        try:
            from app.worker_client import send_task
            send_task(
                "app.tasks.knowledge_scrape.scrape_h1_hacktivity",
                kwargs={"max_records": 1000},
            )
        except Exception:
            pass  # Worker might not be running — setup still succeeds

    return SetupInitResponse(
        success=True,
        admin_username=admin.username,
        message="Platform configured successfully.",
    )
