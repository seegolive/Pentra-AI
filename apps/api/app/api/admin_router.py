"""Admin API endpoints — admin-only operations.

Routes:
  GET  /api/v1/admin/stats                      — KB + system stats
  GET  /api/v1/admin/users                      — list all users
  POST /api/v1/admin/users                      — create user
  PATCH /api/v1/admin/users/{id}                — update user role/active
  DELETE /api/v1/admin/users/{id}               — delete user
  POST /api/v1/admin/users/{id}/reset-password
  POST /api/v1/admin/knowledge/reembed          — reset is_embedded + trigger re-embed
  POST /api/v1/admin/knowledge/bulk-import      — trigger bulk import task
  GET  /api/v1/admin/knowledge/jobs             — list recent import jobs
"""

from __future__ import annotations

import secrets
import string
from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_admin
from app.db.base import get_db
from app.db.models import EngagementORM, FindingORM, UserORM, WorkspaceORM
from app.core.security import hash_password

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class UserAdminResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    username: str
    email: str
    is_admin: bool
    is_active: bool
    created_at: datetime


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: str = Field(max_length=200)
    password: str = Field(min_length=8, max_length=128)
    is_admin: bool = False


class UserUpdateRequest(BaseModel):
    is_active: bool | None = None
    is_admin: bool | None = None


class KBStatsResponse(BaseModel):
    total_records: int
    total_knowledge_records: int = 0  # alias for total_records
    embedded_records: int
    records_by_source: dict[str, int]
    records_by_vuln_class: dict[str, int]
    total_users: int
    total_workspaces: int
    total_engagements: int
    total_findings: int
    findings_by_severity: dict[str, int] = {}


class BulkImportRequest(BaseModel):
    source: Literal["h1_graphql", "bugcrowd", "rss_feeds", "payloads_all_things"]
    max_records: int = Field(default=1000, ge=1, le=50000)
    start_page: int = Field(default=1, ge=1, description="Start scraping from this page number (use >1 to skip already-scraped pages)")
    overwrite_existing: bool = False


class BulkImportResponse(BaseModel):
    task_id: str
    source: str
    message: str
    max_records: int


class ReembedRequest(BaseModel):
    model: str = Field(default="bge-m3", description="Embedding model to use (must be available in Ollama)")
    batch_size: int = Field(default=50, ge=1, le=500)


class ReembedResponse(BaseModel):
    reset_count: int
    model: str
    message: str


class ResetPasswordResponse(BaseModel):
    temporary_password: str
    message: str


# ── Stats endpoint ────────────────────────────────────────────────────────────

@router.get("/stats", response_model=KBStatsResponse, summary="Knowledge base stats", description="Return aggregate statistics about the knowledge base: total records, embedding coverage, source breakdown.")
async def get_admin_stats(
    db: AsyncSession = Depends(get_db),
    _: UserORM = Depends(get_current_admin),
) -> KBStatsResponse:
    """Platform-wide stats for admin dashboard."""
    # Counts from PostgreSQL
    users_count = (await db.execute(select(func.count(UserORM.id)))).scalar_one()
    ws_count = (await db.execute(select(func.count(WorkspaceORM.id)))).scalar_one()
    eng_count = (await db.execute(select(func.count(EngagementORM.id)))).scalar_one()
    find_count = (await db.execute(select(func.count(FindingORM.id)))).scalar_one()

    sev_rows = (await db.execute(
        select(FindingORM.severity, func.count(FindingORM.id))
        .group_by(FindingORM.severity)
    )).all()
    findings_by_severity = {str(row[0]): row[1] for row in sev_rows}

    # KB stats via shared repository (same DB session)
    try:
        from pentra_knowledge.db.repository import KnowledgeRepository

        repo = KnowledgeRepository(db)
        total_records = await repo.count_all()
        embedded_records = await repo.count_embedded()
        by_source = await repo.count_by_field("source")
        by_vuln = await repo.count_by_field("vuln_class")
    except Exception:
        total_records = 0
        embedded_records = 0
        by_source = {}
        by_vuln = {}

    return KBStatsResponse(
        total_records=total_records,
        total_knowledge_records=total_records,
        embedded_records=embedded_records,
        records_by_source=by_source,
        records_by_vuln_class=by_vuln,
        total_users=users_count,
        total_workspaces=ws_count,
        total_engagements=eng_count,
        total_findings=find_count,
        findings_by_severity=findings_by_severity,
    )


# ── User management ───────────────────────────────────────────────────────────

@router.get("/users", response_model=list[UserAdminResponse], summary="List users (admin)", description="Admin-only: list all operator accounts with status and role information.")
async def list_users(
    db: AsyncSession = Depends(get_db),
    _: UserORM = Depends(get_current_admin),
) -> list[UserAdminResponse]:
    result = await db.execute(select(UserORM).order_by(UserORM.created_at))
    return [UserAdminResponse.model_validate(u) for u in result.scalars().all()]


@router.post("/users", response_model=UserAdminResponse, status_code=201, summary="Create user (admin)", description="Admin-only: create a new operator account, optionally granting admin privileges.")
async def create_user(
    data: UserCreateRequest,
    db: AsyncSession = Depends(get_db),
    _: UserORM = Depends(get_current_admin),
) -> UserAdminResponse:
    # Check username uniqueness
    existing = await db.execute(
        select(UserORM).where(UserORM.username == data.username)
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="Username already exists")

    user = UserORM(
        username=data.username,
        email=data.email,
        hashed_password=hash_password(data.password),
        is_admin=data.is_admin,
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return UserAdminResponse.model_validate(user)


@router.patch("/users/{user_id}", response_model=UserAdminResponse, summary="Update user (admin)", description="Admin-only: update account fields (email, is_active, is_admin).")
async def update_user(
    user_id: UUID,
    data: UserUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_admin: UserORM = Depends(get_current_admin),
) -> UserAdminResponse:
    result = await db.execute(select(UserORM).where(UserORM.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    # Prevent self-deactivation
    if user.id == current_admin.id and data.is_active is False:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")

    if data.is_active is not None:
        user.is_active = data.is_active  # type: ignore[assignment]
    if data.is_admin is not None:
        user.is_admin = data.is_admin  # type: ignore[assignment]

    await db.commit()
    await db.refresh(user)
    return UserAdminResponse.model_validate(user)


@router.delete("/users/{user_id}", status_code=204, summary="Delete user (admin)", description="Admin-only: permanently delete an operator account. Cannot delete your own account.")
async def delete_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_admin: UserORM = Depends(get_current_admin),
) -> None:
    result = await db.execute(select(UserORM).where(UserORM.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == current_admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    await db.delete(user)
    await db.commit()


@router.post("/users/{user_id}/reset-password", response_model=ResetPasswordResponse, summary="Reset password (admin)", description="Admin-only: set a new password for any operator account.")
async def reset_user_password(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_admin: UserORM = Depends(get_current_admin),
) -> ResetPasswordResponse:
    result = await db.execute(select(UserORM).where(UserORM.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == current_admin.id:
        raise HTTPException(status_code=400, detail="Use your profile settings to change your own password")

    alphabet = string.ascii_letters + string.digits + "!@#$%"
    temp_password = "".join(secrets.choice(alphabet) for _ in range(16))
    user.hashed_password = hash_password(temp_password)  # type: ignore[assignment]
    await db.commit()
    return ResetPasswordResponse(
        temporary_password=temp_password,
        message="Password reset. Share this with the user securely — it is shown only once.",
    )


# ── Knowledge bulk-import ─────────────────────────────────────────────────────

@router.post(
    "/knowledge/reembed",
    response_model=ReembedResponse,
    summary="Re-embed all knowledge records (admin)",
    description=(
        "Admin-only: reset is_embedded=False for all KB records so the worker's "
        "embed_pending_records task re-processes them with the specified model. "
        "The worker must be running for embedding to actually happen."
    ),
)
async def trigger_reembed(
    config: ReembedRequest,
    _: UserORM = Depends(get_current_admin),
) -> ReembedResponse:
    """Reset all KB records to unembedded so they get re-indexed."""
    from pentra_knowledge.db.base import AsyncSessionLocal as KBSession
    from pentra_knowledge.db.repository import KnowledgeRepository

    async with KBSession()() as kb_session:
        repo = KnowledgeRepository(kb_session)
        reset_count = await repo.reset_embeddings()

    return ReembedResponse(
        reset_count=reset_count,
        model=config.model,
        message=(
            f"Reset {reset_count} records to unembedded. "
            f"Worker will re-embed using model '{config.model}' on next cycle."
        ),
    )


@router.post("/knowledge/bulk-import", response_model=BulkImportResponse, summary="Bulk import knowledge records (admin)", description="Admin-only: import a list of knowledge records (JSON array) in batch. Skips duplicates.", )
async def trigger_bulk_import(
    config: BulkImportRequest,
    _: UserORM = Depends(get_current_admin),
) -> BulkImportResponse:
    """Trigger a bulk knowledge import Celery task. Admin only."""
    from app.worker_client import send_task

    task_map = {
        "h1_graphql": "app.tasks.knowledge_scrape.scrape_h1_hacktivity",
        "bugcrowd": "app.tasks.bugcrowd_scraper.scrape_bugcrowd_disclosures",
        "rss_feeds": "app.tasks.rss_ingestion.ingest_rss_feeds",
        "payloads_all_things": "app.tasks.payloads_all_things.import_payloads",
    }

    task_name = task_map[config.source]
    task_id = send_task(
        task_name,
        kwargs={"max_records": config.max_records, "start_page": config.start_page, "overwrite": config.overwrite_existing},
    )

    return BulkImportResponse(
        task_id=task_id,
        source=config.source,
        message=f"Import task queued for source '{config.source}'",
        max_records=config.max_records,
    )


# ── Backup ────────────────────────────────────────────────────────────────────

@router.post(
    "/backup/trigger",
    summary="Trigger manual backup",
    description="Admin-only: trigger a manual backup of PostgreSQL and Qdrant to MinIO.",
)
async def trigger_backup(
    _: UserORM = Depends(get_current_admin),
) -> dict:
    """Trigger a manual platform backup."""
    import uuid  # noqa: PLC0415
    job_id = str(uuid.uuid4())
    # In production this would enqueue a Celery backup task.
    # For now return a job ID as acknowledgment.
    return {"status": "triggered", "job_id": job_id}
