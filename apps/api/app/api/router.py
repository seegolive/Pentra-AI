"""Workspace and Engagement CRUD + HITL + WebSocket feed routers.

Route summary:
  POST   /api/v1/workspaces/               create workspace
  GET    /api/v1/workspaces/               list workspaces
  GET    /api/v1/workspaces/{id}           get workspace

  POST   /api/v1/engagements/              create engagement
  GET    /api/v1/engagements/              list engagements (optionally by workspace)
  GET    /api/v1/engagements/{id}          get engagement
  POST   /api/v1/engagements/{id}/start    start the LangGraph agent
  POST   /api/v1/engagements/{id}/approve  resume after HITL pause
  GET    /api/v1/engagements/{id}/findings list findings for engagement

  WS     /ws/engagements/{id}/feed         live event stream
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
import uuid
from datetime import UTC, datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import (
    EngagementCreate,
    EngagementExportBundle,
    EngagementImportRequest,
    EngagementResponse,
    FindingExport,
    FindingPatch,
    FindingResponse,
    HitlDecision,
    KBManualInjectRequest,
    KBUrlInjectRequest,
    KnowledgeInjectRequest,
    KnowledgeInjectResponse,
    PayloadGenerateAPIRequest,
    PayloadGenerateAPIResponse,
    PayloadItem,
    SubscanRequest,
    WorkspaceCreate,
    WorkspaceResponse,
)
from app.core.deps import get_current_user
from app.db.base import get_db
from app.db.models import AuditLogORM, EngagementORM, FindingORM, UserORM, WorkspaceORM
from app.ws.manager import ws_manager

router = APIRouter(prefix="/api/v1", tags=["engagements"])
log = logging.getLogger(__name__)

# Registry of active agent tasks, keyed by engagement_id (str).
# Used by the /stop endpoint to cancel a running scan.
_active_tasks: dict[str, asyncio.Task] = {}

# Per-engagement locks that prevent two concurrent /approve calls from
# launching two simultaneous graph.astream_events() on the same thread_id.
_approve_locks: dict[str, asyncio.Lock] = {}
_live_feed_engagement_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "live_feed_engagement_id",
    default=None,
)


class _LiveFeedLogHandler(logging.Handler):
    """Forward selected Python logs into one engagement's WebSocket feed."""

    _LOGGER_PREFIXES = (
        "pentra_agent",
        "pentra_tools",
        "app.api.router",
        "app.core.agent",
        "app.resume_agent",
    )

    def __init__(self, engagement_id: str, loop: asyncio.AbstractEventLoop) -> None:
        super().__init__(level=logging.INFO)
        self.engagement_id = engagement_id
        self.loop = loop
        self.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        if _live_feed_engagement_id.get() != self.engagement_id:
            return
        if not record.name.startswith(self._LOGGER_PREFIXES):
            return

        try:
            message = self.format(record)
            if len(message) > 4000:
                message = f"{message[:4000]}..."
            payload = {
                "type": "terminal_output",
                "message": message,
                "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
                "data": {
                    "logger": record.name,
                    "level": record.levelname,
                },
            }
            asyncio.run_coroutine_threadsafe(
                ws_manager.broadcast(self.engagement_id, payload), self.loop
            )
        except Exception:
            self.handleError(record)


def _attach_live_feed_log_handler(engagement_id: str) -> _LiveFeedLogHandler:
    handler = _LiveFeedLogHandler(engagement_id, asyncio.get_running_loop())
    logging.getLogger().addHandler(handler)
    return handler


def _detach_live_feed_log_handler(handler: _LiveFeedLogHandler) -> None:
    logging.getLogger().removeHandler(handler)


# ── Workspaces ────────────────────────────────────────────────────────────────

@router.post(
    "/workspaces/",
    response_model=WorkspaceResponse,
    status_code=201,
    summary="Create workspace",
    description="Create a new workspace to group security engagements. Each workspace is owned by the authenticated user.",
)
async def create_workspace(
    data: WorkspaceCreate,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> WorkspaceResponse:
    ws = WorkspaceORM(name=data.name, description=data.description, owner_id=current_user.id)
    db.add(ws)
    await db.commit()
    await db.refresh(ws)
    return WorkspaceResponse.model_validate(ws)


@router.get(
    "/workspaces/",
    response_model=list[WorkspaceResponse],
    summary="List workspaces",
    description="Return all workspaces owned by the authenticated user. Admins see all workspaces.",
)
async def list_workspaces(
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> list[WorkspaceResponse]:
    query = select(WorkspaceORM).order_by(WorkspaceORM.created_at.desc())
    if not current_user.is_admin:
        query = query.where(WorkspaceORM.owner_id == current_user.id)
    result = await db.execute(query)
    return [WorkspaceResponse.model_validate(w) for w in result.scalars().all()]


@router.get(
    "/workspaces/{workspace_id}",
    response_model=WorkspaceResponse,
    summary="Get workspace",
    description="Retrieve a single workspace by ID. Returns 404 if not found, 403 if the user lacks access.",
)
async def get_workspace(
    workspace_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> WorkspaceResponse:
    ws = await db.get(WorkspaceORM, workspace_id)
    if ws is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    if not current_user.is_admin and ws.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    return WorkspaceResponse.model_validate(ws)


# ── Engagements ───────────────────────────────────────────────────────────────

@router.post(
    "/engagements/",
    response_model=EngagementResponse,
    status_code=201,
    summary="Create engagement",
    description="Create a new security engagement inside a workspace. Specify in-scope targets, exclusions, LLM model, and execution mode (semi_auto or agentic).",
)
async def create_engagement(
    data: EngagementCreate,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> EngagementResponse:
    # Verify workspace exists
    ws = await db.get(WorkspaceORM, data.workspace_id)
    if ws is None:
        raise HTTPException(status_code=404, detail="Workspace not found")

    eng_id = uuid.uuid4()
    eng = EngagementORM(
        id=eng_id,
        workspace_id=data.workspace_id,
        name=data.name,
        description=data.description,
        mode=data.mode,
        in_scope=data.in_scope,
        out_of_scope=data.out_of_scope,
        llm_model=data.llm_model,
        scan_preset=data.scan_preset,
        opsec_mode=data.opsec_mode,
        request_jitter_ms=data.request_jitter_ms,
        scan_sequential=data.scan_sequential,
        auto_approve_exploit_validation=data.auto_approve_exploit_validation,
        langgraph_thread_id=str(eng_id),  # thread_id == engagement_id
        created_by=current_user.id,
    )
    db.add(eng)
    await db.commit()
    await db.refresh(eng)
    return EngagementResponse.model_validate(eng)


@router.get(
    "/engagements",
    response_model=list[EngagementResponse],
    include_in_schema=False,
)
@router.get(
    "/engagements/",
    response_model=list[EngagementResponse],
    summary="List engagements",
    description="Return all engagements. Optionally filter by workspace_id.",
)
async def list_engagements(
    workspace_id: UUID | None = Query(default=None),
    limit: int | None = Query(default=None, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> list[EngagementResponse]:
    stmt = select(EngagementORM).order_by(EngagementORM.created_at.desc())
    if workspace_id is not None:
        stmt = stmt.where(EngagementORM.workspace_id == workspace_id)
    if limit is not None:
        stmt = stmt.limit(limit)
    result = await db.execute(stmt)
    return [EngagementResponse.model_validate(e) for e in result.scalars().all()]


@router.get(
    "/engagements/{engagement_id}",
    response_model=EngagementResponse,
    summary="Get engagement",
    description="Retrieve a single engagement by ID including its current status and scope.",
)
async def get_engagement(
    engagement_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> EngagementResponse:
    eng = await db.get(EngagementORM, engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return EngagementResponse.model_validate(eng)


@router.post(
    "/engagements/{engagement_id}/start",
    summary="Start engagement",
    description="Launch the LangGraph agent for this engagement. Transitions status from planning/paused → active. The agent runs in a background task and pushes events via WebSocket.",
)
async def start_engagement(
    engagement_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> dict:
    """Launch the LangGraph agent for this engagement in a background task."""
    eng = await db.get(EngagementORM, engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    if eng.status not in ("planning", "paused"):
        raise HTTPException(status_code=409, detail=f"Engagement is already {eng.status}")

    # Update status
    eng.status = "active"
    # Fix: DB column is TIMESTAMP WITHOUT TIME ZONE — must use naive UTC datetime
    eng.started_at = datetime.now(timezone.utc).replace(tzinfo=None)
    await db.commit()

    # Audit log
    db.add(AuditLogORM(
        engagement_id=engagement_id,
        actor="api",
        action="engagement_started",
        detail={"mode": eng.mode},
    ))
    await db.commit()

    # Launch agent in background and register task for cancellation via /stop
    task = asyncio.create_task(_run_agent(eng))
    _active_tasks[str(engagement_id)] = task
    task.add_done_callback(lambda _: _active_tasks.pop(str(engagement_id), None))

    return {"status": "started", "engagement_id": str(engagement_id)}


@router.post(
    "/engagements/{engagement_id}/approve",
    summary="Submit HITL decision",
    description="Resume a paused LangGraph thread after a human-in-the-loop review. Actions: approve, skip, or modify (with modified_data payload).",
)
async def approve_action(
    engagement_id: UUID,
    decision: HitlDecision,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> dict:
    """Resume a paused LangGraph thread after a HITL decision."""
    from app.core.agent import get_agent_service

    eng = await db.get(EngagementORM, engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="Engagement not found")

    # Audit log
    db.add(AuditLogORM(
        engagement_id=engagement_id,
        actor="user",
        action="hitl_decision",
        detail={"decision": decision.action},
    ))
    await db.commit()

    # Guard against concurrent /approve calls for the same engagement.
    # Two simultaneous approvals would launch two graph.astream_events() on
    # the same thread_id, causing checkpoint races and orphaned tasks.
    eid_str = str(engagement_id)
    if eid_str not in _approve_locks:
        _approve_locks[eid_str] = asyncio.Lock()
    lock = _approve_locks[eid_str]
    if lock.locked():
        return {"status": "already_resuming", "decision": decision.action}

    async def _locked_resume() -> None:
        async with lock:
            await _resume_agent(eid_str, decision.action)

    # Resume agent in background; register for cancellation via /stop
    _resume_task = asyncio.create_task(_locked_resume())
    _active_tasks[eid_str] = _resume_task
    _resume_task.add_done_callback(lambda _: _active_tasks.pop(eid_str, None))
    _resume_task.add_done_callback(lambda _: _approve_locks.pop(eid_str, None))

    return {"status": "resumed", "decision": decision.action}


@router.patch(
    "/engagements/{engagement_id}/mode",
    summary="Update engagement mode",
    description="Switch between semi_auto (HITL required) and agentic (fully automatic, no interrupts).",
)
async def update_engagement_mode(
    engagement_id: UUID,
    body: dict,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> dict:
    """Set engagement mode to 'semi_auto' or 'agentic'.

    If the engagement is currently awaiting approval and mode is set to
    'agentic', automatically resumes the graph as well.
    """
    mode = body.get("mode", "")
    if mode not in ("semi_auto", "agentic"):
        raise HTTPException(status_code=422, detail="mode must be 'semi_auto' or 'agentic'")

    eng = await db.get(EngagementORM, engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    if eng.status in ("completed", "cancelled", "failed"):
        raise HTTPException(status_code=409, detail=f"Engagement is already {eng.status}")

    eng.mode = mode
    db.add(AuditLogORM(
        engagement_id=engagement_id,
        actor="user",
        action="mode_changed",
        detail={"mode": mode, "changed_by": str(current_user.id)},
    ))
    await db.commit()
    await db.refresh(eng)

    # If currently paused and switching to agentic, auto-resume (guarded like /approve)
    auto_resumed = False
    if mode == "agentic" and eng.status == "awaiting_approval":
        eid_str = str(engagement_id)
        if eid_str not in _approve_locks:
            _approve_locks[eid_str] = asyncio.Lock()
        lock = _approve_locks[eid_str]
        if not lock.locked():
            async def _locked_mode_resume() -> None:
                async with lock:
                    await _resume_agent(eid_str, "approve")
            _mode_task = asyncio.create_task(_locked_mode_resume())
            _active_tasks[eid_str] = _mode_task
            _mode_task.add_done_callback(lambda _: _active_tasks.pop(eid_str, None))
            _mode_task.add_done_callback(lambda _: _approve_locks.pop(eid_str, None))
            auto_resumed = True

    return {"status": "updated", "mode": mode, "auto_resumed": auto_resumed}


@router.patch(
    "/engagements/{engagement_id}/stop",
    summary="Stop engagement",
    description="Cancel a running engagement. Kills the background agent task and sets status to 'cancelled'.",
)
async def stop_engagement(
    engagement_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> dict:
    eng = await db.get(EngagementORM, engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    if not current_user.is_admin and eng.created_by != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    # Cancel running asyncio task unconditionally — must happen before the
    # early-return guard, because status may already be 'cancelled' in DB while
    # the task is still running (stop_engagement was called before the task had
    # a chance to observe the DB change).
    task = _active_tasks.pop(str(engagement_id), None)
    if task and not task.done():
        task.cancel()

    if eng.status in ("completed", "cancelled"):
        return {"status": eng.status, "message": "Engagement already finished"}

    eng.status = "cancelled"
    eng.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.add(AuditLogORM(
        engagement_id=engagement_id,
        actor="user",
        action="engagement_cancelled",
        detail={"cancelled_by": str(current_user.id)},
    ))
    await db.commit()

    await ws_manager.broadcast(str(engagement_id), {
        "type": "agent_cancelled",
        "message": "Engagement cancelled by user",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    return {"status": "cancelled", "engagement_id": str(engagement_id)}


@router.post(
    "/engagements/{engagement_id}/subscan",
    summary="Run targeted subscan",
    description="Launch a focused vulnerability scan on a subset of URLs from this engagement. Returns a task_id to track progress.",
)
async def run_subscan(
    engagement_id: UUID,
    body: SubscanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> dict:
    eng = await db.get(EngagementORM, engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    if not current_user.is_admin and eng.created_by != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    from app.worker_client import send_task
    task_id = send_task(
        "app.tasks.agent.run_subscan",
        kwargs={
            "engagement_id": str(engagement_id),
            "target_urls": body.target_urls,
        },
    )

    db.add(AuditLogORM(
        engagement_id=engagement_id,
        actor="user",
        action="subscan_queued",
        detail={"target_urls": body.target_urls, "task_id": task_id},
    ))
    await db.commit()

    return {"task_id": task_id, "status": "queued"}


# ── Findings ──────────────────────────────────────────────────────────────────

@router.get(
    "/engagements/{engagement_id}/findings",
    response_model=list[FindingResponse],
    summary="List findings",
    description="Return all findings for an engagement, ordered by discovery date descending.",
)
async def list_findings(
    engagement_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> list[FindingResponse]:
    result = await db.execute(
        select(FindingORM)
        .where(FindingORM.engagement_id == engagement_id)
        .order_by(FindingORM.discovered_at.desc())
    )
    return [FindingResponse.model_validate(f) for f in result.scalars().all()]


@router.get(
    "/findings/recent",
    response_model=list[FindingResponse],
    summary="Recent findings",
    description="Return the N most recent findings across all engagements the user can access.",
)
async def get_recent_findings(
    limit: int = Query(default=5, le=20),
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> list[FindingResponse]:
    stmt = (
        select(FindingORM)
        .join(EngagementORM, FindingORM.engagement_id == EngagementORM.id)
        .join(WorkspaceORM, EngagementORM.workspace_id == WorkspaceORM.id)
        .order_by(FindingORM.discovered_at.desc())
        .limit(limit)
    )
    if not current_user.is_admin:
        stmt = stmt.where(WorkspaceORM.owner_id == current_user.id)
    result = await db.execute(stmt)
    return [FindingResponse.model_validate(f) for f in result.scalars().all()]


@router.get(
    "/engagements/{engagement_id}/learning",
    summary="Get engagement learning record",
    description="Return the EngagementLearning record saved after a completed engagement.",
)
async def get_engagement_learning(
    engagement_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> dict:
    from app.db.models import EngagementLearningORM
    from sqlalchemy import select as sa_select
    result = await db.execute(
        sa_select(EngagementLearningORM)
        .where(EngagementLearningORM.engagement_id == engagement_id)
        .order_by(EngagementLearningORM.created_at.desc())
        .limit(1)
    )
    learning = result.scalar_one_or_none()
    if learning is None:
        raise HTTPException(status_code=404, detail="No learning record for this engagement")
    return {
        "id": str(learning.id),
        "engagement_id": str(learning.engagement_id),
        "tech_stack": learning.tech_stack,
        "target_pattern": learning.target_pattern,
        "effective_tools": learning.effective_tools,
        "effective_techniques": learning.effective_techniques,
        "failed_tools": learning.failed_tools,
        "failed_techniques": learning.failed_techniques,
        "high_value_endpoints": learning.high_value_endpoints,
        "findings_count": learning.findings_count,
        "high_critical_count": learning.high_critical_count,
        "engagement_duration_minutes": learning.engagement_duration_minutes,
        "created_at": learning.created_at.isoformat(),
    }


# ── Audit Logs ────────────────────────────────────────────────────────────────

@router.get(
    "/engagements/{engagement_id}/audit",
    summary="List audit logs",
    description="Return append-only audit log entries for an engagement.",
)
async def list_audit_logs(
    engagement_id: UUID,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> list[dict]:
    result = await db.execute(
        select(AuditLogORM)
        .where(AuditLogORM.engagement_id == engagement_id)
        .order_by(AuditLogORM.created_at.desc())
        .limit(limit)
    )
    return [
        {
            "id": str(log.id),
            "engagement_id": str(log.engagement_id),
            "action": log.action,
            "actor": log.actor,
            "detail": log.detail,
            "created_at": log.created_at.isoformat() if log.created_at else None,
        }
        for log in result.scalars().all()
    ]


# ── Export / Import ───────────────────────────────────────────────────────────

@router.get(
    "/engagements/{engagement_id}/export",
    response_model=EngagementExportBundle,
    summary="Export engagement",
    description="Download the full engagement and all its findings as a portable JSON bundle. Can be re-imported into any Pentra AI instance.",
)
async def export_engagement(
    engagement_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> EngagementExportBundle:
    """Download a full engagement + findings bundle as JSON."""
    eng = await db.get(EngagementORM, engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="Engagement not found")

    findings_result = await db.execute(
        select(FindingORM)
        .where(FindingORM.engagement_id == engagement_id)
        .order_by(FindingORM.discovered_at.asc())
    )
    findings = findings_result.scalars().all()

    return EngagementExportBundle(
        exported_at=datetime.now(timezone.utc),
        engagement=EngagementResponse.model_validate(eng),
        findings=[
            FindingExport(
                title=f.title,
                vuln_class=f.vuln_class,
                severity=f.severity,
                cvss_score=f.cvss_score,
                target_url=f.target_url,
                http_method=f.http_method,
                request_raw=f.request_raw,
                response_raw=f.response_raw,
                reproduction_steps=f.reproduction_steps,
                status=f.status,
                discovered_by=f.discovered_by,
                description=f.description,
                cve_ids=f.cve_ids or [],
            )
            for f in findings
        ],
    )


@router.post(
    "/workspaces/{workspace_id}/engagements/import",
    response_model=EngagementResponse,
    status_code=201,
    summary="Import engagement",
    description="Import a previously exported engagement bundle into an existing workspace. Findings are recreated with new IDs.",
)
async def import_engagement(
    workspace_id: UUID,
    body: EngagementImportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> EngagementResponse:
    """Import an engagement bundle into an existing workspace."""
    ws = await db.get(WorkspaceORM, workspace_id)
    if ws is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    if not current_user.is_admin and ws.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    src = body.bundle.engagement
    new_id = uuid.uuid4()
    eng = EngagementORM(
        id=new_id,
        workspace_id=workspace_id,
        name=body.new_name or f"[Import] {src.name}",
        description=src.description,
        mode=src.mode,
        status="planning",  # always start fresh
        in_scope=src.in_scope,
        out_of_scope=src.out_of_scope,
        llm_model=src.llm_model,
        opsec_mode=src.opsec_mode,
        request_jitter_ms=src.request_jitter_ms,
        scan_sequential=src.scan_sequential,
        auto_approve_exploit_validation=src.auto_approve_exploit_validation,
        langgraph_thread_id=str(new_id),
        created_by=current_user.id,
    )
    db.add(eng)
    await db.flush()

    for finding in body.bundle.findings:
        db.add(FindingORM(
            engagement_id=new_id,
            title=finding.title,
            vuln_class=finding.vuln_class,
            severity=finding.severity,
            cvss_score=finding.cvss_score,
            target_url=finding.target_url,
            http_method=finding.http_method,
            request_raw=finding.request_raw,
            response_raw=finding.response_raw,
            reproduction_steps=finding.reproduction_steps,
            status=finding.status,
            discovered_by=finding.discovered_by,
            description=finding.description,
            cve_ids=finding.cve_ids,
        ))

    db.add(AuditLogORM(
        engagement_id=new_id,
        actor=f"user/{current_user.username}",
        action="engagement_imported",
        detail={
            "source_engagement_id": str(src.id),
            "findings_count": len(body.bundle.findings),
        },
    ))
    await db.commit()
    await db.refresh(eng)
    return EngagementResponse.model_validate(eng)


@router.post(
    "/findings/{finding_id}/submit-to-knowledge",
    response_model=KnowledgeInjectResponse,
    status_code=201,
    summary="Submit finding to knowledge base",
    description="Convert a confirmed finding into a KnowledgeRecord. Feeds the platform's self-learning loop so future engagements benefit from discovered techniques.",
)
async def submit_finding_to_knowledge(
    finding_id: UUID,
    body: KnowledgeInjectRequest,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> KnowledgeInjectResponse:
    """Convert a confirmed finding into a KnowledgeRecord.

    This feeds the platform's self-learning loop — confirmed findings from
    engagements are ingested into the knowledge base so future hunts benefit.
    """
    finding = await db.get(FindingORM, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    from pentra_knowledge.db.base import AsyncSessionLocal as KBSession
    from pentra_knowledge.db.repository import KnowledgeRepository

    import hashlib
    source_id = hashlib.sha256(f"finding:{finding_id}".encode()).hexdigest()[:32]

    async with KBSession()() as kb_db:
        repo = KnowledgeRepository(kb_db)
        existing = await repo.get_by_source_id(source_id)
        if existing:
            return KnowledgeInjectResponse(
                knowledge_record_id=str(existing.id),
                message="Already exists in knowledge base",
            )

        record_data: dict = {
            "source": "pentra_finding",
            "source_id": source_id,
            "source_url": finding.target_url,
            "title": finding.title,
            "vuln_class": finding.vuln_class,
            "vuln_subclass": "",
            "severity": finding.severity,
            "program": "pentra_engagement",
            "tech_stack": [],
            "platform_type": ["web"],
            "attack_technique": body.technique or finding.title,
            "attack_steps": finding.reproduction_steps or [],
            "key_insight": body.key_insight or finding.title,
            "indicators": [],
            "pentra_tags": ["finding", "confirmed"] + (body.tags or []),
        }

        orm = await repo.create(record_data)
        await kb_db.commit()

    # Write audit log
    db.add(AuditLogORM(
        engagement_id=finding.engagement_id,
        actor=f"user/{current_user.username}",
        action="submitted_finding_to_knowledge",
        detail={"finding_id": str(finding_id), "knowledge_record_id": str(orm.id)},
    ))
    await db.commit()

    return KnowledgeInjectResponse(
        knowledge_record_id=str(orm.id),
        message="Finding submitted to knowledge base successfully",
    )


# ── Finding Patch ─────────────────────────────────────────────────────────────

@router.patch(
    "/findings/{finding_id}",
    response_model=FindingResponse,
    summary="Patch finding",
    description="Partially update a finding. Currently supports updating `status`.",
)
async def patch_finding(
    finding_id: UUID,
    body: FindingPatch,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> FindingResponse:
    finding = await db.get(FindingORM, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    if body.status is not None:
        finding.status = body.status

    db.add(AuditLogORM(
        engagement_id=finding.engagement_id,
        actor=f"user/{current_user.username}",
        action="finding_patched",
        detail={"finding_id": str(finding_id), "status": body.status},
    ))
    await db.commit()
    await db.refresh(finding)
    return FindingResponse.model_validate(finding)


# ── KB Manual Inject ──────────────────────────────────────────────────────────

@router.post(
    "/knowledge/inject",
    response_model=KnowledgeInjectResponse,
    status_code=201,
    summary="Manually inject knowledge record",
    description="Directly add a structured knowledge record (technique, CVE write-up, tool docs) without running a scraper.",
)
async def inject_knowledge_record(
    body: KBManualInjectRequest,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> KnowledgeInjectResponse:
    """Manually inject a knowledge record into the KB.

    Allows operators to add custom techniques, CVE write-ups, or
    tool documentation directly without running a scraper.
    """
    from pentra_knowledge.db.base import AsyncSessionLocal as KBSession
    from pentra_knowledge.db.repository import KnowledgeRepository
    import hashlib

    source_id = hashlib.sha256(
        f"manual:{current_user.id}:{body.title}".encode()
    ).hexdigest()[:32]

    async with KBSession()() as kb_db:
        repo = KnowledgeRepository(kb_db)
        existing = await repo.get_by_source_id(source_id)
        if existing:
            return KnowledgeInjectResponse(
                knowledge_record_id=str(existing.id),
                message="Record with this title already exists",
            )

        record_data: dict = {
            "source": body.source,
            "source_id": source_id,
            "source_url": body.url or "",
            "title": body.title,
            "vuln_class": body.vuln_class,
            "vuln_subclass": "",
            "severity": body.severity,
            "program": "manual",
            "tech_stack": body.tech_stack or [],
            "platform_type": ["web"],
            "attack_technique": body.technique or body.title,
            "attack_steps": [],
            "key_insight": body.key_insight or body.title,
            "indicators": [],
            "pentra_tags": ["manual"] + (body.tags or []),
        }

        orm = await repo.create(record_data)
        await kb_db.commit()

    return KnowledgeInjectResponse(
        knowledge_record_id=str(orm.id),
        message="Knowledge record created successfully",
    )


@router.post(
    "/knowledge/inject/url",
    response_model=KnowledgeInjectResponse,
    status_code=201,
    summary="Inject knowledge from URL",
    description="Fetch a public URL (blog post, writeup, CVE advisory), extract text, and queue it for embedding into the knowledge base.",
)
async def inject_knowledge_from_url(
    body: KBUrlInjectRequest,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> KnowledgeInjectResponse:
    """Fetch a URL, extract text content, and inject as a knowledge record.

    The Worker's embed_pending_records task will embed it on the next cycle.
    """
    import hashlib
    import httpx as _httpx
    import re as _re

    from pentra_knowledge.db.base import AsyncSessionLocal as KBSession
    from pentra_knowledge.db.repository import KnowledgeRepository

    source_id = hashlib.sha256(body.url.encode()).hexdigest()[:32]

    # Fetch URL content
    try:
        async with _httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
            resp = await client.get(body.url, headers={"User-Agent": "PentraAI-KB/1.0"})
            resp.raise_for_status()
            raw_html = resp.text
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Failed to fetch URL: {exc}") from exc

    # Strip HTML tags for raw text
    raw_text = _re.sub(r"<[^>]+>", " ", raw_html)
    raw_text = _re.sub(r"\s+", " ", raw_text).strip()[:15000]

    # Extract a title from <title> or first H1/H2
    title_match = _re.search(r"<title[^>]*>([^<]+)</title>", raw_html, _re.I)
    h1_match = _re.search(r"<h[12][^>]*>([^<]+)</h[12]>", raw_html, _re.I)
    title = (title_match or h1_match)
    title = title.group(1).strip()[:200] if title else body.url

    async with KBSession()() as kb_db:
        repo = KnowledgeRepository(kb_db)
        existing = await repo.get_by_source_id(source_id)
        if existing:
            return KnowledgeInjectResponse(
                knowledge_record_id=str(existing.id),
                message="URL already exists in knowledge base",
            )

        record_data: dict = {
            "source": "custom",
            "source_id": source_id,
            "source_url": body.url,
            "title": title,
            "vuln_class": body.vuln_class or "other",
            "vuln_subclass": "",
            "severity": "info",
            "program": "manual",
            "tech_stack": [],
            "platform_type": ["web"],
            "attack_technique": "",
            "attack_steps": [],
            "key_insight": "",
            "indicators": [],
            "pentra_tags": ["url_inject"] + (body.tags or []),
        }

        orm = await repo.create(record_data)
        await kb_db.commit()

    return KnowledgeInjectResponse(
        knowledge_record_id=str(orm.id),
        message="URL content fetched and queued for embedding",
    )


@router.post(
    "/knowledge/inject/file",
    response_model=KnowledgeInjectResponse,
    status_code=201,
    summary="Inject knowledge from file upload",
    description="Upload a Markdown, plain-text, or PDF write-up and ingest it as a knowledge record. The Worker embeds it on the next processing cycle.",
)
async def inject_knowledge_from_file(
    file: UploadFile,
    vuln_class: str = "other",
    tags: str = "",
    current_user: UserORM = Depends(get_current_user),
) -> KnowledgeInjectResponse:
    """Upload a Markdown or plain-text write-up and inject it as a knowledge record.

    PDF support requires `pypdf` installed in the API service.
    The Worker's embed_pending_records task will embed on the next cycle.
    """
    import hashlib

    from pentra_knowledge.db.base import AsyncSessionLocal as KBSession
    from pentra_knowledge.db.repository import KnowledgeRepository

    if file.size and file.size > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 5 MB)")

    content_bytes = await file.read()
    filename = file.filename or "upload"
    content_type = file.content_type or ""

    # Extract text
    if "pdf" in content_type or filename.endswith(".pdf"):
        try:
            import pypdf, io
            reader = pypdf.PdfReader(io.BytesIO(content_bytes))
            raw_text = "\n".join(
                page.extract_text() for page in reader.pages if page.extract_text()
            )[:15000]
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"PDF parse error: {exc}") from exc
    else:
        # Markdown / plain text
        try:
            raw_text = content_bytes.decode("utf-8", errors="replace")[:15000]
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"File decode error: {exc}") from exc

    if not raw_text.strip():
        raise HTTPException(status_code=422, detail="Could not extract text from file")

    # Title: first non-empty line or filename
    first_line = next((l.strip().lstrip("#").strip() for l in raw_text.splitlines() if l.strip()), None)
    title = (first_line or filename)[:200]

    source_id = hashlib.sha256(content_bytes).hexdigest()[:32]
    tag_list = [t.strip() for t in tags.split(",") if t.strip()]

    async with KBSession()() as kb_db:
        repo = KnowledgeRepository(kb_db)
        existing = await repo.get_by_source_id(source_id)
        if existing:
            return KnowledgeInjectResponse(
                knowledge_record_id=str(existing.id),
                message="File already exists in knowledge base",
            )

        record_data: dict = {
            "source": "custom",
            "source_id": source_id,
            "source_url": "",
            "title": title,
            "vuln_class": vuln_class if vuln_class and vuln_class != "other" else "other",
            "vuln_subclass": "",
            "severity": "info",
            "program": "manual",
            "tech_stack": [],
            "platform_type": ["web"],
            "attack_technique": "",
            "attack_steps": [],
            "key_insight": "",
            "indicators": [],
            "pentra_tags": ["file_upload"] + tag_list,
        }

        orm = await repo.create(record_data)
        await kb_db.commit()

    return KnowledgeInjectResponse(
        knowledge_record_id=str(orm.id),
        message="File content ingested and queued for embedding",
    )


# ── Payload Generator ─────────────────────────────────────────────────────────

@router.post(
    "/payloads/generate",
    response_model=PayloadGenerateAPIResponse,
    summary="Generate attack payloads",
    description="Generate context-aware attack payloads using LLM reasoning + RAG knowledge base. Queries the KB for similar vulnerability patterns, then passes them with target context to the LLM.",
)
async def generate_payloads(
    data: PayloadGenerateAPIRequest,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> PayloadGenerateAPIResponse:
    """Generate context-aware payloads using LLM + RAG knowledge base.

    Queries the knowledge base for similar vuln patterns, then passes them
    together with the target context to the LLM for targeted payload generation.
    """
    from app.core.config import get_api_settings
    from pentra_knowledge.services.search import hybrid_search
    from pentra_payload.generator import PayloadGenerator
    from pentra_payload.models import PayloadContext
    from pentra_shared.types.vuln_class import VulnClass

    settings = get_api_settings()

    # Resolve vuln_class enum safely
    try:
        vc = VulnClass(data.vuln_class)
    except ValueError:
        vc = VulnClass.OTHER

    # RAG: find relevant KB records for this vuln class + tech stack
    search_query = (
        f"{data.vuln_class} {data.parameter_name} {' '.join(data.tech_stack)}"
    ).strip()
    kb_results = await hybrid_search(
        query=search_query,
        db=db,
        vuln_class=[data.vuln_class] if data.vuln_class else None,
        top_k=8,
    )
    knowledge_dicts = [r.model_dump() if hasattr(r, "model_dump") else dict(r) for r in kb_results]

    ctx = PayloadContext(
        vuln_class=vc,
        tech_stack=data.tech_stack,
        target_url=data.target_url,
        parameter_name=data.parameter_name,
        parameter_value=data.parameter_value,
        parameter_position=data.parameter_position,  # type: ignore[arg-type]
        http_method=data.http_method,
        additional_context=data.additional_context,
    )

    ollama_url = getattr(settings, "ollama_url", "http://localhost:11434")
    model = getattr(settings, "ollama_model_default", "qwen2.5:32b")
    generator = PayloadGenerator(ollama_url=ollama_url, model=model)
    payloads = await generator.generate(ctx, knowledge_dicts, count=data.count)

    return PayloadGenerateAPIResponse(
        payloads=[
            PayloadItem(
                value=p.value,
                rationale=p.rationale,
                severity_hint=p.severity_hint,
                requires_encoding=p.requires_encoding,
            )
            for p in payloads
        ],
        knowledge_used=len(knowledge_dicts),
        model_used=model,
    )


# ── Event history (REST fallback for page refresh) ───────────────────────────

@router.get("/engagements/{engagement_id}/events")
async def get_engagement_events(
    engagement_id: UUID,
    limit: int = Query(default=200, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> list[dict]:
    """Return event history for an engagement.

    Priority: in-memory ring buffer first (fast, no DB hit).
    Fallback: DB query when buffer is empty (e.g. after server restart).
    Used by the frontend on page load to restore history.
    """
    # Try in-memory buffer first
    history = ws_manager.get_history(str(engagement_id))
    if history:
        return history[-limit:]

    # DB fallback — reads persisted events (Task 19.4)
    try:
        from sqlalchemy import select
        from app.db.models import AgentEventORM

        result = await db.execute(
            select(AgentEventORM)
            .where(AgentEventORM.engagement_id == engagement_id)
            .order_by(AgentEventORM.created_at.desc())
            .limit(limit)
        )
        events = result.scalars().all()
        return [
            {
                "type": e.event_type,
                "node": e.node,
                "content": e.content,
                **(e.data or {}),
                "timestamp": e.created_at.isoformat(),
            }
            for e in reversed(events)  # chronological order
        ]
    except Exception as exc:
        log.warning("[events] DB fallback failed: %s", exc)
        return []


# ── WebSocket live feed ───────────────────────────────────────────────────────

@router.websocket("/ws/engagements/{engagement_id}/feed")
async def engagement_feed(
    websocket: WebSocket,
    engagement_id: UUID,
    token: str = Query(...),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Real-time event stream for a running engagement."""
    from app.core.security import decode_token
    try:
        payload = decode_token(token)
        user_id = payload.get("sub")
    except Exception:
        await websocket.close(code=4401)
        return
    eng = await db.get(EngagementORM, engagement_id)
    if eng is None or str(eng.created_by) != user_id:
        await websocket.close(code=4403)
        return
    eid = str(engagement_id)
    await ws_manager.connect(websocket, eid)
    try:
        while True:
            await asyncio.sleep(20)
            await websocket.send_json({"type": "ping", "engagement_id": eid})
    except Exception:  # WebSocketDisconnect, RuntimeError("send after close"), etc.
        pass
    finally:
        await ws_manager.disconnect(websocket, eid)


# ── Internal helper ───────────────────────────────────────────────────────────


class _EngagementCancelled(Exception):
    """Raised inside _run_agent when DB shows status='cancelled' from another worker/process."""


async def _run_agent(eng: EngagementORM) -> None:
    """Background task: run the LangGraph agent and stream events to WebSocket."""
    import json

    from app.core.agent import get_agent_service

    engagement_id = str(eng.id)
    agent_service = get_agent_service()
    live_log_token = _live_feed_engagement_id.set(engagement_id)
    live_log_handler = _attach_live_feed_log_handler(engagement_id)
    log.info("[live_feed] terminal output attached for engagement %s", engagement_id)

    # Derive the primary domain for tools (subfinder, crt.sh, etc.) from in_scope.
    # Rules:
    #   - Skip CIDR ranges (nmap handles those separately via ip_ranges)
    #   - Strip wildcard prefix: "*.example.com" → "example.com"
    #   - Pick the shortest non-CIDR entry (most likely the root domain)
    import re as _re
    _cidr_re = _re.compile(r"^\d+\.\d+\.\d+\.\d+/\d+$")
    _non_cidr = [s for s in eng.in_scope if not _cidr_re.match(s)]
    _ip_ranges = [s for s in eng.in_scope if _cidr_re.match(s)]
    if _non_cidr:
        # Strip wildcard prefixes, then pick shortest (root domain, not subdomain)
        _stripped = [_re.sub(r"^\*\.", "", s) for s in _non_cidr]
        _domain = min(_stripped, key=len)
    else:
        _domain = ""

    # Build base_urls from all non-CIDR in_scope items (not just the first)
    def _to_base_url(scope_entry: str) -> str:
        bare = _re.sub(r"^\*\.", "", scope_entry)
        scheme = "http" if bare.split(":")[0] in ("localhost", "127.0.0.1", "::1") else "https"
        return f"{scheme}://{bare}"

    _base_urls = [_to_base_url(s) for s in _non_cidr] if _non_cidr else []

    initial_state = {
        "engagement_id": engagement_id,
        "target": {
            "domain": _domain,
            "ip_ranges": _ip_ranges,
            "base_urls": _base_urls,
        },
        "scope": {
            "in_scope": list(eng.in_scope),
            "out_of_scope": list(eng.out_of_scope),
        },
        "mode": eng.mode,
        "llm_model": eng.llm_model,
        "opsec_mode": eng.opsec_mode,
        "request_jitter_ms": eng.request_jitter_ms,
        "scan_sequential": bool(getattr(eng, "scan_sequential", False)),
        "auto_approve_exploit_validation": bool(getattr(eng, "auto_approve_exploit_validation", False)),
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

    def _ts() -> str:
        return datetime.now(UTC).isoformat()

    await ws_manager.broadcast(engagement_id, {
        "type": "agent_start",
        "message": "Agent starting…",
        "timestamp": _ts(),
    })

    _chk_engine = None
    try:
        # One shared session factory for cross-worker cancellation checks (one query per node)
        from sqlalchemy.ext.asyncio import AsyncSession as _AS, create_async_engine as _cae
        from sqlalchemy.orm import sessionmaker as _sm_chk
        from app.core.config import get_api_settings as _get_s
        _chk_engine = _cae(_get_s().database_url, echo=False, pool_size=1, max_overflow=0)
        _chk_session = _sm_chk(_chk_engine, class_=_AS, expire_on_commit=False)

        # Apply scan preset env vars before graph invocation so vuln_hunt_node
        # reads the correct tool flags and limits for this engagement.
        try:
            from pentra_agent.scan_presets import get_preset as _get_preset
            _preset_name = getattr(eng, "scan_preset", "fast") or "fast"
            _get_preset(_preset_name).apply_to_env()
            log.info("[_run_agent] Preset '%s' applied for engagement %s", _preset_name, engagement_id)
        except Exception as _preset_exc:
            log.warning("[_run_agent] Failed to apply preset (non-fatal): %s", _preset_exc)

        # Stream events from the graph using astream_events
        graph = agent_service.graph
        config = {"configurable": {"thread_id": engagement_id}}

        async for event in graph.astream_events(initial_state, config=config, version="v2"):
            kind = event.get("event", "")
            name = event.get("name", "")

            if kind == "on_chain_start" and name not in ("LangGraph", "__start__"):
                await ws_manager.broadcast(engagement_id, {
                    "type": "agent_step",
                    "message": f"▶ {name}",
                    "timestamp": _ts(),
                })
            elif kind == "on_chain_end" and name not in ("LangGraph", "__end__"):
                data = event.get("data", {})
                output = data.get("output", {})
                phase = output.get("current_phase", "") if isinstance(output, dict) else ""
                msg = f"✓ {name}" + (f" → {phase}" if phase else "")
                await ws_manager.broadcast(engagement_id, {
                    "type": "agent_step",
                    "message": msg,
                    "timestamp": _ts(),
                })
                # Check DB status at each node boundary — handles cross-worker cancellation
                # where task.cancel() in stop_engagement can't reach us (different process)
                async with _chk_session() as _cs:
                    _ce = await _cs.get(EngagementORM, uuid.UUID(engagement_id))
                    if _ce and _ce.status == "cancelled":
                        raise _EngagementCancelled()
        # After astream_events loop — check if the graph is paused at an interrupt
        config = {"configurable": {"thread_id": engagement_id}}
        graph_state = await graph.aget_state(config)
        is_interrupted = bool(getattr(graph_state, "next", None))

        if is_interrupted:
            # Extract interrupt payloads from pending tasks
            interrupt_payloads = []
            for task in getattr(graph_state, "tasks", []):
                for intr in getattr(task, "interrupts", []):
                    iv = intr.value if hasattr(intr, "value") else intr
                    interrupt_payloads.append(iv)

            payload = interrupt_payloads[0] if interrupt_payloads else {"phase": "unknown"}

            # ── Update DB status → awaiting_approval ──────────────────────
            from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
            from sqlalchemy.orm import sessionmaker as _sm
            from app.core.config import get_api_settings as _get_s
            _engine = create_async_engine(_get_s().database_url, echo=False)
            _asession = _sm(_engine, class_=AsyncSession, expire_on_commit=False)
            async with _asession() as _sess:
                _eng = await _sess.get(EngagementORM, uuid.UUID(engagement_id))
                if _eng:
                    _eng.status = "awaiting_approval"
                    await _sess.commit()
            await _engine.dispose()

            await ws_manager.broadcast(engagement_id, {
                "type": "AWAITING_APPROVAL",
                "message": "⏸ Waiting for human approval",
                "timestamp": _ts(),
                "data": payload,
                "next_nodes": list(getattr(graph_state, "next", [])),
            })
        else:
            # ── Update DB status → completed ──────────────────────────────
            from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
            from sqlalchemy.orm import sessionmaker as _sm
            from app.core.config import get_api_settings as _get_s
            _engine = create_async_engine(_get_s().database_url, echo=False)
            _asession = _sm(_engine, class_=AsyncSession, expire_on_commit=False)
            async with _asession() as _sess:
                _eng = await _sess.get(EngagementORM, uuid.UUID(engagement_id))
                if _eng:
                    _eng.status = "completed"
                    _eng.completed_at = datetime.now(UTC).replace(tzinfo=None)
                    await _sess.commit()
            await _engine.dispose()

            await ws_manager.broadcast(engagement_id, {
                "type": "agent_complete",
                "message": "✅ Agent run complete",
                "timestamp": _ts(),
            })

    except _EngagementCancelled:
        # Cancelled by user — DB status already set by stop_engagement; just notify the feed
        await ws_manager.broadcast(engagement_id, {
            "type": "agent_cancelled",
            "message": "⛔ Engagement cancelled",
            "timestamp": _ts(),
        })
    except Exception as exc:  # noqa: BLE001
        import logging as _log
        _log.getLogger(__name__).error("[_run_agent] %s: %s", type(exc).__name__, exc, exc_info=True)
        # Update DB status → failed so the engagement doesn't stay stuck as active
        try:
            from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
            from sqlalchemy.orm import sessionmaker as _sm
            from app.core.config import get_api_settings as _get_s
            _engine2 = create_async_engine(_get_s().database_url, echo=False)
            _asession2 = _sm(_engine2, class_=AsyncSession, expire_on_commit=False)
            async with _asession2() as _sess2:
                _eng2 = await _sess2.get(EngagementORM, uuid.UUID(engagement_id))
                if _eng2 and _eng2.status not in ("completed", "awaiting_approval"):
                    _eng2.status = "failed"
                    await _sess2.commit()
            await _engine2.dispose()
        except Exception:  # noqa: BLE001
            pass
        await ws_manager.broadcast(engagement_id, {
            "type": "error",
            "message": f"❌ Agent error: {exc}",
            "timestamp": _ts(),
        })
    finally:
        _detach_live_feed_log_handler(live_log_handler)
        _live_feed_engagement_id.reset(live_log_token)
        if _chk_engine is not None:
            await _chk_engine.dispose()


async def _resume_agent(engagement_id: str, user_decision: str) -> None:
    """Background task: update state with HITL decision, then stream resumed agent events."""
    from app.core.agent import get_agent_service
    from langgraph.types import Command

    agent_service = get_agent_service()
    graph = agent_service.graph
    config = {"configurable": {"thread_id": engagement_id}}
    live_log_token = _live_feed_engagement_id.set(engagement_id)
    live_log_handler = _attach_live_feed_log_handler(engagement_id)
    log.info("[live_feed] terminal output attached for engagement %s", engagement_id)

    def _ts() -> str:
        return datetime.now(UTC).isoformat()

    try:
        # ── Update DB status → active (leaving awaiting_approval) ──────────────
        from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
        from sqlalchemy.orm import sessionmaker as _sm
        from app.core.config import get_api_settings as _get_s
        _engine = create_async_engine(_get_s().database_url, echo=False)
        _asession = _sm(_engine, class_=AsyncSession, expire_on_commit=False)
        async with _asession() as _sess:
            _eng = await _sess.get(EngagementORM, uuid.UUID(engagement_id))
            if _eng:
                _eng.status = "active"
                await _sess.commit()
        await _engine.dispose()

        await ws_manager.broadcast(engagement_id, {
            "type": "agent_resumed",
            "message": f"▶ Resuming with decision: {user_decision}",
            "timestamp": _ts(),
        })

        # Resume the interrupt() call with the user's decision value
        async for event in graph.astream_events(Command(resume=user_decision), config=config, version="v2"):
            kind = event.get("event", "")
            name = event.get("name", "")

            if kind == "on_chain_start" and name not in ("LangGraph", "__start__"):
                await ws_manager.broadcast(engagement_id, {
                    "type": "agent_step",
                    "message": f"▶ {name}",
                    "timestamp": _ts(),
                })
            elif kind == "on_chain_end" and name not in ("LangGraph", "__end__"):
                data = event.get("data", {})
                output = data.get("output", {})
                phase = output.get("current_phase", "") if isinstance(output, dict) else ""
                msg = f"✓ {name}" + (f" → {phase}" if phase else "")
                await ws_manager.broadcast(engagement_id, {
                    "type": "agent_step",
                    "message": msg,
                    "timestamp": _ts(),
                })

        # After stream ends, check if paused again (another interrupt)
        graph_state = await graph.aget_state(config)
        is_interrupted = bool(getattr(graph_state, "next", None))

        if is_interrupted:
            interrupt_payloads = []
            for task in getattr(graph_state, "tasks", []):
                for intr in getattr(task, "interrupts", []):
                    iv = intr.value if hasattr(intr, "value") else intr
                    interrupt_payloads.append(iv)
            payload = interrupt_payloads[0] if interrupt_payloads else {"phase": "unknown"}

            # ── Update DB status → awaiting_approval ──────────────────────
            from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
            from sqlalchemy.orm import sessionmaker as _sm
            from app.core.config import get_api_settings as _get_s
            _engine = create_async_engine(_get_s().database_url, echo=False)
            _asession = _sm(_engine, class_=AsyncSession, expire_on_commit=False)
            async with _asession() as _sess:
                _eng = await _sess.get(EngagementORM, uuid.UUID(engagement_id))
                if _eng:
                    _eng.status = "awaiting_approval"
                    await _sess.commit()
            await _engine.dispose()

            await ws_manager.broadcast(engagement_id, {
                "type": "AWAITING_APPROVAL",
                "message": "⏸ Waiting for human approval",
                "timestamp": _ts(),
                "data": payload,
                "next_nodes": list(getattr(graph_state, "next", [])),
            })
        else:
            # ── Update DB status → completed ──────────────────────────────
            from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
            from sqlalchemy.orm import sessionmaker as _sm
            from app.core.config import get_api_settings as _get_s
            _engine = create_async_engine(_get_s().database_url, echo=False)
            _asession = _sm(_engine, class_=AsyncSession, expire_on_commit=False)
            async with _asession() as _sess:
                _eng = await _sess.get(EngagementORM, uuid.UUID(engagement_id))
                if _eng:
                    _eng.status = "completed"
                    _eng.completed_at = datetime.now(UTC).replace(tzinfo=None)
                    await _sess.commit()
            await _engine.dispose()

            await ws_manager.broadcast(engagement_id, {
                "type": "agent_complete",
                "message": "✅ Agent run complete",
                "timestamp": _ts(),
            })

    except Exception as exc:  # noqa: BLE001
        import traceback
        import logging as _logging
        _log = _logging.getLogger("app.resume_agent")
        _log.exception("[_resume_agent] Fatal error for engagement %s: %s", engagement_id, exc)
        # Also write to file in case WS broadcast fails
        try:
            with open("/tmp/resume-errors.log", "a") as _f:
                _f.write(f"{_ts()} engagement={engagement_id} error={exc}\n{traceback.format_exc()}\n---\n")
        except Exception:  # noqa: BLE001
            pass
        await ws_manager.broadcast(engagement_id, {
            "type": "error",
            "message": f"❌ Resume error: {exc}",
            "timestamp": _ts(),
        })
    finally:
        _detach_live_feed_log_handler(live_log_handler)
        _live_feed_engagement_id.reset(live_log_token)
