"""Report generation endpoint.

Routes:
  GET /api/v1/engagements/{id}/report?format=markdown|html|pdf|h1
"""

from __future__ import annotations

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.db.base import get_db
from app.db.models import EngagementORM, FindingORM, UserORM

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["reports"])


@router.get(
    "/engagements/{engagement_id}/report",
    summary="Generate engagement report",
    description="Generate a Markdown report for an engagement including executive summary, findings, CVSS scores, and remediation recommendations. Returns plain text Markdown.",
)
async def get_report(
    engagement_id: UUID,
    format: str = Query(default="markdown", pattern="^(markdown|html|pdf|h1)$"),
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
):
    """Generate a report for an engagement.

    - **markdown** — Markdown text (default)
    - **html** — Standalone HTML with embedded CSS
    - **pdf** — Binary PDF (Content-Type: application/pdf)
    - **h1** — HackerOne submission format per finding
    """
    try:
        from pentra_report import ReportData, ReportFormat, ReportGenerator
        from pentra_report.generator import FindingReport
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="pentra-report not installed") from exc

    # Load engagement
    result = await db.execute(select(EngagementORM).where(EngagementORM.id == engagement_id))
    eng = result.scalar_one_or_none()
    if eng is None:
        raise HTTPException(status_code=404, detail="Engagement not found")

    # Load findings
    f_result = await db.execute(
        select(FindingORM).where(FindingORM.engagement_id == engagement_id)
    )
    findings_orm = f_result.scalars().all()

    findings = [
        FindingReport(
            title=f.title,
            severity=f.severity,
            vuln_class=f.vuln_class,
            cvss_score=f.cvss_score,
            cvss_vector=f.cvss_vector,
            target_url=f.target_url or "",
            http_method=f.http_method or "GET",
            description=f.description or "",
            reproduction_steps=list(f.reproduction_steps or []),
            request_raw=f.request_raw or "",
            response_raw=f.response_raw or "",
            status=f.status or "open",
            discovered_by=f.discovered_by or "",
            discovered_at=str(f.discovered_at)[:10] if f.discovered_at else "",
        )
        for f in findings_orm
    ]

    data = ReportData(
        engagement_name=eng.name,
        target_domain=eng.in_scope[0] if eng.in_scope else "",
        in_scope=list(eng.in_scope),
        out_of_scope=list(eng.out_of_scope or []),
        mode=eng.mode,
        llm_model=eng.llm_model,
        started_at=str(eng.started_at) if eng.started_at else "",
        completed_at=str(eng.completed_at) if eng.completed_at else "",
        findings=findings,
    )

    gen = ReportGenerator()
    fmt = ReportFormat(format)
    output = gen.render(data, fmt)

    if fmt == ReportFormat.PDF:
        return Response(
            content=output,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="report-{engagement_id}.pdf"'
            },
        )
    elif fmt == ReportFormat.HTML:
        return HTMLResponse(content=output)
    elif fmt == ReportFormat.H1:
        import json  # noqa: PLC0415
        return JSONResponse(content=json.loads(output))
    else:
        return PlainTextResponse(content=output)


@router.get(
    "/engagements/{engagement_id}/report/h1-summary",
    summary="Generate H1-ready executive summary report",
    description="Generate a HackerOne-ready Markdown report with LLM executive summary.",
)
async def get_h1_summary_report(
    engagement_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> PlainTextResponse:
    """Generate full H1-ready report with LLM executive summary (Task 19.5)."""
    try:
        from pentra_report.h1_report import generate_h1_report
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="pentra-report not installed") from exc

    # Load engagement
    result = await db.execute(select(EngagementORM).where(EngagementORM.id == engagement_id))
    eng = result.scalar_one_or_none()
    if eng is None:
        raise HTTPException(status_code=404, detail="Engagement not found")

    # Load findings
    f_result = await db.execute(
        select(FindingORM).where(FindingORM.engagement_id == engagement_id)
    )
    findings_orm = f_result.scalars().all()

    if not findings_orm:
        return PlainTextResponse(content="# No findings for this engagement.\n")

    findings = [
        {
            "title": f.title,
            "severity": f.severity,
            "vuln_class": f.vuln_class,
            "cvss_score": f.cvss_score,
            "target_url": f.target_url or "",
            "description": f.description or "",
            "impact": f.impact or "",
            "remediation": f.remediation or "",
            "request_raw": f.request_raw or "",
            "response_raw": f.response_raw or "",
            "payload": getattr(f, "payload", "") or "",
        }
        for f in findings_orm
    ]

    engagement_dict = {
        "target_domain": eng.in_scope[0] if eng.in_scope else "",
        "id": str(engagement_id),
        "duration_minutes": (
            int((eng.completed_at - eng.started_at).total_seconds() / 60)
            if eng.completed_at and eng.started_at
            else 0
        ),
    }

    try:
        from pentra_agent.llm.client import LLMClient
        from app.core.config import get_api_settings
        _s = get_api_settings()
        llm = LLMClient(
            base_url=_s.ollama_url + "/v1",
            model=eng.llm_model or _s.ollama_model_default,
        )
        report_md = await generate_h1_report(
            engagement=engagement_dict,
            findings=findings,
            llm=llm,
        )
    except Exception as exc:
        log.error("[h1_summary] Report generation failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Report generation failed: {exc}") from exc

    return PlainTextResponse(
        content=report_md,
        headers={
            "Content-Disposition": f'attachment; filename="h1-report-{engagement_id}.md"',
        },
    )

