"""Internal API — endpoints called by pentra-agent (not exposed to end users).

All routes require the ``X-Internal-Token`` header matching ``INTERNAL_API_TOKEN``.
These endpoints are NOT authenticated via JWT — they use a shared secret that is
only known to services running inside the same deployment.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_api_settings
from app.db.base import get_db
from app.db.models import EngagementORM, FindingORM

log = logging.getLogger(__name__)

router = APIRouter(prefix="/internal", tags=["internal"])


# ── Auth dependency ───────────────────────────────────────────────────────────

def verify_internal_token(
    x_internal_token: str = Header(..., alias="X-Internal-Token"),
) -> None:
    settings = get_api_settings()
    expected = settings.internal_api_token
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Internal API token not configured",
        )
    if x_internal_token != expected:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid internal token",
        )


# ── Schemas ───────────────────────────────────────────────────────────────────

class FindingPayload(BaseModel):
    title: str
    vuln_class: str = "Unknown"
    severity: str = "info"
    target_url: str = ""
    http_method: str = "GET"
    request_raw: str = ""
    response_raw: str = ""
    description: str | None = None
    impact: str | None = None
    remediation: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    reproduction_steps: list = Field(default_factory=list)
    knowledge_refs: list = Field(default_factory=list)
    cve_ids: list = Field(default_factory=list)
    chains: list | None = None
    discovered_by: str = "agent"


class BulkFindingsRequest(BaseModel):
    engagement_id: str
    findings: list[FindingPayload]


class BulkFindingsResponse(BaseModel):
    created: int
    skipped: int
    engagement_id: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post(
    "/findings/bulk",
    response_model=BulkFindingsResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Bulk-persist agent findings",
    description=(
        "Called by the pentra-agent report_node to persist all findings "
        "discovered during an engagement. Skips duplicates (title + url match)."
    ),
    dependencies=[Depends(verify_internal_token)],
)
async def bulk_create_findings(
    body: BulkFindingsRequest,
    db: AsyncSession = Depends(get_db),
) -> BulkFindingsResponse:
    try:
        engagement_id = UUID(body.engagement_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid engagement_id UUID")

    # Verify engagement exists
    eng = await db.get(EngagementORM, engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="Engagement not found")

    # Load existing finding keys to skip duplicates
    from sqlalchemy import select
    existing_result = await db.execute(
        select(FindingORM.title, FindingORM.target_url)
        .where(FindingORM.engagement_id == engagement_id)
    )
    existing_keys: set[tuple[str, str]] = {
        (row.title, row.target_url) for row in existing_result
    }

    created = 0
    skipped = 0

    for f in body.findings:
        key = (f.title, f.target_url)
        if key in existing_keys:
            skipped += 1
            continue

        finding = FindingORM(
            id=uuid4(),
            engagement_id=engagement_id,
            title=f.title,
            vuln_class=f.vuln_class,
            severity=f.severity.lower(),
            target_url=f.target_url,
            http_method=f.http_method,
            request_raw=f.request_raw,
            response_raw=f.response_raw,
            description=f.description,
            impact=f.impact,
            remediation=f.remediation,
            cvss_score=f.cvss_score,
            cvss_vector=f.cvss_vector,
            reproduction_steps=f.reproduction_steps,
            knowledge_refs=f.knowledge_refs,
            cve_ids=f.cve_ids,
            chains=f.chains,
            discovered_by=f.discovered_by,
            discovered_at=datetime.now(timezone.utc).replace(tzinfo=None),
            status="new",
        )
        db.add(finding)
        existing_keys.add(key)
        created += 1

    await db.commit()
    log.info(
        "[internal] bulk_create_findings: engagement=%s created=%d skipped=%d",
        body.engagement_id, created, skipped,
    )

    return BulkFindingsResponse(
        created=created,
        skipped=skipped,
        engagement_id=body.engagement_id,
    )
