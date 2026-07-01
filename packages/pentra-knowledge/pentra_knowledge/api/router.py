"""FastAPI router for the Knowledge Engine.

Endpoints:
    GET  /knowledge/search         — hybrid semantic + lexical search
    GET  /knowledge/{id}           — retrieve a single record by UUID
    POST /knowledge/inject         — manually inject a fully-structured record
    POST /knowledge/inject/raw     — inject raw text + trigger LLM extraction
"""

from uuid import UUID, uuid4
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_knowledge.api.schemas import (
    KnowledgeInjectRequest,
    KnowledgeInjectResponse,
    KnowledgeRawInjectRequest,
    KnowledgeSummary,
    SearchResponse,
)
from pentra_knowledge.config import get_settings
from pentra_knowledge.db.base import get_db
from pentra_knowledge.db.repository import KnowledgeRepository
from pentra_knowledge.services.search import hybrid_search
from pentra_shared.types import KnowledgeRecord, KnowledgeSource, Severity, VulnClass

router = APIRouter(prefix="/knowledge", tags=["knowledge"])


@router.get("/search", response_model=SearchResponse)
async def search_knowledge(
    q: str = Query(default="", min_length=0, max_length=1000, description="Search query (optional when filters provided)"),
    vuln_class: list[VulnClass] | None = Query(default=None),
    severity: list[Severity] | None = Query(default=None),
    tech_stack: list[str] | None = Query(default=None),
    source: list[KnowledgeSource] | None = Query(default=None),
    top_k: int = Query(default=8, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
) -> SearchResponse:
    """Search the knowledge base using BGE-M3 hybrid retrieval.

    Combines dense semantic search and sparse lexical matching with optional
    metadata filters.  Results are ordered by Reciprocal Rank Fusion score.

    The query should describe the attack context, e.g.:
        "IDOR on Rails REST API with numeric user IDs"
    """
    settings = get_settings()
    effective_top_k = min(top_k, settings.knowledge_search_max_top_k)

    records = await hybrid_search(
        query=q,
        db=db,
        vuln_class=[vc.value for vc in vuln_class] if vuln_class else None,
        severity=[s.value for s in severity] if severity else None,
        tech_stack=tech_stack,
        source=[src for src in source] if source else None,
        top_k=effective_top_k,
    )

    return SearchResponse(
        results=[KnowledgeSummary.from_record(r) for r in records],
        total=len(records),
        query=q,
    )


@router.get("/{record_id}", response_model=KnowledgeRecord)
async def get_knowledge_record(
    record_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> KnowledgeRecord:
    """Retrieve a single knowledge record by its UUID.

    Returns the full record including all attack intelligence fields.
    Embedding vectors are excluded from the response.
    """
    repo = KnowledgeRepository(db)
    record = await repo.get_by_id(record_id)

    if record is None:
        raise HTTPException(status_code=404, detail="Knowledge record not found")

    return record


@router.post("/inject", response_model=KnowledgeInjectResponse, status_code=202)
async def inject_knowledge(
    payload: KnowledgeInjectRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> KnowledgeInjectResponse:
    """Manually inject a fully-structured knowledge record.

    Saves to PostgreSQL immediately. Embedding into Qdrant is triggered
    as a background task.

    Returns 409 if a record with the same source_id already exists.
    """
    repo = KnowledgeRepository(db)

    if await repo.exists_by_source_id(payload.source_id):
        raise HTTPException(
            status_code=409,
            detail=f"Record with source_id '{payload.source_id}' already exists",
        )

    now = datetime.now(timezone.utc)
    record_id = uuid4()

    await repo.create(
        {
            "id": record_id,
            "source": payload.source,
            "source_id": payload.source_id,
            "source_url": payload.source_url,
            "ingested_at": now,
            "updated_at": now,
            "title": payload.title,
            "vuln_class": payload.vuln_class.value,
            "vuln_subclass": payload.vuln_subclass,
            "severity": payload.severity.value,
            "cvss_score": payload.cvss_score,
            "cvss_vector": payload.cvss_vector,
            "cve_id": payload.cve_id,
            "program": payload.program,
            "tech_stack": payload.tech_stack,
            "platform_type": payload.platform_type,
            "endpoint_pattern": payload.endpoint_pattern,
            "http_method": payload.http_method,
            "auth_required": payload.auth_required,
            "attack_technique": payload.attack_technique,
            "attack_steps": payload.attack_steps,
            "payload_pattern": payload.payload_pattern,
            "indicators": payload.indicators,
            "prerequisites": payload.prerequisites,
            "what_tools_missed": payload.what_tools_missed,
            "chained_with": payload.chained_with,
            "impact": payload.impact,
            "impact_category": payload.impact_category,
            "bounty_usd": payload.bounty_usd,
            "key_insight": payload.key_insight,
            "unique_factor": payload.unique_factor,
            "pentra_tags": payload.pentra_tags,
            "is_embedded": False,
        }
    )

    settings = get_settings()
    background_tasks.add_task(_embed_record_bg, str(record_id), payload, settings)

    return KnowledgeInjectResponse(id=record_id)


@router.post("/inject/raw", response_model=KnowledgeInjectResponse, status_code=202)
async def inject_knowledge_raw(
    payload: KnowledgeRawInjectRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> KnowledgeInjectResponse:
    """Inject a raw text report — LLM extraction runs automatically.

    Accepts a title + raw report text (e.g. a writeup, H1 report copy-paste).
    The record is saved immediately with available metadata; LLM extraction
    and Qdrant embedding run as a background task.

    Use this endpoint to inject custom writeups, internal findings, or
    any free-form vulnerability description into the knowledge base.
    """
    repo = KnowledgeRepository(db)

    source_id = payload.source_id or f"custom_{uuid4().hex[:12]}"
    if await repo.exists_by_source_id(source_id):
        raise HTTPException(
            status_code=409,
            detail=f"Record with source_id '{source_id}' already exists",
        )

    now = datetime.now(timezone.utc)
    record_id = uuid4()

    # Save minimal record immediately — LLM will fill the rest
    await repo.create({
        "id": record_id,
        "source": payload.source or "custom",
        "source_id": source_id,
        "source_url": payload.source_url,
        "ingested_at": now,
        "updated_at": now,
        "title": payload.title[:500],
        "raw_content": payload.raw_text[:10000] if payload.raw_text else "",
        "vuln_class": (payload.vuln_class.value if payload.vuln_class else "other"),
        "severity": (payload.severity.value if payload.severity else "info"),
        "program": (payload.program or "custom")[:200],
        "bounty_usd": payload.bounty_usd,
        "is_embedded": False,
        # All LLM-extracted fields start empty
        "attack_technique": "",
        "key_insight": "",
        "indicators": [],
        "attack_steps": [],
        "prerequisites": [],
        "tech_stack": [],
        "platform_type": [],
        "http_method": [],
        "impact_category": [],
        "chained_with": [],
        "pentra_tags": [],
    })

    settings = get_settings()
    background_tasks.add_task(
        _llm_extract_and_embed_bg, str(record_id), payload, settings
    )

    return KnowledgeInjectResponse(
        id=record_id,
        status="queued",
        message="Record saved. LLM extraction and embedding running in background.",
    )


# ── Background task helpers ────────────────────────────────────────────────────

async def _embed_record_bg(record_id: str, payload: KnowledgeInjectRequest, settings) -> None:
    """Embed an already-structured record into Qdrant (background task)."""
    try:
        from pentra_knowledge.db.database import get_session_factory
        from pentra_knowledge.db.repository import KnowledgeRepository
        from pentra_knowledge.services.embedding import EmbeddingService

        session_factory = get_session_factory(settings.database_url)
        repo = KnowledgeRepository(session_factory)
        embed_svc = EmbeddingService(settings)

        text = " ".join(filter(None, [
            payload.title,
            payload.attack_technique,
            payload.key_insight,
            " ".join(payload.indicators),
            payload.impact,
        ]))
        vector = await embed_svc.embed(text)
        await embed_svc.upsert_point(record_id, vector, {"title": payload.title})
        await repo.mark_embedded(record_id)
    except Exception as exc:
        import logging
        logging.getLogger(__name__).error("Background embed failed for %s: %s", record_id, exc)


async def _llm_extract_and_embed_bg(
    record_id: str,
    payload: "KnowledgeRawInjectRequest",
    settings,
) -> None:
    """Run LLM extraction on raw text, update the record, then embed (background task)."""
    import json
    import re
    import httpx
    import logging
    from pentra_knowledge.db.database import get_session_factory
    from pentra_knowledge.db.repository import KnowledgeRepository
    from pentra_knowledge.services.embedding import EmbeddingService

    log = logging.getLogger(__name__)
    session_factory = get_session_factory(settings.database_url)
    repo = KnowledgeRepository(session_factory)
    embed_svc = EmbeddingService(settings)

    try:
        system = (
            "/no_think\n"
            "You are a security researcher extracting structured threat intelligence "
            "from a vulnerability report. "
            "Return ONLY a valid JSON object — no explanation, no markdown fences."
        )
        user = f"""Analyze this vulnerability report and extract security intelligence.

Title: {payload.title}
Program: {payload.program or 'unknown'}
Severity: {payload.severity.value if payload.severity else 'unknown'}

Report text:
{(payload.raw_text or '')[:4000]}

Extract this JSON:
{{
  "vuln_class":        "primary vulnerability class",
  "tech_stack":        ["technologies involved"],
  "platform_type":     ["web|api|mobile|cloud|network"],
  "endpoint_pattern":  "generalised URL",
  "http_method":       ["GET|POST|..."],
  "auth_required":     true,
  "attack_technique":  "HOW the bug was exploited (2-3 sentences)",
  "attack_steps":      ["step 1", "step 2", "step 3"],
  "indicators":        ["observable signals"],
  "prerequisites":     ["conditions required"],
  "what_tools_missed": "why automated tools missed this",
  "impact":            "impact if exploited",
  "impact_category":   ["account_takeover|data_exfil|rce|dos|information_disclosure|privilege_escalation"],
  "key_insight":       "the aha moment — what made this non-obvious",
  "unique_factor":     "what made this hard to find"
}}"""

        async with httpx.AsyncClient(base_url=settings.ollama_url) as client:
            resp = await client.post(
                "/api/chat",
                json={
                    "model": settings.ollama_model_fast,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "stream": False,
                    "options": {"temperature": 0.1, "num_predict": 2000},
                },
                timeout=90.0,
            )
            resp.raise_for_status()
            raw = resp.json()["message"]["content"].strip()
            raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
            if raw.startswith("```"):
                parts = raw.split("```")
                raw = parts[1].lstrip("json").strip() if len(parts) >= 2 else ""
            llm = json.loads(raw)

        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        await repo.update(record_id, {
            "updated_at": now,
            "vuln_class": llm.get("vuln_class", "other"),
            "tech_stack": llm.get("tech_stack", []),
            "platform_type": llm.get("platform_type", []),
            "endpoint_pattern": llm.get("endpoint_pattern", ""),
            "http_method": llm.get("http_method", []),
            "auth_required": bool(llm.get("auth_required", True)),
            "attack_technique": llm.get("attack_technique", ""),
            "attack_steps": llm.get("attack_steps", []),
            "indicators": llm.get("indicators", []),
            "prerequisites": llm.get("prerequisites", []),
            "what_tools_missed": llm.get("what_tools_missed", ""),
            "impact": llm.get("impact", ""),
            "impact_category": llm.get("impact_category", []),
            "key_insight": llm.get("key_insight", ""),
            "unique_factor": llm.get("unique_factor", ""),
        })

        text = " ".join(filter(None, [
            payload.title,
            llm.get("attack_technique", ""),
            llm.get("key_insight", ""),
            " ".join(llm.get("indicators", [])),
            llm.get("impact", ""),
        ]))
        vector = await embed_svc.embed(text)
        await embed_svc.upsert_point(record_id, vector, {"title": payload.title})
        await repo.mark_embedded(record_id)
        log.info("Raw inject %s: LLM extraction + embed complete", record_id)

    except Exception as exc:
        log.error("LLM extract/embed failed for raw inject %s: %s", record_id, exc)

