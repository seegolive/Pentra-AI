"""Knowledge update & maintenance Celery tasks.

Provides two task families:

1. **embed_pending_records**
   Scans ``knowledge_records`` for rows where ``is_embedded = FALSE`` and
   pushes them into Qdrant.  Runs in batches so the Ollama embedding endpoint
   is not flooded.  Safe to run repeatedly — already-embedded records are
   skipped via the DB flag.

2. **reextract_sparse_records**
   Finds records where ``key_insight`` is empty (i.e. LLM extraction was
   skipped or failed during seeding) and re-runs the fast LLM extraction
   pipeline on them, then embeds the updated records.

Both tasks are idempotent and can be triggered manually via the REST API or
scheduled via Celery Beat.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import httpx

from app.core.config import settings
from app.worker import celery_app

log = logging.getLogger(__name__)

# ── Shared helpers ─────────────────────────────────────────────────────────────

_EXTRACTION_SYSTEM = (
    "/no_think\n"
    "You are a security researcher extracting structured threat intelligence "
    "from a vulnerability report title and metadata. "
    "Return ONLY a valid JSON object — no explanation, no markdown fences."
)

_EXTRACTION_USER_TPL = """\
Analyze this vulnerability report and extract security intelligence.

Title: {title}
Vulnerability type: {vuln_class}
Severity: {severity}
Program: {program}
Raw content: {raw_content}

Extract this JSON:
{{
  "tech_stack":        ["technologies involved"],
  "platform_type":     ["web|api|mobile|cloud|network"],
  "endpoint_pattern":  "generalised URL e.g. /api/v1/users/{{id}}",
  "http_method":       ["GET|POST|PUT|DELETE|PATCH"],
  "auth_required":     true,
  "attack_technique":  "HOW the bug was exploited (2-3 sentences)",
  "attack_steps":      ["step 1", "step 2", "step 3"],
  "indicators":        ["observable signals the bug may exist"],
  "prerequisites":     ["conditions required for exploitation"],
  "what_tools_missed": "why automated scanners missed this",
  "impact":            "impact if exploited",
  "impact_category":   ["account_takeover|data_exfil|rce|dos|information_disclosure|privilege_escalation"],
  "key_insight":       "the aha moment — what made this non-obvious (2-4 sentences)",
  "unique_factor":     "what made this hard to find or fix"
}}"""


async def _llm_extract(
    record: Any,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
) -> dict[str, Any]:
    """Run fast LLM extraction on a single knowledge record ORM object.

    Uses raw_content if available, otherwise falls back to title only.
    Returns an empty dict on any failure (non-fatal — record is unchanged).
    """
    async with semaphore:
        raw_content = (getattr(record, "raw_content", None) or "")[:4000]
        title = getattr(record, "title", "") or ""
        try:
            resp = await client.post(
                "/api/chat",
                json={
                    "model": settings.ollama_model_fast,
                    "messages": [
                        {"role": "system", "content": _EXTRACTION_SYSTEM},
                        {
                            "role": "user",
                            "content": _EXTRACTION_USER_TPL.format(
                                title=title,
                                vuln_class=getattr(record, "vuln_class", "unknown") or "unknown",
                                severity=getattr(record, "severity", "unknown") or "unknown",
                                program=getattr(record, "program", "") or "",
                                raw_content=raw_content,
                            ),
                        },
                    ],
                    "stream": False,
                    "options": {"temperature": 0.1, "num_predict": 2000},
                },
                timeout=60.0,
            )
            resp.raise_for_status()
            raw: str = resp.json()["message"]["content"].strip()
            raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
            if raw.startswith("```"):
                parts = raw.split("```")
                raw = parts[1].lstrip("json").strip() if len(parts) >= 2 else ""
            return json.loads(raw)
        except Exception as exc:
            log.warning("LLM extraction failed for '%s': %s", title[:60], exc)
            return {}


async def _embed_and_upsert(
    record: Any,
    repo: Any,
) -> bool:
    """Embed a single ORM record and upsert into Qdrant.

    Returns True on success, False on any failure.
    """
    from pentra_knowledge.services.embedding import embed, build_embedding_text
    from pentra_knowledge.services.search import upsert_to_qdrant

    rec_dict = {
        "title": record.title or "",
        "vuln_class": record.vuln_class or "",
        "attack_technique": record.attack_technique or "",
        "key_insight": record.key_insight or "",
        "unique_factor": record.unique_factor or "",
        "indicators": record.indicators or [],
        "tech_stack": record.tech_stack or [],
        "prerequisites": record.prerequisites or [],
        "what_tools_missed": record.what_tools_missed or "",
    }
    try:
        text = build_embedding_text(rec_dict)
        result = await embed(text)
        await upsert_to_qdrant(
            record_id=record.id,
            dense=result.dense,
            sparse=result.sparse,
            payload={
                "source_id": record.source_id,
                "title": record.title,
                "vuln_class": record.vuln_class,
                "severity": record.severity,
                "program": record.program,
                "tech_stack": record.tech_stack or [],
                "source": record.source,
            },
        )
        await repo.mark_embedded(
            record.id,
            model=result.model,
            version=1,
        )
        return True
    except Exception as exc:
        log.warning("Embed failed for record %s: %s", record.id, exc)
        return False


# ── Task 1: embed pending records ──────────────────────────────────────────────

async def _run_embed_pending(batch_size: int, max_records: int) -> dict[str, int]:
    """Async core of ``embed_pending_records``."""
    from pentra_knowledge.db.base import AsyncSessionLocal
    from pentra_knowledge.db.repository import KnowledgeRepository

    session_factory = AsyncSessionLocal()

    stats = {"processed": 0, "embedded": 0, "skipped": 0, "errors": 0}
    offset = 0

    while True:
        if max_records and stats["processed"] >= max_records:
            break

        remaining = (max_records - stats["processed"]) if max_records else batch_size
        current_batch = min(batch_size, remaining)

        async with session_factory() as session:
            repo = KnowledgeRepository(session)
            records = await repo.list_unembedded(limit=current_batch)

        if not records:
            log.info("No more unembedded records — done")
            break

        log.info("Embedding batch of %d records (offset=%d)", len(records), offset)

        for record in records:
            async with session_factory() as session:
                repo = KnowledgeRepository(session)
                success = await _embed_and_upsert(record, repo)
                if success:
                    await session.commit()
                    stats["embedded"] += 1
                else:
                    stats["errors"] += 1

        stats["processed"] += len(records)
        offset += len(records)

        if len(records) < current_batch:
            break

    return stats


@celery_app.task(
    name="app.tasks.knowledge_update.embed_pending_records",
    bind=True,
    max_retries=2,
    default_retry_delay=60,
    time_limit=7200,   # 2 hour hard limit
    soft_time_limit=6900,
)
def embed_pending_records(
    self,
    batch_size: int = 50,
    max_records: int = 0,
) -> dict[str, int]:
    """Celery task: embed all unembedded knowledge records into Qdrant.

    Args:
        batch_size:   Records per DB fetch (default 50).
        max_records:  Hard cap on total records to process (0 = all).

    Returns:
        Stats dict with processed/embedded/errors counts.
    """
    log.info(
        "Starting embed_pending_records | batch_size=%d max_records=%d",
        batch_size,
        max_records,
    )
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    try:
        stats = loop.run_until_complete(_run_embed_pending(batch_size, max_records))
        log.info("embed_pending_records complete: %s", stats)
        return stats
    except Exception as exc:
        log.error("embed_pending_records failed: %s", exc)
        raise self.retry(exc=exc)


# ── Task 2: re-extract sparse records ─────────────────────────────────────────

async def _run_reextract_sparse(batch_size: int, max_records: int) -> dict[str, int]:
    """Async core of ``reextract_sparse_records``."""
    from sqlalchemy import select
    from pentra_knowledge.db.base import AsyncSessionLocal
    from pentra_knowledge.db.models import KnowledgeRecordORM
    from pentra_knowledge.db.repository import KnowledgeRepository
    from pentra_knowledge.config import get_settings

    kb = get_settings()
    session_factory = AsyncSessionLocal()

    stats = {"processed": 0, "updated": 0, "re_embedded": 0, "errors": 0}
    semaphore = asyncio.Semaphore(3)
    # Fix: TIMESTAMP WITHOUT TIME ZONE requires naive UTC datetime
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    offset = 0
    async with httpx.AsyncClient(base_url=kb.ollama_url) as llm_client:
        while True:
            if max_records and stats["processed"] >= max_records:
                break

            remaining = (max_records - stats["processed"]) if max_records else batch_size
            current_batch = min(batch_size, remaining)

            # Fetch records missing key_insight (failed extraction during seeding)
            async with session_factory() as session:
                result = await session.execute(
                    select(KnowledgeRecordORM)
                    .where(
                        (KnowledgeRecordORM.key_insight == "")
                        | (KnowledgeRecordORM.key_insight.is_(None))
                    )
                    .offset(offset)
                    .limit(current_batch)
                )
                records = list(result.scalars().all())

            if not records:
                log.info("No more sparse records — reextraction done")
                break

            log.info(
                "Re-extracting %d sparse records (offset=%d)", len(records), offset
            )

            # Run LLM extraction concurrently
            llm_results = await asyncio.gather(
                *[_llm_extract(r, llm_client, semaphore) for r in records],
                return_exceptions=False,
            )

            for record, llm in zip(records, llm_results):
                if not llm:
                    stats["errors"] += 1
                    continue

                update_data: dict[str, Any] = {
                    "updated_at": now,
                    "tech_stack": llm.get("tech_stack") or record.tech_stack or [],
                    "platform_type": llm.get("platform_type") or record.platform_type or [],
                    "endpoint_pattern": llm.get("endpoint_pattern") or record.endpoint_pattern or "",
                    "http_method": llm.get("http_method") or record.http_method or [],
                    "auth_required": bool(llm.get("auth_required", record.auth_required)),
                    "attack_technique": llm.get("attack_technique") or "",
                    "attack_steps": llm.get("attack_steps") or [],
                    "indicators": llm.get("indicators") or [],
                    "prerequisites": llm.get("prerequisites") or [],
                    "what_tools_missed": llm.get("what_tools_missed") or "",
                    "impact": llm.get("impact") or record.impact or "",
                    "impact_category": llm.get("impact_category") or [],
                    "key_insight": llm.get("key_insight") or "",
                    "unique_factor": llm.get("unique_factor") or "",
                    # Reset embedding flag so embed_pending_records picks it up
                    "is_embedded": False,
                }

                try:
                    async with session_factory() as session:
                        repo = KnowledgeRepository(session)
                        await repo.update(record.id, update_data)
                        await session.commit()
                    stats["updated"] += 1
                except Exception as exc:
                    log.warning("DB update failed for %s: %s", record.id, exc)
                    stats["errors"] += 1
                    continue

                # Re-embed with updated content
                async with session_factory() as session:
                    # Fetch fresh ORM row with updated fields
                    fresh = await session.get(KnowledgeRecordORM, record.id)
                    if fresh:
                        repo = KnowledgeRepository(session)
                        success = await _embed_and_upsert(fresh, repo)
                        if success:
                            stats["re_embedded"] += 1
                            await session.commit()

            stats["processed"] += len(records)
            offset += len(records)

            if len(records) < current_batch:
                break

    return stats


@celery_app.task(
    name="app.tasks.knowledge_update.reextract_sparse_records",
    bind=True,
    max_retries=2,
    default_retry_delay=120,
    time_limit=21600,   # 6 hour hard limit
    soft_time_limit=21300,
)
def reextract_sparse_records(
    self,
    batch_size: int = 20,
    max_records: int = 0,
) -> dict[str, int]:
    """Celery task: re-run LLM extraction on records with empty key_insight.

    Records that failed LLM extraction during the CSV seed pass have empty
    ``key_insight`` fields and are not useful for RAG.  This task re-runs
    extraction on them and resets ``is_embedded = FALSE`` so the embedding
    backfill task will pick them up.

    Args:
        batch_size:   Records per batch (default 20 — LLM-heavy).
        max_records:  Hard cap (0 = all sparse records).

    Returns:
        Stats dict with processed/updated/re_embedded/errors counts.
    """
    log.info(
        "Starting reextract_sparse_records | batch_size=%d max_records=%d",
        batch_size,
        max_records,
    )
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    try:
        stats = loop.run_until_complete(_run_reextract_sparse(batch_size, max_records))
        log.info("reextract_sparse_records complete: %s", stats)
        return stats
    except Exception as exc:
        log.error("reextract_sparse_records failed: %s", exc)
        raise self.retry(exc=exc)
