"""Bugcrowd public disclosures scraper — Celery task.

Scrapes Bugcrowd's public researcher disclosures.
Rate limits:
  - 2s delay between page requests (polite crawling)
  - Dedup via source_id before any LLM call
  - Respects max_records limit
"""
from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime

import httpx

from app.core.config import settings
from app.worker import celery_app

log = logging.getLogger(__name__)

BUGCROWD_API_URL = "https://bugcrowd.com/disclosures.json"
_HEADERS = {
    "User-Agent": "Mozilla/5.0 (security-research/pentra-ai)",
    "Accept": "application/json",
}

# Map Bugcrowd severity strings to Pentra severity
_SEVERITY_MAP: dict[str, str] = {
    "p1": "critical",
    "p2": "high",
    "p3": "medium",
    "p4": "low",
    "p5": "info",
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
}

# Map common Bugcrowd vuln category labels → pentra vuln_class
_VULN_CLASS_MAP: dict[str, str] = {
    "cross-site scripting": "XSS",
    "xss": "XSS",
    "sql injection": "SQLi",
    "sqli": "SQLi",
    "idor": "IDOR",
    "insecure direct object reference": "IDOR",
    "ssrf": "SSRF",
    "server-side request forgery": "SSRF",
    "rce": "RCE",
    "remote code execution": "RCE",
    "open redirect": "Open Redirect",
    "information disclosure": "Info Disclosure",
    "authentication bypass": "Auth Bypass",
    "privilege escalation": "Privilege Escalation",
    "csrf": "CSRF",
    "xxe": "XXE",
    "path traversal": "Path Traversal",
    "lfi": "LFI",
    "broken access control": "Broken Access Control",
    "business logic": "Business Logic",
}


def _guess_vuln_class(category: str | None, title: str) -> str:
    """Best-effort vuln_class from category label + title."""
    text = (category or "") + " " + title
    text_lower = text.lower()
    for key, val in _VULN_CLASS_MAP.items():
        if key in text_lower:
            return val
    return "Other"


async def _scrape_all(max_records: int = 1000) -> list[dict]:
    """Paginate Bugcrowd disclosures JSON API, return raw record dicts."""
    records: list[dict] = []
    page = 1

    async with httpx.AsyncClient(
        headers=_HEADERS,
        follow_redirects=True,
        timeout=30.0,
    ) as client:
        while len(records) < max_records:
            try:
                resp = await client.get(
                    BUGCROWD_API_URL,
                    params={"page": page, "disclosed": "true"},
                )
                resp.raise_for_status()
                data = resp.json()
            except (httpx.HTTPError, ValueError) as exc:
                log.warning("Bugcrowd page %d failed: %s", page, exc)
                break

            disclosures = data.get("disclosures", [])
            if not disclosures:
                log.info("Bugcrowd: no more disclosures at page %d", page)
                break

            records.extend(disclosures)
            log.info("Bugcrowd: fetched page %d, total so far: %d", page, len(records))

            if not data.get("has_next_page", False):
                break

            page += 1
            await asyncio.sleep(2.0)

    return records[:max_records]


async def _run_scrape(max_records: int, overwrite: bool) -> dict:
    """Async core of the scraper — import into knowledge DB."""
    import uuid as uuid_mod

    from app.core.config import settings as worker_settings
    from pentra_knowledge.db.models import KnowledgeRecordORM
    from pentra_knowledge.ingestion.processor import KnowledgeProcessor
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

    engine = create_async_engine(worker_settings.database_url, echo=False)
    SessionLocal = async_sessionmaker(engine, expire_on_commit=False)

    processor = KnowledgeProcessor(
        ollama_url=worker_settings.ollama_url,
        model=worker_settings.ollama_model_fast,
    )

    raw_records = await _scrape_all(max_records)
    imported = 0
    skipped = 0

    async with SessionLocal() as db:
        from pentra_knowledge.db.repository import KnowledgeRepository
        repo = KnowledgeRepository(db)

        for item in raw_records:
            try:
                source_id = f"bugcrowd_{item.get('id', str(uuid_mod.uuid4()))}"

                if not overwrite and await repo.exists_by_source_id(source_id):
                    skipped += 1
                    continue

                title = item.get("title") or item.get("friendly_identifier", "Untitled")
                category = item.get("vulnerability_type") or item.get("category_label")
                severity_raw = (item.get("severity") or "").lower()
                severity = _SEVERITY_MAP.get(severity_raw, "info")
                vuln_class = _guess_vuln_class(category, title)
                program = item.get("program", {}).get("name", "bugcrowd")
                disclosed_at = item.get("disclosed_at", "")
                description = item.get("description") or title

                raw_text = (
                    f"Title: {title}\n"
                    f"Program: {program}\n"
                    f"Severity: {severity}\n"
                    f"Category: {category or 'N/A'}\n"
                    f"Disclosed: {disclosed_at}\n\n"
                    f"{description}"
                )

                # LLM extraction
                extracted = await processor.extract(
                    title=title,
                    vuln_class=vuln_class,
                    severity=severity,
                    program=program,
                    raw_content=raw_text[:3000],
                )

                from pentra_knowledge.db.models import KnowledgeRecordORM as KR
                record = KR(
                    source="bugcrowd",
                    source_id=source_id,
                    title=title,
                    vuln_class=vuln_class,
                    severity=severity,
                    program=program,
                    raw_text=raw_text[:10000],
                    key_insight=extracted.get("key_insight", ""),
                    technique=extracted.get("technique", ""),
                    tech_stack=extracted.get("tech_stack", []),
                    platform_type=extracted.get("platform_type", []),
                    endpoint_pattern=extracted.get("endpoint_pattern", ""),
                    http_method=extracted.get("http_method", []),
                    auth_required=extracted.get("auth_required", True),
                    indicators=extracted.get("indicators", []),
                    tags=[vuln_class.lower(), "bugcrowd"],
                    is_embedded=False,
                )
                db.add(record)
                imported += 1

                if imported % 50 == 0:
                    await db.commit()
                    log.info("Bugcrowd: committed %d records", imported)

            except Exception as exc:
                log.warning("Bugcrowd: failed to process record %s: %s", item.get("id"), exc)
                continue

        await db.commit()

    await engine.dispose()
    return {"imported": imported, "skipped": skipped, "source": "bugcrowd"}


@celery_app.task(
    name="app.tasks.bugcrowd_scraper.scrape_bugcrowd_disclosures",
    bind=True,
    max_retries=3,
    default_retry_delay=120,
)
def scrape_bugcrowd_disclosures(
    self,
    max_records: int = 1000,
    overwrite: bool = False,
) -> dict:
    """Celery task: scrape Bugcrowd public disclosures and import into KB."""
    log.info("Starting Bugcrowd scrape: max_records=%d", max_records)
    try:
        result = asyncio.get_event_loop().run_until_complete(
            _run_scrape(max_records=max_records, overwrite=overwrite)
        )
        log.info("Bugcrowd scrape done: %s", result)
        return result
    except Exception as exc:
        log.error("Bugcrowd scrape failed: %s", exc)
        raise self.retry(exc=exc)
