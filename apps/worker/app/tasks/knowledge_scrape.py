"""H1 Hacktivity public report scraper — Celery task.

Scrapes HackerOne's public REST Hacktivity API to fetch disclosed vulnerability
reports with full narrative. This gives the LLM extraction pipeline actual report
content rather than just a title — critical for high-quality knowledge extraction.

API: GET https://api.hackerone.com/v1/hackers/hacktivity
Docs: https://api.hackerone.com/hacker-resources/#hacktivity-get-hacktivity

Credentials: set H1_API_USERNAME and H1_API_TOKEN in .env
If not set, scrape will be skipped with a warning.

Rate limits:
  - 1 concurrent fetch
  - 2s delay between page requests
  - Exponential backoff on 429/5xx
  - Dedup via source_id before any LLM call
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.core.config import settings
from app.worker import celery_app

log = logging.getLogger(__name__)


# ── HTTP helpers ──────────────────────────────────────────────────────────────

@retry(
    retry=retry_if_exception_type((httpx.HTTPStatusError, httpx.TransportError)),
    wait=wait_exponential(multiplier=2, min=4, max=60),
    stop=stop_after_attempt(5),
    reraise=True,
)
async def _fetch_page(
    client: httpx.AsyncClient,
    page_num: int,
    page_size: int,
) -> dict[str, Any]:
    """Fetch one page of Hacktivity disclosures via the H1 REST API."""
    resp = await client.get(
        f"{settings.h1_api_url}/hackers/hacktivity",
        params={
            "queryString": "disclosed:true",
            "page[number]": page_num,
            "page[size]": page_size,
        },
        timeout=30.0,
    )
    if resp.status_code == 429:
        retry_after = int(resp.headers.get("Retry-After", "60"))
        log.warning("H1 rate-limited — sleeping %ds", retry_after)
        await asyncio.sleep(retry_after)
        resp.raise_for_status()
    resp.raise_for_status()
    return resp.json()


# ── Row normaliser ─────────────────────────────────────────────────────────────

def _normalise_item(item: dict[str, Any]) -> dict[str, Any] | None:
    """Convert a Hacktivity REST API item into the flat dict used by the pipeline."""
    attrs = item.get("attributes") or {}
    rels = item.get("relationships") or {}

    report_id = str(item.get("id") or "")
    if not report_id:
        return None

    reporter_attrs = ((rels.get("reporter") or {}).get("data") or {}).get("attributes") or {}
    program_attrs = ((rels.get("program") or {}).get("data") or {}).get("attributes") or {}
    generated_attrs = ((rels.get("report_generated_content") or {}).get("data") or {}).get("attributes") or {}

    summary = generated_attrs.get("hacktivity_summary") or ""
    clean_summary = re.sub(r"<[^>]+>", "", summary).strip()[:4000]

    severity = (attrs.get("severity_rating") or "unknown").lower()

    bounty_raw = attrs.get("total_awarded_amount") or 0
    try:
        bounty = int(float(str(bounty_raw).replace(",", "")))
    except (ValueError, TypeError):
        bounty = 0

    return {
        "id": report_id,
        "title": (attrs.get("title") or "")[:500],
        "program": (program_attrs.get("handle") or program_attrs.get("name") or "unknown")[:200],
        "link": attrs.get("url") or f"https://hackerone.com/reports/{report_id}",
        "bounty": bounty,
        "vuln_type": (attrs.get("cwe") or "Unknown")[:200],
        "severity": severity,
        "cwe": attrs.get("cwe") or "",
        "cvss_score": None,
        "disclosed_at": attrs.get("disclosed_at") or "",
        "description": clean_summary,
        "reporter": reporter_attrs.get("username") or "",
    }


# ── Async scrape orchestrator ─────────────────────────────────────────────────

async def _run_scrape(max_pages: int, start_page: int = 1) -> dict[str, int]:
    """Async entry point — fetches pages and upserts into the knowledge pipeline.

    Args:
        max_pages: Stop after this many pages from start_page (0 = all).
        start_page: First page to fetch (default 1). Use >1 to skip already-scraped pages.

    Returns stats dict: {scraped, inserted, skipped, errors}.
    """
    # Lazy import to avoid circular deps at module load
    from pentra_knowledge.db.base import _get_session_factory
    from pentra_knowledge.db.repository import KnowledgeRepository
    from pentra_knowledge.config import KnowledgeSettings

    # Check credentials
    if not settings.h1_api_username or not settings.h1_api_token:
        log.error(
            "H1_API_USERNAME and H1_API_TOKEN not set — cannot scrape H1 Hacktivity. "
            "Set these in your .env file. See https://docs.hackerone.com/en/articles/8130022-api-authentication"
        )
        return {"scraped": 0, "inserted": 0, "skipped": 0, "errors": 1}

    kb_settings = KnowledgeSettings()
    session_factory = _get_session_factory()

    stats = {"scraped": 0, "inserted": 0, "skipped": 0, "errors": 0}
    page_num = max(1, start_page)

    async with httpx.AsyncClient(
        auth=(settings.h1_api_username, settings.h1_api_token),
        headers={"Accept": "application/json", "User-Agent": "Pentra-AI/1.0 (security-research)"},
    ) as client:
        while True:
            if max_pages and page_num > (start_page - 1 + max_pages):
                log.info("Reached max_pages=%d from start_page=%d, stopping", max_pages, start_page)
                break

            try:
                data = await _fetch_page(client, page_num, settings.h1_scrape_page_size)
                await asyncio.sleep(settings.h1_scrape_delay_seconds)
            except Exception as exc:
                log.error("Failed to fetch page %d: %s", page_num, exc)
                stats["errors"] += 1
                break

            items = data.get("data") or []
            if not items:
                log.info("No more items — scrape complete")
                break

            rows = [r for item in items if (r := _normalise_item(item))]
            stats["scraped"] += len(rows)

            # Process through the same LLM+embed pipeline as the CSV seed
            try:
                async with session_factory() as session:
                    repo = KnowledgeRepository(session)
                    inserted, skipped, errors = await _process_batch_inline(
                        rows, repo, session, None, kb_settings
                    )
                stats["inserted"] += inserted
                stats["skipped"] += skipped
                stats["errors"] += errors
            except Exception as exc:
                log.error("Batch processing error on page %d: %s", page_num, exc)
                stats["errors"] += len(rows)

            log.info(
                "Page %d done | scraped=%d inserted=%d skipped=%d",
                page_num,
                stats["scraped"],
                stats["inserted"],
                stats["skipped"],
            )
            page_num += 1

            # H1 REST API: if returned fewer items than page_size, we're done
            if len(items) < settings.h1_scrape_page_size:
                log.info("Last page received (%d items) — all pages consumed", len(items))
                break

    return stats


async def _process_batch_inline(
    rows: list[dict[str, Any]],
    repo: Any,
    session: Any,
    embed_svc: Any,
    kb_settings: Any,
) -> tuple[int, int, int]:
    """Process a batch of normalised H1 rows through LLM extraction + storage.

    Uses the actual pentra_knowledge repository API (create + mark_embedded).
    Returns (inserted, skipped, errors).
    """
    import httpx as _httpx
    from pentra_knowledge.services.search import upsert_to_qdrant
    from pentra_knowledge.services.embedding import embed as kb_embed, build_embedding_text

    # Fix: TIMESTAMP WITHOUT TIME ZONE requires naive UTC datetime
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    inserted = skipped = errors = 0

    # Dedup — check source_ids one by one using repo.exists_by_source_id
    to_process: list[dict[str, Any]] = []
    for row in rows:
        source_id = str(row.get("id") or row.get("link", "").rstrip("/").rsplit("/", 1)[-1])
        try:
            if await repo.exists_by_source_id(source_id):
                skipped += 1
                continue
        except Exception:
            pass
        to_process.append(row)

    if not to_process:
        return inserted, skipped, errors

    # LLM extraction using description field
    llm_results: list[dict[str, Any]] = []
    async with _httpx.AsyncClient(base_url=kb_settings.ollama_url) as llm_client:
        sem = asyncio.Semaphore(3)
        tasks = [
            _llm_extract_with_description(row, llm_client, kb_settings.ollama_model_fast, sem)
            for row in to_process
        ]
        llm_results = await asyncio.gather(*tasks, return_exceptions=False)

    # Insert into PostgreSQL and embed into Qdrant
    for row, llm in zip(to_process, llm_results):
        try:
            rec = _build_h1_record(row, llm if isinstance(llm, dict) else {}, now)
        except Exception as exc:
            log.warning("Failed to build record for '%s': %s", row.get("title", "")[:60], exc)
            errors += 1
            continue

        try:
            orm = await repo.create(rec)
            await session.commit()
            inserted += 1
        except Exception as exc:
            log.error("DB insert failed for '%s': %s", rec.get("source_id"), exc)
            await session.rollback()
            errors += 1
            continue

        # Embed into Qdrant (non-fatal — knowledge_update task will retry unembedded)
        try:
            embed_text = build_embedding_text(rec)
            embedding_result = await kb_embed(embed_text)
            payload = {
                "vuln_class": orm.vuln_class,
                "severity": orm.severity,
                "tech_stack": orm.tech_stack,
                "source": orm.source,
                "program": orm.program,
            }
            await upsert_to_qdrant(
                orm.id,
                embedding_result.dense,
                embedding_result.sparse,
                payload,
            )
            await repo.mark_embedded(
                orm.id,
                model=kb_settings.ollama_model_embedding,
                version=1,
            )
            await session.commit()
        except Exception as exc:
            log.warning("Embed failed for %s (will retry later): %s", rec.get("source_id"), exc)

    return inserted, skipped, errors


async def _llm_extract_with_description(
    row: dict[str, Any],
    client: httpx.AsyncClient,
    model: str,
    semaphore: asyncio.Semaphore,
) -> dict[str, Any]:
    """LLM extraction using full report description — produces much richer output
    than title-only extraction used in CSV seed.

    The description field contains the actual PoC, root cause analysis, and
    impact — giving the model concrete evidence to extract from."""
    async with semaphore:
        description = row.get("description") or ""
        title = row.get("title") or ""
        system = (
            "/no_think\n"
            "You are a security researcher extracting structured threat intelligence "
            "from HackerOne bug bounty disclosure reports. "
            "Return ONLY a valid JSON object — no explanation, no markdown fences."
        )
        user = f"""Analyze this HackerOne disclosure and extract security intelligence.

Title: {title}
Vulnerability type: {row.get('vuln_type', 'Unknown')}
Severity: {row.get('severity', 'unknown')}
Program: {row.get('program', '')}
Bounty paid: ${row.get('bounty', 0)}
CWE: {row.get('cwe', '')}

Report description:
{description}

Extract this JSON:
{{
  "vuln_class":        "one of: idor|bola|bfla|privilege_escalation|sqli|xss_stored|xss_reflected|xss_dom|mxss|xxe|ssti|cmdi|auth_bypass|session|oauth_misconfig|jwt_issues|ssrf|path_traversal|rce|deserialization|race_condition|mass_assignment|param_pollution|workflow_bypass|api_key_leak|pii_exposure|debug_info|source_code|subdomain_takeover|cache_poisoning|cloud_misconfig|cors|introspection|query_depth|batch_abuse|field_suggestion|dos|open_redirect|buffer_overflow|use_after_free|integer_overflow|weak_algo|padding_oracle|timing_attack|other",
  "tech_stack":        ["technologies involved"],
  "platform_type":     ["web|api|mobile|cloud|network"],
  "endpoint_pattern":  "generalised URL e.g. /api/v1/users/{{id}}",
  "http_method":       ["GET|POST|PUT|DELETE|PATCH"],
  "auth_required":     true,
  "attack_technique":  "HOW the bug was exploited (2-3 sentences)",
  "attack_steps":      ["step 1", "step 2", "step 3"],
  "indicators":        ["observable signals the bug may exist"],
  "prerequisites":     ["conditions required for exploitation"],
  "what_tools_missed": "why Burp/Nuclei/scanners missed this",
  "impact":            "impact if exploited",
  "impact_category":   ["account_takeover|data_exfil|rce|dos|information_disclosure|privilege_escalation"],
  "key_insight":       "the aha moment — what made this non-obvious (2-4 sentences)",
  "unique_factor":     "what made this hard to find or hard to fix"
}}"""

        try:
            resp = await client.post(
                "/api/chat",
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "stream": False,
                    "options": {"temperature": 0.1, "num_predict": 2000},
                },
                timeout=60.0,
            )
            resp.raise_for_status()
            raw: str = resp.json()["message"]["content"].strip()

            import re as _re
            raw = _re.sub(r"<think>.*?</think>", "", raw, flags=_re.DOTALL).strip()
            if raw.startswith("```"):
                parts = raw.split("```")
                raw = parts[1].lstrip("json").strip() if len(parts) >= 2 else ""

            return json.loads(raw)
        except Exception as exc:
            log.warning("LLM extraction failed for '%s': %s", title[:60], exc)
            return {}


def _build_h1_record(
    row: dict[str, Any],
    llm: dict[str, Any],
    now: datetime,
) -> dict[str, Any]:
    """Merge H1 GraphQL row + LLM output into a knowledge record dict."""
    source_id = str(row.get("id") or row.get("link", "").rstrip("/").rsplit("/", 1)[-1])
    link = row.get("link", "")
    source_url = ("https://" + link) if link and not link.startswith("http") else link

    disclosed_raw = str(row.get("disclosed_at") or "").strip()
    try:
        ingested_at = datetime.strptime(
            disclosed_raw[:19], "%Y-%m-%dT%H:%M:%S"
        ).replace(tzinfo=None)
    except (ValueError, TypeError):
        ingested_at = now

    data: dict[str, Any] = {
        "source": "hackerone",
        "source_id": source_id,
        "source_url": source_url or None,
        "title": row.get("title", "")[:500],
        "full_text": row.get("description") or "",  # raw H1 description → ORM full_text cache
        "program": row.get("program", "unknown")[:200],
        "severity": row.get("severity", "info"),
        "cvss_score": row.get("cvss_score"),
        # H1 provides CWE (weakness), not CVE — ORM has no cwe_id column, skip
        "bounty_usd": row.get("bounty") or 0,
        "vuln_class": (llm.get("vuln_class") or row.get("vuln_type") or "other")[:50],
        "tech_stack": llm.get("tech_stack") or [],
        "platform_type": llm.get("platform_type") or [],
        "endpoint_pattern": (llm.get("endpoint_pattern") or "")[:500],
        "http_method": llm.get("http_method") or [],
        "auth_required": bool(llm.get("auth_required", True)),
        "attack_technique": (llm.get("attack_technique") or "")[:2000],
        "attack_steps": llm.get("attack_steps") or [],
        "indicators": llm.get("indicators") or [],
        "prerequisites": llm.get("prerequisites") or [],
        "what_tools_missed": (llm.get("what_tools_missed") or "")[:2000],
        "impact": (llm.get("impact") or "")[:2000],
        "impact_category": llm.get("impact_category") or [],
        "key_insight": (llm.get("key_insight") or "")[:3000],
        "unique_factor": (llm.get("unique_factor") or "")[:2000],
        "is_embedded": False,
        "ingested_at": ingested_at,
        "updated_at": now,
    }

    # Compute quality_score inline (mirrors KnowledgeRecord.calculate_quality_score)
    score = 0.0
    if data["key_insight"]:
        score += 0.20
    if data["attack_technique"]:
        score += 0.20
    if data["indicators"]:
        score += 0.15
    if data["attack_steps"]:
        score += 0.15
    if data["what_tools_missed"]:
        score += 0.10
    if data["tech_stack"]:
        score += 0.10
    bounty = data.get("bounty_usd") or 0
    if bounty >= 5000:
        score += 0.10
    elif bounty > 0:
        score += 0.05
    data["quality_score"] = round(min(score, 1.0), 4)
    return data


def _record_embed_text(rec: dict[str, Any]) -> str:
    """Build the text string to embed for a knowledge record."""
    parts = [
        rec.get("title") or "",
        rec.get("attack_technique") or "",
        rec.get("key_insight") or "",
        " ".join(rec.get("indicators") or []),
        rec.get("impact") or "",
    ]
    return " ".join(p for p in parts if p).strip()


# ── Celery task ───────────────────────────────────────────────────────────────

@celery_app.task(
    name="app.tasks.knowledge_scrape.scrape_h1_hacktivity",
    bind=True,
    max_retries=3,
    default_retry_delay=300,  # 5 min
    time_limit=14400,          # 4 hour hard limit
    soft_time_limit=13800,
)
def scrape_h1_hacktivity(self, max_pages: int = 0, max_records: int = 0, start_page: int = 1, overwrite: bool = False) -> dict[str, int]:
    """Celery task: scrape H1 Hacktivity public disclosures.

    Args:
        max_pages: Maximum pages to fetch from start_page (0 = all). Each page = 50 reports.
        max_records: Alternative limit — converted to pages (50 reports/page).
                     If both given, max_records takes precedence when > 0.
        start_page: First page to fetch (default 1). Set to 21 to skip already-scraped pages.
        overwrite: Ignored (reserved for future use).

    Returns:
        Stats dict with scraped/inserted/skipped/errors counts.
    """
    if max_records > 0 and max_pages == 0:
        max_pages = max(1, max_records // settings.h1_scrape_page_size)
    log.info(
        "Starting H1 Hacktivity scrape | start_page=%d max_pages=%d (max_records=%d)",
        start_page, max_pages, max_records,
    )
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    try:
        stats = loop.run_until_complete(_run_scrape(max_pages, start_page=start_page))
        log.info("H1 scrape complete: %s", stats)
        return stats
    except Exception as exc:
        log.error("H1 scrape failed: %s", exc)
        raise self.retry(exc=exc)
