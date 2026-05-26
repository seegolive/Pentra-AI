"""H1 Hacktivity public report scraper — Celery task.

Scrapes HackerOne's public GraphQL API to fetch disclosed vulnerability reports
with full narrative. This gives the LLM extraction pipeline actual report content
(description, PoC, timeline) rather than just a title — critical for high-quality
knowledge extraction against hardened production targets.

Rate limits:
  - 2 concurrent fetches max
  - 2s delay between page requests
  - Exponential backoff on 429/5xx
  - Dedup via source_id before any LLM call
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime
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

# ── H1 GraphQL query ──────────────────────────────────────────────────────────

_HACKTIVITY_QUERY = """
query HacktivityPageQuery(
  $querystring: String
  $orderBy: HacktivityItemOrderInput
  $secureOrderBy: FiltersHacktivityItemFilterOrder
  $where: FiltersHacktivityItemFilterInput
  $count: Int
  $cursor: String
) {
  hacktivity_items(
    first: $count
    after: $cursor
    query: $querystring
    order_by: $orderBy
    secure_order_by: $secureOrderBy
    where: $where
  ) {
    total_count
    pageInfo {
      endCursor
      hasNextPage
    }
    edges {
      node {
        ... on Disclosed {
          id
          databaseId: _id
          disclosed_at
          severity_rating
          currency
          total_awarded_amount
          report {
            id
            databaseId: _id
            title
            disclosed_at
            created_at
            vulnerability_information
            reporter {
              username
            }
            weakness {
              id
              name
              external_id
            }
            severity {
              rating
              score
            }
            team {
              handle
              name
            }
          }
        }
      }
    }
  }
}
"""

_H1_HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (research-tool; contact: security-research)",
    "X-Auth-Token": "",  # public endpoint, no token needed
}


# ── HTTP helpers ──────────────────────────────────────────────────────────────

@retry(
    retry=retry_if_exception_type((httpx.HTTPStatusError, httpx.TransportError)),
    wait=wait_exponential(multiplier=2, min=4, max=60),
    stop=stop_after_attempt(5),
    reraise=True,
)
async def _fetch_page(
    client: httpx.AsyncClient,
    cursor: str | None,
    page_size: int,
) -> dict[str, Any]:
    """Fetch one page of Hacktivity disclosures with retry/backoff."""
    variables: dict[str, Any] = {
        "count": page_size,
        "orderBy": {"field": "disclosed_at", "direction": "DESC"},
        "where": {"report": {"disclosed_at": {"_is_null": False}}},
    }
    if cursor:
        variables["cursor"] = cursor

    resp = await client.post(
        settings.h1_graphql_url,
        json={"query": _HACKTIVITY_QUERY, "variables": variables},
        headers=_H1_HEADERS,
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

def _normalise_edge(edge: dict[str, Any]) -> dict[str, Any] | None:
    """Convert a Hacktivity GraphQL edge into the flat dict expected by the
    knowledge pipeline (matches reddelexc CSV column layout + extras)."""
    node = edge.get("node")
    if not node:
        return None
    report = node.get("report")
    if not report:
        return None

    team = report.get("team") or {}
    weakness = report.get("weakness") or {}
    severity_obj = report.get("severity") or {}

    # Strip HTML / markdown from vulnerability_information for cleaner LLM input
    raw_info: str = report.get("vulnerability_information") or ""
    clean_info = re.sub(r"<[^>]+>", "", raw_info).strip()
    # Truncate to 4000 chars so the LLM prompt stays within context window
    clean_info = clean_info[:4000]

    bounty_raw = node.get("total_awarded_amount") or "0"
    try:
        bounty = int(float(str(bounty_raw).replace(",", "")))
    except (ValueError, TypeError):
        bounty = 0

    disclosed_raw = node.get("disclosed_at") or report.get("disclosed_at") or ""

    return {
        # Matches fields used by seed pipeline
        "id": str(report.get("databaseId") or report.get("id") or ""),
        "title": (report.get("title") or "")[:500],
        "program": (team.get("handle") or team.get("name") or "unknown")[:200],
        "link": f"hackerone.com/reports/{report.get('databaseId') or report.get('id')}",
        "bounty": bounty,
        "vuln_type": (weakness.get("name") or "Unknown")[:200],
        "severity": (
            severity_obj.get("rating")
            or node.get("severity_rating")
            or "unknown"
        ).lower(),
        "cwe": weakness.get("external_id") or "",
        "cvss_score": severity_obj.get("score"),
        "disclosed_at": disclosed_raw,
        # Extra — full narrative for richer LLM extraction
        "description": clean_info,
        "reporter": (report.get("reporter") or {}).get("username") or "",
    }


# ── Async scrape orchestrator ─────────────────────────────────────────────────

async def _run_scrape(max_pages: int) -> dict[str, int]:
    """Async entry point — fetches pages and upserts into the knowledge pipeline.

    Returns stats dict: {scraped, inserted, skipped, errors}.
    """
    # Lazy import to avoid circular deps at module load
    from pentra_knowledge.db.database import get_session_factory
    from pentra_knowledge.db.repository import KnowledgeRepository
    from pentra_knowledge.services.embedding import EmbeddingService
    from pentra_knowledge.config import KnowledgeSettings

    kb_settings = KnowledgeSettings()
    session_factory = get_session_factory(kb_settings.database_url)
    repo = KnowledgeRepository(session_factory)
    embed_svc = EmbeddingService(kb_settings)

    stats = {"scraped": 0, "inserted": 0, "skipped": 0, "errors": 0}
    cursor: str | None = None
    page = 0

    semaphore = asyncio.Semaphore(settings.h1_scrape_concurrency)

    async with httpx.AsyncClient() as client:
        while True:
            if max_pages and page >= max_pages:
                log.info("Reached max_pages=%d, stopping", max_pages)
                break

            try:
                async with semaphore:
                    data = await _fetch_page(client, cursor, settings.h1_scrape_page_size)
                    await asyncio.sleep(settings.h1_scrape_delay_seconds)
            except Exception as exc:
                log.error("Failed to fetch page %d: %s", page + 1, exc)
                stats["errors"] += 1
                break

            items_data = (
                data.get("data", {})
                .get("hacktivity_items", {})
            )
            edges = items_data.get("edges") or []
            page_info = items_data.get("pageInfo") or {}

            if not edges:
                log.info("No more edges — scrape complete")
                break

            rows = [r for e in edges if (r := _normalise_edge(e))]
            stats["scraped"] += len(rows)

            # Process through the same LLM+embed pipeline as the CSV seed
            from scripts.seed_knowledge import _process_batch  # type: ignore[import]
            # Fallback: inline processing if seed script not importable
            try:
                inserted, skipped, errors = await _process_batch_inline(
                    rows, repo, embed_svc, kb_settings
                )
                stats["inserted"] += inserted
                stats["skipped"] += skipped
                stats["errors"] += errors
            except Exception as exc:
                log.error("Batch processing error on page %d: %s", page + 1, exc)
                stats["errors"] += len(rows)

            page += 1
            log.info(
                "Page %d done | scraped=%d inserted=%d skipped=%d",
                page,
                stats["scraped"],
                stats["inserted"],
                stats["skipped"],
            )

            if not page_info.get("hasNextPage"):
                log.info("hasNextPage=False — all pages consumed")
                break
            cursor = page_info.get("endCursor")

    return stats


async def _process_batch_inline(
    rows: list[dict[str, Any]],
    repo: Any,
    embed_svc: Any,
    kb_settings: Any,
) -> tuple[int, int, int]:
    """Process a batch of normalised H1 rows through LLM extraction + storage.

    Reuses the same logic as seed_knowledge but inline to avoid import coupling.
    Returns (inserted, skipped, errors).
    """
    import httpx as _httpx
    from pentra_knowledge.db.models import KnowledgeRecord
    from pentra_knowledge.db.repository import KnowledgeRepository

    now = datetime.utcnow()  # noqa: DTZ003 — naive UTC for asyncpg 0.31
    inserted = skipped = errors = 0

    # Check which source_ids already exist
    source_ids = [
        str(r.get("id") or r.get("link", "").rstrip("/").rsplit("/", 1)[-1])
        for r in rows
    ]
    existing: set[str] = set()
    try:
        existing = await repo.get_existing_source_ids(source_ids)
    except Exception:
        pass

    to_process = [r for r in rows if
                  str(r.get("id") or r.get("link", "").rstrip("/").rsplit("/", 1)[-1])
                  not in existing]
    skipped = len(rows) - len(to_process)

    if not to_process:
        return inserted, skipped, errors

    # LLM extraction using description field (full narrative — much richer!)
    llm_results: list[dict[str, Any]] = []
    async with _httpx.AsyncClient(base_url=kb_settings.ollama_url) as llm_client:
        sem = asyncio.Semaphore(3)
        tasks = [
            _llm_extract_with_description(row, llm_client, kb_settings.ollama_model_fast, sem)
            for row in to_process
        ]
        llm_results = await asyncio.gather(*tasks, return_exceptions=False)

    # Build records and upsert
    records = []
    for row, llm in zip(to_process, llm_results):
        try:
            rec = _build_h1_record(row, llm if isinstance(llm, dict) else {}, now)
            records.append(rec)
        except Exception as exc:
            log.warning("Failed to build record for '%s': %s", row.get("title", "")[:60], exc)
            errors += 1

    if records:
        try:
            await repo.bulk_upsert(records)
            inserted += len(records)
        except Exception as exc:
            log.error("DB upsert failed: %s", exc)
            errors += len(records)

    # Embed into Qdrant
    for rec in records:
        try:
            text = _record_embed_text(rec)
            vector = await embed_svc.embed(text)
            await embed_svc.upsert_point(str(rec["id"]), vector, rec)
            await repo.mark_embedded(str(rec["id"]))
        except Exception as exc:
            log.warning("Embed failed for %s: %s", rec.get("source_id"), exc)

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
    from pentra_knowledge.db.repository import _coerce_list  # type: ignore[attr-defined]

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

    return {
        "source": "hackerone",
        "source_id": source_id,
        "source_url": source_url or None,
        "title": row.get("title", "")[:500],
        "raw_content": row.get("description") or "",
        "program": row.get("program", "unknown")[:200],
        "severity": row.get("severity", "info"),
        "cvss_score": row.get("cvss_score"),
        "cwe_id": row.get("cwe") or None,
        "bounty_usd": row.get("bounty") or 0,
        "vuln_class": (llm.get("vuln_class") or row.get("vuln_type") or "other")[:100],
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
def scrape_h1_hacktivity(self, max_pages: int = 0) -> dict[str, int]:
    """Celery task: scrape H1 Hacktivity public disclosures.

    Args:
        max_pages: Maximum pages to fetch (0 = all). Each page = 25 reports.

    Returns:
        Stats dict with scraped/inserted/skipped/errors counts.
    """
    log.info("Starting H1 Hacktivity scrape | max_pages=%d", max_pages)
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    try:
        stats = loop.run_until_complete(_run_scrape(max_pages))
        log.info("H1 scrape complete: %s", stats)
        return stats
    except Exception as exc:
        log.error("H1 scrape failed: %s", exc)
        raise self.retry(exc=exc)
