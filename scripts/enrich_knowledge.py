#!/usr/bin/env python3
"""Retroactively enrich low-quality knowledge records with improved LLM extraction.

Finds records where LLM extraction failed or produced fallback data, then
re-runs the improved extraction prompt and updates both PostgreSQL and Qdrant.

A record is considered "low quality" when it matches any of:
  - key_insight contains the fallback template phrase ('found in' / 'discovered in')
  - attack_steps is an empty JSON array AND payload_pattern is NULL
  - attack_technique ends with 'discovered in <program>.'  (fallback template)

Usage:
    # Dry-run — show how many records would be enriched
    uv run python scripts/enrich_knowledge.py --dry-run

    # Enrich up to 200 low-quality records
    uv run python scripts/enrich_knowledge.py --limit 200

    # Enrich all low-quality records (can take hours)
    uv run python scripts/enrich_knowledge.py

    # Skip Qdrant re-embedding (DB update only)
    uv run python scripts/enrich_knowledge.py --skip-embed
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx
from sqlalchemy import select, text, update

# ── Monorepo path bootstrap ────────────────────────────────────────────────────
_REPO_ROOT = Path(__file__).resolve().parent.parent
_KNOWLEDGE_PKG = _REPO_ROOT / "packages" / "pentra-knowledge"
sys.path.insert(0, str(_KNOWLEDGE_PKG))
sys.path.insert(0, str(_REPO_ROOT / "packages" / "pentra-shared"))

# pydantic-settings resolves env_file=".env" relative to CWD.
# The .env with DB credentials lives in packages/pentra-knowledge/, so
# change CWD there before settings are first instantiated.
import os as _os
_os.chdir(str(_KNOWLEDGE_PKG))

from pentra_knowledge.config import get_settings  # noqa: E402
from pentra_knowledge.db.base import _get_session_factory  # noqa: E402
from pentra_knowledge.db.models import KnowledgeRecordORM  # noqa: E402
from pentra_knowledge.services.embedding import embed  # noqa: E402
from pentra_knowledge.services.search import (  # noqa: E402
    ensure_collection_exists,
    upsert_to_qdrant,
)
from pentra_shared.types import VulnClass  # noqa: E402

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger("enrich_knowledge")

# ── LLM prompt (identical to seed_knowledge.py to ensure consistent extraction) ─
_SYSTEM_PROMPT = (
    "/no_think\n"
    "You are a security researcher extracting structured threat intelligence "
    "from HackerOne bug bounty disclosures. "
    "Return ONLY a valid JSON object — no explanation, no markdown fences, no thinking."
)

_USER_PROMPT_TMPL = """\
Analyze this HackerOne report and extract security intelligence.

Report metadata:
  Title: {title}
  Vulnerability type: {vuln_type}
  Severity: {severity}
  Program: {program}
  Bounty paid: ${bounty}

Extract the following JSON object:
{{
  "vuln_class":        "one of: idor, bola, bfla, sqli, xss_reflected, xss_stored, xss_dom, xxe, ssti, cmdi, ssrf, rce, path_traversal, deserialization, auth_bypass, mass_assignment, race_condition, dos, open_redirect, cors, subdomain_takeover, oauth_misconfig, session, pii_exposure, api_key_leak, debug_info, privilege_escalation, workflow_bypass, cloud_misconfig, cache_poisoning, buffer_overflow, use_after_free, integer_overflow, introspection, batch_abuse, weak_algo, timing_attack",
  "tech_stack":        ["technologies involved, e.g. Ruby on Rails, AWS S3"],
  "platform_type":     ["one or more of: web, api, mobile, cloud, network"],
  "endpoint_pattern":  "generalised URL e.g. /api/v1/users/{{id}}",
  "http_method":       ["HTTP methods: GET, POST, PUT, DELETE, PATCH"],
  "auth_required":     true,
  "attack_technique":  "1-2 sentences: HOW the bug was exploited",
  "attack_steps":      ["step 1", "step 2", "step 3"],
  "payload_pattern":   "concrete payload or request snippet, e.g. ?id=1 OR 1=1 or <script>alert(1)</script> or {{\\"alias1\\": mutation, \\"alias2\\": mutation}}",
  "indicators":        ["observable signal that this bug may exist"],
  "prerequisites":     ["condition that must be true for bug to exist"],
  "what_tools_missed": "why automated scanners (Burp/Nuclei) missed this",
  "impact":            "impact if exploited",
  "impact_category":   ["one or more of: account_takeover, data_exfil, rce, dos, information_disclosure, privilege_escalation"],
  "key_insight":       "the aha moment — 1-3 sentences, what made this non-obvious",
  "unique_factor":     "what made this hard to find"
}}"""


def _repair_truncated_json(raw: str) -> dict:
    """Attempt to recover a valid JSON object from a truncated LLM response."""
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    lines = raw.rstrip().split("\n")
    for i in range(len(lines), 0, -1):
        candidate = "\n".join(lines[:i]).rstrip().rstrip(",")
        for close in ["}}", "}", "]}", "\"}"]:
            try:
                return json.loads(candidate + close)
            except json.JSONDecodeError:
                continue
    return {}


async def _llm_extract(
    title: str,
    vuln_type: str,
    severity: str,
    program: str,
    bounty: str,
    client: httpx.AsyncClient,
    model: str,
    semaphore: asyncio.Semaphore,
) -> dict[str, Any]:
    """Re-run LLM extraction for a single record. Returns {} on total failure."""
    async with semaphore:
        prompt = _USER_PROMPT_TMPL.format(
            title=title,
            vuln_type=vuln_type or "Unknown",
            severity=severity or "unknown",
            program=program or "unknown",
            bounty=bounty or "0",
        )
        for attempt in range(2):
            try:
                response = await client.post(
                    "/api/chat",
                    json={
                        "model": model,
                        "messages": [
                            {"role": "system", "content": _SYSTEM_PROMPT},
                            {"role": "user", "content": prompt},
                        ],
                        "stream": False,
                        "options": {"temperature": 0.1, "num_predict": 3000},
                    },
                )
                response.raise_for_status()
                raw_content: str = response.json()["message"]["content"].strip()

                # Strip qwen3 <think>...</think> blocks
                raw_content = re.sub(r"<think>.*?</think>", "", raw_content, flags=re.DOTALL).strip()

                # Strip markdown code fences
                if raw_content.startswith("```"):
                    parts = raw_content.split("```")
                    raw_content = parts[1].lstrip("json").strip() if len(parts) >= 2 else ""

                if not raw_content:
                    if attempt == 0:
                        log.debug("Empty LLM response for '%s', retrying", title[:60])
                        continue
                    break

                result = _repair_truncated_json(raw_content)
                if result:
                    return result
                if attempt == 0:
                    log.debug("JSON parse failed for '%s', retrying", title[:60])
                    continue

            except Exception as exc:
                if attempt == 0:
                    log.debug("LLM call failed for '%s': %s — retrying", title[:60], exc)
                    continue
                log.warning("LLM extraction failed for '%s': %s", title[:60], exc)
                return {}

        log.warning("LLM extraction failed for '%s' after retries", title[:60])
        return {}


def _coerce_list(value: Any, default: list) -> list:
    return value if isinstance(value, list) else default


def _build_full_text(orm: KnowledgeRecordORM, llm: dict[str, Any]) -> str:
    """Build enriched full_text for re-embedding."""
    def _get(key: str) -> Any:
        return llm.get(key, "")

    parts = [
        orm.title or "",
        orm.vuln_subclass or orm.vuln_class or "",
        str(_get("attack_technique") or orm.attack_technique or ""),
        str(_get("key_insight") or orm.key_insight or ""),
        str(_get("unique_factor") or orm.unique_factor or ""),
        str(_get("impact") or orm.impact or ""),
        str(_get("endpoint_pattern") or orm.endpoint_pattern or ""),
        " ".join(_coerce_list(_get("attack_steps"), orm.attack_steps or [])),
        " ".join(_coerce_list(_get("indicators"), orm.indicators or [])),
        " ".join(_coerce_list(_get("tech_stack"), orm.tech_stack or [])),
        " ".join(_coerce_list(_get("prerequisites"), orm.prerequisites or [])),
        str(_get("payload_pattern") or orm.payload_pattern or ""),
    ]
    return "\n".join(p for p in parts if p.strip()).strip()


def _build_update_values(orm: KnowledgeRecordORM, llm: dict[str, Any], now: datetime) -> dict[str, Any]:
    """Merge LLM extraction results with existing ORM fields for UPDATE."""
    def _get(key: str) -> Any:
        return llm.get(key, "")

    # Only update fields that LLM returned (non-empty) — preserve existing good data
    values: dict[str, Any] = {"updated_at": now}

    if _get("vuln_class"):
        try:
            values["vuln_class"] = VulnClass(str(llm["vuln_class"]).lower().strip()).value
        except ValueError:
            pass

    if _get("tech_stack"):
        tech = _coerce_list(_get("tech_stack"), [])
        if tech:
            values["tech_stack"] = tech

    if _get("platform_type"):
        pt = _coerce_list(_get("platform_type"), [])
        if pt:
            values["platform_type"] = pt

    if _get("endpoint_pattern"):
        values["endpoint_pattern"] = str(_get("endpoint_pattern"))[:500]

    if _get("http_method"):
        hm = _coerce_list(_get("http_method"), [])
        if hm:
            values["http_method"] = hm

    if "auth_required" in llm:
        values["auth_required"] = bool(llm["auth_required"])

    if _get("attack_technique"):
        values["attack_technique"] = str(_get("attack_technique"))

    if _get("attack_steps"):
        steps = _coerce_list(_get("attack_steps"), [])
        if steps:
            values["attack_steps"] = steps

    if _get("payload_pattern"):
        values["payload_pattern"] = str(_get("payload_pattern"))

    if _get("indicators"):
        ind = _coerce_list(_get("indicators"), [])
        if ind:
            values["indicators"] = ind

    if _get("prerequisites"):
        prereq = _coerce_list(_get("prerequisites"), [])
        if prereq:
            values["prerequisites"] = prereq

    if _get("what_tools_missed"):
        values["what_tools_missed"] = str(_get("what_tools_missed"))

    if _get("impact"):
        values["impact"] = str(_get("impact"))

    if _get("impact_category"):
        ic = _coerce_list(_get("impact_category"), [])
        if ic:
            values["impact_category"] = ic

    if _get("key_insight"):
        values["key_insight"] = str(_get("key_insight"))

    if _get("unique_factor"):
        values["unique_factor"] = str(_get("unique_factor"))

    # Rebuild full_text with all enriched data
    values["full_text"] = _build_full_text(orm, llm)

    return values


async def _embed_and_upsert(
    record_id: UUID,
    full_text: str,
    orm: KnowledgeRecordORM,
    llm: dict[str, Any],
    semaphore: asyncio.Semaphore,
) -> bool:
    """Re-embed full_text and upsert to Qdrant. Returns True on success."""
    async with semaphore:
        try:
            result = await embed(full_text)
            payload = {
                "vuln_class": llm.get("vuln_class") or orm.vuln_class,
                "severity": orm.severity,
                "tech_stack": llm.get("tech_stack") or orm.tech_stack,
                "source": orm.source,
                "program": orm.program,
                "title": orm.title,
                "key_insight": llm.get("key_insight") or orm.key_insight,
                "attack_technique": llm.get("attack_technique") or orm.attack_technique,
                "endpoint_pattern": llm.get("endpoint_pattern") or orm.endpoint_pattern,
                "source_url": orm.source_url,
                "bounty_usd": orm.bounty_usd,
                "impact_category": llm.get("impact_category") or orm.impact_category,
            }
            await upsert_to_qdrant(
                record_id=record_id,
                dense=result.dense,
                sparse=result.sparse,
                payload=payload,
            )
            return True
        except Exception as exc:
            log.warning("Qdrant upsert failed for %s: %s", record_id, exc)
            return False


# ── Low-quality detection query ────────────────────────────────────────────────
_LOWQ_WHERE = text("""
    (
        key_insight LIKE '%found in%'
        OR key_insight LIKE '%discovered in%'
        OR key_insight LIKE '%Security issue%'
        OR key_insight LIKE '%Vulnerability discovered%'
        OR attack_technique LIKE '%discovered in%'
        OR attack_technique LIKE '%Vulnerability discovered in%'
        OR (attack_steps = '[]'::jsonb AND payload_pattern IS NULL)
    )
""")


async def main(args: argparse.Namespace) -> None:
    settings = get_settings()
    session_factory = _get_session_factory()
    ollama_model = settings.ollama_model_fast

    llm_sem = asyncio.Semaphore(5)
    embed_sem = asyncio.Semaphore(10)

    async with httpx.AsyncClient(
        base_url=settings.ollama_url,
        timeout=httpx.Timeout(120.0),
    ) as client:
        # ── Count low-quality records ──────────────────────────────────────────
        async with session_factory() as db:
            count_result = await db.execute(
                select(KnowledgeRecordORM.id).where(_LOWQ_WHERE)
            )
            low_q_ids: list[UUID] = [row[0] for row in count_result.all()]

        total = len(low_q_ids)
        log.info("Found %d low-quality records to enrich", total)

        if args.dry_run:
            log.info("Dry-run mode — exiting without changes")
            return

        if args.limit:
            low_q_ids = low_q_ids[: args.limit]
            log.info("Limited to %d records", len(low_q_ids))

        if not low_q_ids:
            log.info("Nothing to enrich — all records look good")
            return

        # ── Ensure Qdrant collection exists ───────────────────────────────────
        if not args.skip_embed:
            await ensure_collection_exists()

        now = datetime.utcnow()
        enriched = 0
        failed_llm = 0
        failed_embed = 0

        # Process in small batches to avoid long-running transactions
        BATCH = 20
        for batch_start in range(0, len(low_q_ids), BATCH):
            batch_ids = low_q_ids[batch_start : batch_start + BATCH]
            batch_num = batch_start // BATCH + 1
            total_batches = (len(low_q_ids) + BATCH - 1) // BATCH
            log.info(
                "Batch %d/%d — enriching %d records",
                batch_num, total_batches, len(batch_ids),
            )

            # Load ORM rows for this batch
            async with session_factory() as db:
                result = await db.execute(
                    select(KnowledgeRecordORM).where(KnowledgeRecordORM.id.in_(batch_ids))
                )
                orm_rows: list[KnowledgeRecordORM] = list(result.scalars().all())

            # Run LLM extraction concurrently for this batch
            llm_tasks = [
                _llm_extract(
                    title=orm.title or "",
                    vuln_type=orm.vuln_subclass or orm.vuln_class or "",
                    severity=orm.severity or "unknown",
                    program=orm.program or "unknown",
                    bounty=str(orm.bounty_usd) if orm.bounty_usd else "0",
                    client=client,
                    model=ollama_model,
                    semaphore=llm_sem,
                )
                for orm in orm_rows
            ]
            llm_results: list[dict[str, Any]] = await asyncio.gather(*llm_tasks)

            # Apply updates
            async with session_factory() as db:
                for orm, llm in zip(orm_rows, llm_results):
                    if not llm:
                        log.debug("No LLM result for '%s' — skipping update", orm.title[:60] if orm.title else "?")
                        failed_llm += 1
                        continue

                    update_vals = _build_update_values(orm, llm, now)
                    await db.execute(
                        update(KnowledgeRecordORM)
                        .where(KnowledgeRecordORM.id == orm.id)
                        .values(**update_vals)
                    )
                    enriched += 1

                await db.commit()
                log.info("Committed updates in batch %d/%d", batch_num, total_batches)

            # Re-embed updated records
            if not args.skip_embed:
                embed_tasks = []
                for orm, llm in zip(orm_rows, llm_results):
                    if not llm:
                        continue
                    full_text = _build_full_text(orm, llm)
                    embed_tasks.append(
                        _embed_and_upsert(
                            record_id=orm.id,
                            full_text=full_text,
                            orm=orm,
                            llm=llm,

                            semaphore=embed_sem,
                        )
                    )
                embed_results = await asyncio.gather(*embed_tasks)
                batch_embed_ok = sum(1 for r in embed_results if r)
                batch_embed_fail = len(embed_results) - batch_embed_ok
                failed_embed += batch_embed_fail
                log.info(
                    "Batch %d/%d embedded: %d ok, %d failed",
                    batch_num, total_batches, batch_embed_ok, batch_embed_fail,
                )

        log.info(
            "Enrichment complete — %d updated, %d LLM failures, %d embed failures (total candidates: %d)",
            enriched, failed_llm, failed_embed, total,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Re-enrich low-quality knowledge records")
    parser.add_argument("--limit", type=int, default=0, help="Max records to process (0 = all)")
    parser.add_argument("--dry-run", action="store_true", help="Count candidates only, no changes")
    parser.add_argument("--skip-embed", action="store_true", help="Skip Qdrant re-embedding (DB update only)")
    args = parser.parse_args()
    asyncio.run(main(args))
