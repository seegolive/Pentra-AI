#!/usr/bin/env python3
"""Fill NULL payload_pattern for all existing knowledge records.

Uses a fast, focused LLM prompt — only extracts payload_pattern.
Runs concurrently (8 workers) and updates DB in batches.

Usage:
    DATABASE_URL=... OLLAMA_URL=... uv run python scripts/fill_payload_pattern.py
    DATABASE_URL=... OLLAMA_URL=... uv run python scripts/fill_payload_pattern.py --limit 500
    DATABASE_URL=... OLLAMA_URL=... uv run python scripts/fill_payload_pattern.py --dry-run
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import re
import sys
from datetime import datetime, timezone
from uuid import UUID

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger("fill_payload")

_SYSTEM = (
    "/no_think\n"
    "You are a security researcher. Reply ONLY with a short payload snippet — "
    "no explanation, no markdown, no JSON. Just the raw payload string."
)

_PROMPT = """\
Vulnerability: {vuln_class}
Title: {title}
Attack: {attack}

Give me ONE concrete payload snippet or request example for this vulnerability type.
Examples: ?id=1 OR 1=1--  or  <script>alert(1)</script>  or  /../../../etc/passwd  or  {{7*7}}
Reply with ONLY the payload, nothing else."""


async def _get_payload(
    record_id: UUID,
    title: str,
    vuln_class: str,
    attack: str,
    client: httpx.AsyncClient,
    model: str,
    sem: asyncio.Semaphore,
) -> tuple[UUID, str | None]:
    async with sem:
        prompt = _PROMPT.format(
            vuln_class=vuln_class or "unknown",
            title=(title or "")[:200],
            attack=(attack or "")[:300],
        )
        for attempt in range(2):
            try:
                resp = await client.post(
                    "/api/chat",
                    json={
                        "model": model,
                        "messages": [
                            {"role": "system", "content": _SYSTEM},
                            {"role": "user", "content": prompt},
                        ],
                        "stream": False,
                        "options": {"temperature": 0.1, "num_predict": 200},
                    },
                )
                resp.raise_for_status()
                raw = resp.json()["message"]["content"].strip()
                # Strip think blocks
                raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
                # Strip markdown fences
                if raw.startswith("```"):
                    parts = raw.split("```")
                    raw = parts[1].lstrip("\n").strip() if len(parts) >= 2 else raw
                if raw and len(raw) < 1000:
                    return record_id, raw
            except Exception as exc:
                if attempt == 0:
                    await asyncio.sleep(1)
                    continue
                log.debug("LLM failed for %s: %s", record_id, exc)
        return record_id, None


async def main(args: argparse.Namespace) -> None:
    db_url = os.environ.get("DATABASE_URL")
    ollama_url = os.environ.get("OLLAMA_URL", "http://localhost:11434")
    model = os.environ.get("OLLAMA_MODEL_FAST", "qwen2.5:7b")

    if not db_url:
        log.error("DATABASE_URL not set")
        sys.exit(1)

    engine = create_async_engine(db_url, pool_size=5, max_overflow=10)

    async with AsyncSession(engine) as s:
        rows = (await s.execute(text(
            "SELECT id, title, vuln_class, attack_technique FROM knowledge_records "
            "WHERE payload_pattern IS NULL ORDER BY quality_score DESC"
        ))).fetchall()

    total = len(rows)
    log.info("Found %d records with NULL payload_pattern", total)

    if args.dry_run:
        log.info("Dry-run — exiting")
        await engine.dispose()
        return

    if args.limit:
        rows = rows[:args.limit]
        log.info("Limited to %d records", len(rows))

    sem = asyncio.Semaphore(args.concurrency)

    async with httpx.AsyncClient(
        base_url=ollama_url,
        timeout=httpx.Timeout(60.0),
    ) as client:
        updated = 0
        failed = 0
        BATCH = 50

        for batch_start in range(0, len(rows), BATCH):
            batch = rows[batch_start:batch_start + BATCH]
            batch_num = batch_start // BATCH + 1
            total_batches = (len(rows) + BATCH - 1) // BATCH
            log.info("Batch %d/%d — processing %d records", batch_num, total_batches, len(batch))

            tasks = [
                _get_payload(
                    record_id=row[0],
                    title=row[1] or "",
                    vuln_class=row[2] or "",
                    attack=row[3] or "",
                    client=client,
                    model=model,
                    sem=sem,
                )
                for row in batch
            ]
            results = await asyncio.gather(*tasks)

            # Bulk update in one transaction
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            updates = [(rid, payload) for rid, payload in results if payload]
            no_payload = [rid for rid, payload in results if not payload]

            if updates:
                async with AsyncSession(engine) as s:
                    for rid, payload in updates:
                        await s.execute(
                            text("UPDATE knowledge_records SET payload_pattern = :p, updated_at = :t WHERE id = :id"),
                            {"p": payload[:2000], "t": now, "id": rid},
                        )
                    await s.commit()
                updated += len(updates)
            failed += len(no_payload)
            log.info(
                "  Batch done — updated: %d, failed: %d | Total so far: %d/%d",
                len(updates), len(no_payload), updated, len(rows),
            )

    log.info("=== DONE: updated=%d, failed=%d, total_target=%d", updated, failed, len(rows))
    await engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--concurrency", type=int, default=8)
    asyncio.run(main(parser.parse_args()))
