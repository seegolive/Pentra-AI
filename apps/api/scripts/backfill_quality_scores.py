"""Backfill quality_score for existing knowledge_records rows.

Usage:
    cd apps/api
    DATABASE_URL="postgresql+asyncpg://..." uv run python scripts/backfill_quality_scores.py

Computes KnowledgeRecord.calculate_quality_score() for every row in
knowledge_records and writes the result back to the DB.  Safe to re-run
(idempotent — overwrites with the freshly computed value each time).
"""

import asyncio
import os
import sys
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

# Ensure app packages are on sys.path when running as a script
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.base import Base  # noqa: F401 — ensures models are registered
from pentra_knowledge.db.models import KnowledgeRecordORM
from pentra_shared.types import KnowledgeRecord


BATCH_SIZE = 500


async def backfill(database_url: str) -> None:
    engine = create_async_engine(database_url, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)  # type: ignore[call-overload]

    async with async_session() as session:
        # Count rows
        from sqlalchemy import func, select as sa_select
        count_result = await session.execute(sa_select(func.count()).select_from(KnowledgeRecordORM))
        total = count_result.scalar_one()
        print(f"Total knowledge_records: {total}")

        updated = 0
        offset = 0

        while True:
            result = await session.execute(
                select(KnowledgeRecordORM).offset(offset).limit(BATCH_SIZE)
            )
            rows = result.scalars().all()
            if not rows:
                break

            for row in rows:
                # Build a minimal KnowledgeRecord to call calculate_quality_score
                record = KnowledgeRecord(
                    id=row.id,
                    source=row.source,  # type: ignore[arg-type]
                    source_id=row.source_id,
                    title=row.title,
                    vuln_class=row.vuln_class,  # type: ignore[arg-type]
                    severity=row.severity,  # type: ignore[arg-type]
                    program=row.program,
                    key_insight=row.key_insight,
                    attack_technique=row.attack_technique,
                    attack_steps=row.attack_steps,
                    indicators=row.indicators,
                    what_tools_missed=row.what_tools_missed,
                    tech_stack=row.tech_stack,
                    bounty_usd=row.bounty_usd,
                    chained_with=row.chained_with,
                    cvss_score=row.cvss_score,
                )
                new_score = record.calculate_quality_score()
                await session.execute(
                    update(KnowledgeRecordORM)
                    .where(KnowledgeRecordORM.id == row.id)
                    .values(quality_score=new_score)
                )
                updated += 1

            await session.commit()
            offset += BATCH_SIZE
            print(f"  Updated {updated}/{total} rows …", end="\r", flush=True)

        print(f"\nDone — {updated} rows backfilled.")

    await engine.dispose()


if __name__ == "__main__":
    url = os.environ.get("DATABASE_URL")
    if not url:
        print("ERROR: DATABASE_URL environment variable is not set.", file=sys.stderr)
        sys.exit(1)
    asyncio.run(backfill(url))
