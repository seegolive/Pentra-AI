"""Task 5.2 — CVE correlation Celery task.

Polls for findings that have not been CVE-enriched yet
(cve_ids is empty list) and runs CVEEnrichmentService on each.

Run manually:
    celery -A app.worker call app.tasks.cve_enrichment.enrich_pending_findings
"""
from __future__ import annotations

import asyncio
import logging
import os

from celery import shared_task

log = logging.getLogger(__name__)


async def _enrich_batch(batch_size: int) -> dict:
    """Fetch unenriched findings from the DB and run CVE enrichment."""
    import sqlalchemy as sa
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker

    from pentra_knowledge.services.cve_enrichment import CVEEnrichmentService

    database_url = os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://pentra:pentra@localhost:5432/pentra",
    )
    nvd_api_key = os.environ.get("NVD_API_KEY") or None

    engine = create_async_engine(database_url, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    service = CVEEnrichmentService(api_key=nvd_api_key)

    enriched_count = 0
    skipped_count = 0

    try:
        async with async_session() as session:
            # Fetch findings with empty cve_ids
            result = await session.execute(
                sa.text(
                    """
                    SELECT id, title, vuln_class, description
                    FROM findings
                    WHERE cve_ids = '[]'::jsonb
                      AND status != 'false_positive'
                    ORDER BY discovered_at DESC
                    LIMIT :limit
                    """
                ),
                {"limit": batch_size},
            )
            rows = result.fetchall()

        if not rows:
            log.info("[cve_enrichment] No unenriched findings found")
            return {"enriched": 0, "skipped": 0}

        log.info("[cve_enrichment] Enriching %d findings", len(rows))

        for row in rows:
            finding_id, title, vuln_class, description = row
            try:
                enrichment = await service.enrich(
                    title=title,
                    vuln_class=vuln_class,
                    description=description or "",
                )

                async with async_session() as session:
                    await session.execute(
                        sa.text(
                            """
                            UPDATE findings
                            SET cve_ids   = :cve_ids::jsonb,
                                cve_data  = :cve_data::jsonb
                            WHERE id = :id
                            """
                        ),
                        {
                            "id": str(finding_id),
                            "cve_ids": __import__("json").dumps(enrichment.cve_ids),
                            "cve_data": (
                                __import__("json").dumps(enrichment.cve_data.model_dump())
                                if enrichment.cve_data
                                else "null"
                            ),
                        },
                    )
                    await session.commit()

                if enrichment.enriched:
                    enriched_count += 1
                    log.info(
                        "[cve_enrichment] Finding %s → %s",
                        finding_id,
                        enrichment.cve_ids,
                    )
                else:
                    skipped_count += 1

            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "[cve_enrichment] Failed to enrich finding %s: %s",
                    finding_id,
                    exc,
                )
                skipped_count += 1

    finally:
        await engine.dispose()

    return {"enriched": enriched_count, "skipped": skipped_count}


@shared_task(
    name="app.tasks.cve_enrichment.enrich_pending_findings",
    bind=True,
    max_retries=1,
    default_retry_delay=600,
    acks_late=True,
)
def enrich_pending_findings(self, batch_size: int = 20) -> dict:
    """
    Celery task — enrich unprocessed findings with CVE data from NVD.

    Runs daily (configured in beat_schedule).  Can also be called manually:

        celery -A app.worker call app.tasks.cve_enrichment.enrich_pending_findings
    """
    log.info("[cve_enrichment] Starting CVE enrichment, batch_size=%d", batch_size)
    try:
        result = asyncio.get_event_loop().run_until_complete(
            _enrich_batch(batch_size)
        )
        log.info("[cve_enrichment] Finished: %s", result)
        return result
    except Exception as exc:  # noqa: BLE001
        log.error("[cve_enrichment] Task failed: %s", exc)
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc)
        return {"error": str(exc), "enriched": 0, "skipped": 0}
