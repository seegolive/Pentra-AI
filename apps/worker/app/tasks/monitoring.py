"""Continuous monitoring Celery task — delta detection between recon snapshots.

For each engagement with monitoring enabled, runs a lightweight recon (subfinder +
httpx port probe), compares with the previous snapshot, persists alerts for any
changes, and queues notifications.

Beat schedule entry (added to ``core/config.py``)::

    "monitoring-daily": {
        "task": "app.tasks.monitoring.run_all_engagement_monitors",
        "schedule": 86400.0,   # every 24 hours
    }
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import httpx

from app.worker import celery_app

log = logging.getLogger(__name__)


# ── Celery task entry points ──────────────────────────────────────────────────

@celery_app.task(name="app.tasks.monitoring.run_all_engagement_monitors", bind=True, max_retries=2)
def run_all_engagement_monitors(self) -> dict:
    """Scan all active engagements for recon changes."""
    return asyncio.get_event_loop().run_until_complete(_run_all())


@celery_app.task(name="app.tasks.monitoring.run_engagement_monitor", bind=True, max_retries=2)
def run_engagement_monitor(self, engagement_id: str) -> dict:
    """Scan a single engagement for recon changes."""
    return asyncio.get_event_loop().run_until_complete(_run_single(engagement_id))


# ── Async implementation ──────────────────────────────────────────────────────

async def _run_all() -> dict:
    """Find all active engagements and run delta scan for each."""
    from app.core.config import get_api_settings
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
    from sqlalchemy.orm import sessionmaker

    settings = get_api_settings()
    engine = create_async_engine(settings.database_url, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    try:
        async with async_session() as db:
            from app.db.models import EngagementORM
            result = await db.execute(
                select(EngagementORM).where(
                    EngagementORM.status.in_(["running", "completed"])
                )
            )
            engagements = result.scalars().all()

        total = 0
        for eng in engagements:
            try:
                await _run_single(str(eng.id))
                total += 1
            except Exception as exc:  # noqa: BLE001
                log.warning("Monitor failed for engagement %s: %s", eng.id, exc)

        return {"scanned": total}
    finally:
        await engine.dispose()


async def _run_single(engagement_id: str) -> dict:
    """Run delta scan for one engagement, persist snapshot + alerts."""
    from app.core.config import get_api_settings
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
    from sqlalchemy.orm import sessionmaker

    settings = get_api_settings()
    engine = create_async_engine(settings.database_url, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    try:
        async with async_session() as db:
            from app.db.models import EngagementORM, ReconSnapshotORM, MonitoringAlertORM

            # Load engagement
            result = await db.execute(
                select(EngagementORM).where(EngagementORM.id == UUID(engagement_id))
            )
            engagement = result.scalar_one_or_none()
            if not engagement:
                log.warning("Engagement %s not found", engagement_id)
                return {"error": "not_found"}

            in_scope = engagement.in_scope or []
            if not in_scope:
                return {"skipped": "no_scope"}

            # Run lightweight recon
            current = await _collect_snapshot(in_scope, settings)

            # Load previous snapshot
            prev_result = await db.execute(
                select(ReconSnapshotORM)
                .where(ReconSnapshotORM.engagement_id == UUID(engagement_id))
                .order_by(ReconSnapshotORM.snapshot_at.desc())
                .limit(1)
            )
            previous = prev_result.scalar_one_or_none()

            # Persist current snapshot
            snap = ReconSnapshotORM(
                engagement_id=UUID(engagement_id),
                snapshot_at=datetime.now(UTC),
                subdomains=current["subdomains"],
                open_ports=current["open_ports"],
                endpoints=current["endpoints"],
                tech_stack=current["tech_stack"],
                raw_summary=f"Auto-snapshot {datetime.now(UTC).isoformat()}",
            )
            db.add(snap)

            # Compute delta if we have a previous snapshot
            alerts: list[MonitoringAlertORM] = []
            if previous:
                deltas = _detect_delta(previous, current)
                for delta in deltas:
                    alert = MonitoringAlertORM(
                        engagement_id=UUID(engagement_id),
                        alert_type=delta["type"],
                        detail=delta,
                        notified=False,
                    )
                    db.add(alert)
                    alerts.append(alert)

            await db.commit()

            alert_count = len(alerts)
            if alert_count > 0:
                log.info(
                    "Engagement %s: %d delta alert(s) detected",
                    engagement_id,
                    alert_count,
                )
                # Queue notification task
                from app.tasks.notifications import send_monitoring_alerts
                send_monitoring_alerts.delay(engagement_id, [a.alert_type for a in alerts])

            return {"engagement_id": engagement_id, "alerts": alert_count}
    finally:
        await engine.dispose()


async def _collect_snapshot(in_scope: list[str], settings: Any) -> dict:
    """Collect lightweight recon data: passive subdomain list + HTTP probe."""
    subdomains: list[dict] = []  # SubdomainInfo dicts: {host, source, status_code?, ip?}
    endpoints: list[str] = []
    open_ports: dict[str, list[int]] = {}
    tech_stack: list[str] = []
    _seen_hosts: set[str] = set()

    for scope_entry in in_scope[:5]:  # cap to 5 scope entries per cycle
        domain = scope_entry.lstrip("*.").strip()
        if not domain:
            continue

        # Passive subdomain enum via subfinder (if available)
        try:
            proc = await asyncio.create_subprocess_exec(
                "subfinder", "-d", domain, "-silent",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            for line in stdout.decode().splitlines():
                sub = line.strip()
                if sub and sub not in _seen_hosts:
                    subdomains.append({"host": sub, "source": "subfinder"})
                    _seen_hosts.add(sub)
        except (FileNotFoundError, asyncio.TimeoutError):
            if domain not in _seen_hosts:
                subdomains.append({"host": domain, "source": "scope"})
                _seen_hosts.add(domain)

        # HTTP probe: check if host is alive and capture status_code
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
                for port in [80, 443, 8080, 8443]:
                    scheme = "https" if port in (443, 8443) else "http"
                    url = f"{scheme}://{domain}:{port}/"
                    try:
                        resp = await client.get(url)
                        if resp.status_code < 600:
                            open_ports.setdefault(domain, []).append(port)
                            endpoints.append(url)
                            # Enrich the subdomain entry with status_code
                            for entry in subdomains:
                                if entry["host"] == domain and "status_code" not in entry:
                                    entry["status_code"] = resp.status_code
                            # Rudimentary tech detection from response headers
                            server = resp.headers.get("server", "")
                            x_powered = resp.headers.get("x-powered-by", "")
                            if server:
                                tech_stack.append(server)
                            if x_powered:
                                tech_stack.append(x_powered)
                    except Exception:  # noqa: BLE001
                        pass
        except Exception as exc:  # noqa: BLE001
            log.debug("HTTP probe failed for %s: %s", domain, exc)

    return {
        "subdomains": sorted(subdomains, key=lambda s: s["host"]),
        "open_ports": open_ports,
        "endpoints": sorted(set(endpoints)),
        "tech_stack": sorted(set(tech_stack)),
    }


def _detect_delta(previous: Any, current: dict) -> list[dict]:
    """Compare previous snapshot ORM with current dict and return change list."""
    deltas: list[dict] = []

    def _host(s: Any) -> str:
        return s["host"] if isinstance(s, dict) else str(s)

    prev_subs: set[str] = {_host(s) for s in (previous.subdomains or [])}
    curr_subs: set[str] = {_host(s) for s in current["subdomains"]}

    for new_sub in curr_subs - prev_subs:
        deltas.append({"type": "new_subdomain", "value": new_sub})

    for removed in prev_subs - curr_subs:
        deltas.append({"type": "removed_subdomain", "value": removed})

    # Port changes per host
    prev_ports: dict = previous.open_ports or {}
    curr_ports: dict = current["open_ports"]
    all_hosts = set(prev_ports) | set(curr_ports)
    for host in all_hosts:
        prev_set = set(prev_ports.get(host, []))
        curr_set = set(curr_ports.get(host, []))
        for port in curr_set - prev_set:
            deltas.append({"type": "new_port", "host": host, "port": port})

    # New endpoints
    prev_eps = set(previous.endpoints or [])
    curr_eps = set(current["endpoints"])
    for ep in curr_eps - prev_eps:
        deltas.append({"type": "new_endpoint", "value": ep})

    return deltas
