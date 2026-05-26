"""Notification Celery tasks — Slack webhook + Telegram bot.

Sends alerts for:
- Monitoring delta detection (new subdomain / port / endpoint)
- New confirmed finding

Configuration (via environment variables)::

    SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
    TELEGRAM_BOT_TOKEN=1234567890:ABC...
    TELEGRAM_CHAT_ID=-1001234567890

Both are optional. If not configured, the task logs and skips silently.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from app.worker import celery_app

log = logging.getLogger(__name__)


# ── Celery tasks ──────────────────────────────────────────────────────────────

@celery_app.task(name="app.tasks.notifications.send_monitoring_alerts", bind=True, max_retries=3)
def send_monitoring_alerts(self, engagement_id: str, alert_types: list[str]) -> dict:
    """Send monitoring delta alerts via Slack + Telegram."""
    return asyncio.get_event_loop().run_until_complete(
        _send_monitoring_alerts(engagement_id, alert_types)
    )


@celery_app.task(name="app.tasks.notifications.send_finding_alert", bind=True, max_retries=3)
def send_finding_alert(self, engagement_id: str, finding_title: str, severity: str) -> dict:
    """Send a new confirmed finding notification."""
    return asyncio.get_event_loop().run_until_complete(
        _send_finding_alert(engagement_id, finding_title, severity)
    )


# ── Async implementations ─────────────────────────────────────────────────────

async def _send_monitoring_alerts(engagement_id: str, alert_types: list[str]) -> dict:
    from app.core.config import get_api_settings

    settings = get_api_settings()
    slack_url = getattr(settings, "slack_webhook_url", "") or ""
    tg_token = getattr(settings, "telegram_bot_token", "") or ""
    tg_chat = getattr(settings, "telegram_chat_id", "") or ""

    summary = _format_alert_summary(alert_types)
    text = (
        f"🔍 *Pentra AI — Monitoring Alert*\n"
        f"Engagement: `{engagement_id}`\n"
        f"{summary}"
    )
    markdown_text = (
        f"🔍 **Pentra AI — Monitoring Alert**\n"
        f"Engagement: `{engagement_id}`\n"
        f"{summary}"
    )

    results: dict[str, Any] = {}

    if slack_url:
        results["slack"] = await _slack_send(slack_url, markdown_text)

    if tg_token and tg_chat:
        results["telegram"] = await _telegram_send(tg_token, tg_chat, text)

    if not slack_url and not (tg_token and tg_chat):
        log.debug("No notification channels configured — skipping alert for %s", engagement_id)

    # Mark alerts as notified in DB
    await _mark_alerts_notified(engagement_id)

    return results


async def _send_finding_alert(engagement_id: str, finding_title: str, severity: str) -> dict:
    from app.core.config import get_api_settings

    settings = get_api_settings()
    slack_url = getattr(settings, "slack_webhook_url", "") or ""
    tg_token = getattr(settings, "telegram_bot_token", "") or ""
    tg_chat = getattr(settings, "telegram_chat_id", "") or ""

    severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
        severity.lower(), "⚪"
    )
    text = (
        f"{severity_emoji} *Pentra AI — New Finding*\n"
        f"Engagement: `{engagement_id}`\n"
        f"Title: {finding_title}\n"
        f"Severity: {severity.upper()}"
    )

    results: dict[str, Any] = {}

    if slack_url:
        results["slack"] = await _slack_send(slack_url, text)

    if tg_token and tg_chat:
        results["telegram"] = await _telegram_send(tg_token, tg_chat, text)

    return results


# ── Channel helpers ───────────────────────────────────────────────────────────

async def _slack_send(webhook_url: str, text: str) -> str:
    """POST to Slack incoming webhook. Returns 'ok' or error message."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(webhook_url, json={"text": text})
            resp.raise_for_status()
            return "ok"
    except Exception as exc:  # noqa: BLE001
        log.warning("Slack notification failed: %s", exc)
        return f"error: {exc}"


async def _telegram_send(bot_token: str, chat_id: str, text: str) -> str:
    """Send message via Telegram Bot API. Returns 'ok' or error message."""
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json={
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "Markdown",
            })
            resp.raise_for_status()
            return "ok"
    except Exception as exc:  # noqa: BLE001
        log.warning("Telegram notification failed: %s", exc)
        return f"error: {exc}"


def _format_alert_summary(alert_types: list[str]) -> str:
    counts: dict[str, int] = {}
    for t in alert_types:
        counts[t] = counts.get(t, 0) + 1
    lines = []
    labels = {
        "new_subdomain": "New subdomain(s)",
        "removed_subdomain": "Removed subdomain(s)",
        "new_port": "New open port(s)",
        "new_endpoint": "New endpoint(s)",
    }
    for key, count in counts.items():
        label = labels.get(key, key)
        lines.append(f"• {label}: {count}")
    return "\n".join(lines) if lines else "• Changes detected"


async def _mark_alerts_notified(engagement_id: str) -> None:
    """Set notified=True on all pending alerts for this engagement."""
    from uuid import UUID
    from sqlalchemy import update
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
    from sqlalchemy.orm import sessionmaker
    from app.core.config import get_api_settings
    from app.db.models import MonitoringAlertORM

    settings = get_api_settings()
    engine = create_async_engine(settings.database_url, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with async_session() as db:
            await db.execute(
                update(MonitoringAlertORM)
                .where(
                    MonitoringAlertORM.engagement_id == UUID(engagement_id),
                    MonitoringAlertORM.notified.is_(False),
                )
                .values(notified=True)
            )
            await db.commit()
    except Exception as exc:  # noqa: BLE001
        log.warning("Failed to mark alerts notified: %s", exc)
    finally:
        await engine.dispose()
