"""Tests for worker/app/tasks/notifications.py helpers.

_format_alert_summary is pure Python. Slack/Telegram send functions
are tested with mocked httpx.
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.tasks.notifications import (
    _format_alert_summary,
    _slack_send,
    _telegram_send,
)


# ── _format_alert_summary ─────────────────────────────────────────────────────

def test_format_alert_summary_single_type():
    result = _format_alert_summary(["new_subdomain"])
    assert "New subdomain(s): 1" in result


def test_format_alert_summary_multiple_same_type():
    result = _format_alert_summary(["new_subdomain", "new_subdomain", "new_subdomain"])
    assert "New subdomain(s): 3" in result


def test_format_alert_summary_mixed_types():
    result = _format_alert_summary([
        "new_subdomain",
        "new_port",
        "new_port",
        "new_endpoint",
    ])
    assert "New subdomain(s): 1" in result
    assert "New open port(s): 2" in result
    assert "New endpoint(s): 1" in result


def test_format_alert_summary_removed_subdomain():
    result = _format_alert_summary(["removed_subdomain"])
    assert "Removed subdomain(s): 1" in result


def test_format_alert_summary_empty_list():
    result = _format_alert_summary([])
    assert "Changes detected" in result


def test_format_alert_summary_unknown_type():
    result = _format_alert_summary(["unknown_type"])
    assert "unknown_type" in result or "1" in result


def test_format_alert_summary_starts_with_bullet():
    result = _format_alert_summary(["new_port"])
    assert result.startswith("•")


def test_format_alert_summary_multiline_for_multiple_types():
    result = _format_alert_summary(["new_subdomain", "new_port"])
    lines = result.strip().splitlines()
    assert len(lines) == 2


# ── _slack_send — mocked httpx ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_slack_send_ok():
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("app.tasks.notifications.httpx.AsyncClient", return_value=mock_client):
        result = await _slack_send("https://hooks.slack.com/test", "hello")

    assert result == "ok"


@pytest.mark.asyncio
async def test_slack_send_returns_error_string_on_exception():
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(side_effect=Exception("Connection refused"))

    with patch("app.tasks.notifications.httpx.AsyncClient", return_value=mock_client):
        result = await _slack_send("https://hooks.slack.com/test", "hello")

    assert result.startswith("error:")


# ── _telegram_send — mocked httpx ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_telegram_send_ok():
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("app.tasks.notifications.httpx.AsyncClient", return_value=mock_client):
        result = await _telegram_send("TOKEN", "-100123", "hello")

    assert result == "ok"
    called_url = mock_client.post.call_args[0][0]
    assert "TOKEN/sendMessage" in called_url


@pytest.mark.asyncio
async def test_telegram_send_returns_error_on_failure():
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(side_effect=Exception("Timeout"))

    with patch("app.tasks.notifications.httpx.AsyncClient", return_value=mock_client):
        result = await _telegram_send("TOKEN", "-100123", "hello")

    assert result.startswith("error:")
