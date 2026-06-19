"""Tests for report generation endpoints (Sprint 34).

Tests exercise get_report and get_h1_summary_report without a live
database or LLM, using mocked DB sessions and pentra-report package.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
from uuid import uuid4

import pytest

from app.api.report_router import get_report, get_h1_summary_report
from app.db.models import EngagementORM, FindingORM, UserORM


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_user() -> UserORM:
    u = UserORM()
    u.id = uuid4()
    u.username = "tester"
    u.email = "tester@test.com"
    u.hashed_password = "x"
    u.is_active = True
    u.is_admin = False
    return u


def _make_engagement(user_id=None) -> EngagementORM:
    e = EngagementORM()
    e.id = uuid4()
    e.workspace_id = uuid4()
    e.name = "Test Engagement"
    e.description = None
    e.mode = "semi_auto"
    e.status = "completed"
    e.in_scope = ["target.com"]
    e.out_of_scope = []
    e.llm_model = "qwen2.5-coder:32b"
    e.langgraph_thread_id = str(uuid4())
    e.opsec_mode = False
    e.request_jitter_ms = 0
    e.created_by = user_id or uuid4()
    e.created_at = datetime.now(timezone.utc)
    e.updated_at = datetime.now(timezone.utc)
    e.started_at = None
    e.completed_at = None
    e.monitoring_enabled = False
    e.monitoring_interval_hours = 24
    return e


def _make_finding(engagement_id=None) -> FindingORM:
    f = FindingORM()
    f.id = uuid4()
    f.engagement_id = engagement_id or uuid4()
    f.title = "SQL Injection in /login"
    f.vuln_class = "sqli"
    f.severity = "critical"
    f.cvss_score = 9.8
    f.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    f.target_url = "https://target.com/login"
    f.http_method = "POST"
    f.request_raw = "POST /login HTTP/1.1\nHost: target.com\n\nusername=admin'--&password=x"
    f.response_raw = "HTTP/1.1 200 OK\n\nWelcome admin"
    f.screenshot_path = None
    f.impact = "Full database read/write access"
    f.remediation = "Use parameterized queries"
    f.reproduction_steps = ["Send payload", "Observe response"]
    f.knowledge_refs = []
    f.status = "open"
    f.discovered_by = "pentra-agent"
    f.discovered_at = datetime.now(timezone.utc)
    f.description = "Classic SQLi via login form"
    f.cve_ids = []
    f.cve_data = None
    f.chains = None
    return f


def _mock_db(eng, findings):
    """Return a mock AsyncSession with pre-configured execute results."""
    db = AsyncMock()

    eng_result = MagicMock()
    eng_result.scalar_one_or_none.return_value = eng

    finding_result = MagicMock()
    finding_result.scalars.return_value.all.return_value = findings

    db.execute.side_effect = [eng_result, finding_result]
    return db


# ── get_report tests ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_report_markdown_returns_text():
    user = _make_user()
    eng = _make_engagement(user.id)
    finding = _make_finding(eng.id)
    db = _mock_db(eng, [finding])

    result = await get_report(eng.id, format="markdown", db=db, current_user=user)

    assert result.status_code == 200
    body = result.body.decode()
    assert "# Pentra AI" in body or "Security Assessment" in body
    assert "SQL Injection" in body
    assert "critical" in body.lower()


@pytest.mark.asyncio
async def test_get_report_html_returns_html_response():
    user = _make_user()
    eng = _make_engagement(user.id)
    finding = _make_finding(eng.id)
    db = _mock_db(eng, [finding])

    result = await get_report(eng.id, format="html", db=db, current_user=user)

    assert result.status_code == 200
    body = result.body.decode()
    assert "<html" in body.lower() or "<!DOCTYPE" in body.lower() or "SQL Injection" in body


@pytest.mark.asyncio
async def test_get_report_h1_returns_json():
    import json
    user = _make_user()
    eng = _make_engagement(user.id)
    finding = _make_finding(eng.id)
    db = _mock_db(eng, [finding])

    result = await get_report(eng.id, format="h1", db=db, current_user=user)

    assert result.status_code == 200
    data = json.loads(result.body)
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["title"] == "SQL Injection in /login"
    assert data[0]["severity"] == "critical"


@pytest.mark.asyncio
async def test_get_report_404_if_engagement_missing():
    from fastapi import HTTPException
    user = _make_user()

    db = AsyncMock()
    eng_result = MagicMock()
    eng_result.scalar_one_or_none.return_value = None
    db.execute.return_value = eng_result

    with pytest.raises(HTTPException) as exc_info:
        await get_report(uuid4(), format="markdown", db=db, current_user=user)

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_get_report_empty_findings_renders_placeholder():
    user = _make_user()
    eng = _make_engagement(user.id)
    db = _mock_db(eng, [])

    result = await get_report(eng.id, format="markdown", db=db, current_user=user)

    assert result.status_code == 200
    body = result.body.decode()
    assert "No open findings" in body or "0" in body


@pytest.mark.asyncio
async def test_get_report_pdf_calls_weasyprint():
    user = _make_user()
    eng = _make_engagement(user.id)
    db = _mock_db(eng, [])

    fake_weasyprint = MagicMock()
    fake_html_instance = MagicMock()
    fake_html_instance.write_pdf.return_value = b"%PDF-1.4 fake"
    fake_weasyprint.HTML.return_value = fake_html_instance

    with patch.dict("sys.modules", {"weasyprint": fake_weasyprint}):
        result = await get_report(eng.id, format="pdf", db=db, current_user=user)

    assert result.status_code == 200
    assert result.headers["content-type"] == "application/pdf"
    assert b"%PDF" in result.body


# ── get_h1_summary_report tests ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_h1_summary_returns_markdown_with_llm():
    user = _make_user()
    eng = _make_engagement(user.id)
    finding = _make_finding(eng.id)
    db = _mock_db(eng, [finding])

    mock_llm = AsyncMock()
    mock_llm.complete.return_value = "This assessment found a critical SQLi vulnerability."

    with patch("app.core.config.get_api_settings") as mock_settings, \
         patch("pentra_agent.llm.client.LLMClient") as MockLLM:
        mock_settings.return_value.ollama_url = "http://localhost:11434"
        mock_settings.return_value.ollama_model_default = "qwen2.5-coder:32b"
        MockLLM.return_value = mock_llm

        result = await get_h1_summary_report(eng.id, db=db, current_user=user)

    assert result.status_code == 200
    body = result.body.decode()
    assert "SQL Injection" in body or "target" in body.lower()


@pytest.mark.asyncio
async def test_get_h1_summary_empty_findings_returns_placeholder():
    user = _make_user()
    eng = _make_engagement(user.id)
    db = _mock_db(eng, [])

    result = await get_h1_summary_report(eng.id, db=db, current_user=user)

    assert result.status_code == 200
    assert b"No findings" in result.body


@pytest.mark.asyncio
async def test_get_h1_summary_404_if_engagement_missing():
    from fastapi import HTTPException
    user = _make_user()

    db = AsyncMock()
    eng_result = MagicMock()
    eng_result.scalar_one_or_none.return_value = None
    db.execute.return_value = eng_result

    with pytest.raises(HTTPException) as exc_info:
        await get_h1_summary_report(uuid4(), db=db, current_user=user)

    assert exc_info.value.status_code == 404
