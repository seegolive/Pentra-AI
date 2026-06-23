"""Tests for ReportGenerator — Markdown, HTML, H1, and PDF output.

All tests are pure Python — no DB, no LLM, no network.
PDF tests mock weasyprint to avoid the system dependency.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from pentra_report.generator import (
    FindingReport,
    ReportData,
    ReportFormat,
    ReportGenerator,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _finding(
    title="SQL Injection in /login",
    severity="critical",
    vuln_class="sqli",
    status="open",
    **kwargs,
) -> FindingReport:
    return FindingReport(
        title=title,
        severity=severity,
        vuln_class=vuln_class,
        cvss_score=kwargs.get("cvss_score", 9.8),
        cvss_vector=kwargs.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        target_url=kwargs.get("target_url", "https://target.com/login"),
        http_method=kwargs.get("http_method", "POST"),
        description=kwargs.get("description", "Unauthenticated SQLi"),
        reproduction_steps=kwargs.get("reproduction_steps", ["Send payload", "Observe response"]),
        request_raw=kwargs.get("request_raw", "POST /login HTTP/1.1"),
        response_raw=kwargs.get("response_raw", "HTTP/1.1 200 OK"),
        status=status,
        discovered_by=kwargs.get("discovered_by", "pentra-agent"),
        discovered_at=kwargs.get("discovered_at", "2026-06-23"),
    )


_SENTINEL = object()

def _data(findings=_SENTINEL) -> ReportData:
    return ReportData(
        engagement_name="Acme Corp Pentest",
        target_domain="target.com",
        in_scope=["target.com", "*.api.target.com"],
        out_of_scope=["admin.target.com"],
        mode="semi_auto",
        llm_model="qwen2.5-coder:32b",
        started_at="2026-06-23T09:00:00",
        completed_at="2026-06-23T17:00:00",
        findings=[_finding()] if findings is _SENTINEL else findings,
    )


# ── FindingReport ─────────────────────────────────────────────────────────────

def test_finding_severity_label_uppercase():
    f = _finding(severity="critical")
    assert f.severity_label == "CRITICAL"


def test_finding_severity_label_high():
    f = _finding(severity="high")
    assert f.severity_label == "HIGH"


def test_finding_severity_color_critical():
    f = _finding(severity="critical")
    assert f.severity_color == "#dc2626"


def test_finding_severity_color_high():
    f = _finding(severity="high")
    assert f.severity_color == "#ea580c"


def test_finding_severity_color_unknown_defaults():
    f = _finding(severity="unknown")
    assert f.severity_color == "#6b7280"


# ── ReportData ────────────────────────────────────────────────────────────────

def test_report_data_severity_counts():
    findings = [
        _finding(severity="critical"),
        _finding(severity="critical"),
        _finding(severity="high"),
        _finding(severity="medium"),
        _finding(severity="low"),
        _finding(severity="info"),
    ]
    data = _data(findings=findings)
    assert data.critical_count == 2
    assert data.high_count == 1
    assert data.medium_count == 1
    assert data.low_count == 1
    assert data.info_count == 1


def test_report_data_open_findings_excludes_false_positives():
    findings = [
        _finding(status="open"),
        _finding(title="FP", status="false_positive"),
        _finding(title="Dupe", status="duplicate"),
    ]
    data = _data(findings=findings)
    assert len(data.open_findings) == 1
    assert data.open_findings[0].title == "SQL Injection in /login"


def test_report_data_empty_findings():
    data = _data(findings=[])
    assert data.critical_count == 0
    assert data.open_findings == []


def test_report_data_generated_at_is_set():
    data = _data()
    assert data.generated_at  # non-empty ISO timestamp


# ── ReportGenerator — Markdown ────────────────────────────────────────────────

def test_render_markdown_returns_string():
    gen = ReportGenerator()
    result = gen.render(_data(), ReportFormat.MARKDOWN)
    assert isinstance(result, str)


def test_render_markdown_contains_engagement_name():
    gen = ReportGenerator()
    result = gen.render(_data(), ReportFormat.MARKDOWN)
    assert "Acme Corp Pentest" in result


def test_render_markdown_contains_finding_title():
    gen = ReportGenerator()
    result = gen.render(_data(), ReportFormat.MARKDOWN)
    assert "SQL Injection in /login" in result


def test_render_markdown_contains_severity():
    gen = ReportGenerator()
    result = gen.render(_data(), ReportFormat.MARKDOWN)
    assert "critical" in result.lower()


def test_render_markdown_empty_findings():
    gen = ReportGenerator()
    result = gen.render(_data(findings=[]), ReportFormat.MARKDOWN)
    assert isinstance(result, str)
    assert "Acme Corp Pentest" in result


# ── ReportGenerator — HTML ────────────────────────────────────────────────────

def test_render_html_returns_string():
    gen = ReportGenerator()
    result = gen.render(_data(), ReportFormat.HTML)
    assert isinstance(result, str)
    assert "<html" in result.lower() or "<!DOCTYPE" in result.lower() or "<body" in result.lower()


def test_render_html_contains_finding():
    gen = ReportGenerator()
    result = gen.render(_data(), ReportFormat.HTML)
    assert "SQL Injection in /login" in result


# ── ReportGenerator — H1 JSON ─────────────────────────────────────────────────

def test_render_h1_returns_json_array():
    gen = ReportGenerator()
    result = gen.render(_data(), ReportFormat.H1)
    parsed = json.loads(result)
    assert isinstance(parsed, list)
    assert len(parsed) == 1


def test_render_h1_contains_required_fields():
    gen = ReportGenerator()
    result = json.loads(gen.render(_data(), ReportFormat.H1))
    item = result[0]
    assert item["title"] == "SQL Injection in /login"
    assert item["severity"] == "critical"
    assert item["vuln_class"] == "sqli"
    assert item["target_url"] == "https://target.com/login"
    assert item["cvss_score"] == 9.8


def test_render_h1_excludes_false_positives():
    findings = [
        _finding(title="Real Finding", status="open"),
        _finding(title="FP", status="false_positive"),
    ]
    gen = ReportGenerator()
    result = json.loads(gen.render(_data(findings=findings), ReportFormat.H1))
    assert len(result) == 1
    assert result[0]["title"] == "Real Finding"


def test_render_h1_empty_findings_returns_empty_array():
    gen = ReportGenerator()
    result = json.loads(gen.render(_data(findings=[]), ReportFormat.H1))
    assert result == []


def test_render_h1_multiple_findings():
    findings = [_finding(title=f"Bug {i}", severity="high") for i in range(3)]
    gen = ReportGenerator()
    result = json.loads(gen.render(_data(findings=findings), ReportFormat.H1))
    assert len(result) == 3


# ── ReportGenerator — PDF ────────────────────────────────────────────────────

def test_render_pdf_returns_bytes():
    fake_wp = MagicMock()
    fake_html = MagicMock()
    fake_html.write_pdf.return_value = b"%PDF-1.4 fake content"
    fake_wp.HTML.return_value = fake_html

    with patch.dict("sys.modules", {"weasyprint": fake_wp}):
        gen = ReportGenerator()
        result = gen.render(_data(), ReportFormat.PDF)

    assert isinstance(result, bytes)
    assert result.startswith(b"%PDF")


def test_render_pdf_without_weasyprint_raises():
    with patch.dict("sys.modules", {"weasyprint": None}):
        gen = ReportGenerator()
        with pytest.raises((RuntimeError, ImportError)):
            gen.render(_data(), ReportFormat.PDF)


# ── Unknown format ────────────────────────────────────────────────────────────

def test_render_unknown_format_raises_value_error():
    gen = ReportGenerator()
    with pytest.raises(ValueError):
        gen.render(_data(), "xml")  # type: ignore[arg-type]
