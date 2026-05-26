"""Report generator — Markdown, HTML, PDF, and HackerOne-format outputs.

Usage::

    gen = ReportGenerator()
    md  = gen.render(data, fmt=ReportFormat.MARKDOWN)
    pdf = gen.render(data, fmt=ReportFormat.PDF)   # returns bytes
    h1  = gen.render(data, fmt=ReportFormat.H1)    # HackerOne submission text
"""

from __future__ import annotations

import importlib.resources
import logging
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape
from pydantic import BaseModel, Field

log = logging.getLogger(__name__)

# ── Enums ─────────────────────────────────────────────────────────────────────

class ReportFormat(str, Enum):
    MARKDOWN = "markdown"
    HTML     = "html"
    PDF      = "pdf"
    H1       = "h1"        # HackerOne submission format


# ── Input model ───────────────────────────────────────────────────────────────

class FindingReport(BaseModel):
    """A single finding as consumed by the report renderer."""
    title: str
    severity: str          # critical / high / medium / low / info
    vuln_class: str
    cvss_score: float | None = None
    target_url: str
    http_method: str = "GET"
    description: str = ""
    reproduction_steps: list[str] = Field(default_factory=list)
    request_raw: str = ""
    response_raw: str = ""
    curl_command: str = ""
    status: str = "open"
    discovered_by: str = ""
    discovered_at: str = ""

    @property
    def severity_label(self) -> str:
        return self.severity.upper()

    @property
    def severity_color(self) -> str:
        return {
            "critical": "#dc2626",
            "high":     "#ea580c",
            "medium":   "#d97706",
            "low":      "#2563eb",
            "info":     "#6b7280",
        }.get(self.severity.lower(), "#6b7280")


class ReportData(BaseModel):
    """All data required to render a report."""
    engagement_name: str
    target_domain: str
    in_scope: list[str]
    out_of_scope: list[str] = Field(default_factory=list)
    mode: str = "semi_auto"
    llm_model: str = ""
    started_at: str = ""
    completed_at: str = ""
    findings: list[FindingReport] = Field(default_factory=list)
    tech_stack: list[str] = Field(default_factory=list)
    subdomains: list[str] = Field(default_factory=list)
    analyst_notes: str = ""
    generated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.lower() == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.lower() == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.lower() == "medium")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.lower() == "low")

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.lower() == "info")

    @property
    def open_findings(self) -> list[FindingReport]:
        return [f for f in self.findings if f.status not in ("false_positive", "duplicate")]


# ── Generator ─────────────────────────────────────────────────────────────────

class ReportGenerator:
    """Renders a ReportData instance into the requested format."""

    def __init__(self) -> None:
        self._env = Environment(
            loader=PackageLoader("pentra_report", "templates"),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        # Register custom filters
        self._env.filters["severity_color"] = lambda s: {
            "critical": "#dc2626", "high": "#ea580c",
            "medium": "#d97706",   "low": "#2563eb", "info": "#6b7280",
        }.get(s.lower(), "#6b7280")
        self._env.filters["upper_first"] = lambda s: s[0].upper() + s[1:] if s else s

    # ── Public API ─────────────────────────────────────────────────────────

    def render(self, data: ReportData, fmt: ReportFormat) -> str | bytes:
        """Render the report.

        Returns ``str`` for MARKDOWN / HTML / H1,
        Returns ``bytes`` for PDF.
        """
        if fmt == ReportFormat.MARKDOWN:
            return self._render_markdown(data)
        elif fmt == ReportFormat.HTML:
            return self._render_html(data)
        elif fmt == ReportFormat.PDF:
            return self._render_pdf(data)
        elif fmt == ReportFormat.H1:
            return self._render_h1(data)
        else:
            raise ValueError(f"Unknown format: {fmt}")

    # ── Internal renderers ────────────────────────────────────────────────

    def _render_markdown(self, data: ReportData) -> str:
        tmpl = self._env.get_template("report.md.j2")
        return tmpl.render(**data.model_dump(), data=data)

    def _render_html(self, data: ReportData) -> str:
        tmpl = self._env.get_template("report.html.j2")
        return tmpl.render(**data.model_dump(), data=data)

    def _render_pdf(self, data: ReportData) -> bytes:
        try:
            import weasyprint  # noqa: PLC0415
        except ImportError as exc:
            raise RuntimeError(
                "PDF generation requires weasyprint: uv add weasyprint"
            ) from exc

        html = self._render_html(data)
        return weasyprint.HTML(string=html).write_pdf()

    def _render_h1(self, data: ReportData) -> str:
        """Render one HackerOne report per finding (joined with ---).

        HackerOne format: Title, Severity, Summary, Steps to Reproduce,
        Impact, Supporting Material.
        """
        tmpl = self._env.get_template("report_h1.md.j2")
        parts = []
        for finding in data.open_findings:
            parts.append(tmpl.render(finding=finding, data=data))
        return "\n\n---\n\n".join(parts) if parts else "# No open findings to report."
