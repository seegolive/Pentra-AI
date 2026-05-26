"""Pydantic models for screenshot & evidence capture output."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class EvidenceResult(BaseModel):
    """Structured result returned by ScreenshotCapture."""

    model_config = ConfigDict(from_attributes=True)

    finding_id: UUID
    """The finding this evidence is attached to."""

    screenshot_url: str | None = None
    """MinIO URL for the viewport screenshot (PNG)."""

    full_page_url: str | None = None
    """MinIO URL for the full-page screenshot (PNG)."""

    http_evidence_url: str | None = None
    """MinIO URL for the request/response evidence text file."""

    error: str | None = None
    """Error message if capture failed (partial results may still be present)."""

    @property
    def has_visual(self) -> bool:
        return self.screenshot_url is not None or self.full_page_url is not None

    @property
    def has_http(self) -> bool:
        return self.http_evidence_url is not None
