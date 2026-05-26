"""Screenshot & evidence capture tool — Playwright + MinIO.

Captures visual and HTTP evidence for security findings and uploads them to
MinIO (S3-compatible) for persistent storage.
"""

from pentra_tools.screenshot.capture import ScreenshotCapture
from pentra_tools.screenshot.models import EvidenceResult

__all__ = ["ScreenshotCapture", "EvidenceResult"]
