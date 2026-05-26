"""Screenshot and HTTP evidence capture using Playwright + MinIO.

Captures visual and HTTP evidence for security findings and uploads them to
MinIO for persistent storage.  Requires the ``screenshot`` optional extras::

    uv add pentra-tools[screenshot]

All methods perform a scope check before capturing to ensure the target URL
is within the engagement's allowed targets.
"""

from __future__ import annotations

import io
import logging
import os
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from pentra_scope import ScopeEnforcer, ScopeViolationError

from pentra_tools.screenshot.models import EvidenceResult

log = logging.getLogger(__name__)

# ── MinIO / S3 configuration (from environment) ───────────────────────────────
_MINIO_URL = os.getenv("MINIO_URL", "http://localhost:9000")
_MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "pentra")
_MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "")
_MINIO_BUCKET = os.getenv("MINIO_BUCKET_EVIDENCE", "evidence")

_ENDPOINT_URL = _MINIO_URL  # MinIO uses S3-compatible API


def _minio_client() -> Any:
    """Return a boto3 S3 client pointed at MinIO."""
    try:
        import boto3  # type: ignore[import]
    except ImportError as exc:
        raise ImportError(
            "boto3 is required for MinIO uploads. "
            "Install it with: uv add pentra-tools[screenshot]"
        ) from exc

    return boto3.client(
        "s3",
        endpoint_url=_ENDPOINT_URL,
        aws_access_key_id=_MINIO_ACCESS_KEY,
        aws_secret_access_key=_MINIO_SECRET_KEY,
    )


def _ensure_bucket(client: Any) -> None:
    """Create the evidence bucket if it does not exist."""
    try:
        client.head_bucket(Bucket=_MINIO_BUCKET)
    except Exception:  # noqa: BLE001
        client.create_bucket(Bucket=_MINIO_BUCKET)


def _upload_bytes(client: Any, key: str, data: bytes, content_type: str) -> str:
    """Upload *data* to MinIO and return the public URL string."""
    _ensure_bucket(client)
    client.put_object(
        Bucket=_MINIO_BUCKET,
        Key=key,
        Body=io.BytesIO(data),
        ContentType=content_type,
    )
    return f"{_ENDPOINT_URL}/{_MINIO_BUCKET}/{key}"


def _object_key(finding_id: UUID, suffix: str) -> str:
    ts = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return f"findings/{finding_id}/{ts}-{suffix}"


class ScreenshotCapture:
    """Capture screenshot and HTTP evidence for security findings.

    Parameters
    ----------
    scope_enforcer:
        A :class:`pentra_scope.ScopeEnforcer` instance configured with the
        engagement's in-scope and out-of-scope targets.  Every method calls
        :meth:`validate_or_raise` before performing any network operation.
    viewport_width:
        Browser viewport width in pixels (default 1280).
    viewport_height:
        Browser viewport height in pixels (default 800).
    timeout_ms:
        Maximum time (ms) to wait for page load (default 15 000).
    """

    def __init__(
        self,
        scope_enforcer: ScopeEnforcer,
        viewport_width: int = 1280,
        viewport_height: int = 800,
        timeout_ms: int = 15_000,
    ) -> None:
        self.scope = scope_enforcer
        self.viewport_width = viewport_width
        self.viewport_height = viewport_height
        self.timeout_ms = timeout_ms

    async def capture_finding_evidence(
        self,
        url: str,
        finding_id: UUID,
        cookies: list[dict[str, str]] | None = None,
        extra_headers: dict[str, str] | None = None,
        wait_for_selector: str | None = None,
    ) -> EvidenceResult:
        """Navigate to *url* and capture viewport + full-page screenshots.

        Both screenshots are uploaded to MinIO and their URLs are returned in
        the :class:`EvidenceResult`.

        Parameters
        ----------
        url:
            Target URL to screenshot. Must be in scope.
        finding_id:
            UUID of the finding this evidence belongs to.
        cookies:
            Optional list of cookie dicts (``{"name": ..., "value": ..., "domain": ...}``).
        extra_headers:
            Optional HTTP headers to inject (e.g. auth tokens).
        wait_for_selector:
            Optional CSS selector to wait for before taking the screenshot.
        """
        try:
            from playwright.async_api import async_playwright  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "playwright is required for screenshot capture. "
                "Install it with: uv add pentra-tools[screenshot] && playwright install chromium"
            ) from exc

        # Scope check — always first
        self.scope.validate_or_raise(url)

        client = _minio_client()
        result = EvidenceResult(finding_id=finding_id)

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                ctx = await browser.new_context(
                    viewport={"width": self.viewport_width, "height": self.viewport_height},
                    extra_http_headers=extra_headers or {},
                    ignore_https_errors=True,
                )
                if cookies:
                    await ctx.add_cookies(cookies)

                page = await ctx.new_page()
                await page.goto(url, timeout=self.timeout_ms, wait_until="networkidle")

                if wait_for_selector:
                    await page.wait_for_selector(wait_for_selector, timeout=self.timeout_ms)

                # Viewport screenshot
                vp_bytes: bytes = await page.screenshot(type="png", full_page=False)
                vp_key = _object_key(finding_id, "viewport.png")
                result.screenshot_url = _upload_bytes(client, vp_key, vp_bytes, "image/png")
                log.info("[screenshot] viewport uploaded → %s", result.screenshot_url)

                # Full-page screenshot
                fp_bytes: bytes = await page.screenshot(type="png", full_page=True)
                fp_key = _object_key(finding_id, "full-page.png")
                result.full_page_url = _upload_bytes(client, fp_key, fp_bytes, "image/png")
                log.info("[screenshot] full-page uploaded → %s", result.full_page_url)

                await browser.close()
        except ScopeViolationError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.warning("[screenshot] capture_finding_evidence failed: %s", exc)
            result.error = str(exc)

        return result

    async def capture_http_evidence(
        self,
        request_raw: str,
        response_raw: str,
        finding_id: UUID,
    ) -> str | None:
        """Store raw HTTP request/response as a text file in MinIO.

        Parameters
        ----------
        request_raw:
            Raw HTTP request string (e.g. from Burp proxy history).
        response_raw:
            Raw HTTP response string.
        finding_id:
            UUID of the finding this evidence belongs to.

        Returns
        -------
        str or None
            The MinIO URL of the uploaded evidence file, or *None* on error.
        """
        separator = "\n" + "=" * 80 + "\n"
        content = (
            f"[REQUEST]\n{request_raw}{separator}[RESPONSE]\n{response_raw}"
        )
        data = content.encode("utf-8", errors="replace")
        key = _object_key(finding_id, "http-evidence.txt")

        try:
            client = _minio_client()
            url = _upload_bytes(client, key, data, "text/plain; charset=utf-8")
            log.info("[screenshot] HTTP evidence uploaded → %s", url)
            return url
        except Exception as exc:  # noqa: BLE001
            log.warning("[screenshot] capture_http_evidence failed: %s", exc)
            return None
