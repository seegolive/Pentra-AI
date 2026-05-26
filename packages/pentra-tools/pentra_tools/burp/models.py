"""Pydantic models for Burp Suite MCP responses.

All models use ``extra="allow"`` so they survive future Burp API additions
without breaking. Fields are typed strictly for what we actively use; any
additional JSON keys are stored in ``model_extra``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class ProxyEntry(BaseModel):
    """One item from Burp's proxy HTTP history.

    Burp serialises ``ProxyHttpRequestResponse`` to JSON. The exact field
    names vary by Burp version; we capture the most useful subset.
    """

    model_config = {"extra": "allow"}

    # Identification
    id: str = ""

    # Request
    url: str = ""
    method: str = "GET"
    request: str | None = None          # raw HTTP request text
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str | None = None

    # Response
    response: str | None = None         # raw HTTP response text
    response_status: int | None = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: str | None = None

    # Connection info
    host: str = ""
    port: int = 443
    is_https: bool = True

    # Timing
    timestamp: datetime | None = None

    @classmethod
    def from_burp_json(cls, raw: dict[str, Any]) -> "ProxyEntry":
        """Construct from Burp's serialised proxy item (flexible mapping)."""
        # Burp may nest the request under "request" as an object or as a raw string
        request_obj = raw.get("request") or {}
        response_obj = raw.get("response") or {}

        # Extract URL from request object if not at top level
        url = raw.get("url", "")
        method = raw.get("method", "")

        if isinstance(request_obj, dict):
            url = url or request_obj.get("url", "")
            method = method or request_obj.get("method", "GET")
            request_raw = request_obj.get("raw", request_obj.get("body", ""))
            req_headers = request_obj.get("headers", {})
            req_body = request_obj.get("body", None)
        else:
            request_raw = str(request_obj) if request_obj else None
            req_headers = {}
            req_body = None

        if isinstance(response_obj, dict):
            status = response_obj.get(
                "statusCode",
                response_obj.get(
                    "status_code",
                    raw.get("responseStatus", raw.get("statusCode")),
                ),
            )
            resp_raw = response_obj.get("raw", response_obj.get("body", ""))
            resp_headers = response_obj.get("headers", {})
            resp_body = response_obj.get("body", None)
        else:
            status = raw.get("responseStatus", raw.get("statusCode", raw.get("status_code")))
            resp_raw = str(response_obj) if response_obj else None
            resp_headers = {}
            resp_body = None

        # Extract host/port from URL if not explicit
        host = raw.get("host", "")
        port = int(raw.get("port", 443))
        if not host and url:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)

        return cls(
            id=str(raw.get("id", raw.get("messageId", ""))),
            url=url,
            method=method or "GET",
            request=request_raw,
            request_headers=req_headers if isinstance(req_headers, dict) else {},
            request_body=req_body,
            response=resp_raw,
            response_status=int(status) if status is not None else None,
            response_headers=resp_headers if isinstance(resp_headers, dict) else {},
            response_body=resp_body,
            host=host,
            port=port,
            is_https=raw.get("isHttps", raw.get("is_https", port == 443)),
        )


class SitemapEntry(BaseModel):
    """One URL entry from Burp's site map."""

    model_config = {"extra": "allow"}

    url: str
    method: str = "GET"
    response_status: int | None = None
    note: str | None = None


class HttpRequest(BaseModel):
    """A raw HTTP request ready to send to Burp's Repeater or HTTP engine."""

    content: str                  # raw HTTP text (CRLF-separated lines)
    target_hostname: str
    target_port: int = 443
    uses_https: bool = True
    tab_name: str | None = None


class RepeaterTab(BaseModel):
    """A created Repeater tab in Burp Suite."""

    tab_id: str = ""
    tab_name: str | None = None
    url: str = ""
    method: str = "GET"


class ScanTask(BaseModel):
    """A submitted or in-progress Burp active scan task."""

    task_id: str = ""
    url: str
    status: str = "running"
    note: str | None = None


class ScanIssue(BaseModel):
    """One issue from Burp's active scanner (Pro only)."""

    model_config = {"extra": "allow"}

    issue_type: str = ""
    severity: Literal["high", "medium", "low", "information"] = "information"
    confidence: Literal["certain", "firm", "tentative"] = "tentative"
    url: str = ""
    detail: str = ""
    remediation: str | None = None
    request: str | None = None
    response: str | None = None

    @classmethod
    def from_burp_json(cls, raw: dict[str, Any]) -> "ScanIssue":
        return cls(
            issue_type=raw.get("issueName", raw.get("issue_type", raw.get("type", ""))),
            severity=_normalise_severity(raw.get("severity", "information")),
            confidence=_normalise_confidence(raw.get("confidence", "tentative")),
            url=raw.get("url", ""),
            detail=raw.get("issueDetail", raw.get("detail", "")),
            remediation=raw.get("remediationDetail", raw.get("remediation")),
            request=raw.get("requestResponse", {}).get("request") if isinstance(raw.get("requestResponse"), dict) else None,
            response=raw.get("requestResponse", {}).get("response") if isinstance(raw.get("requestResponse"), dict) else None,
        )


class CollaboratorPayload(BaseModel):
    """A generated Burp Collaborator payload (Pro only)."""

    payload: str          # e.g. "xyz.oastify.com"
    payload_id: str


class CollaboratorInteraction(BaseModel):
    """One OOB interaction received by the Burp Collaborator server."""

    model_config = {"extra": "allow"}

    interaction_type: Literal["dns", "http", "smtp"] = "dns"
    timestamp: datetime | None = None
    client_ip: str = ""
    data: dict[str, Any] = Field(default_factory=dict)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _normalise_severity(value: str) -> Literal["high", "medium", "low", "information"]:
    v = value.lower().strip()
    if v in ("high", "medium", "low", "information"):
        return v  # type: ignore[return-value]
    return "information"


def _normalise_confidence(value: str) -> Literal["certain", "firm", "tentative"]:
    v = value.lower().strip()
    if v in ("certain", "firm", "tentative"):
        return v  # type: ignore[return-value]
    return "tentative"
