"""Burp Suite MCP client — Model Context Protocol SSE transport.

Connects to the PortSwigger official MCP Server Burp extension.
Protocol: MCP over SSE (Server-Sent Events).

SSE endpoint: GET  {base_url}/          (root path — NOT /sse)
Messages:     POST {base_url}/?sessionId=<id>

Tool names (from Tools.kt in PortSwigger/mcp-server):
  get_proxy_http_history           paginated proxy HTTP history
  get_proxy_http_history_regex     proxy history filtered by regex
  get_proxy_websocket_history      proxy WebSocket history
  get_scanner_issues               active scan findings (Pro only)
  create_repeater_tab              create a Repeater tab
  send_to_intruder                 send request to Intruder
  send_http1_request               issue HTTP/1.1 request via Burp
  generate_collaborator_payload    OOB Collaborator payload (Pro only)
  get_collaborator_interactions    poll Collaborator OOB hits (Pro only)
  set_proxy_intercept_state        enable/disable intercept
  set_task_execution_engine_state  pause/unpause scanner engine

Reference: https://github.com/PortSwigger/mcp-server
"""

from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator
from urllib.parse import urlparse

from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
from mcp.types import TextContent

from pentra_tools.burp.exceptions import (
    BurpConnectionError,
    BurpMCPToolError,
    BurpNotProError,
)
from pentra_tools.burp.models import (
    CollaboratorInteraction,
    CollaboratorPayload,
    HttpRequest,
    ProxyEntry,
    RepeaterTab,
    ScanIssue,
    ScanTask,
    SitemapEntry,
)

log = logging.getLogger(__name__)

BURP_MCP_URL = os.getenv("BURP_MCP_URL", "http://127.0.0.1:9876")

_PAGE_SIZE = 50
_PRO_ONLY_TOOLS = {"get_scanner_issues", "generate_collaborator_payload", "get_collaborator_interactions"}


class BurpMCPClient:
    """Async client for the PortSwigger Burp Suite MCP extension.

    Each public method opens its own MCP SSE session, calls the required
    tool(s), then closes the session. This keeps the client stateless and
    resilient to Burp restarts at the cost of a small per-call connection
    overhead (typically < 50 ms on localhost).

    Usage::

        client = BurpMCPClient()
        if not await client.health_check():
            raise RuntimeError("Burp Suite not running or MCP extension not loaded")

        history = await client.get_proxy_history(filter_regex=r"api\\.target\\.com", limit=200)
    """

    def __init__(self, base_url: str = BURP_MCP_URL) -> None:
        self.base_url = base_url.rstrip("/")
        # Burp MCP SSE stream is at the root path, not /sse
        self._sse_url = self.base_url
        # Burp MCP checks Host header — always send localhost regardless of IP
        # (required when connecting via WSL2 NAT or Docker bridge)
        parsed = urlparse(self.base_url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self._host_header = f"localhost:{port}"

    # ── Session management ─────────────────────────────────────────────────────

    @asynccontextmanager
    async def _session(self) -> AsyncGenerator[ClientSession, None]:
        """Open an MCP SSE session, yield it, close on exit."""
        try:
            async with sse_client(
                self._sse_url,
                headers={"Host": self._host_header},
            ) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    log.debug("[BurpMCP] session opened at %s", self._sse_url)
                    yield session
        except BurpConnectionError:
            raise
        except Exception as exc:
            raise BurpConnectionError(
                f"Cannot connect to Burp MCP server at {self._sse_url}. "
                "Ensure Burp Suite is running with the MCP extension enabled."
            ) from exc

    async def _call_tool(
        self,
        session: ClientSession,
        name: str,
        arguments: dict[str, Any],
    ) -> list[str]:
        """Call a named MCP tool and return its text content items.

        Raises:
            BurpNotProError: for Pro-only tools when running Community edition
            BurpMCPToolError: for other tool failures
        """
        log.debug("[BurpMCP] calling tool %r with %s", name, arguments)
        result = await session.call_tool(name, arguments)

        if result.isError:
            error_text = " ".join(
                c.text for c in result.content if isinstance(c, TextContent)
            )
            if name in _PRO_ONLY_TOOLS or "professional" in error_text.lower():
                raise BurpNotProError(name)
            raise BurpMCPToolError(name, error_text)

        return [c.text for c in result.content if isinstance(c, TextContent) and c.text]

    async def _paginate(
        self,
        session: ClientSession,
        tool_name: str,
        base_args: dict[str, Any],
        limit: int,
    ) -> list[str]:
        """Collect pages from a Burp paginated MCP tool (count + offset pattern)."""
        items: list[str] = []
        offset = 0
        page_size = min(_PAGE_SIZE, limit)

        while len(items) < limit:
            args = {**base_args, "count": page_size, "offset": offset}
            page = await self._call_tool(session, tool_name, args)
            if not page:
                break
            items.extend(page)
            if len(page) < page_size:
                break  # last (partial) page
            offset += len(page)

        return items[:limit]

    # ── Public API ─────────────────────────────────────────────────────────────

    async def health_check(self) -> bool:
        """Return True if the Burp MCP server is reachable and responsive.

        Never raises — returns False on any failure so callers can gate cleanly.
        """
        try:
            async with self._session() as session:
                tools = await session.list_tools()
                names = [t.name for t in tools.tools]
                log.info("[BurpMCP] health_check OK — %d tools: %s", len(names), names)
                return True
        except Exception as exc:
            log.warning("[BurpMCP] health_check FAILED: %s", exc)
            return False

    async def list_tools(self) -> list[str]:
        """Return names of all tools currently exposed by the Burp MCP server."""
        async with self._session() as session:
            result = await session.list_tools()
            return [t.name for t in result.tools]

    async def get_proxy_history(
        self,
        filter_regex: str | None = None,
        limit: int = 100,
    ) -> list[ProxyEntry]:
        """Fetch HTTP proxy history entries, optionally filtered by URL regex.

        Args:
            filter_regex: Regex matched against the full request text by Burp.
                          Example: r"api\\.target\\.com"
            limit:        Maximum entries to return.

        Returns:
            List of ProxyEntry objects in Burp newest-first order.
        """
        async with self._session() as session:
            if filter_regex:
                tool = "get_proxy_http_history_regex"
                base_args: dict[str, Any] = {"regex": filter_regex}
            else:
                tool = "get_proxy_http_history"
                base_args = {}
            raw_items = await self._paginate(session, tool, base_args, limit)

        entries: list[ProxyEntry] = []
        for raw in raw_items:
            try:
                data = json.loads(raw)
                entries.append(
                    ProxyEntry.from_burp_json(data)
                    if isinstance(data, dict)
                    else ProxyEntry(url=raw)
                )
            except Exception:
                entries.append(ProxyEntry(request=raw))

        log.info("[BurpMCP] get_proxy_history: %d entries", len(entries))
        return entries

    async def get_sitemap(
        self,
        url_prefix: str | None = None,
    ) -> list[SitemapEntry]:
        """Derive a site map from proxy history (deduplicated by method+URL).

        Note:
            Burp MCP v1 has no native sitemap tool. This derives unique
            endpoints from proxy history. For full coverage use Burp Spider.
        """
        history = await self.get_proxy_history(
            filter_regex=url_prefix.replace(".", r"\\.") if url_prefix else None,
            limit=1000,
        )
        seen: set[tuple[str, str]] = set()
        sitemap: list[SitemapEntry] = []
        for entry in history:
            key = (entry.method.upper(), entry.url)
            if key in seen:
                continue
            if url_prefix and not entry.url.startswith(url_prefix):
                continue
            seen.add(key)
            sitemap.append(
                SitemapEntry(
                    url=entry.url,
                    method=entry.method,
                    response_status=entry.response_status,
                )
            )
        log.info("[BurpMCP] get_sitemap: %d unique endpoints", len(sitemap))
        return sitemap

    async def send_to_repeater(
        self,
        request: HttpRequest,
        tab_name: str | None = None,
    ) -> RepeaterTab:
        """Create a Repeater tab in Burp with the supplied HTTP request.

        Args:
            request:  HttpRequest to load into Repeater.
            tab_name: Optional display name for the new Repeater tab.

        Returns:
            RepeaterTab confirming the tab was created.
        """
        name = tab_name or request.tab_name
        # Normalise to CRLF as expected by Burp
        content = request.content.replace("\r\n", "\n").replace("\n", "\r\n")

        async with self._session() as session:
            await self._call_tool(
                session,
                "create_repeater_tab",
                {
                    "content": content,
                    "targetHostname": request.target_hostname,
                    "targetPort": request.target_port,
                    "usesHttps": request.uses_https,
                    "tabName": name,
                },
            )

        log.info("[BurpMCP] send_to_repeater: tab for %s", request.target_hostname)
        scheme = "https" if request.uses_https else "http"
        return RepeaterTab(
            tab_name=name,
            url=f"{scheme}://{request.target_hostname}:{request.target_port}/",
            method=_extract_method(request.content),
        )

    async def trigger_active_scan(
        self,
        url: str,
        scope: list[str],
    ) -> ScanTask:
        """Trigger active scanning of a URL via Burp.

        Implementation note:
            Burp MCP v1 has no direct "start active scan" tool. This method:
              1. Ensures the scanner task execution engine is running.
              2. Sends a GET probe through Burp HTTP engine — adds the URL to
                 proxy history and triggers passive analysis. Active scanning
                 proceeds when Burp Pro Scanner is configured for auto-scan on
                 in-scope traffic.

        Args:
            url:   Full URL to probe (e.g. "https://target.com/api/users").
            scope: In-scope domain list (logging only; caller must scope-check).

        Returns:
            ScanTask with status="running" and a note about the limitation.
        """
        from urllib.parse import urlparse

        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        uses_https = parsed.scheme == "https"
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        raw_req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: PentraAI/1.0\r\n"
            "Connection: close\r\n\r\n"
        )

        async with self._session() as session:
            await self._call_tool(
                session, "set_task_execution_engine_state", {"running": True}
            )
            await self._call_tool(
                session,
                "send_http1_request",
                {"content": raw_req, "targetHostname": host, "targetPort": port, "usesHttps": uses_https},
            )

        log.info("[BurpMCP] trigger_active_scan: probe sent for %s", url)
        return ScanTask(
            task_id=f"mcp-{hash(url) & 0xFFFFFF:06x}",
            url=url,
            status="running",
            note=(
                "Probe sent via Burp HTTP engine. Active scanning proceeds when "
                "Burp Pro Scanner is configured for auto-scan on in-scope traffic."
            ),
        )

    async def get_scan_results(
        self,
        scan_id: str | None = None,
        limit: int = 200,
    ) -> list[ScanIssue]:
        """Return active scan findings from Burp (Pro only).

        Args:
            scan_id: Optional URL prefix to filter results.
            limit:   Maximum issues to return.

        Raises:
            BurpNotProError: if running Burp Community edition.
        """
        async with self._session() as session:
            raw_items = await self._paginate(session, "get_scanner_issues", {}, limit)

        issues: list[ScanIssue] = []
        for raw in raw_items:
            try:
                data = json.loads(raw)
                issue = (
                    ScanIssue.from_burp_json(data)
                    if isinstance(data, dict)
                    else ScanIssue(detail=raw)
                )
                if scan_id and scan_id.startswith("http") and scan_id not in issue.url:
                    continue
                issues.append(issue)
            except Exception:
                issues.append(ScanIssue(detail=raw))

        log.info("[BurpMCP] get_scan_results: %d issues", len(issues))
        return issues

    async def generate_collaborator_payload(
        self,
        custom_data: str | None = None,
    ) -> CollaboratorPayload:
        """Generate a Burp Collaborator OOB payload URL (Pro only).

        Args:
            custom_data: Optional label embedded in the payload for tracking.

        Returns:
            CollaboratorPayload with .payload (inject this) and .payload_id.

        Raises:
            BurpNotProError: if running Burp Community edition.
        """
        args: dict[str, Any] = {}
        if custom_data:
            args["customData"] = custom_data

        async with self._session() as session:
            texts = await self._call_tool(session, "generate_collaborator_payload", args)

        # Response format:
        # "Payload: xyz.oastify.com\nPayload ID: abc123\nCollaborator server: oastify.com"
        response_text = "\n".join(texts)
        payload = ""
        payload_id = ""
        for line in response_text.splitlines():
            if line.startswith("Payload:") and "ID" not in line:
                payload = line.split(":", 1)[1].strip()
            elif line.startswith("Payload ID:"):
                payload_id = line.split(":", 1)[1].strip()

        if not payload:
            raise BurpMCPToolError(
                "generate_collaborator_payload",
                f"Could not parse payload from response: {response_text!r}",
            )

        log.info("[BurpMCP] Collaborator payload: %s (id=%s)", payload, payload_id)
        return CollaboratorPayload(payload=payload, payload_id=payload_id)

    async def poll_collaborator(
        self,
        payload_id: str | None = None,
    ) -> list[CollaboratorInteraction]:
        """Poll Burp Collaborator for OOB interactions (Pro only).

        Args:
            payload_id: ID from generate_collaborator_payload. If None,
                        returns all interactions since Burp started.

        Raises:
            BurpNotProError: if running Burp Community edition.
        """
        args: dict[str, Any] = {}
        if payload_id:
            args["payloadId"] = payload_id

        async with self._session() as session:
            texts = await self._call_tool(session, "get_collaborator_interactions", args)

        if not texts or texts[0].strip() == "No interactions detected":
            return []

        interactions: list[CollaboratorInteraction] = []
        for raw in texts:
            try:
                data = json.loads(raw)
                if isinstance(data, dict):
                    interactions.append(CollaboratorInteraction(**data))
            except (json.JSONDecodeError, Exception):
                pass  # skip non-JSON informational lines

        log.info("[BurpMCP] poll_collaborator: %d interactions", len(interactions))
        return interactions

    async def set_proxy_intercept(self, enabled: bool) -> None:
        """Enable or disable Burp Proxy intercept."""
        async with self._session() as session:
            await self._call_tool(
                session, "set_proxy_intercept_state", {"intercepting": enabled}
            )
        log.info("[BurpMCP] proxy intercept = %s", enabled)

    async def send_http1_request(
        self,
        hostname: str,
        port: int,
        uses_https: bool,
        content: str,
    ) -> str:
        """Send a raw HTTP/1.1 request through Burp HTTP engine.

        The request appears in proxy history and is subject to Burp scanning rules.
        """
        content = content.replace("\r\n", "\n").replace("\n", "\r\n")
        async with self._session() as session:
            texts = await self._call_tool(
                session,
                "send_http1_request",
                {"content": content, "targetHostname": hostname, "targetPort": port, "usesHttps": uses_https},
            )
        return "\n".join(texts)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_method(raw_request: str) -> str:
    """Extract HTTP method from the first line of a raw request."""
    first_line = raw_request.lstrip().split("\n")[0].split("\r")[0]
    parts = first_line.split()
    return parts[0].upper() if parts else "GET"
