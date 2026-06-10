"""Burp Suite MCP client — Model Context Protocol SSE transport.

Connects to the PortSwigger official MCP Server Burp extension.
Protocol: MCP over SSE (Server-Sent Events).

Full coverage for all 27 tools from Tools.kt:
  GROUP 1:  health_check, list_tools
  GROUP 2:  send_http1_request, send_http2_request
  GROUP 3:  get_proxy_http_history, get_proxy_http_history_regex,
            get_proxy_websocket_history, get_proxy_websocket_history_regex
  GROUP 4:  get_scanner_issues, generate_collaborator_payload, get_collaborator_interactions
  GROUP 5:  create_repeater_tab, create_repeater_tab_http2, send_to_intruder
  GROUP 6:  get_organizer_items, get_organizer_items_regex
  GROUP 7:  set_proxy_intercept_state, set_task_execution_engine_state
  GROUP 8:  get_active_editor_contents, set_active_editor_contents
  GROUP 9:  output_project_options, output_user_options, set_project_options, set_user_options
  GROUP 10: url_encode, url_decode, base64_encode, base64_decode, generate_random_string

Reference: https://github.com/PortSwigger/mcp-server
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
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

BURP_MCP_URL = os.getenv("BURP_MCP_URL", "http://127.0.0.1:9877")

_PAGE_SIZE = 50
# Phrases that Burp MCP returns when a feature requires Professional edition
_PRO_EDITION_PHRASES = ("professional", "community edition", "pro edition", "pro only")


# ── New response dataclasses (added in BURP-MCP-MAXIMIZE.md overhaul) ─────────

@dataclass
class WebSocketEntry:
    """One WebSocket message from Burp's proxy WebSocket history."""
    url: str = ""
    direction: str = ""          # "client_to_server" | "server_to_client"
    message: str = ""
    timestamp: str | None = None


@dataclass
class OrganizerItem:
    """One saved item from Burp Organizer."""
    url: str = ""
    method: str = "GET"
    request_raw: str = ""
    notes: str | None = None


@dataclass
class BurpHttpResponse:
    """Parsed HTTP response returned by send_http1_request / send_http2_request."""
    status_code: int = 0
    headers: dict = field(default_factory=dict)
    body: str = ""
    protocol: str = "HTTP/1.1"
    raw: str = ""


# ── Exception aliases for BURP-MCP-MAXIMIZE.md compatibility ─────────────────
# BurpMCPError / BurpNotAvailableError are referenced in the spec; map them to
# our existing exception hierarchy so existing callers are unaffected.

BurpMCPError = BurpConnectionError
BurpNotAvailableError = BurpConnectionError


class BurpMCPClient:
    """Async client for the PortSwigger Burp Suite MCP extension.

    Each public method opens its own MCP SSE session, calls the required
    tool(s), then closes the session.  Sessions are short-lived but the
    client automatically reuses an existing persistent session when one is
    held open via :py:meth:`open_session` / :py:meth:`close_session`.

    .. tip::
        For sequential multi-tool workflows (e.g. inside an agent node) call
        :py:meth:`open_session` before the first tool and :py:meth:`close_session`
        after the last.  This reuses a **single** SSE connection for all calls,
        avoiding Burp's session-pool limit (~4 concurrent sessions).

    Full 27-tool coverage (see module docstring for groups).

    Usage::

        client = BurpMCPClient()
        if not await client.health_check():
            raise RuntimeError("Burp Suite not running or MCP extension not loaded")

        # Multi-tool workflow — keep one session open:
        async with client.managed_session():
            history = await client.get_proxy_history(filter_regex=r"api\\.target\\.com", limit=200)
            ws_msgs  = await client.get_proxy_websocket_history(limit=50)
            await client.set_proxy_intercept_state(False)
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

        # Persistent session state (set by managed_session / open_session)
        self._persistent_session: ClientSession | None = None
        self._session_stack: list[Any] = []  # holds __aexit__ callables

    # ── Session management ─────────────────────────────────────────────────────

    @asynccontextmanager
    async def managed_session(self) -> AsyncGenerator[None, None]:
        """Context manager: open one SSE session, reuse for all inner calls.

        Usage::

            async with client.managed_session():
                await client.set_proxy_intercept_state(False)
                await client.get_proxy_history()
                await client.url_encode("test")
                # ... all reuse the same SSE connection

        Nesting is safe: the outer managed_session wins and the inner call is
        a no-op.
        """
        if self._persistent_session is not None:
            # Already inside a managed_session — just reuse it
            yield
            return
        cm = contextlib.AsyncExitStack()
        try:
            await cm.__aenter__()
            read, write = await cm.enter_async_context(
                sse_client(
                    self._sse_url,
                    headers={"Host": self._host_header},
                    sse_read_timeout=60 * 30,  # 30 min — prevents ReadTimeout during long tool runs
                )
            )
            session = await cm.enter_async_context(ClientSession(read, write))
            await session.initialize()
            self._persistent_session = session
            log.debug("[BurpMCP] managed_session opened at %s", self._sse_url)
            yield
        except Exception as exc:
            if isinstance(exc, ExceptionGroup) or (
                hasattr(exc, "exceptions") and isinstance(getattr(exc, "exceptions", None), (list, tuple))
            ):
                sub = exc.exceptions[0]  # type: ignore[union-attr]
                raise BurpConnectionError(
                    f"Cannot connect to Burp MCP server at {self._sse_url}. "
                    "Ensure Burp Suite is running with the MCP extension enabled."
                ) from sub
            raise
        finally:
            self._persistent_session = None
            await cm.__aexit__(None, None, None)

    @asynccontextmanager
    async def _session(self) -> AsyncGenerator[ClientSession, None]:
        """Open an MCP SSE session, yield it, close on exit.

        If a persistent session is held (via :py:meth:`managed_session`),
        yields that session directly without opening a new connection.

        Only maps *connection-phase* errors to BurpConnectionError.  Exceptions
        that propagate out from inside the ``yield`` (i.e. from tool calls) are
        re-raised unchanged so that BurpMCPToolError / BurpNotProError are not
        accidentally swallowed and reported as a connection failure.
        """
        # Fast path: reuse persistent session
        if self._persistent_session is not None:
            yield self._persistent_session
            return

        _connected = False
        try:
            async with sse_client(
                self._sse_url,
                headers={"Host": self._host_header},
                sse_read_timeout=60 * 30,  # 30 min — prevents ReadTimeout during long tool runs
            ) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    _connected = True
                    log.debug("[BurpMCP] session opened at %s", self._sse_url)
                    yield session
        except BurpConnectionError:
            raise
        except BaseException as exc:
            # Unwrap anyio/asyncio ExceptionGroup → surface the real first sub-exception
            # so that BurpMCPToolError / BurpNotProError propagate correctly.
            if isinstance(exc, ExceptionGroup) or (
                hasattr(exc, "exceptions") and isinstance(getattr(exc, "exceptions", None), (list, tuple))
            ):
                sub = exc.exceptions[0]  # type: ignore[union-attr]
                if isinstance(sub, (BurpConnectionError, BurpNotProError, BurpMCPToolError)):
                    raise sub from exc
                if _connected:
                    raise sub from exc
                raise BurpConnectionError(
                    f"Cannot connect to Burp MCP server at {self._sse_url}. "
                    "Ensure Burp Suite is running with the MCP extension enabled."
                ) from exc
            if _connected:
                raise
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
        import asyncio as _asyncio
        log.debug("[BurpMCP] calling tool %r with %s", name, arguments)
        result = await session.call_tool(name, arguments)

        if result.isError:
            error_text = " ".join(
                c.text for c in result.content if isinstance(c, TextContent)
            )
            if any(p in error_text.lower() for p in _PRO_EDITION_PHRASES):
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
            # Burp MCP may return a single text blob with multiple JSON objects
            # separated by "\n\n" (one object per history entry).
            # Try direct JSON parse first; fall back to splitting by \n\n.
            parsed_from_blob = False
            try:
                data = json.loads(raw)
                entries.append(
                    ProxyEntry.from_burp_json(data)
                    if isinstance(data, dict)
                    else ProxyEntry(url=raw)
                )
                parsed_from_blob = True
            except json.JSONDecodeError:
                for chunk in raw.split("\n\n"):
                    chunk = chunk.strip()
                    if not chunk:
                        continue
                    try:
                        data = json.loads(chunk)
                        entries.append(
                            ProxyEntry.from_burp_json(data)
                            if isinstance(data, dict)
                            else ProxyEntry(url=chunk)
                        )
                        parsed_from_blob = True
                    except Exception:
                        pass
                if not parsed_from_blob:
                    entries.append(ProxyEntry(request=raw))
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
        import asyncio as _asyncio
        import re as _re

        args: dict[str, Any] = {}
        if custom_data:
            # Burp Collaborator requires: alphanumeric only, max 16 chars
            safe = _re.sub(r"[^A-Za-z0-9]", "", custom_data)[:16]
            if safe:
                args["customData"] = safe

        # Retry once on transient SSE TaskGroup errors
        last_exc: Exception | None = None
        for attempt in range(2):
            try:
                async with self._session() as session:
                    texts = await self._call_tool(session, "generate_collaborator_payload", args)
                break  # success
            except BurpNotProError:
                raise
            except BurpConnectionError:
                raise
            except Exception as exc:
                last_exc = exc
                if attempt == 0:
                    log.debug("[BurpMCP] generate_collaborator_payload retry after: %s", exc)
                    await _asyncio.sleep(1)
                    continue
                raise last_exc  # re-raise after 2 failures
        else:
            raise last_exc  # type: ignore[misc]

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
        """Enable or disable Burp Proxy intercept (legacy — delegates to set_proxy_intercept_state)."""
        await self.set_proxy_intercept_state(enabled)

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

    async def send_request(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str = "",
        extra_headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> tuple[str, str]:
        """High-level helper: build and send HTTP request via Burp, return (raw_request, raw_response).

        Automatically parses the URL into hostname/port/path components.
        The request appears in Burp proxy history and triggers passive scanning.

        Args:
            url:           Full URL, e.g. "http://target.com/api?id=1".
            method:        HTTP method (GET, POST, PUT, DELETE, etc.).
            headers:       Optional headers to include (merges with defaults).
            body:          Optional request body for POST/PUT.
            extra_headers: Additional headers (e.g. auth headers) merged last.
            cookies:       Optional cookie dict injected as Cookie header.

        Returns:
            (raw_request, raw_response) — both as strings.
        """
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        uses_https = parsed.scheme == "https"
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        default_headers: dict[str, str] = {
            "Host": hostname if port in (80, 443) else f"{hostname}:{port}",
            "User-Agent": "Mozilla/5.0 (PentraAI/1.0) SecurityResearch",
            "Accept": "*/*",
            "Connection": "close",
        }
        if body:
            default_headers["Content-Length"] = str(len(body.encode()))
            if "Content-Type" not in (headers or {}):
                default_headers["Content-Type"] = "application/x-www-form-urlencoded"
        if headers:
            default_headers.update(headers)
        if extra_headers:
            default_headers.update(extra_headers)
        if cookies:
            cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
            if "Cookie" in default_headers:
                default_headers["Cookie"] += f"; {cookie_header}"
            else:
                default_headers["Cookie"] = cookie_header

        raw_request = f"{method.upper()} {path} HTTP/1.1\r\n"
        for k, v in default_headers.items():
            raw_request += f"{k}: {v}\r\n"
        raw_request += "\r\n"
        if body:
            raw_request += body

        raw_response = await self.send_http1_request(hostname, port, uses_https, raw_request)
        log.debug("[BurpMCP] send_request %s %s → %d bytes", method.upper(), url, len(raw_response))
        return raw_request, raw_response

    # ── GROUP 2 extension: HTTP/2 ─────────────────────────────────────────────

    async def send_http2_request(
        self,
        hostname: str,
        port: int,
        uses_https: bool,
        content: str,
    ) -> BurpHttpResponse:
        """Send a raw HTTP/2 request through Burp HTTP engine.

        HTTP/2 exposes different attack surfaces: header injection, stream
        manipulation, priority attacks, H2-to-H1 desync.

        Returns BurpHttpResponse with parsed status_code, headers, body.
        """
        h2_params = _raw_to_h2_params(content, hostname)
        async with self._session() as session:
            texts = await self._call_tool(
                session,
                "send_http2_request",
                {
                    "headers": h2_params["headers"],
                    "pseudoHeaders": h2_params["pseudoHeaders"],
                    "requestBody": h2_params["requestBody"],
                    "targetHostname": hostname,
                    "targetPort": port,
                    "usesHttps": uses_https,
                },
            )
        raw = "\n".join(texts)
        return _parse_burp_http_response(raw, "HTTP/2")

    # ── GROUP 3 extension: WebSocket history ──────────────────────────────────

    async def get_proxy_websocket_history(
        self,
        limit: int = 50,
    ) -> list[WebSocketEntry]:
        """Fetch WebSocket proxy history.

        Surfaces WS injection, auth bypass, and CSRF-over-WS targets.
        """
        async with self._session() as session:
            raw_items = await self._paginate(
                session, "get_proxy_websocket_history", {}, limit
            )
        return _parse_websocket_history(raw_items)

    async def get_proxy_websocket_history_regex(
        self,
        filter_regex: str,
        limit: int = 50,
    ) -> list[WebSocketEntry]:
        """Fetch WebSocket proxy history filtered by regex.

        Args:
            filter_regex: Regex matched against WebSocket message content.
            limit:        Maximum messages to return.
        """
        async with self._session() as session:
            raw_items = await self._paginate(
                session,
                "get_proxy_websocket_history_regex",
                {"regex": filter_regex},
                limit,
            )
        return _parse_websocket_history(raw_items)

    # ── GROUP 5 extension: Repeater / Intruder ────────────────────────────────

    async def create_repeater_tab(
        self,
        host: str,
        port: int,
        request: str,
        use_https: bool = True,
        tab_name: str | None = None,
    ) -> RepeaterTab:
        """Create a Repeater tab using low-level (host, port, raw request) API.

        Args:
            host:      Target hostname (e.g. "testaspnet.vulnweb.com").
            port:      Target port (e.g. 443).
            request:   Raw HTTP request string.
            use_https: Whether to use HTTPS.
            tab_name:  Optional tab display name (e.g. "PentraAI: SQLi on id").
        """
        request = request.replace("\r\n", "\n").replace("\n", "\r\n")
        async with self._session() as session:
            await self._call_tool(
                session,
                "create_repeater_tab",
                {
                    "content": request,
                    "targetHostname": host,
                    "targetPort": port,
                    "usesHttps": use_https,
                    "tabName": tab_name or f"PentraAI: {host}",
                },
            )
        scheme = "https" if use_https else "http"
        log.info("[BurpMCP] create_repeater_tab: tab for %s", host)
        return RepeaterTab(
            tab_name=tab_name,
            url=f"{scheme}://{host}:{port}/",
            method=_extract_method(request),
        )

    async def create_repeater_tab_http2(
        self,
        host: str,
        port: int,
        request: str,
        use_https: bool = True,
        tab_name: str | None = None,
    ) -> RepeaterTab:
        """Create a Repeater tab for HTTP/2 requests.

        Use for HTTP/2 specific testing: H2 header injection, stream manipulation.
        """
        h2_params = _raw_to_h2_params(request, host)
        async with self._session() as session:
            await self._call_tool(
                session,
                "create_repeater_tab_http2",
                {
                    "headers": h2_params["headers"],
                    "pseudoHeaders": h2_params["pseudoHeaders"],
                    "requestBody": h2_params["requestBody"],
                    "targetHostname": host,
                    "targetPort": port,
                    "usesHttps": use_https,
                    "tabName": tab_name or f"PentraAI H2: {host}",
                },
            )
        scheme = "https" if use_https else "http"
        log.info("[BurpMCP] create_repeater_tab_http2: tab for %s", host)
        return RepeaterTab(
            tab_name=tab_name,
            url=f"{scheme}://{host}:{port}/",
            method=h2_params["pseudoHeaders"].get(":method", "GET"),
        )

    async def send_to_intruder(
        self,
        host: str,
        port: int,
        request: str,
        use_https: bool = True,
        insertion_points: list[dict] | None = None,
        tab_name: str | None = None,
    ) -> dict:
        """Send a request to Burp Intruder for fuzzing.

        After calling this, the researcher can immediately launch the attack
        from Burp Suite UI.

        Args:
            host:             Target hostname.
            port:             Target port.
            request:          Raw HTTP request string.
            use_https:        Whether to use HTTPS.
            insertion_points: List of {"start": int, "end": int} byte offsets.
                              If None, Burp auto-detects insertion points.
            tab_name:         Optional display name for the Intruder tab.
        """
        request = request.replace("\r\n", "\n").replace("\n", "\r\n")
        # Note: Burp MCP send_to_intruder does not accept insertionPoints via MCP.
        # Burp auto-detects insertion points. The insertion_points param is
        # retained in the Python signature for documentation purposes only.
        params: dict[str, Any] = {
            "content": request,
            "targetHostname": host,
            "targetPort": port,
            "usesHttps": use_https,
            "tabName": tab_name or f"PentraAI Intruder: {host}",
        }

        async with self._session() as session:
            texts = await self._call_tool(session, "send_to_intruder", params)

        log.info("[BurpMCP] send_to_intruder: request queued for %s — launch from Burp UI", host)
        return {"status": "queued", "host": host, "response": "\n".join(texts)}

    # ── GROUP 6: Organizer ────────────────────────────────────────────────────

    async def get_organizer_items(
        self,
        limit: int = 50,
    ) -> list[OrganizerItem]:
        """Fetch items from Burp Organizer.

        Organizer contains requests saved manually by the researcher.
        Useful for context: what the researcher has already analysed.
        """
        async with self._session() as session:
            raw_items = await self._paginate(
                session, "get_organizer_items", {}, limit
            )
        return _parse_organizer_items(raw_items)

    async def get_organizer_items_regex(
        self,
        filter_regex: str,
        limit: int = 20,
    ) -> list[OrganizerItem]:
        """Fetch Organizer items filtered by regex.

        Args:
            filter_regex: Regex matched against the request content.
            limit:        Maximum items to return.
        """
        async with self._session() as session:
            raw_items = await self._paginate(
                session,
                "get_organizer_items_regex",
                {"regex": filter_regex},
                limit,
            )
        return _parse_organizer_items(raw_items)

    # ── GROUP 7: Intercept & Engine Control ───────────────────────────────────

    async def set_proxy_intercept_state(
        self,
        enabled: bool,
    ) -> bool:
        """Toggle proxy intercept on or off programmatically.

        ALWAYS call set_proxy_intercept_state(False) before automated scanning
        to prevent requests from being blocked by intercept.

        Args:
            enabled: True = intercept on, False = intercept off.
        """
        async with self._session() as session:
            await self._call_tool(
                session,
                "set_proxy_intercept_state",
                {"intercepting": enabled},
            )
        log.info("[BurpMCP] Proxy intercept: %s", "ENABLED" if enabled else "DISABLED")
        return True

    async def set_task_execution_engine_state(
        self,
        running: bool,
    ) -> bool:
        """Pause or resume Burp's task execution engine.

        Args:
            running: True = engine running, False = engine paused.
        """
        async with self._session() as session:
            await self._call_tool(
                session,
                "set_task_execution_engine_state",
                {"running": running},
            )
        log.info("[BurpMCP] Task engine: %s", "RUNNING" if running else "PAUSED")
        return True

    # ── GROUP 8: Editor Control ───────────────────────────────────────────────

    async def get_active_editor_contents(self) -> str:
        """Get contents of the currently active Burp editor."""
        async with self._session() as session:
            texts = await self._call_tool(session, "get_active_editor_contents", {})
        return "\n".join(texts)

    async def set_active_editor_contents(
        self,
        contents: str,
    ) -> bool:
        """Inject content into the active Burp editor.

        Args:
            contents: Text to inject into the active editor.
        """
        async with self._session() as session:
            await self._call_tool(
                session,
                "set_active_editor_contents",
                {"text": contents},
            )
        log.info("[BurpMCP] Active editor contents updated (%d bytes)", len(contents))
        return True

    # ── GROUP 9: Configuration ────────────────────────────────────────────────

    async def get_project_options(self) -> dict:
        """Export current project options as a dict.

        Useful for: backup scope, SSL config, session handling rules.
        Call before set_project_options() to get the current state to modify.
        """
        async with self._session() as session:
            texts = await self._call_tool(session, "output_project_options", {})
        raw = "\n".join(texts)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"raw": raw}

    async def get_user_options(self) -> dict:
        """Export current user options as a dict.

        Useful for: proxy settings, upstream proxy, SSL passthrough config.
        """
        async with self._session() as session:
            texts = await self._call_tool(session, "output_user_options", {})
        raw = "\n".join(texts)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"raw": raw}

    async def set_project_scope(
        self,
        in_scope_urls: list[str],
        out_of_scope_urls: list[str] | None = None,
    ) -> bool:
        """Set Burp project scope programmatically.

        Syncs scope from Pentra AI engagement to Burp Pro.
        Ensures Burp scanner only scans in-scope URLs.

        IMPORTANT: Call this at the start of every engagement.

        Args:
            in_scope_urls:     List of in-scope domains/URLs.
            out_of_scope_urls: List of explicitly out-of-scope domains/URLs.
        """
        current = await self.get_project_options()

        include = [
            {"enabled": True, "scheme": "", "host": url, "port": "", "file": ""}
            for url in in_scope_urls
        ]
        exclude = [
            {"enabled": True, "scheme": "", "host": url, "port": "", "file": ""}
            for url in (out_of_scope_urls or [])
        ]

        current.setdefault("target", {})
        current["target"]["scope"] = {
            "advanced_mode": False,
            "include": include,
            "exclude": exclude,
        }

        async with self._session() as session:
            await self._call_tool(
                session,
                "set_project_options",
                {"json": json.dumps(current)},
            )
        log.info(
            "[BurpMCP] Scope set: %d in-scope, %d out-of-scope",
            len(in_scope_urls),
            len(out_of_scope_urls or []),
        )
        return True

    async def set_project_options_raw(self, options_json: str) -> bool:
        """Set raw project options JSON (advanced use)."""
        async with self._session() as session:
            await self._call_tool(
                session,
                "set_project_options",
                {"json": options_json},
            )
        return True

    async def set_user_options_raw(self, options_json: str) -> bool:
        """Set raw user options JSON (advanced use)."""
        async with self._session() as session:
            await self._call_tool(
                session,
                "set_user_options",
                {"json": options_json},
            )
        return True

    # ── GROUP 10: Encoding Utilities ──────────────────────────────────────────

    async def url_encode(self, text: str) -> str:
        """URL encode via Burp — consistent with Burp Decoder."""
        async with self._session() as session:
            texts = await self._call_tool(session, "url_encode", {"content": text})
        result = "\n".join(texts).strip()
        return result if result else text

    async def url_decode(self, text: str) -> str:
        """URL decode via Burp.

        Handles double-encoding, partial encoding, and non-standard encodings.
        """
        async with self._session() as session:
            texts = await self._call_tool(session, "url_decode", {"content": text})
        result = "\n".join(texts).strip()
        return result if result else text

    async def base64_encode(self, data: str) -> str:
        """Base64 encode via Burp."""
        async with self._session() as session:
            texts = await self._call_tool(session, "base64_encode", {"content": data})
        return "\n".join(texts).strip()

    async def base64_decode(self, data: str) -> str:
        """Base64 decode via Burp.

        Use for: decode JWT tokens, cookies, API tokens.
        Handles standard, URL-safe, padded/unpadded variants.
        """
        async with self._session() as session:
            texts = await self._call_tool(session, "base64_decode", {"content": data})
        return "\n".join(texts).strip()

    async def generate_random_string(self, length: int = 16, character_set: str = "ALPHANUMERIC") -> str:
        """Generate a random string via Burp.

        Use for: unique injection markers, canary values, CSRF nonces.

        Args:
            length:        Length of the random string to generate.
            character_set: Burp character set name — "ALPHANUMERIC" (default),
                           "ALPHA", "NUMERIC", "LETTERS_UPPERCASE", etc.
        """
        async with self._session() as session:
            texts = await self._call_tool(
                session, "generate_random_string",
                {"length": length, "characterSet": character_set},
            )
        return "\n".join(texts).strip()

    # ── Scanner compatibility ─────────────────────────────────────────────────

    async def get_collaborator_interactions(
        self,
        payload: str,
    ) -> list[CollaboratorInteraction]:
        """Poll Burp Collaborator by payload domain string (BURP-MCP-MAXIMIZE API).

        This is an alias for poll_collaborator() that accepts the payload domain
        (e.g. "xyz123.oastify.com") instead of the internal payload_id.
        """
        return await self.poll_collaborator(payload_id=payload)


# ── Module-level parser functions ─────────────────────────────────────────────

def _parse_proxy_history(raw_items: list[str]) -> list[ProxyEntry]:
    """Parse a list of raw MCP text items into ProxyEntry objects."""
    entries: list[ProxyEntry] = []
    for raw in raw_items:
        try:
            data = json.loads(raw)
            entries.append(
                ProxyEntry.from_burp_json(data) if isinstance(data, dict) else ProxyEntry(url=raw)
            )
        except json.JSONDecodeError:
            added = False
            for chunk in raw.split("\n\n"):
                chunk = chunk.strip()
                if not chunk:
                    continue
                try:
                    data = json.loads(chunk)
                    entries.append(
                        ProxyEntry.from_burp_json(data) if isinstance(data, dict) else ProxyEntry(url=chunk)
                    )
                    added = True
                except Exception:
                    pass
            if not added:
                entries.append(ProxyEntry(request=raw))
        except Exception:
            entries.append(ProxyEntry(request=raw))
    return entries


def _parse_websocket_history(raw_items: list[str]) -> list[WebSocketEntry]:
    """Parse raw MCP text items into WebSocketEntry objects."""
    entries: list[WebSocketEntry] = []
    for raw in raw_items:
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                entries.append(WebSocketEntry(
                    url=data.get("url", ""),
                    direction=data.get("direction", ""),
                    message=data.get("message", data.get("body", "")),
                    timestamp=data.get("timestamp"),
                ))
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        entries.append(WebSocketEntry(
                            url=item.get("url", ""),
                            direction=item.get("direction", ""),
                            message=item.get("message", item.get("body", "")),
                            timestamp=item.get("timestamp"),
                        ))
        except (json.JSONDecodeError, Exception):
            if raw.strip():
                entries.append(WebSocketEntry(message=raw))
    return entries


def _parse_scanner_issues(raw_items: list[str]) -> list[ScanIssue]:
    """Parse raw MCP text items into ScanIssue objects."""
    issues: list[ScanIssue] = []
    for raw in raw_items:
        try:
            data = json.loads(raw)
            issues.append(
                ScanIssue.from_burp_json(data) if isinstance(data, dict) else ScanIssue(detail=raw)
            )
        except Exception:
            issues.append(ScanIssue(detail=raw))
    return issues


def _parse_organizer_items(raw_items: list[str]) -> list[OrganizerItem]:
    """Parse raw MCP text items into OrganizerItem objects."""
    items: list[OrganizerItem] = []
    for raw in raw_items:
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                items.append(OrganizerItem(
                    url=data.get("url", ""),
                    method=data.get("method", "GET"),
                    request_raw=data.get("request", ""),
                    notes=data.get("notes"),
                ))
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        items.append(OrganizerItem(
                            url=item.get("url", ""),
                            method=item.get("method", "GET"),
                            request_raw=item.get("request", ""),
                            notes=item.get("notes"),
                        ))
        except (json.JSONDecodeError, Exception):
            pass
    return items


def _parse_burp_http_response(raw: str, protocol: str = "HTTP/1.1") -> BurpHttpResponse:
    """Parse a raw HTTP response string into BurpHttpResponse."""
    if not raw:
        return BurpHttpResponse(protocol=protocol, raw=raw)

    lines = raw.split("\n")
    status_code = 0
    headers: dict[str, str] = {}
    body_lines: list[str] = []
    in_body = False

    for i, line in enumerate(lines):
        line = line.rstrip("\r")
        if i == 0:
            parts = line.split(" ", 2)
            if len(parts) >= 2:
                try:
                    status_code = int(parts[1])
                except ValueError:
                    pass
        elif not in_body:
            if line == "":
                in_body = True
            elif ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip().lower()] = value.strip()
        else:
            body_lines.append(line)

    return BurpHttpResponse(
        status_code=status_code,
        headers=headers,
        body="\n".join(body_lines),
        protocol=protocol,
        raw=raw,
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _raw_to_h2_params(content: str, hostname: str) -> dict:
    """Parse a raw HTTP/1-style request string into Burp HTTP/2 structured params.

    Burp's send_http2_request and create_repeater_tab_http2 tools expect
    separate ``headers``, ``pseudoHeaders``, and ``requestBody`` fields
    rather than a raw byte string.

    Returns a dict with keys:
        ``headers``       — regular HTTP headers (dict[str, str])
        ``pseudoHeaders`` — HTTP/2 pseudo-headers (:method, :path, :scheme, :authority)
        ``requestBody``   — request body string
    """
    lines = content.replace("\r\n", "\n").split("\n")
    method = "GET"
    path = "/"
    headers: dict[str, str] = {}
    body_lines: list[str] = []
    in_body = False

    for i, line in enumerate(lines):
        if i == 0:
            parts = line.split(" ", 2)
            if len(parts) >= 2:
                method = parts[0].upper()
                path = parts[1]
        elif not in_body:
            if line == "":
                in_body = True
            elif ":" in line:
                key, _, value = line.partition(":")
                key = key.strip()
                value = value.strip()
                if key.lower() == "host":
                    hostname = value  # override with actual Host header if present
                else:
                    headers[key] = value
        else:
            body_lines.append(line)

    pseudo_headers = {
        ":method": method,
        ":path": path,
        ":scheme": "https",
        ":authority": hostname,
    }

    return {
        "headers": headers,
        "pseudoHeaders": pseudo_headers,
        "requestBody": "\n".join(body_lines).strip(),
    }


def _extract_method(raw_request: str) -> str:
    """Extract the HTTP method from the first line of a raw request string."""
    if not raw_request:
        return "GET"
    sep = "\r\n" if "\r\n" in raw_request else "\n"
    first_line = raw_request.split(sep, 1)[0].strip()
    parts = first_line.split(" ", 1)
    if parts and parts[0].isupper():
        return parts[0]
    return "GET"
