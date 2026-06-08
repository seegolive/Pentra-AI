"""Tests for the Burp Suite MCP client.

Integration tests (require a real Burp Suite instance) are skipped unless
BURP_MCP_ENABLED=true is set in the environment.

Offline tests use mocked MCP sessions and run unconditionally.
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pentra_tools.burp.client import BurpMCPClient, _extract_method
from pentra_tools.burp.exceptions import (
    BurpConnectionError,
    BurpMCPToolError,
    BurpNotProError,
)
from pentra_tools.burp.models import (
    CollaboratorPayload,
    HttpRequest,
    ProxyEntry,
    RepeaterTab,
    ScanIssue,
    ScanTask,
    SitemapEntry,
)

# ── Helpers ────────────────────────────────────────────────────────────────────

_BURP_AVAILABLE = os.getenv("BURP_MCP_ENABLED", "false").lower() == "true"

burp_integration = pytest.mark.skipif(
    not _BURP_AVAILABLE,
    reason="Burp Suite Pro not available (set BURP_MCP_ENABLED=true to run)",
)


def _make_text_content(text: str) -> MagicMock:
    """Create a fake MCP TextContent item."""
    from mcp.types import TextContent

    tc = MagicMock(spec=TextContent)
    tc.text = text
    return tc


def _make_call_result(texts: list[str], is_error: bool = False) -> MagicMock:
    """Create a fake MCP CallToolResult."""
    result = MagicMock()
    result.isError = is_error
    result.content = [_make_text_content(t) for t in texts]
    return result


def _make_list_tools_result(tool_names: list[str]) -> MagicMock:
    """Create a fake MCP ListToolsResult."""
    result = MagicMock()
    tools = []
    for n in tool_names:
        t = MagicMock()
        t.name = n  # set as attribute, not MagicMock display name
        tools.append(t)
    result.tools = tools
    return result


@asynccontextmanager
async def _mock_session_ctx(session: AsyncMock):
    """Context manager that yields the given mock session."""
    yield session


# ── Unit tests — offline (no Burp needed) ─────────────────────────────────────


class TestHelpers:
    def test_extract_method_get(self):
        raw = "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n"
        assert _extract_method(raw) == "GET"

    def test_extract_method_post(self):
        raw = "POST /api/login HTTP/1.1\r\nHost: example.com\r\n\r\nbody"
        assert _extract_method(raw) == "POST"

    def test_extract_method_empty(self):
        assert _extract_method("") == "GET"

    def test_extract_method_lf_only(self):
        raw = "DELETE /resource HTTP/1.1\nHost: example.com\n\n"
        assert _extract_method(raw) == "DELETE"


class TestProxyEntryParsing:
    def test_from_burp_json_full(self):
        raw = {
            "id": "42",
            "url": "https://api.target.com/users",
            "method": "GET",
            "responseStatus": 200,
            "request": "GET /users HTTP/1.1\r\nHost: api.target.com\r\n\r\n",
            "response": "HTTP/1.1 200 OK\r\n\r\n[]",
            "host": "api.target.com",
            "port": 443,
            "isHttps": True,
        }
        entry = ProxyEntry.from_burp_json(raw)
        assert entry.url == "https://api.target.com/users"
        assert entry.method == "GET"
        assert entry.response_status == 200
        assert entry.is_https is True

    def test_from_burp_json_minimal(self):
        raw = {"url": "http://example.com/", "method": "POST"}
        entry = ProxyEntry.from_burp_json(raw)
        assert entry.url == "http://example.com/"
        assert entry.method == "POST"
        assert entry.response_status is None

    def test_extra_fields_allowed(self):
        raw = {"url": "http://x.com/", "method": "GET", "unknownField": "abc"}
        entry = ProxyEntry.from_burp_json(raw)
        assert entry.url == "http://x.com/"

    def test_url_extracted_from_raw_http_request_when_url_absent(self):
        """When Burp omits 'url', reconstruct it from the raw request line + Host header.

        No port/isHttps in raw dict → defaults to port 443 → https scheme.
        """
        raw = {
            "request": "GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nAccept: */*\r\n\r\n",
            "response": "HTTP/1.1 200 OK\r\n\r\n{}",
            "notes": "",
        }
        entry = ProxyEntry.from_burp_json(raw)
        assert entry.url == "https://httpbin.org/ip"  # default port=443 → https
        assert entry.method == "GET"

    def test_url_extracted_with_https_port(self):
        """Port 443 → https scheme."""
        raw = {
            "request": "POST /login HTTP/1.1\r\nHost: secure.example.com\r\n\r\nbody",
            "response": "HTTP/1.1 302 Found\r\n\r\n",
            "port": 443,
            "isHttps": True,
        }
        entry = ProxyEntry.from_burp_json(raw)
        assert entry.url == "https://secure.example.com/login"
        assert entry.method == "POST"


class TestMultiEntryBlobParsing:
    """Burp sometimes returns multiple JSON objects in one TextContent blob."""

    @pytest.mark.asyncio
    async def test_multi_entry_blob_parsed_correctly(self):
        entry1 = json.dumps({
            "request": "GET /ip HTTP/1.1\r\nHost: httpbin.org\r\n\r\n",
            "response": "HTTP/1.1 200 OK\r\n\r\n{}",
            "notes": "",
            "port": 80,
            "isHttps": False,
        })
        entry2 = json.dumps({
            "request": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "response": "HTTP/1.1 200 OK\r\n\r\n",
            "notes": "",
            "port": 80,
            "isHttps": False,
        })
        blob = entry1 + "\n\n" + entry2  # Burp-style multi-entry blob

        mock_session = AsyncMock()
        mock_session.call_tool.side_effect = [
            _make_call_result([blob]),
            _make_call_result([]),
        ]

        client = BurpMCPClient()
        with patch.object(client, "_session", return_value=_mock_session_ctx(mock_session)):
            entries = await client.get_proxy_history(limit=50)

        assert len(entries) == 2
        assert entries[0].url == "http://httpbin.org/ip"
        assert entries[1].url == "http://example.com/"


class TestHealthCheck:
    @pytest.mark.asyncio
    async def test_health_check_success(self):
        mock_session = AsyncMock()
        mock_session.list_tools.return_value = _make_list_tools_result(
            ["get_proxy_http_history", "create_repeater_tab"]
        )

        client = BurpMCPClient()
        with patch.object(client, "_session", return_value=_mock_session_ctx(mock_session)):
            result = await client.health_check()

        assert result is True

    @pytest.mark.asyncio
    async def test_health_check_connection_error_returns_false(self):
        client = BurpMCPClient("http://127.0.0.1:9999")
        with patch.object(
            client,
            "_session",
            side_effect=BurpConnectionError("not reachable"),
        ):
            result = await client.health_check()

        assert result is False

    @pytest.mark.asyncio
    async def test_list_tools_returns_names(self):
        mock_session = AsyncMock()
        mock_session.list_tools.return_value = _make_list_tools_result(
            ["get_proxy_http_history", "get_scanner_issues", "create_repeater_tab"]
        )

        client = BurpMCPClient()
        with patch.object(client, "_session", return_value=_mock_session_ctx(mock_session)):
            names = await client.list_tools()

        assert "get_proxy_http_history" in names
        assert "get_scanner_issues" in names


class TestGetProxyHistory:
    @pytest.mark.asyncio
    async def test_returns_parsed_entries(self):
        entry_json = json.dumps({
            "url": "https://api.target.com/users",
            "method": "GET",
            "responseStatus": 200,
            "host": "api.target.com",
            "port": 443,
            "isHttps": True,
        })
        mock_session = AsyncMock()
        # First page returns 1 item, second returns empty → stop
        mock_session.call_tool.side_effect = [
            _make_call_result([entry_json]),
            _make_call_result([]),
        ]

        client = BurpMCPClient()
        with patch.object(client, "_session", return_value=_mock_session_ctx(mock_session)):
            entries = await client.get_proxy_history(limit=50)

        assert len(entries) == 1
        assert entries[0].url == "https://api.target.com/users"
        assert entries[0].method == "GET"
        assert entries[0].response_status == 200

    @pytest.mark.asyncio
    async def test_uses_regex_tool_when_filter_given(self):
        mock_session = AsyncMock()
        mock_session.call_tool.side_effect = [
            _make_call_result([]),
        ]

        client = BurpMCPClient()
        with patch.object(client, "_session", return_value=_mock_session_ctx(mock_session)):
            await client.get_proxy_history(filter_regex=r"api\.target\.com", limit=10)

        call_args = mock_session.call_tool.call_args
        assert call_args[0][0] == "get_proxy_http_history_regex"
        assert call_args[0][1]["regex"] == r"api\.target\.com"

    @pytest.mark.asyncio
    async def test_pagination_collects_multiple_pages(self):
        # Page 1: 50 items (full page), Page 2: 30 items (partial → stop)
        page1 = [json.dumps({"url": f"http://x.com/{i}", "method": "GET"}) for i in range(50)]
        page2 = [json.dumps({"url": f"http://x.com/{i}", "method": "GET"}) for i in range(50, 80)]

        mock_session = AsyncMock()
        mock_session.call_tool.side_effect = [
            _make_call_result(page1),
            _make_call_result(page2),
            _make_call_result([]),  # safety stop
        ]

        client = BurpMCPClient()
        with patch.object(client, "_session", return_value=_mock_session_ctx(mock_session)):
            entries = await client.get_proxy_history(limit=200)

        assert len(entries) == 80

    @pytest.mark.asyncio
    async def test_limit_respected(self):
        page = [json.dumps({"url": f"http://x.com/{i}", "method": "GET"}) for i in range(50)]

        mock_session = AsyncMock()
        mock_session.call_tool.return_value = _make_call_result(page)

        client = BurpMCPClient()
        with patch.object(client, "_session", return_value=_mock_session_ctx(mock_session)):
            entries = await client.get_proxy_history(limit=5)

        assert len(entries) == 5

    @pytest.mark.asyncio
    async def test_malformed_json_stored_as_raw(self):
        mock_session = AsyncMock()
        mock_session.call_tool.side_effect = [
            _make_call_result(["not valid json"]),
            _make_call_result([]),
        ]

        client = BurpMCPClient()
        with patch.object(client, "_session", return_value=_mock_session_ctx(mock_session)):
            entries = await client.get_proxy_history(limit=10)

        assert len(entries) == 1
        assert entries[0].request == "not valid json"


class TestSendToRepeater:
    @pytest.mark.asyncio
    async def test_creates_repeater_tab(self):
        mock_session = AsyncMock()
        mock_session.call_tool.return_value = _make_call_result(["Tab created"])

        client = BurpMCPClient()
        request = HttpRequest(
            content="GET / HTTP/1.1\r\nHost: target.com\r\n\r\n",
            target_hostname="target.com",
            target_port=443,
            uses_https=True,
            tab_name="Test Tab",
        )
        with patch.object(client, "_session", return_value=_mock_session_ctx(mock_session)):
            tab = await client.send_to_repeater(request)

        assert isinstance(tab, RepeaterTab)
        assert tab.tab_name == "Test Tab"
        assert "target.com" in tab.url
        assert tab.method == "GET"

    @pytest.mark.asyncio
    async def test_normalises_crlf(self):
        mock_session = AsyncMock()
        mock_session.call_tool.return_value = _make_call_result(["Tab created"])

        client = BurpMCPClient()
        request = HttpRequest(
            content="GET / HTTP/1.1\nHost: target.com\n\n",  # LF only
            target_hostname="target.com",
            target_port=80,
            uses_https=False,
        )
        with patch.object(client, "_session", return_value=_mock_session_ctx(mock_session)):
            await client.send_to_repeater(request)

        sent_content = mock_session.call_tool.call_args[0][1]["content"]
        assert "\r\n" in sent_content


class TestCollaborator:
    @pytest.mark.asyncio
    async def test_parse_collaborator_response(self):
        mock_session = AsyncMock()
        mock_session.call_tool.return_value = _make_call_result([
            "Payload: abc123xyz.oastify.com\nPayload ID: def456\nCollaborator server: oastify.com"
        ])

        client = BurpMCPClient()
        with patch.object(client, "_session", return_value=_mock_session_ctx(mock_session)):
            cp = await client.generate_collaborator_payload()

        assert cp.payload == "abc123xyz.oastify.com"
        assert cp.payload_id == "def456"

    @pytest.mark.asyncio
    async def test_collaborator_raises_on_unparseable(self):
        mock_session = AsyncMock()
        mock_session.call_tool.return_value = _make_call_result(["unexpected response format"])

        client = BurpMCPClient()
        with patch.object(client, "_session", return_value=_mock_session_ctx(mock_session)):
            with pytest.raises(BurpMCPToolError):
                await client.generate_collaborator_payload()

    @pytest.mark.asyncio
    async def test_poll_collaborator_no_interactions(self):
        mock_session = AsyncMock()
        mock_session.call_tool.return_value = _make_call_result(["No interactions detected"])

        client = BurpMCPClient()
        with patch.object(client, "_session", return_value=_mock_session_ctx(mock_session)):
            interactions = await client.poll_collaborator("fake-id")

        assert interactions == []


class TestProOnlyRaisesError:
    @pytest.mark.asyncio
    async def test_get_scan_results_raises_not_pro(self):
        mock_session = AsyncMock()
        mock_session.call_tool.return_value = _make_call_result(
            ["This feature requires Burp Suite Professional"], is_error=True
        )

        client = BurpMCPClient()
        with patch.object(client, "_session", return_value=_mock_session_ctx(mock_session)):
            with pytest.raises(BurpNotProError) as exc_info:
                await client.get_scan_results()

        assert "get_scanner_issues" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_generate_collaborator_raises_not_pro(self):
        mock_session = AsyncMock()
        mock_session.call_tool.return_value = _make_call_result(
            ["Pro only feature"], is_error=True
        )

        client = BurpMCPClient()
        with patch.object(client, "_session", return_value=_mock_session_ctx(mock_session)):
            with pytest.raises(BurpNotProError):
                await client.generate_collaborator_payload()


class TestTriggerActiveScan:
    @pytest.mark.asyncio
    async def test_returns_scan_task(self):
        mock_session = AsyncMock()
        mock_session.call_tool.return_value = _make_call_result(["OK"])

        client = BurpMCPClient()
        with patch.object(client, "_session", return_value=_mock_session_ctx(mock_session)):
            task = await client.trigger_active_scan(
                "https://api.target.com/users", ["target.com"]
            )

        assert isinstance(task, ScanTask)
        assert task.status == "running"
        assert "api.target.com" in task.url
        assert task.note  # should contain explanation

    @pytest.mark.asyncio
    async def test_enables_task_engine(self):
        mock_session = AsyncMock()
        mock_session.call_tool.return_value = _make_call_result(["OK"])

        client = BurpMCPClient()
        with patch.object(client, "_session", return_value=_mock_session_ctx(mock_session)):
            await client.trigger_active_scan("https://target.com/", ["target.com"])

        calls = [c[0][0] for c in mock_session.call_tool.call_args_list]
        assert "set_task_execution_engine_state" in calls
        assert "send_http1_request" in calls


# ── Integration tests — require live Burp Suite ────────────────────────────────


@burp_integration
class TestBurpIntegration:
    @pytest.mark.asyncio
    async def test_health_check(self):
        client = BurpMCPClient()
        assert await client.health_check() is True

    @pytest.mark.asyncio
    async def test_get_proxy_history(self):
        client = BurpMCPClient()
        entries = await client.get_proxy_history(limit=10)
        assert isinstance(entries, list)
        if entries:
            assert isinstance(entries[0], ProxyEntry)
            assert entries[0].url

    @pytest.mark.asyncio
    @pytest.mark.xfail(
        reason="Burp Collaborator requires Pro edition — Community raises BurpNotProError",
        raises=BurpConnectionError,
        strict=False,
    )
    async def test_generate_collaborator_payload(self):
        client = BurpMCPClient()
        cp = await client.generate_collaborator_payload(custom_data="pentra-test")
        assert isinstance(cp, CollaboratorPayload)
        assert cp.payload
        assert "." in cp.payload  # looks like a domain
