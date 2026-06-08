"""Full unit-test suite for BurpMCPClient — 8 tests per BURP-MCP-MAXIMIZE.md.

These tests cover the new 27-tool implementation.  All tests are offline
(no real Burp Suite required) — they mock the MCP SSE _session layer the
same way the existing test_burp_mcp.py does.

Test list (matches BURP-MCP-MAXIMIZE.md spec):
  1.  test_health_check_success
  2.  test_health_check_unreachable
  3.  test_parse_proxy_history_empty
  4.  test_parse_websocket_history
  5.  test_generate_collaborator_payload
  6.  test_set_proxy_intercept_state
  7.  test_encoding_utils
  8.  test_burp_not_available_error
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pentra_tools.burp.client import (
    BurpMCPClient,
    BurpNotAvailableError,
    WebSocketEntry,
    _parse_websocket_history,
)
from pentra_tools.burp.exceptions import BurpConnectionError
from pentra_tools.burp.models import CollaboratorPayload


# ── Helpers (mirrors test_burp_mcp.py style) ──────────────────────────────────

def _make_text_content(text: str) -> MagicMock:
    from mcp.types import TextContent
    tc = MagicMock(spec=TextContent)
    tc.text = text
    return tc


def _make_call_result(texts: list[str], is_error: bool = False) -> MagicMock:
    result = MagicMock()
    result.isError = is_error
    result.content = [_make_text_content(t) for t in texts]
    return result


@asynccontextmanager
async def _mock_session_ctx(mock_session):
    yield mock_session


@asynccontextmanager
async def _failing_session_ctx():
    """Context manager that raises BurpConnectionError on entry."""
    raise BurpConnectionError("Connection refused — Burp not running")
    yield  # pragma: no cover — never reached


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def burp_client():
    return BurpMCPClient(base_url="http://localhost:9877")


# ── Test 1: health_check success ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_health_check_success(burp_client):
    """health_check() returns True when Burp responds with tool list."""
    mock_session = AsyncMock()
    mock_session.list_tools.return_value = MagicMock(
        tools=[
            MagicMock(name="get_proxy_http_history"),
            MagicMock(name="url_encode"),
            MagicMock(name="generate_collaborator_payload"),
        ]
    )
    with patch.object(burp_client, "_session", return_value=_mock_session_ctx(mock_session)):
        result = await burp_client.health_check()

    assert result is True
    mock_session.list_tools.assert_awaited_once()


# ── Test 2: health_check unreachable ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_health_check_unreachable(burp_client):
    """health_check() returns False (never raises) when Burp is unreachable."""
    with patch.object(burp_client, "_session", return_value=_failing_session_ctx()):
        result = await burp_client.health_check()

    assert result is False


# ── Test 3: parse proxy history — empty ───────────────────────────────────────

@pytest.mark.asyncio
async def test_parse_proxy_history_empty(burp_client):
    """get_proxy_history() returns [] when proxy history is empty."""
    mock_session = AsyncMock()
    # Paginator calls call_tool; returning empty list stops iteration immediately.
    mock_session.call_tool.return_value = _make_call_result([])

    with patch.object(burp_client, "_session", return_value=_mock_session_ctx(mock_session)):
        result = await burp_client.get_proxy_history()

    assert result == []
    mock_session.call_tool.assert_awaited_once()


# ── Test 4: parse WebSocket history ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_parse_websocket_history(burp_client):
    """get_proxy_websocket_history() returns parsed WebSocketEntry list."""
    ws_entry = {
        "url": "ws://target.com/ws",
        "direction": "client_to_server",
        "message": '{"action":"ping"}',
        "timestamp": "2026-06-04",
    }
    mock_session = AsyncMock()
    # Return one entry; len(page)=1 < page_size=10 → pagination stops naturally.
    mock_session.call_tool.return_value = _make_call_result([json.dumps(ws_entry)])

    with patch.object(burp_client, "_session", return_value=_mock_session_ctx(mock_session)):
        result = await burp_client.get_proxy_websocket_history(limit=10)

    assert len(result) == 1
    assert isinstance(result[0], WebSocketEntry)
    assert result[0].url == "ws://target.com/ws"
    assert result[0].direction == "client_to_server"
    assert result[0].message == '{"action":"ping"}'
    assert result[0].timestamp == "2026-06-04"


# ── Test 5: generate Collaborator payload ─────────────────────────────────────

@pytest.mark.asyncio
async def test_generate_collaborator_payload(burp_client):
    """generate_collaborator_payload() parses the Burp response format correctly."""
    mock_session = AsyncMock()
    mock_session.call_tool.return_value = _make_call_result([
        "Payload: xyz123.oastify.com\nPayload ID: abc\nCollaborator server: oastify.com"
    ])

    with patch.object(burp_client, "_session", return_value=_mock_session_ctx(mock_session)):
        result = await burp_client.generate_collaborator_payload()

    assert isinstance(result, CollaboratorPayload)
    assert result.payload == "xyz123.oastify.com"
    assert result.payload_id == "abc"


# ── Test 6: set_proxy_intercept_state ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_set_proxy_intercept_state(burp_client):
    """set_proxy_intercept_state() calls the right MCP tool with correct args."""
    mock_session = AsyncMock()
    mock_session.call_tool.return_value = _make_call_result(["OK"])

    with patch.object(burp_client, "_session", return_value=_mock_session_ctx(mock_session)):
        result = await burp_client.set_proxy_intercept_state(enabled=False)

    assert result is True
    # Verify MCP tool name and argument
    call_args = mock_session.call_tool.call_args
    tool_name = call_args[0][0]
    tool_args = call_args[0][1]
    assert tool_name == "set_proxy_intercept_state"
    assert tool_args == {"intercepting": False}


# ── Test 7: encoding utilities ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_encoding_utils(burp_client):
    """url_encode() returns the encoded string from Burp Decoder."""
    mock_session = AsyncMock()
    mock_session.call_tool.return_value = _make_call_result(["hello%20world"])

    with patch.object(burp_client, "_session", return_value=_mock_session_ctx(mock_session)):
        result = await burp_client.url_encode("hello world")

    assert result == "hello%20world"
    # Verify Burp tool was called with the right argument
    call_args = mock_session.call_tool.call_args
    assert call_args[0][0] == "url_encode"
    assert call_args[0][1] == {"content": "hello world"}


# ── Test 8: BurpNotAvailableError alias ───────────────────────────────────────

def test_burp_not_available_error():
    """BurpNotAvailableError is importable and behaves as a BurpConnectionError."""
    err = BurpNotAvailableError("Cannot connect to Burp Suite")
    assert "Cannot connect" in str(err)
    assert isinstance(err, BurpConnectionError)
