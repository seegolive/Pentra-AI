"""Tests for WebSocketManager (Task 12.1).

4 tests covering: broadcast, dead-connection cleanup, disconnect, connection_count.
"""

from __future__ import annotations

import asyncio

import pytest
from unittest.mock import AsyncMock


@pytest.mark.asyncio
async def test_broadcast_sends_to_all_connected():
    """broadcast() must call send_json on every registered connection."""
    from app.core.ws_manager import WebSocketManager

    m = WebSocketManager()
    ws1, ws2 = AsyncMock(), AsyncMock()
    await m.connect(ws1, "eng-1")
    await m.connect(ws2, "eng-1")

    await m.broadcast("eng-1", {"type": "NODE_START", "node": "recon"})

    ws1.send_json.assert_called_once_with({"type": "NODE_START", "node": "recon"})
    ws2.send_json.assert_called_once_with({"type": "NODE_START", "node": "recon"})


@pytest.mark.asyncio
async def test_broadcast_removes_dead_connections():
    """broadcast() must silently remove connections that raise on send_json."""
    from app.core.ws_manager import WebSocketManager

    m = WebSocketManager()
    ws_dead = AsyncMock()
    ws_dead.send_json.side_effect = Exception("connection closed")
    ws_alive = AsyncMock()

    await m.connect(ws_dead, "eng-1")
    await m.connect(ws_alive, "eng-1")

    await m.broadcast("eng-1", {"type": "ping"})

    # Dead connection was removed, alive one stays
    assert m.connection_count("eng-1") == 1
    ws_alive.send_json.assert_called_once_with({"type": "ping"})


def test_disconnect_removes_specific_ws():
    """disconnect() must remove only the specified WebSocket, not others."""
    from app.core.ws_manager import WebSocketManager

    m = WebSocketManager()
    ws1, ws2 = AsyncMock(), AsyncMock()
    asyncio.run(m.connect(ws1, "eng-1"))
    asyncio.run(m.connect(ws2, "eng-1"))

    m.disconnect(ws1, "eng-1")

    assert m.connection_count("eng-1") == 1


def test_connection_count_zero_for_unknown_engagement():
    """connection_count() must return 0 for an engagement with no connections."""
    from app.core.ws_manager import WebSocketManager

    m = WebSocketManager()
    assert m.connection_count("does-not-exist") == 0
