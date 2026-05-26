"""WebSocket connection manager — per-engagement connection pooling.

Singleton ``ws_manager`` is imported by the WebSocket endpoint and by the
Redis bridge, which calls ``broadcast()`` whenever a new event arrives.
"""

from __future__ import annotations

from collections import defaultdict

from fastapi import WebSocket


class WebSocketManager:
    """Manage active WebSocket connections keyed by engagement_id.

    One instance (singleton) is shared across the entire API process.
    All methods are safe to call from within a single asyncio event loop.
    """

    def __init__(self) -> None:
        self._connections: dict[str, list[WebSocket]] = defaultdict(list)

    async def connect(self, websocket: WebSocket, engagement_id: str) -> None:
        """Accept the handshake and register the connection."""
        await websocket.accept()
        self._connections[engagement_id].append(websocket)

    def disconnect(self, websocket: WebSocket, engagement_id: str) -> None:
        """Remove a specific WebSocket from the engagement's connection list."""
        conns = self._connections.get(engagement_id, [])
        if websocket in conns:
            conns.remove(websocket)

    async def broadcast(self, engagement_id: str, event: dict) -> None:
        """Send *event* to every client connected to *engagement_id*.

        Dead connections (send raises an exception) are removed automatically.
        """
        conns = list(self._connections.get(engagement_id, []))
        dead: list[WebSocket] = []
        for ws in conns:
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws, engagement_id)

    def connection_count(self, engagement_id: str) -> int:
        """Return the number of live connections for *engagement_id*."""
        return len(self._connections.get(engagement_id, []))


# Singleton — import this from other modules
ws_manager = WebSocketManager()
