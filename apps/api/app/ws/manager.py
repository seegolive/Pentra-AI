"""WebSocket connection manager for engagement live feed.

Manages per-engagement broadcast channels so the agent can push events
to all connected clients without coupling to FastAPI's request lifecycle.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict

from fastapi import WebSocket

log = logging.getLogger(__name__)


class ConnectionManager:
    """Thread-safe async WebSocket manager for per-engagement feeds."""

    def __init__(self) -> None:
        # engagement_id → set of connected WebSocket objects
        self._connections: dict[str, set[WebSocket]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, engagement_id: str) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections[engagement_id].add(websocket)
        log.info("[ws] client connected to engagement %s", engagement_id)

    async def disconnect(self, websocket: WebSocket, engagement_id: str) -> None:
        async with self._lock:
            self._connections[engagement_id].discard(websocket)
        log.info("[ws] client disconnected from engagement %s", engagement_id)

    async def broadcast(self, engagement_id: str, message: dict) -> None:
        """Send *message* to all clients connected to *engagement_id*."""
        dead: list[WebSocket] = []
        async with self._lock:
            sockets = set(self._connections.get(engagement_id, set()))

        for ws in sockets:
            try:
                await ws.send_json(message)
            except Exception:  # noqa: BLE001
                dead.append(ws)

        if dead:
            async with self._lock:
                for ws in dead:
                    self._connections[engagement_id].discard(ws)


# Singleton — imported by both the router and agent nodes
ws_manager = ConnectionManager()
