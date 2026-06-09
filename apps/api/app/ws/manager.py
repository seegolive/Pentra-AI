"""WebSocket connection manager for engagement live feed.

Manages per-engagement broadcast channels so the agent can push events
to all connected clients without coupling to FastAPI's request lifecycle.

Events are buffered in-memory (last BUFFER_SIZE per engagement) and
replayed to newly connected clients so page refreshes don't lose history.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict, deque

from fastapi import WebSocket

log = logging.getLogger(__name__)

# Max events kept per engagement (in-memory, lost on server restart)
BUFFER_SIZE = 500


class ConnectionManager:
    """Thread-safe async WebSocket manager for per-engagement feeds."""

    def __init__(self) -> None:
        # engagement_id → set of connected WebSocket objects
        self._connections: dict[str, set[WebSocket]] = defaultdict(set)
        # engagement_id → ring buffer of past events
        self._buffer: dict[str, deque[dict]] = defaultdict(lambda: deque(maxlen=BUFFER_SIZE))
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, engagement_id: str) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections[engagement_id].add(websocket)
            # Snapshot buffer so we can replay outside the lock
            history = list(self._buffer[engagement_id])

        # Replay buffered events to the new client so a page refresh restores history
        for event in history:
            try:
                await websocket.send_json(event)
            except Exception:  # noqa: BLE001
                break

        log.info("[ws] client connected to engagement %s (%d events replayed)", engagement_id, len(history))

    async def disconnect(self, websocket: WebSocket, engagement_id: str) -> None:
        async with self._lock:
            self._connections[engagement_id].discard(websocket)
        log.info("[ws] client disconnected from engagement %s", engagement_id)

    async def broadcast(self, engagement_id: str, message: dict) -> None:
        """Buffer *message* then send to all clients connected to *engagement_id*."""
        dead: list[WebSocket] = []
        async with self._lock:
            # Persist to buffer first (survives client disconnects/refreshes)
            if message.get("type") != "ping":
                self._buffer[engagement_id].append(message)
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

    def get_history(self, engagement_id: str) -> list[dict]:
        """Return buffered events for *engagement_id* (used by REST fallback)."""
        return list(self._buffer.get(engagement_id, []))

    def clear_history(self, engagement_id: str) -> None:
        """Clear event buffer for an engagement."""
        if engagement_id in self._buffer:
            self._buffer[engagement_id].clear()

    async def broadcast_and_persist(
        self,
        engagement_id: str,
        message: dict,
        db=None,  # AsyncSession — optional, skips DB persist if None
    ) -> None:
        """Broadcast event AND persist to DB for cross-restart history (Task 19.4).

        DB persistence is best-effort — failure does not block the broadcast.
        Skips persisting: ping events and LLM_STREAM tokens (too voluminous).

        Args:
            engagement_id: The engagement UUID string.
            message:        Event dict (type, node, data, etc.).
            db:             Optional AsyncSession. If None, only broadcasts.
        """
        # Always broadcast to connected clients
        await self.broadcast(engagement_id, message)

        # Persist to DB (skip noisy event types)
        _skip_types = {"ping", "LLM_STREAM", "llm_stream"}
        if db is None or message.get("type") in _skip_types:
            return

        try:
            from app.db.models import AgentEventORM
            from uuid import UUID as _UUID

            eng_uuid = _UUID(engagement_id) if isinstance(engagement_id, str) else engagement_id
            event = AgentEventORM(
                engagement_id=eng_uuid,
                event_type=message.get("type", ""),
                node=message.get("node"),
                content=message.get("content") if isinstance(message.get("content"), str) else None,
                data={k: v for k, v in message.items() if k not in ("type", "node", "content")},
            )
            db.add(event)
            await db.commit()
        except Exception as exc:  # noqa: BLE001
            log.warning("[ws] DB persist failed (non-fatal): %s", exc)


# Singleton — imported by both the router and agent nodes
ws_manager = ConnectionManager()
