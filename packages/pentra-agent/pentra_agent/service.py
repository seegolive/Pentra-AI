"""Agent service — high-level interface used by the FastAPI router and Celery tasks.

Wraps the LangGraph graph lifecycle: create engagement thread, start, resume,
and stream events to WebSocket clients via Redis.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, AsyncIterator

from pentra_agent.graph.builder import build_pentra_graph

log = logging.getLogger(__name__)

# Nodes we surface to the UI — internal LangGraph nodes are skipped
_TRACKED_NODES = {"plan", "hitl_plan", "recon", "hitl_recon", "vuln_hunt", "hitl_exploit", "report"}


def _langgraph_to_ws_event(lg_event: dict) -> dict | None:
    """Convert a raw LangGraph astream_events event to a WebSocket-friendly dict.

    Returns *None* for events that should not be forwarded to clients.
    """
    event_type: str = lg_event.get("event", "")
    node_name: str = lg_event.get("name", "")
    data: dict = lg_event.get("data", {})
    ts = datetime.now(timezone.utc).isoformat()

    if event_type == "on_chain_start":
        if node_name not in _TRACKED_NODES:
            return None
        return {"type": "NODE_START", "node": node_name, "timestamp": ts}

    if event_type == "on_chain_end":
        if node_name not in _TRACKED_NODES:
            return None
        # Detect HITL interrupt
        interrupts = data.get("__interrupt__", [])
        if interrupts:
            interrupt_value = getattr(interrupts[0], "value", {})
            return {
                "type": "AWAITING_APPROVAL",
                "node": node_name,
                "payload": interrupt_value,
                "timestamp": ts,
            }
        # Detect findings update
        output = data.get("output", {})
        if isinstance(output, dict) and output.get("findings"):
            return {
                "type": "FINDINGS_UPDATED",
                "node": node_name,
                "count": len(output["findings"]),
                "timestamp": ts,
            }
        return {"type": "NODE_COMPLETE", "node": node_name, "timestamp": ts}

    if event_type == "on_chat_model_stream":
        chunk = data.get("chunk", {})
        content = getattr(chunk, "content", "") if hasattr(chunk, "content") else ""
        if not content:
            return None
        return {"type": "LLM_STREAM", "node": node_name, "token": content, "timestamp": ts}

    return None


class AgentService:
    """Manages LangGraph engagement threads.

    Typically instantiated via the ``create()`` factory which sets up the
    AsyncPostgresSaver checkpointer and builds the compiled graph.
    """

    def __init__(self, graph=None, *, checkpointer=None) -> None:
        if checkpointer is not None:
            self._graph = build_pentra_graph(checkpointer)
        elif graph is not None:
            self._graph = graph
        else:
            raise ValueError("Either graph or checkpointer must be provided")

    @property
    def graph(self):
        """Compiled LangGraph graph — exposed for direct astream_events use."""
        return self._graph

    # ── Factory ────────────────────────────────────────────────────────────

    @classmethod
    async def create(cls, database_url: str) -> "AgentService":
        """Async factory — build graph with an AsyncPostgresSaver checkpointer.

        ``database_url`` must use the psycopg3 scheme (``postgresql://``).
        The asyncpg prefix is stripped automatically if present.
        """
        from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

        db_url = database_url.replace("postgresql+asyncpg://", "postgresql://")
        async with await AsyncPostgresSaver.from_conn_string(db_url) as checkpointer:
            await checkpointer.setup()
            graph = build_pentra_graph(checkpointer)
            return cls(graph)

    # ── Lifecycle ──────────────────────────────────────────────────────────

    async def start(self, engagement_id: str, initial_state: dict[str, Any]) -> None:
        """Launch a new engagement thread from *initial_state* (fire-and-forget)."""
        config = {"configurable": {"thread_id": engagement_id}}
        log.info("[agent] Starting engagement %s", engagement_id)
        await self._graph.ainvoke(initial_state, config=config)

    async def start_engagement(
        self,
        engagement_id: str,
        initial_state: dict[str, Any],
    ) -> None:
        """Alias for ``start()`` — kept for backward compatibility."""
        await self.start(engagement_id, initial_state)

    async def resume(
        self,
        engagement_id: str,
        user_decision: str,
        *,
        modified_data: dict | None = None,
    ) -> None:
        """Resume a paused engagement after a HITL decision.

        Args:
            engagement_id: Matches the LangGraph thread_id.
            user_decision: One of ``"approve"``, ``"skip"``, ``"modify"``.
            modified_data: Optional payload for modify decisions.
        """
        config = {"configurable": {"thread_id": engagement_id}}

        await self.graph.aupdate_state(
            config=config,
            values={
                "user_decision": user_decision,
                "awaiting_approval": False,
            },
        )

        log.info("[agent] Resuming engagement %s with decision=%s", engagement_id, user_decision)
        await self.graph.ainvoke(None, config=config)

    async def resume_engagement(
        self,
        engagement_id: str,
        decision: str,
        *,
        modified_data: dict | None = None,
    ) -> None:
        """Backward-compat alias for ``resume()``."""
        await self.resume(engagement_id, decision)

    # ── Streaming ──────────────────────────────────────────────────────────

    async def stream_events_during_start(
        self,
        engagement_id: str,
        initial_state: dict[str, Any],
    ) -> AsyncIterator[dict]:
        """Start engagement AND stream events.

        Yields WebSocket-friendly event dicts to the caller so they can be
        forwarded to Redis / WebSocket clients in real time.
        """
        config = {"configurable": {"thread_id": engagement_id}}

        async for event in self.graph.astream_events(
            initial_state, config=config, version="v2"
        ):
            ws_event = _langgraph_to_ws_event(event)
            if ws_event:
                yield ws_event

    async def stream_events(self, engagement_id: str) -> AsyncIterator[dict]:
        """Stream events from an already-started (checkpointed) engagement.

        Used by the WebSocket endpoint to replay / follow an in-progress run.
        """
        config = {"configurable": {"thread_id": engagement_id}}

        async for event in self.graph.astream_events(None, config=config, version="v2"):
            ws_event = _langgraph_to_ws_event(event)
            if ws_event:
                yield ws_event

    # ── State inspection ───────────────────────────────────────────────────

    def get_current_state(self, engagement_id: str) -> dict[str, Any] | None:
        """Return the latest checkpoint values for an engagement thread (sync)."""
        import asyncio

        config = {"configurable": {"thread_id": engagement_id}}

        async def _get():
            snapshot = await self._graph.aget_state(config)
            return dict(snapshot.values) if snapshot else None

        return asyncio.run(_get())

    async def get_state(self, engagement_id: str) -> dict[str, Any] | None:
        """Async version of ``get_current_state()``."""
        config = {"configurable": {"thread_id": engagement_id}}
        snapshot = await self._graph.aget_state(config)
        if snapshot is None:
            return None
        return dict(snapshot.values)
