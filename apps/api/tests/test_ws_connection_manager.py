"""Stress/coverage tests for app.ws.manager.ConnectionManager (Sprint 28.3).

The engagement Live Feed (apps/web ReportViewer / live feed tab) is backed by
``ConnectionManager`` in app/ws/manager.py — a buffered, multi-client WebSocket
broadcaster used by every node in the agent graph via ``broadcast_and_persist``.
This class previously had zero test coverage.
"""

from __future__ import annotations

import asyncio

import pytest
from unittest.mock import AsyncMock


# ── connect / replay history ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_connect_replays_buffered_history_to_new_client():
    """A newly connected client receives all previously broadcast events."""
    from app.ws.manager import ConnectionManager

    m = ConnectionManager()
    ws_old = AsyncMock()
    await m.connect(ws_old, "eng-1")

    for i in range(5):
        await m.broadcast("eng-1", {"type": "NODE_START", "node": f"step-{i}"})

    ws_new = AsyncMock()
    await m.connect(ws_new, "eng-1")

    assert ws_new.send_json.call_count == 5
    sent = [c.args[0]["node"] for c in ws_new.send_json.call_args_list]
    assert sent == [f"step-{i}" for i in range(5)]


@pytest.mark.asyncio
async def test_ping_events_are_not_buffered():
    """'ping' events are broadcast live but never stored in history/replay."""
    from app.ws.manager import ConnectionManager

    m = ConnectionManager()
    ws1 = AsyncMock()
    await m.connect(ws1, "eng-1")

    await m.broadcast("eng-1", {"type": "ping"})
    await m.broadcast("eng-1", {"type": "NODE_START", "node": "recon"})

    assert m.get_history("eng-1") == [{"type": "NODE_START", "node": "recon"}]


# ── broadcast fan-out under load ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_broadcast_fans_out_to_many_clients():
    """A single broadcast reaches every connected client (stress: 50 clients)."""
    from app.ws.manager import ConnectionManager

    m = ConnectionManager()
    clients = [AsyncMock() for _ in range(50)]
    for ws in clients:
        await m.connect(ws, "eng-stress")

    await m.broadcast("eng-stress", {"type": "AGENT_LOG", "content": "hello"})

    for ws in clients:
        ws.send_json.assert_called_once_with({"type": "AGENT_LOG", "content": "hello"})


@pytest.mark.asyncio
async def test_high_volume_broadcast_respects_buffer_size_cap():
    """Broadcasting more than BUFFER_SIZE events keeps only the most recent ones."""
    from app.ws.manager import ConnectionManager, BUFFER_SIZE

    m = ConnectionManager()
    ws = AsyncMock()
    await m.connect(ws, "eng-flood")

    total = BUFFER_SIZE + 100
    for i in range(total):
        await m.broadcast("eng-flood", {"type": "AGENT_LOG", "seq": i})

    history = m.get_history("eng-flood")
    assert len(history) == BUFFER_SIZE
    # Oldest events dropped — buffer holds the most recent BUFFER_SIZE
    assert history[0]["seq"] == total - BUFFER_SIZE
    assert history[-1]["seq"] == total - 1


@pytest.mark.asyncio
async def test_concurrent_broadcasts_do_not_lose_or_duplicate_events():
    """Many concurrent broadcast() calls all land in history exactly once."""
    from app.ws.manager import ConnectionManager

    m = ConnectionManager()
    ws = AsyncMock()
    await m.connect(ws, "eng-concurrent")

    await asyncio.gather(
        *[m.broadcast("eng-concurrent", {"type": "AGENT_LOG", "seq": i}) for i in range(200)]
    )

    history = m.get_history("eng-concurrent")
    assert len(history) == 200
    assert sorted(h["seq"] for h in history) == list(range(200))


# ── dead connection cleanup ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_broadcast_drops_dead_connections_under_load():
    """Clients whose send_json raises are pruned without affecting others."""
    from app.ws.manager import ConnectionManager

    m = ConnectionManager()
    alive = [AsyncMock() for _ in range(10)]
    dead = [AsyncMock() for _ in range(10)]
    for ws in dead:
        ws.send_json.side_effect = Exception("connection closed")

    for ws in alive + dead:
        await m.connect(ws, "eng-mixed")

    await m.broadcast("eng-mixed", {"type": "AGENT_LOG", "content": "ping-test"})

    for ws in alive:
        ws.send_json.assert_called_with({"type": "AGENT_LOG", "content": "ping-test"})

    # Second broadcast — dead clients must no longer be targeted
    for ws in alive + dead:
        ws.send_json.reset_mock()
        ws.send_json.side_effect = None

    await m.broadcast("eng-mixed", {"type": "AGENT_LOG", "content": "second"})

    for ws in alive:
        ws.send_json.assert_called_once_with({"type": "AGENT_LOG", "content": "second"})
    for ws in dead:
        ws.send_json.assert_not_called()


# ── disconnect / per-engagement isolation ───────────────────────────────────

@pytest.mark.asyncio
async def test_disconnect_removes_only_target_client():
    from app.ws.manager import ConnectionManager

    m = ConnectionManager()
    ws1, ws2 = AsyncMock(), AsyncMock()
    await m.connect(ws1, "eng-1")
    await m.connect(ws2, "eng-1")

    await m.disconnect(ws1, "eng-1")
    await m.broadcast("eng-1", {"type": "AGENT_LOG", "content": "after disconnect"})

    ws1.send_json.assert_not_called()
    ws2.send_json.assert_called_once_with({"type": "AGENT_LOG", "content": "after disconnect"})


@pytest.mark.asyncio
async def test_broadcasts_are_isolated_per_engagement():
    """A broadcast to one engagement must not reach clients of another."""
    from app.ws.manager import ConnectionManager

    m = ConnectionManager()
    ws_a, ws_b = AsyncMock(), AsyncMock()
    await m.connect(ws_a, "eng-a")
    await m.connect(ws_b, "eng-b")

    await m.broadcast("eng-a", {"type": "AGENT_LOG", "content": "for A only"})

    ws_a.send_json.assert_called_once()
    ws_b.send_json.assert_not_called()


def test_clear_history_empties_buffer():
    from app.ws.manager import ConnectionManager

    m = ConnectionManager()
    m._buffer["eng-1"].append({"type": "AGENT_LOG", "content": "x"})

    m.clear_history("eng-1")

    assert m.get_history("eng-1") == []


def test_get_history_unknown_engagement_returns_empty_list():
    from app.ws.manager import ConnectionManager

    m = ConnectionManager()
    assert m.get_history("does-not-exist") == []


# ── broadcast_and_persist ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_broadcast_and_persist_skips_db_for_noisy_event_types():
    """ping and LLM_STREAM events broadcast but never hit the DB."""
    from app.ws.manager import ConnectionManager

    m = ConnectionManager()
    ws = AsyncMock()
    await m.connect(ws, "eng-1")
    mock_db = AsyncMock()

    await m.broadcast_and_persist("eng-1", {"type": "ping"}, db=mock_db)
    await m.broadcast_and_persist("eng-1", {"type": "LLM_STREAM", "content": "tok"}, db=mock_db)

    ws.send_json.assert_any_call({"type": "ping"})
    ws.send_json.assert_any_call({"type": "LLM_STREAM", "content": "tok"})
    mock_db.add.assert_not_called()
    mock_db.commit.assert_not_called()


@pytest.mark.asyncio
async def test_broadcast_and_persist_without_db_only_broadcasts():
    """db=None must not raise and must still broadcast to clients."""
    from app.ws.manager import ConnectionManager

    m = ConnectionManager()
    ws = AsyncMock()
    await m.connect(ws, "eng-1")

    await m.broadcast_and_persist("eng-1", {"type": "NODE_START", "node": "recon"}, db=None)

    ws.send_json.assert_called_once_with({"type": "NODE_START", "node": "recon"})
