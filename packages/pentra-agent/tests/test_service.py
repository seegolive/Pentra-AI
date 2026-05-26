"""Tests for AgentService and _langgraph_to_ws_event helper.

Sprint 11.1 — 4 core tests:
  1. resume() updates state and re-invokes the graph
  2. _langgraph_to_ws_event converts on_chain_start → NODE_START
  3. _langgraph_to_ws_event returns None for unknown / internal nodes
  4. _langgraph_to_ws_event detects __interrupt__ → AWAITING_APPROVAL
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock


@pytest.mark.asyncio
async def test_agent_service_resume_updates_state_and_continues():
    """resume() must inject user_decision into checkpoint then re-invoke the graph."""
    mock_graph = MagicMock()
    mock_graph.aupdate_state = AsyncMock()
    mock_graph.ainvoke = AsyncMock()

    from pentra_agent.service import AgentService

    service = AgentService(mock_graph)
    await service.resume("eng-123", "approve")

    # aupdate_state must be called with the correct values
    mock_graph.aupdate_state.assert_called_once()
    call_kwargs = mock_graph.aupdate_state.call_args[1]
    assert call_kwargs["values"]["user_decision"] == "approve"
    assert call_kwargs["values"]["awaiting_approval"] is False

    # Graph must be re-invoked after the state update
    mock_graph.ainvoke.assert_called_once_with(
        None,
        config={"configurable": {"thread_id": "eng-123"}},
    )


def test_langgraph_to_ws_event_converts_node_start():
    """on_chain_start for a tracked node → NODE_START event."""
    from pentra_agent.service import _langgraph_to_ws_event

    event = {"event": "on_chain_start", "name": "recon", "data": {}}
    result = _langgraph_to_ws_event(event)

    assert result is not None
    assert result["type"] == "NODE_START"
    assert result["node"] == "recon"
    assert "timestamp" in result


def test_langgraph_to_ws_event_returns_none_for_unknown_nodes():
    """on_chain_start for an internal / untracked node → None (not forwarded)."""
    from pentra_agent.service import _langgraph_to_ws_event

    event = {"event": "on_chain_start", "name": "some_internal_node", "data": {}}
    result = _langgraph_to_ws_event(event)

    assert result is None


def test_langgraph_to_ws_event_detects_interrupt():
    """on_chain_end with __interrupt__ data → AWAITING_APPROVAL event."""
    from pentra_agent.service import _langgraph_to_ws_event

    class _MockInterrupt:
        value = {"type": "AWAITING_APPROVAL", "phase": "planning"}

    event = {
        "event": "on_chain_end",
        "name": "hitl_plan",
        "data": {"__interrupt__": [_MockInterrupt()]},
    }
    result = _langgraph_to_ws_event(event)

    assert result is not None
    assert result["type"] == "AWAITING_APPROVAL"
    assert result["node"] == "hitl_plan"
    assert "timestamp" in result
