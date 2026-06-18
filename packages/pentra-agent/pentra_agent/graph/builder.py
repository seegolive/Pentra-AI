"""Build the Pentra AI LangGraph StateGraph.

Usage::

    from pentra_agent.graph.builder import build_pentra_graph

    # checkpointer = AsyncPostgresSaver(...)
    graph = build_pentra_graph(checkpointer)
    result = await graph.ainvoke(initial_state, config={"configurable": {"thread_id": engagement_id}})
"""

from __future__ import annotations

import logging

from langgraph.graph import END, START, StateGraph

from pentra_agent.graph.state import PentraState
from pentra_agent.nodes.hitl_nodes import (
    hitl_exploit_review,
    hitl_plan_review,
    hitl_recon_review,
)
from pentra_agent.nodes.crawler_node import crawler_node
from pentra_agent.nodes.osint_node import osint_node
from pentra_agent.nodes.plan_node import plan_node
from pentra_agent.nodes.recon_node import recon_node
from pentra_agent.nodes.report_node import report_node
from pentra_agent.nodes.triage_node import triage_node
from pentra_agent.nodes.vuln_hunt_node import vuln_hunt_node

log = logging.getLogger(__name__)


# ── Routing functions ─────────────────────────────────────────────────────────

def route_after_recon(state: PentraState) -> str:
    """After hitl_recon_review: skip to report if user skipped, else vuln_hunt."""
    if state.get("user_decision") == "skip":
        return "report"
    return "vuln_hunt"


def route_after_vuln_hunt(state: PentraState) -> str:
    """After vuln_hunt: go to hitl_exploit if high/critical findings, else report."""
    findings = state.get("findings", [])
    high_or_critical = any(
        (f.get("severity") or "").lower() in ("high", "critical")
        for f in findings
    )
    if findings and high_or_critical:
        return "hitl_exploit"
    return "report"


def route_after_triage(state: PentraState) -> str:
    """DO NOT STOP directive (Claude-BugHunter).

    - CHAIN_REQUIRED findings → loop back to vuln_hunt (max 3 rounds)
    - High/critical PASS findings → hitl_exploit
    - Otherwise → report
    """
    _MAX_ROUNDS = 3
    findings = state.get("triaged_findings", state.get("findings", []))
    hunt_rounds = state.get("hunt_rounds", 0)

    if hunt_rounds >= _MAX_ROUNDS:
        log.info(
            "[router] DO NOT STOP: max %d rounds reached — forcing exit", _MAX_ROUNDS
        )
        high_value = [
            f for f in findings
            if (f.get("severity") or "").lower() in ("critical", "high")
        ]
        return "hitl_exploit" if high_value else "report"

    chain_required = [
        f for f in findings
        if f.get("triage_verdict") == "CHAIN_REQUIRED"
    ]
    if chain_required:
        log.info(
            "[router] DO NOT STOP: %d CHAIN_REQUIRED findings (round %d/%d) — re-entering vuln_hunt",
            len(chain_required), hunt_rounds + 1, _MAX_ROUNDS,
        )
        return "vuln_hunt"

    high_value = [
        f for f in findings
        if (f.get("severity") or "").lower() in ("critical", "high")
    ]
    return "hitl_exploit" if high_value else "report"


def build_pentra_graph(checkpointer=None):
    """Construct and compile the PentraState graph.

    Args:
        checkpointer: A LangGraph checkpoint saver.  Pass ``AsyncPostgresSaver``
                      in production; pass ``MemorySaver`` for unit tests.
                      If ``None``, the graph is compiled without persistence.

    Returns:
        A compiled ``CompiledStateGraph`` ready for ``.ainvoke()`` / ``.astream()``.
    """
    graph = StateGraph(PentraState)

    # ── Nodes ─────────────────────────────────────────────────────────────
    graph.add_node("osint", osint_node)
    graph.add_node("plan", plan_node)
    graph.add_node("hitl_plan", hitl_plan_review)
    graph.add_node("recon", recon_node)
    graph.add_node("hitl_recon", hitl_recon_review)
    graph.add_node("crawler", crawler_node)
    graph.add_node("vuln_hunt", vuln_hunt_node)
    graph.add_node("triage", triage_node)
    graph.add_node("hitl_exploit", hitl_exploit_review)
    graph.add_node("report", report_node)

    # ── Edges ─────────────────────────────────────────────────────────────
    graph.add_edge(START, "osint")
    graph.add_edge("osint", "plan")
    graph.add_edge("plan", "hitl_plan")
    graph.add_edge("hitl_plan", "recon")
    graph.add_edge("recon", "hitl_recon")
    graph.add_conditional_edges(
        "hitl_recon",
        route_after_recon,
        {"vuln_hunt": "crawler", "report": "report"},
    )
    graph.add_edge("crawler", "vuln_hunt")
    graph.add_edge("vuln_hunt", "triage")
    graph.add_conditional_edges(
        "triage",
        route_after_triage,
        {"vuln_hunt": "vuln_hunt", "hitl_exploit": "hitl_exploit", "report": "report"},
    )
    graph.add_edge("hitl_exploit", "report")
    graph.add_edge("report", END)

    # ── Compile ────────────────────────────────────────────────────────────
    compile_kwargs: dict = {}
    if checkpointer is not None:
        compile_kwargs["checkpointer"] = checkpointer
    # hitl_exploit_review already calls interrupt() internally — no interrupt_before needed.

    return graph.compile(**compile_kwargs)
