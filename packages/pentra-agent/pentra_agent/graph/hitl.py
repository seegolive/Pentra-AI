"""HITL (Human-in-the-Loop) nodes for the Pentra AI agent graph.

These nodes are the only places where ``interrupt()`` is called.

Rules:
- ``hitl_plan_node`` and ``hitl_recon_node``:
    semi_auto  → interrupt and wait for user decision.
    agentic    → auto-approve and write audit log.
- ``hitl_exploit_node``:
    ALWAYS interrupts — destructive action safety gate, not bypassed by any mode.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from langgraph.types import interrupt

from pentra_agent.audit import write_audit_log
from pentra_agent.graph.state import PentraState

log = logging.getLogger(__name__)


# ── Plan review ───────────────────────────────────────────────────────────────

async def hitl_plan_node(state: PentraState) -> dict:
    """Pause for user approval of the pentest plan.

    semi_auto → interrupt (user must approve before recon starts).
    agentic   → auto-approve, write audit log, continue immediately.
    """
    if state["mode"] == "semi_auto":
        interrupt({
            "type": "AWAITING_APPROVAL",
            "phase": "planning",
            "engagement_id": state["engagement_id"],
            "timestamp": datetime.now(UTC).isoformat(),
            "data": {
                "summary": state.get("pentest_plan", ""),
                "proposed_next": "Begin reconnaissance phase",
            },
        })
    else:
        # Agentic mode — auto-approve, but always audit
        await write_audit_log(
            engagement_id=state["engagement_id"],
            actor="agent/agentic",
            action="auto_approved_plan",
            detail={
                "mode": "agentic",
                "reason": "Agentic mode — HITL skipped for planning phase",
                "plan_preview": (state.get("pentest_plan") or "")[:500],
            },
        )
        log.info(
            "[hitl_plan_node] Agentic mode — auto-approved plan for %s",
            state["engagement_id"],
        )

    return {"awaiting_approval": False, "user_decision": None}


# ── Recon review ──────────────────────────────────────────────────────────────

async def hitl_recon_node(state: PentraState) -> dict:
    """Pause for user review after recon completes.

    semi_auto → interrupt (user reviews findings before vuln hunt starts).
    agentic   → auto-approve, write audit log, continue immediately.
    """
    if state["mode"] == "semi_auto":
        interrupt({
            "type": "AWAITING_APPROVAL",
            "phase": "recon",
            "engagement_id": state["engagement_id"],
            "timestamp": datetime.now(UTC).isoformat(),
            "data": {
                "summary": state.get("current_hypothesis", ""),
                "subdomains": state.get("subdomains", []),
                "tech_stack": state.get("tech_stack", []),
                "open_ports": state.get("open_ports", []),
                "knowledge_hints": [
                    k.get("key_insight", "")
                    for k in state.get("knowledge_context", [])[:3]
                ],
                "proposed_next": "Begin vulnerability hunting phase",
            },
        })
    else:
        await write_audit_log(
            engagement_id=state["engagement_id"],
            actor="agent/agentic",
            action="auto_approved_recon",
            detail={
                "mode": "agentic",
                "reason": "Agentic mode — HITL skipped for recon review",
                "subdomains_found": len(state.get("subdomains", [])),
                "tech_stack": state.get("tech_stack", []),
            },
        )
        log.info(
            "[hitl_recon_node] Agentic mode — auto-approved recon for %s",
            state["engagement_id"],
        )

    return {"awaiting_approval": False, "user_decision": None}


# ── Exploit review — ALWAYS interrupts ───────────────────────────────────────

async def hitl_exploit_node(state: PentraState) -> dict:
    """Safety gate before exploit validation — ALWAYS interrupts regardless of mode.

    This node is the hard safety boundary. Destructive payloads must never be
    sent without explicit human approval, even in agentic mode.
    """
    interrupt({
        "type": "AWAITING_APPROVAL",
        "phase": "exploit_val",
        "engagement_id": state["engagement_id"],
        "timestamp": datetime.now(UTC).isoformat(),
        "data": {
            "summary": f"{len(state.get('findings', []))} finding(s) require validation.",
            "findings": state.get("findings", []),
            "proposed_next": "Validate findings with targeted proof-of-concept tests",
            "warning": (
                "⚠️  This phase sends active exploit payloads to the target. "
                "Always requires human approval — not bypassed by agentic mode."
            ),
        },
    })
    await write_audit_log(
        engagement_id=state["engagement_id"],
        actor="agent/hitl",
        action="interrupted_exploit_review",
        detail={
            "mode": state.get("mode", "unknown"),
            "findings_count": len(state.get("findings", [])),
        },
    )
    return {"awaiting_approval": False, "current_phase": "exploit_val", "user_decision": None}
