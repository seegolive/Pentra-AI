"""Human-in-the-Loop nodes.

Uses langgraph interrupt() to pause the graph and wait for a user decision.

Rules:
- hitl_plan_review + hitl_recon_review:
    semi_auto  → interrupt, wait for user.
    agentic    → auto-approve, write audit log.
- hitl_exploit_review:
    interrupts by default; can auto-approve only when the engagement explicitly
    enables auto_approve_exploit_validation.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from langgraph.types import interrupt

from pentra_agent.audit import write_audit_log
from pentra_agent.graph.state import PentraState

log = logging.getLogger(__name__)


# ── Plan review ───────────────────────────────────────────────────────────────

async def hitl_plan_review(state: PentraState) -> dict:
    """Pause after plan is created for user approval before recon starts."""
    if state["mode"] == "semi_auto":
        decision = interrupt({
            "type": "AWAITING_APPROVAL",
            "phase": "planning",
            "engagement_id": state["engagement_id"],
            "timestamp": datetime.now(UTC).isoformat(),
            "data": {
                "plan": state.get("pentest_plan", ""),
                "target": state["target"]["domain"],
                "scope_summary": {
                    "in_scope": state["scope"]["in_scope"],
                    "out_of_scope": state["scope"]["out_of_scope"],
                },
                "knowledge_hints": [
                    k.get("key_insight", "")
                    for k in state.get("knowledge_context", [])[:3]
                ],
            },
        })
        return {"user_decision": decision, "awaiting_approval": False}

    # Agentic mode — auto-approve but always audit
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
    log.info("[hitl_plan_review] Agentic — auto-approved plan for %s", state["engagement_id"])
    return {"user_decision": "approve", "awaiting_approval": False}


# ── Recon review ──────────────────────────────────────────────────────────────

async def hitl_recon_review(state: PentraState) -> dict:
    """Pause after recon for user review of the discovered attack surface."""
    if state["mode"] == "semi_auto":
        decision = interrupt({
            "type": "AWAITING_APPROVAL",
            "phase": "recon",
            "engagement_id": state["engagement_id"],
            "timestamp": datetime.now(UTC).isoformat(),
            "data": {
                "subdomains_found": len(state.get("subdomains", [])),
                "ports_found": len(state.get("open_ports", [])),
                "tech_stack": state.get("tech_stack", []),
                "endpoints_found": len(state.get("endpoints", [])),
                "hypothesis": state.get("current_hypothesis", ""),
                "top_subdomains": [
                    s["host"] for s in state.get("subdomains", [])[:10]
                ],
            },
        })
        return {"user_decision": decision, "awaiting_approval": False}

    await write_audit_log(
        engagement_id=state["engagement_id"],
        actor="agent/agentic",
        action="auto_approved_recon",
        detail={
            "mode": "agentic",
            "subdomains": len(state.get("subdomains", [])),
            "ports": len(state.get("open_ports", [])),
        },
    )
    log.info("[hitl_recon_review] Agentic — auto-approved recon for %s", state["engagement_id"])
    return {"user_decision": "approve", "awaiting_approval": False}


# ── Exploit review — ALWAYS interrupts ────────────────────────────────────────

async def hitl_exploit_review(state: PentraState) -> dict:
    """Safety gate before exploit validation.

    Interrupts by default because exploit validation can be destructive.
    Operators may explicitly enable auto_approve_exploit_validation when they
    want one approval at the beginning and no later exploit-validation pause.
    """
    if state.get("auto_approve_exploit_validation", False):
        await write_audit_log(
            engagement_id=state["engagement_id"],
            actor="agent/auto-approve",
            action="auto_approved_exploit_validation",
            detail={
                "reason": "Engagement configured to bypass exploit-validation approval",
                "mode": state.get("mode"),
                "findings_to_validate": len(state.get("findings", [])),
                "high_or_critical": sum(
                    1
                    for f in state.get("findings", [])
                    if (f.get("severity") or "").lower() in ("high", "critical")
                ),
            },
        )
        log.info(
            "[hitl_exploit_review] Auto-approved exploit validation for %s",
            state["engagement_id"],
        )
        return {"user_decision": "approve", "awaiting_approval": False}

    decision = interrupt({
        "type": "AWAITING_APPROVAL",
        "phase": "exploit_validation",
        "engagement_id": state["engagement_id"],
        "timestamp": datetime.now(UTC).isoformat(),
        "data": {
            "findings_to_validate": len(state.get("findings", [])),
            "findings_preview": [
                {
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                    "url": f.get("target_url"),
                }
                for f in state.get("findings", [])[:5]
            ],
            "warning": (
                "Exploit validation will send active payloads to the target. "
                "Confirm all targets are in scope before approving."
            ),
        },
    })
    return {"user_decision": decision, "awaiting_approval": False}
