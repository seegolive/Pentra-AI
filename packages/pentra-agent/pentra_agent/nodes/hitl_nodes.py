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


# ── HITL analysis helper ──────────────────────────────────────────────────────

def _build_hitl_analysis(
    findings: list[dict],
    waf_info: dict | None,
    tech_stack: list[str],
) -> dict:
    """Compute structured reasoning summary from state data — no LLM call.

    Returns a dict with:
      - high_confidence_findings: list of high/critical findings (title, severity, url)
      - severity_counts: dict[str, int] — counts per severity level
      - risk_flags: list[str] — human-readable risk notes
      - recommendation: str — one-line suggested action
    """
    import collections

    sev_counts: dict[str, int] = collections.Counter(
        (f.get("severity") or "unknown").lower() for f in findings
    )
    high_conf = [
        {
            "title": f.get("title", ""),
            "severity": f.get("severity", ""),
            "url": f.get("target_url", ""),
            "vuln_class": f.get("vuln_class", ""),
        }
        for f in findings
        if (f.get("severity") or "").lower() in ("high", "critical")
    ]

    risk_flags: list[str] = []
    if waf_info and waf_info.get("waf_type"):
        blocking_note = " (actively blocking)" if waf_info.get("is_blocking") else " (detected, not blocking)"
        risk_flags.append(f"WAF detected: {waf_info['waf_type']}{blocking_note}")
    if sev_counts.get("critical", 0) > 0:
        risk_flags.append(f"{sev_counts['critical']} CRITICAL finding(s) — immediate action recommended")
    if tech_stack:
        risk_flags.append(f"Tech stack: {', '.join(tech_stack[:5])}")

    # Build recommendation
    n_high_crit = sev_counts.get("critical", 0) + sev_counts.get("high", 0)
    n_low_med = sev_counts.get("medium", 0) + sev_counts.get("low", 0)
    if n_high_crit == 0 and len(findings) == 0:
        recommendation = "No findings to validate. Safe to approve and proceed to report."
    elif n_high_crit > 0:
        labels = ", ".join(f["vuln_class"] for f in high_conf[:3] if f["vuln_class"])
        recommendation = (
            f"Approve validation of {n_high_crit} high/critical finding(s)"
            + (f" ({labels})" if labels else "")
            + ("." if n_low_med == 0 else f"; consider skipping {n_low_med} medium/low finding(s) to reduce noise.")
        )
    else:
        recommendation = f"Approve validation of {n_low_med} medium/low finding(s) — no high/critical detected."

    return {
        "high_confidence_findings": high_conf,
        "severity_counts": dict(sev_counts),
        "risk_flags": risk_flags,
        "recommendation": recommendation,
    }


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

    _analysis = _build_hitl_analysis(
        state.get("findings", []),
        waf_info=state.get("waf_info"),
        tech_stack=state.get("tech_stack", []),
    )
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
            "llm_analysis": _analysis,
        },
    })
    return {"user_decision": decision, "awaiting_approval": False}
