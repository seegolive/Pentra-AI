"""Report node — deduplicate findings, persist, generate human-readable summary.

This is the final node in the graph. It:
  1. Deduplicates findings by title + URL
  2. Persists findings via the internal API (POST /internal/findings/bulk)
  3. Saves an EngagementLearning record for future plan_node context
  4. Returns a structured markdown report summary in the state messages
"""

from __future__ import annotations

import json
import logging
import os

import httpx
from langchain_core.messages import AIMessage

from pentra_agent.graph.state import PentraState
from pentra_agent.llm.client import LLMClient
from pentra_shared.types import normalize_severity

log = logging.getLogger(__name__)

# Severity ordering for sorting (lower value = higher severity)
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


async def report_node(state: PentraState) -> dict:
    """Deduplicate findings, persist via API, return markdown summary."""
    engagement_id = state["engagement_id"]
    # Use triaged_findings when available (triage_node ran), else fall back to raw findings
    raw_findings: list[dict] = state.get("triaged_findings") or state.get("findings", [])

    # ── 1. Deduplicate — keep highest severity among duplicates ──────────────
    # Normalize all severity values first, then deduplicate by title|url|vuln_class
    # keeping the finding with the highest (lowest _SEV_ORDER) severity so that
    # a CRITICAL from llm_burp_active beats a HIGH from nuclei for the same vuln.
    seen: dict[str, dict] = {}
    for f in raw_findings:
        # Normalize in-place so downstream code never sees raw LLM casing
        f["severity"] = normalize_severity(f.get("severity"))
        key = f"{f.get('title', '')}|{f.get('target_url', '')}|{f.get('vuln_class', '')}"
        if key not in seen:
            seen[key] = f
        else:
            # Prefer the finding with the higher severity
            existing_order = _SEV_ORDER.get(seen[key]["severity"], 4)
            new_order = _SEV_ORDER.get(f["severity"], 4)
            if new_order < existing_order:
                seen[key] = f
    deduped = list(seen.values())

    # Sort by severity
    deduped.sort(key=lambda f: _SEV_ORDER.get(f.get("severity") or "info", 4))

    # ── 1b. CVSS enrichment ───────────────────────────────────────────────────
    try:
        from pentra_shared.utils.cvss import calculate_cvss

        for f in deduped:
            vuln_class = f.get("vuln_class") or f.get("title") or ""
            # Infer auth_required from request headers (cookie / authorization)
            request_raw = (f.get("request") or f.get("request_raw") or "").lower()
            auth_required = "cookie:" in request_raw or "authorization:" in request_raw
            score, vector = calculate_cvss(vuln_class, auth_required=auth_required)
            # Only override if the finding doesn't already have a valid score
            if f.get("cvss_score") is None:
                f["cvss_score"] = score
            f["cvss_vector"] = vector
        log.info("[report_node] CVSS enrichment applied to %d findings", len(deduped))
    except Exception as exc:
        log.warning("[report_node] CVSS enrichment failed (non-fatal): %s", exc)

    # ── 1c. Vulnerability correlation (attack chains) ─────────────────────────
    try:
        llm = LLMClient(
            base_url=os.getenv("OLLAMA_URL", "http://localhost:11434"),
            model=state.get("llm_model", "qwen2.5:32b"),
        )
        deduped = await correlate_findings(
            findings=deduped,
            llm=llm,
            knowledge_context=state.get("knowledge_context", []),
        )
    except Exception as exc:
        log.warning("[report_node] correlate_findings failed (non-fatal): %s", exc)

    # ── 2. Persist via internal API ───────────────────────────────────────────
    persisted_count = 0
    if deduped:
        api_url = os.getenv("INTERNAL_API_URL", "http://localhost:8000")
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    f"{api_url}/internal/findings/bulk",
                    json={
                        "engagement_id": engagement_id,
                        "findings": deduped,
                    },
                    headers={"X-Internal-Token": os.getenv("INTERNAL_API_TOKEN", "")},
                )
                if resp.status_code in (200, 201):
                    persisted_count = resp.json().get("created", len(deduped))
                    log.info("[report_node] Persisted %d findings for %s", persisted_count, engagement_id)
                else:
                    log.warning(
                        "[report_node] Persist returned %d: %s",
                        resp.status_code, resp.text[:200],
                    )
        except Exception as exc:
            log.warning("[report_node] Failed to persist findings: %s", exc)

    # ── 3. Save engagement learning ───────────────────────────────────────────
    await _save_learning(state, deduped)

    # ── 4. Build markdown summary ─────────────────────────────────────────────
    domain = state["target"]["domain"]
    counts = {sev: 0 for sev in _SEV_ORDER}
    for f in deduped:
        sev = (f.get("severity") or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1

    summary_lines = [
        f"# Pentra AI — Engagement Report",
        f"",
        f"**Target:** `{domain}`",
        f"**Scope:** {', '.join(state['scope']['in_scope'])}",
        f"**Engagement ID:** `{engagement_id}`",
        f"",
        f"## Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
        *[f"| {sev.capitalize()} | {counts[sev]} |" for sev in _SEV_ORDER],
        f"",
        f"**Total unique findings:** {len(deduped)}",
        f"",
    ]

    if deduped:
        summary_lines += ["## Findings", ""]
        for i, f in enumerate(deduped[:20], 1):
            severity = (f.get("severity") or "info").upper()
            title = f.get("title", "Unknown")
            url = f.get("target_url", "")
            vuln_class = f.get("vuln_class", "")
            impact = f.get("impact", "")
            remediation = f.get("remediation", "")
            cvss_score = f.get("cvss_score")
            cvss_vector = f.get("cvss_vector", "")
            chains = f.get("chains", [])
            summary_lines += [
                f"### {i}. [{severity}] {title}",
                f"",
                f"**URL:** `{url}`",
                f"**Class:** {vuln_class}",
                f"**CVSS:** {cvss_score:.1f} `{cvss_vector}`" if cvss_score is not None and cvss_vector else (f"**CVSS:** {cvss_score:.1f}" if cvss_score is not None else ""),
                f"**Impact:** {impact}" if impact else "",
                f"**Remediation:** {remediation}" if remediation else "",
            ]
            for ch in chains:
                summary_lines.append(
                    f"⛓️ **Chain: {ch['name']}** ({ch.get('upgraded_severity', '').upper()}) — {ch.get('business_impact', '')}"
                )
            summary_lines.append("")

    if len(deduped) > 20:
        summary_lines.append(f"_... and {len(deduped) - 20} more findings._")

    report_text = "\n".join(line for line in summary_lines)

    return {
        "current_phase": "done",
        "phase_history": ["report"],
        "messages": [AIMessage(content=report_text)],
    }


async def correlate_findings(
    findings: list[dict],
    llm: "LLMClient",
    knowledge_context: list[dict],
) -> list[dict]:
    """Analyse findings for potential attack chains and annotate with chain_info.

    Only runs when >= 2 findings are present. Chains are attached to every
    finding that participates in one; the finding gains a ``chains`` list field.
    Non-fatal: returns the original findings unchanged on any error.
    """
    if len(findings) < 2:
        return findings

    findings_summary = [
        {
            "idx": i,
            "title": f.get("title", "Finding"),
            "vuln_class": f.get("vuln_class", "UNKNOWN"),
            "url": f.get("target_url", ""),
            "severity": f.get("severity", "medium"),
        }
        for i, f in enumerate(findings)
    ]

    chain_patterns = [
        k.get("chained_with", [])
        for k in knowledge_context
        if k.get("chained_with")
    ][:5]

    chain_prompt = f"""You are analyzing penetration testing findings to identify attack chains.

Findings discovered:
{json.dumps(findings_summary, indent=2)}

Known chain patterns from similar engagements:
{json.dumps(chain_patterns, indent=2)}

Identify all possible attack chains. For each chain:
- List the finding indexes that form the chain
- Describe the combined attack scenario
- State the upgraded severity
- Explain the business impact

Return JSON array:
[
  {{
    "chain_indexes": [0, 2],
    "chain_name": "SSRF to Internal RCE",
    "scenario": "SSRF allows access to internal service, combined with exposed Redis...",
    "upgraded_severity": "critical",
    "business_impact": "Full server compromise possible"
  }}
]

Return empty array [] if no meaningful chains exist.
Only include chains where the combination creates significantly higher impact."""

    try:
        chains = await llm.complete_json(
            system="You are a senior penetration tester specializing in vulnerability chaining.",
            user=chain_prompt,
        )
    except Exception as exc:
        log.warning("[report_node] correlate_findings LLM call failed: %s", exc)
        return findings

    if not isinstance(chains, list) or not chains:
        return findings

    # Attach chain info to each participating finding
    for chain in chains:
        chain_indexes = chain.get("chain_indexes", [])
        for idx in chain_indexes:
            if 0 <= idx < len(findings):
                if "chains" not in findings[idx]:
                    findings[idx]["chains"] = []
                findings[idx]["chains"].append({
                    "name": chain.get("chain_name", "Attack Chain"),
                    "scenario": chain.get("scenario", ""),
                    "upgraded_severity": chain.get("upgraded_severity"),
                    "business_impact": chain.get("business_impact", ""),
                    "chain_size": len(chain_indexes),
                })

    chain_names = [c.get("chain_name") for c in chains]
    log.info("[report_node] correlate_findings: %d chains found: %s", len(chains), chain_names)
    return findings


async def _save_learning(state: PentraState, findings: list[dict]) -> None:
    """Persist an EngagementLearning record — best-effort, never raises."""
    try:
        from app.db.base import _get_session_factory
        from app.services.learning import save_engagement_learning

        async with _get_session_factory()() as db:
            await save_engagement_learning(
                engagement_id=state["engagement_id"],
                tech_stack=list(set(state.get("tech_stack", []))),
                findings=findings,
                db=db,
            )
    except Exception as exc:
        log.warning("[report_node] save_engagement_learning failed: %s", exc)
