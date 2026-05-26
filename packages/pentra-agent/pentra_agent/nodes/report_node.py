"""Report node — deduplicate findings, persist, generate human-readable summary.

This is the final node in the graph. It:
  1. Deduplicates findings by title + URL
  2. Persists findings via the internal API (POST /internal/findings/bulk)
  3. Returns a structured markdown report summary in the state messages
"""

from __future__ import annotations

import logging
import os

import httpx
from langchain_core.messages import AIMessage

from pentra_agent.graph.state import PentraState

log = logging.getLogger(__name__)

# Severity ordering for sorting
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


async def report_node(state: PentraState) -> dict:
    """Deduplicate findings, persist via API, return markdown summary."""
    engagement_id = state["engagement_id"]
    raw_findings: list[dict] = state.get("findings", [])

    # ── 1. Deduplicate ────────────────────────────────────────────────────────
    seen: set[str] = set()
    deduped: list[dict] = []
    for f in raw_findings:
        key = f"{f.get('title', '')}|{f.get('target_url', '')}|{f.get('vuln_class', '')}"
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # Sort by severity
    deduped.sort(key=lambda f: _SEV_ORDER.get((f.get("severity") or "info").lower(), 4))

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

    # ── 3. Build markdown summary ─────────────────────────────────────────────
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
            summary_lines += [
                f"### {i}. [{severity}] {title}",
                f"",
                f"**URL:** `{url}`",
                f"**Class:** {vuln_class}",
                f"**Impact:** {impact}" if impact else "",
                f"**Remediation:** {remediation}" if remediation else "",
                f"",
            ]

    if len(deduped) > 20:
        summary_lines.append(f"_... and {len(deduped) - 20} more findings._")

    report_text = "\n".join(line for line in summary_lines)

    return {
        "current_phase": "done",
        "phase_history": ["report"],
        "messages": [AIMessage(content=report_text)],
    }
