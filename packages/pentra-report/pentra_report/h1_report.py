"""H1-Ready Executive Summary Report — Task 19.5 (Sprint 19).

Generates professional, HackerOne-ready bug bounty reports using LLM
to write the executive summary section. The rest is template-driven.

Usage:
    from pentra_report.h1_report import generate_h1_report

    report_md = await generate_h1_report(
        engagement={"target_domain": "target.com", "id": "...", "duration_minutes": 47},
        findings=confirmed_findings,
        llm=llm_client,
    )
"""

from __future__ import annotations

import logging
from datetime import datetime, UTC

log = logging.getLogger(__name__)

# Severity order for sorting
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

EXECUTIVE_SUMMARY_PROMPT = """You are writing a professional security assessment report for HackerOne submission.

Engagement details:
- Target: {target}
- Duration: {duration} minutes
- Findings: {findings_count} total ({critical} critical, {high} high, {medium} medium, {low} low)

Top findings:
{top_findings}

Write a concise executive summary (3-4 paragraphs):
1. Scope and methodology (tools used: Burp Suite Pro, custom LLM agent, nuclei)
2. Key findings and their SPECIFIC business impact (name the exact vulnerabilities found)
3. Immediate remediation priorities
4. Overall security posture assessment

Rules:
- Be specific — name actual vulnerability classes and endpoints
- Do NOT use generic boilerplate like "security is important"
- Write as a professional security researcher
- No markdown headers — plain paragraphs only"""


async def generate_h1_report(
    engagement: dict,
    findings: list[dict],
    llm,  # LLMClient instance
) -> str:
    """Generate H1-ready Markdown report with LLM executive summary.

    Args:
        engagement: Dict with target_domain, id, duration_minutes, etc.
        findings:   List of confirmed finding dicts from vuln_hunt_node.
        llm:        LLMClient instance for executive summary generation.

    Returns:
        Full Markdown report string.
    """
    # Sort findings by severity
    sorted_findings = sorted(
        findings,
        key=lambda f: _SEVERITY_ORDER.get(str(f.get("severity", "info")).lower(), 4),
    )

    critical = [f for f in findings if str(f.get("severity", "")).lower() == "critical"]
    high = [f for f in findings if str(f.get("severity", "")).lower() == "high"]
    medium = [f for f in findings if str(f.get("severity", "")).lower() == "medium"]
    low = [f for f in findings if str(f.get("severity", "")).lower() == "low"]

    top_findings_text = "\n".join(
        f"- [{str(f.get('severity', '?')).upper()}] {f.get('title', '?')} "
        f"({f.get('vuln_class', '?')}) at {f.get('target_url', '?')}"
        for f in sorted_findings[:5]
    )

    # Generate executive summary via LLM
    exec_summary = ""
    try:
        exec_summary = await llm.complete(
            system="You are a professional security researcher writing HackerOne reports. Be specific and technical.",
            user=EXECUTIVE_SUMMARY_PROMPT.format(
                target=engagement.get("target_domain", "unknown"),
                duration=engagement.get("duration_minutes", "N/A"),
                findings_count=len(findings),
                critical=len(critical),
                high=len(high),
                medium=len(medium),
                low=len(low),
                top_findings=top_findings_text or "No significant findings.",
            ),
        )
        log.info("[h1_report] Executive summary generated: %d chars", len(exec_summary))
    except Exception as exc:
        log.warning("[h1_report] LLM summary failed (using fallback): %s", exc)
        exec_summary = (
            f"Security assessment of {engagement.get('target_domain', 'target')} identified "
            f"{len(findings)} vulnerability/vulnerabilities "
            f"({len(critical)} critical, {len(high)} high, {len(medium)} medium). "
            "See findings section for details."
        )

    # Build report sections
    now = datetime.now(UTC).strftime("%Y-%m-%d")
    target = engagement.get("target_domain", "target")
    eng_id = engagement.get("id", "")[:8]

    sections = [
        f"# Security Assessment Report — {target}",
        f"\n**Date:** {now}  ",
        f"**Engagement ID:** {eng_id}  ",
        f"**Severity Summary:** {len(critical)}C · {len(high)}H · {len(medium)}M · {len(low)}L  ",
        f"**Total Findings:** {len(findings)}",
        "\n---\n",
        "## Executive Summary",
        "\n" + exec_summary,
        "\n---\n",
        "## Findings",
    ]

    for i, finding in enumerate(sorted_findings, 1):
        sev = str(finding.get("severity", "info")).upper()
        title = finding.get("title", "Untitled Finding")
        vuln_class = finding.get("vuln_class", "")
        url = finding.get("target_url", "")
        description = finding.get("description", "")
        impact = finding.get("impact", "")
        remediation = finding.get("remediation", "Implement proper input validation.")
        request_raw = finding.get("request_raw", finding.get("request", ""))
        response_raw = finding.get("response_raw", finding.get("response", ""))
        cvss = finding.get("cvss_score", "N/A")
        payload = finding.get("payload", "")

        section_parts = [
            f"\n### {i}. {title}",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| **Severity** | {sev} |",
            f"| **CVSS Score** | {cvss} |",
            f"| **Vulnerability Class** | {vuln_class} |",
            f"| **Endpoint** | `{url}` |",
        ]

        if payload:
            section_parts.append(f"| **Confirmed Payload** | `{payload[:100]}` |")

        section_parts += [
            "",
            "**Description:**",
            description,
        ]

        if impact:
            section_parts += ["", "**Impact:**", impact]

        if request_raw:
            # Truncate long requests
            req_snippet = str(request_raw)[:600]
            section_parts += [
                "",
                "**Request (evidence):**",
                "```http",
                req_snippet,
                "```",
            ]

        if response_raw:
            resp_snippet = str(response_raw)[:400]
            section_parts += [
                "",
                "**Response (evidence):**",
                "```",
                resp_snippet,
                "```",
            ]

        section_parts += [
            "",
            "**Remediation:**",
            remediation,
        ]

        sections.append("\n".join(section_parts))

    # Appendix
    sections += [
        "\n---\n",
        "## Appendix — Methodology",
        "",
        "**Tools used:**",
        "- Pentra AI (custom LLM-driven agent) — autonomous vulnerability hunting",
        "- Burp Suite Pro — proxy, active scanner, Collaborator OOB",
        "- Nuclei — template-based vulnerability scanning",
        "- subfinder — subdomain enumeration",
        "- Custom payload library — ExploitArsenal (MSSQL, MySQL, XSS, Path Traversal)",
        "",
        "**Testing approach:**",
        "1. Passive recon — subdomain enumeration, tech stack detection, WAF profiling",
        "2. Crawl via Burp proxy — capture all traffic for LLM analysis",
        "3. LLM injection candidate identification — ReAct reasoning per endpoint",
        "4. Active payload testing — ExploitArsenal + LLM-crafted payloads",
        "5. Confirmation — timing anomaly, error-based, and reflection verification",
        "6. Two-stage triage — HTTP re-probe for HIGH/CRITICAL findings",
    ]

    return "\n".join(sections)
