"""Triage Gate — LLM validate setiap finding sebelum persist ke DB.

7-Question gate (dari BugHunter triage-validation skill):
  1. Reproducible  2. In-scope  3. Real impact  4. Novel
  5. Chainable     6. Evidenced  7. Not duplicate

Output per finding: PASS / DOWNGRADE / KILL / CHAIN_REQUIRED
Findings yang KILL di-drop; DOWNGRADE severity diturunkan.

Berjalan setelah vuln_hunt_node, sebelum hitl_exploit/report.
Hasil ditulis ke `triaged_findings` (bukan `findings`) agar tidak
trigger operator.add reducer.
"""

from __future__ import annotations

import logging
import os

from langchain_core.messages import AIMessage

from pentra_agent.graph.state import PentraState
from pentra_agent.llm.client import LLMClient

logger = logging.getLogger(__name__)

TRIAGE_PROMPT = """You are a senior bug bounty validator applying strict triage criteria.

Evaluate this security finding using the 7-Question Gate:

1. REPRODUCIBLE: Can this be reproduced with the provided steps?
2. IN_SCOPE: Is the vulnerable URL/parameter within the engagement scope?
3. REAL_IMPACT: Is the impact real (not theoretical)? Can it affect real users/data?
4. NOVEL: Is this genuinely new? Not just a version disclosure or best-practice recommendation?
5. CHAINABLE: If low severity, can it chain with other findings to increase impact?
6. EVIDENCED: Is there request/response evidence that proves the finding?
7. NOT_DUPLICATE: Is this different from other findings in this engagement?

Finding to evaluate:
Title: {title}
Vuln Class: {vuln_class}
Severity: {severity}
URL: {target_url}
Description: {description}
Request evidence: {request_evidence}
Response evidence: {response_evidence}

Other findings in this engagement: {other_titles}

Return JSON:
{{
  "verdict": "PASS" | "DOWNGRADE" | "KILL" | "CHAIN_REQUIRED",
  "final_severity": "critical|high|medium|low|info",
  "reason": "one sentence explanation",
  "chain_suggestion": "if CHAIN_REQUIRED: what to chain with",
  "downgrade_reason": "if DOWNGRADE: why severity is lower"
}}"""


async def triage_node(state: PentraState) -> dict:
    """Triage gate — validate setiap finding, write ke `triaged_findings`."""
    findings = state.get("findings", [])
    if not findings:
        return {
            "triaged_findings": [],
            "messages": [AIMessage(content="Triage complete: 0 findings to evaluate.")],
        }

    llm = LLMClient(
        base_url=_get_ollama_url(),
        model=state["llm_model"],
    )

    other_titles = [f.get("title", "") for f in findings]
    triaged: list[dict] = []
    killed = 0
    downgraded = 0

    for finding in findings:
        try:
            result = await llm.complete_json(
                system="You are a strict bug bounty validator. Return only valid JSON.",
                user=TRIAGE_PROMPT.format(
                    title=finding.get("title", ""),
                    vuln_class=finding.get("vuln_class", ""),
                    severity=finding.get("severity", ""),
                    target_url=finding.get("target_url", ""),
                    description=str(finding.get("description", ""))[:500],
                    request_evidence=str(finding.get("request_raw", ""))[:300],
                    response_evidence=str(finding.get("response_raw", ""))[:300],
                    other_titles=str(other_titles[:10]),
                ),
            )

            verdict = result.get("verdict", "PASS")
            finding = dict(finding)  # shallow copy to avoid mutating state list
            finding["triage_verdict"] = verdict
            finding["triage_reason"] = result.get("reason", "")

            if verdict == "KILL":
                killed += 1
                logger.info(
                    "[triage] KILL: %s — %s",
                    finding.get("title"),
                    result.get("reason"),
                )
                continue  # drop — tidak masuk triaged list

            if verdict == "DOWNGRADE":
                downgraded += 1
                old_sev = finding.get("severity")
                finding["severity"] = result.get("final_severity", old_sev)
                logger.info(
                    "[triage] DOWNGRADE: %s %s→%s — %s",
                    finding.get("title"),
                    old_sev,
                    finding["severity"],
                    result.get("reason"),
                )

            if verdict == "CHAIN_REQUIRED":
                finding["chain_suggestion"] = result.get("chain_suggestion", "")
                logger.info(
                    "[triage] CHAIN_REQUIRED: %s — %s",
                    finding.get("title"),
                    result.get("chain_suggestion"),
                )

            triaged.append(finding)

        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "[triage] LLM triage failed for %s: %s — keeping finding",
                finding.get("title"),
                exc,
            )
            triaged.append(dict(finding))

    summary = (
        f"Triage complete: {len(triaged)} passed, "
        f"{killed} killed, {downgraded} downgraded."
    )
    logger.info("[triage] %s", summary)

    return {
        "triaged_findings": triaged,
        "messages": [AIMessage(content=summary)],
    }


def _get_ollama_url() -> str:
    return os.getenv("OLLAMA_URL", "http://localhost:11434") + "/v1"
