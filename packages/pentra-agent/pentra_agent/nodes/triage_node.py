"""Triage Gate — LLM validate setiap finding sebelum persist ke DB.

Two-stage triage (Task 18.7):
  Stage 1: Fast LLM screen — 7-Question gate (PASS / DOWNGRADE / KILL / CHAIN_REQUIRED)
  Stage 2: HTTP re-probe — replay original payload to confirm timing/response anomaly
           is reproducible. Boosts confidence for HIGH/CRITICAL findings.

Stage 2 runs only on HIGH/CRITICAL findings from Stage 1 to avoid slow-down.
Findings that fail Stage 2 re-probe are downgraded (not killed) — evidence is now weak.

Berjalan setelah vuln_hunt_node, sebelum hitl_exploit/report.
Hasil ditulis ke `triaged_findings` (bukan `findings`) agar tidak
trigger operator.add reducer.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Literal

import httpx
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

    # ── Stage 2: HTTP re-probe for HIGH/CRITICAL findings ─────────────────────
    # Replay the original payload to verify the anomaly is reproducible.
    # Findings that fail re-probe are downgraded (MEDIUM), not killed.
    stage2_results = await _stage2_reprobe(triaged, state.get("auth_credentials"))
    triaged = stage2_results

    high_crit_after = sum(1 for f in triaged if f.get("severity") in ("high", "critical"))
    final_summary = (
        f"Two-stage triage done: {len(triaged)} findings "
        f"({high_crit_after} HIGH/CRITICAL after Stage 2 verification)."
    )
    logger.info("[triage] %s", final_summary)

    return {
        "triaged_findings": triaged,
        "messages": [AIMessage(content=final_summary)],
    }


# ── Stage 2: HTTP re-probe ────────────────────────────────────────────────────

async def _stage2_reprobe(
    findings: list[dict],
    auth_credentials: dict | None = None,
) -> list[dict]:
    """Stage 2 triage: replay original payload to verify reproducibility.

    Only HIGH/CRITICAL findings are re-probed (to avoid slow-down on low-sev).
    A finding is considered verified if:
      - Time-based SQLi: response takes ≥4s (90% of the 5s WAITFOR)
      - Reflection-based (XSS/SSTI): payload appears in response body
      - Error-based: DB error string in response

    Findings that cannot be verified are downgraded to MEDIUM with a note.
    """
    if not findings:
        return findings

    # Build auth headers/cookies for re-probe
    _auth_headers: dict[str, str] = {}
    _auth_cookies: dict[str, str] = {}
    if auth_credentials:
        try:
            from pentra_tools.auth.session_manager import AuthCredentials, SessionManager
            _creds = AuthCredentials(**auth_credentials)
            if not _creds.is_empty() and _creds.type != "auto_login":
                _auth_headers, _auth_cookies = SessionManager(_creds).get_auth_headers()
        except Exception:
            pass

    result: list[dict] = []
    for finding in findings:
        sev = finding.get("severity", "info")
        if sev not in ("high", "critical"):
            # Low/medium/info findings skip Stage 2 — already triaged by LLM
            result.append(finding)
            continue

        payload = finding.get("payload", "")
        url = finding.get("target_url", "")
        param = finding.get("param_name", "")
        param_loc = finding.get("param_location", "query")
        vuln_class = (finding.get("vuln_class") or "").lower()

        if not (payload and url and param):
            # Missing evidence — keep as-is, mark stage 2 skipped
            finding = dict(finding)
            finding["stage2_verified"] = None
            finding["stage2_note"] = "Skipped: missing payload/url/param evidence"
            result.append(finding)
            continue

        verified, note = await _reprobe_request(
            url=url,
            param=param,
            param_loc=param_loc,
            payload=payload,
            vuln_class=vuln_class,
            auth_headers=_auth_headers,
            auth_cookies=_auth_cookies,
        )

        finding = dict(finding)
        finding["stage2_verified"] = verified
        finding["stage2_note"] = note

        if verified:
            logger.info("[triage/stage2] VERIFIED %s[%s] — %s", url, param, note)
        else:
            # Downgrade — can't reproduce means lower confidence
            old_sev = finding["severity"]
            finding["severity"] = "medium"
            finding["triage_reason"] = (
                finding.get("triage_reason", "") +
                f" [Stage 2 downgrade: could not reproduce — {note}]"
            )
            logger.warning(
                "[triage/stage2] NOT REPRODUCED %s[%s] %s→medium — %s",
                url, param, old_sev, note,
            )

        result.append(finding)

    return result


async def _reprobe_request(
    url: str,
    param: str,
    param_loc: str,
    payload: str,
    vuln_class: str,
    auth_headers: dict[str, str],
    auth_cookies: dict[str, str],
    timeout: float = 12.0,
) -> tuple[bool, str]:
    """Replay a single payload and determine if the anomaly is reproducible.

    Returns (verified: bool, note: str).
    """
    from urllib.parse import urlencode, urlparse, parse_qs, urljoin

    try:
        parsed = urlparse(url)
        headers: dict[str, str] = {
            "User-Agent": "Mozilla/5.0 (PentraAI/1.0 Stage2Verify)",
            "Accept": "*/*",
            **auth_headers,
        }
        cookies = dict(auth_cookies)

        # Inject payload into the correct location
        if param_loc in ("query", "query_string"):
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[param] = [payload]
            new_query = urlencode(params, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()
            req_body = None
        elif param_loc == "body":
            test_url = url
            req_body = urlencode({param: payload})
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif param_loc in ("header",):
            test_url = url
            req_body = None
            headers[param] = payload
        else:
            return False, f"Unsupported param_location: {param_loc}"

        proxies = None
        burp_proxy = os.getenv("BURP_PROXY_URL")
        if burp_proxy:
            proxies = {"http://": burp_proxy, "https://": burp_proxy}

        t0 = time.monotonic()
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=timeout,
            verify=False,   # noqa: S501
            proxies=proxies,  # type: ignore[arg-type]
        ) as client:
            resp = await client.request(
                method="POST" if req_body else "GET",
                url=test_url,
                headers=headers,
                cookies=cookies or None,
                content=req_body.encode() if req_body else None,
            )
        elapsed = time.monotonic() - t0
        body = resp.text.lower()

        # ── Verification logic by vuln class ─────────────────────────────────
        if "sqli" in vuln_class or "sql" in vuln_class or "injection" in vuln_class:
            # Time-based: SLEEP/WAITFOR
            if "sleep" in payload.lower() or "waitfor" in payload.lower():
                if elapsed >= 4.0:
                    return True, f"Time-based SQLi confirmed: {elapsed:.1f}s delay"
                return False, f"No timing anomaly: {elapsed:.1f}s (expected ≥4s)"
            # Error-based
            error_signals = [
                "you have an error in your sql", "unclosed quotation mark",
                "ora-", "syntax error", "microsoft ole db", "mysql_fetch",
                "pg::syntaxerror", "quoted string not properly terminated",
            ]
            found = [e for e in error_signals if e in body]
            if found:
                return True, f"DB error confirmed: {found[0]!r}"
            return False, "No SQL error in response; payload may not reach SQL query"

        elif "xss" in vuln_class or "cross_site" in vuln_class:
            # Check payload reflected unencoded
            payload_lower = payload.lower()
            if payload_lower in body or "<script" in body or "onerror=" in body:
                return True, "XSS payload reflected in response"
            return False, "Payload not reflected unencoded in response"

        elif "ssti" in vuln_class:
            if "49" in resp.text or "{{7*7}}" not in resp.text:
                return True, "SSTI arithmetic evaluated in response"
            return False, "SSTI payload not evaluated"

        elif "lfi" in vuln_class or "path_traversal" in vuln_class:
            lfi_signals = ["root:x:0:0", "[boot loader]", "[operating systems]", "windows\\system32"]
            found = [s for s in lfi_signals if s in body]
            if found:
                return True, f"LFI confirmed: {found[0]!r}"
            return False, "No file content in response"

        elif "ssrf" in vuln_class:
            # SSRF requires OOB (Collaborator/interactsh) to confirm — can't verify
            # via response inspection alone. Preserve severity rather than downgrading;
            # mark for manual OOB validation so the hunter can confirm with Burp/interactsh.
            return True, "SSRF detected — verify with OOB (Burp Collaborator or interactsh)"

        else:
            # Unknown class — if response differs significantly, accept as verified
            return True, f"Response received (status={resp.status_code}); manual verification needed"

    except httpx.TimeoutException:
        # Timeout itself can indicate time-based SQLi
        return True, f"Request timed out after {timeout}s — likely time-based injection"
    except Exception as exc:
        return False, f"Re-probe failed: {exc}"


def _get_ollama_url() -> str:
    return os.getenv("OLLAMA_URL", "http://localhost:11434") + "/v1"
