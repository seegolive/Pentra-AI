"""Subscan — Task 18.12 (reNgine pattern).

Focused re-scan on a specific subset of endpoints/params from a previous scan.
Used to:
  1. Deepen testing on endpoints that had anomalies but no confirmed findings
  2. Re-test after a WAF rule change or application patch
  3. Test a specific newly-discovered endpoint without re-running full scan

Subscan injects targeted endpoints directly into the vuln_hunt_node state,
bypassing the full recon phase. Useful for fast iterative testing.

Usage (in live_scan.py):
    uv run python live_scan.py --domain target.com --subscan-url "https://target.com/api/v2/users?id=1"
    uv run python live_scan.py --domain target.com --subscan-json /tmp/prev_scan.json

Usage (programmatic):
    from pentra_agent.subscan import SubscanSpec, build_subscan_state
    spec = SubscanSpec(
        domain="target.com",
        focus_endpoints=[{"url": "...", "method": "GET", "params": ["id"]}],
        preset="full",
    )
    state = build_subscan_state(spec, auth_credentials=creds)
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urlparse, parse_qs

log = logging.getLogger(__name__)

PresetName = Literal["full", "fast", "stealth", "quick", "authenticated"]


@dataclass
class SubscanSpec:
    """Specification for a focused sub-scan.

    Attributes:
        domain:              Target domain (must match scope).
        focus_endpoints:     Specific endpoints to test. Each is a dict with
                             url, method, and optionally params list.
        focus_params:        If provided, only test these parameter names
                             (useful to re-test one specific param).
        preset:              Scan engine preset to use (default: "full").
        extra_test_types:    Additional vuln types to test on every endpoint
                             (e.g. ["ssrf", "xxe"] to add OOB testing).
        reason:              Human note explaining why this subscan was triggered.
    """
    domain: str
    focus_endpoints: list[dict] = field(default_factory=list)
    focus_params: list[str] = field(default_factory=list)
    preset: PresetName = "full"
    extra_test_types: list[str] = field(default_factory=list)
    reason: str = ""


def parse_subscan_url(url: str) -> dict:
    """Parse a single URL into an endpoint dict for subscan injection.

    Extracts URL query params and assigns heuristic test_types.

    Returns:
        {url, method, params: [str], test_types: [str]}
    """
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query, keep_blank_values=True).keys())

    # Heuristic test_type assignment
    test_types: list[str] = []
    for param in params:
        low = param.lower()
        if any(k in low for k in ("id", "user", "uid", "cat", "pid")):
            test_types += ["sqli", "idor"]
        elif any(k in low for k in ("url", "redirect", "next", "ref")):
            test_types += ["open_redirect", "ssrf"]
        elif any(k in low for k in ("file", "path", "dir", "page", "load")):
            test_types += ["lfi", "path_traversal"]
        elif any(k in low for k in ("q", "search", "query", "name", "text")):
            test_types += ["xss", "sqli"]
        else:
            test_types += ["sqli", "xss"]

    return {
        "url": url,
        "method": "GET",
        "params": params,
        "test_types": list(set(test_types)) or ["sqli", "xss"],
    }


def build_subscan_state(
    spec: SubscanSpec,
    auth_credentials: dict | None = None,
    base_state: dict | None = None,
) -> dict:
    """Build an initial state dict for vuln_hunt_node, skipping recon.

    Injects focus_endpoints directly so vuln_hunt runs on a targeted subset.

    Args:
        spec:            SubscanSpec with endpoints to test.
        auth_credentials: Optional auth dict (from Task 18.6).
        base_state:      Optionally merge with a previous scan state (e.g. for
                         tech_stack, knowledge_context from earlier run).

    Returns:
        State dict ready to pass directly to vuln_hunt_node.
    """
    import uuid

    # Convert focus_endpoints into Endpoint TypedDict format
    endpoints: list[dict] = []
    for ep in spec.focus_endpoints:
        url = ep.get("url", "")
        if not url:
            continue
        parsed_ep = parse_subscan_url(url)
        # Merge extra_test_types from spec
        test_types = list(set(parsed_ep["test_types"] + spec.extra_test_types))
        # Filter to focus_params if provided
        params = ep.get("params", parsed_ep["params"])
        if spec.focus_params:
            params = [p for p in params if p in spec.focus_params]
        endpoints.append({
            "url": url,
            "method": ep.get("method", "GET"),
            "params": params,
            "source": "subscan",
            "test_types": test_types,
        })

    # Build state
    state: dict = {
        "engagement_id": str(uuid.uuid4()),
        "target": {"domain": spec.domain},
        "scope": {"in_scope": [spec.domain], "out_of_scope": []},
        "mode": "agentic",
        "current_phase": "vuln_hunt",  # skip recon
        "phase_history": ["recon"],    # mark recon as done
        "subdomains": [{"host": spec.domain, "ip": None, "source": "subscan", "is_alive": True, "status_code": 200, "tech_stack": []}],
        "endpoints": endpoints,
        "tech_stack": [],
        "findings": [],
        "triaged_findings": [],
        "messages": [],
        "awaiting_approval": False,
        "knowledge_context": [],
        "tool_outputs": [],
        "hunt_rounds": 0,
        "llm_model": "qwen2.5:32b",
        "pentest_plan": (
            f"Subscan of {spec.domain}. Reason: {spec.reason or 'targeted re-test'}. "
            f"Focus: {len(endpoints)} specific endpoint(s). "
            "Test thoroughly — this is a focused engagement, not a quick pass."
        ),
        "auth_credentials": auth_credentials,
        "rate_limit_info": {"safe_rps": 5, "delay_ms": 200, "is_limited": False, "notes": []},
        "waf_info": {"waf_type": "unknown", "is_blocking": False, "bypass_strategies": [], "safe_rps": 5},
        "osint_results": {},
    }

    # Merge optional fields from a base state (e.g. tech_stack, knowledge_context)
    if base_state:
        for key in ("tech_stack", "knowledge_context", "waf_info", "rate_limit_info"):
            if base_state.get(key):
                state[key] = base_state[key]

    log.info(
        "[subscan] Built subscan state: %d endpoints, preset=%s, auth=%s, reason=%r",
        len(endpoints), spec.preset, bool(auth_credentials), spec.reason,
    )
    return state


def load_subscan_from_report(report_path: str, min_severity: str = "medium") -> list[dict]:
    """Load focus endpoints from a previous scan JSON report.

    Extracts endpoints from findings at or above min_severity.
    Useful for 'deepen testing on everything HIGH+ from last scan'.

    Args:
        report_path:   Path to the JSON report file from a previous scan.
        min_severity:  Minimum severity to include. Default: "medium".

    Returns:
        List of endpoint dicts ready for SubscanSpec.focus_endpoints.
    """
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    threshold = severity_order.get(min_severity.lower(), 2)

    try:
        with open(report_path) as f:
            report = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        log.error("[subscan] Failed to load report %s: %s", report_path, exc)
        return []

    findings = report.get("findings", [])
    endpoints: dict[str, dict] = {}

    for finding in findings:
        sev = finding.get("severity", "info").lower()
        if severity_order.get(sev, 99) > threshold:
            continue
        url = finding.get("target_url", "")
        if not url:
            continue
        # Collect unique URLs
        if url not in endpoints:
            endpoints[url] = {"url": url, "method": "GET", "params": []}
        param = finding.get("param_name", "")
        if param and param not in endpoints[url]["params"]:
            endpoints[url]["params"].append(param)

    result = list(endpoints.values())
    log.info("[subscan] Loaded %d focus endpoints from %s (min_severity=%s)", len(result), report_path, min_severity)
    return result
