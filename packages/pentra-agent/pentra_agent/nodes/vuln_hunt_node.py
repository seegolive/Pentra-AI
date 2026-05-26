"""Vuln hunt node — active vulnerability scanning across all gathered endpoints.

Pipeline:
  1. nuclei  → template-based scanning (non-destructive templates only here)
  2. ffuf    → parameter/endpoint fuzzing on discovered endpoints
  3. Burp proxy history — pull any matching entries from Burp MCP (optional)
  4. LLM     → synthesize findings, classify severity, deduplicate

All scanning is guarded by scope check before each tool call.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os

from langchain_core.messages import AIMessage

from pentra_agent.graph.state import PentraState
from pentra_agent.llm.client import LLMClient

try:
    from pentra_tools.burp.client import BurpMCPClient
    from pentra_tools.burp.exceptions import BurpConnectionError, BurpNotProError
    _BURP_AVAILABLE = True
except ImportError:
    _BURP_AVAILABLE = False

from pentra_scope import ScopeEnforcer
from pentra_scope.errors import ScopeViolationError

log = logging.getLogger(__name__)


# ── Burp MCP config helpers ───────────────────────────────────────────────────

def _get_burp_config() -> tuple[str | None, bool]:
    """Read Burp MCP config from environment.

    Returns:
        (burp_url, is_enabled) — burp_url is None if BURP_MCP_URL is not set.
    """
    url = os.getenv("BURP_MCP_URL", "").strip()
    enabled = os.getenv("BURP_MCP_ENABLED", "false").lower() == "true"
    return (url if url else None, enabled)


async def _check_burp_connection(burp_url: str) -> bool:
    """Verify Burp MCP server is reachable via health check.

    Logs INFO on success and WARNING on failure so operators always
    know whether Burp is active for this run.
    """
    if not _BURP_AVAILABLE:
        log.warning(
            "[vuln_hunt_node] pentra-tools Burp module not installed — "
            "skipping Burp integration"
        )
        return False
    try:
        client = BurpMCPClient(base_url=burp_url)
        ok = await client.health_check()
        if ok:
            log.info("[vuln_hunt_node] Burp MCP connected at %s", burp_url)
        else:
            log.warning(
                "[vuln_hunt_node] Burp MCP health check FAILED at %s — "
                "skipping Burp integration",
                burp_url,
            )
        return ok
    except Exception as exc:
        log.warning(
            "[vuln_hunt_node] Burp MCP unreachable at %s: %s — "
            "skipping Burp integration",
            burp_url,
            exc,
        )
        return False


async def vuln_hunt_node(state: PentraState) -> dict:
    """Orchestrate active vuln scanning across discovered endpoints."""
    domain = state["target"]["domain"]
    endpoints = state.get("endpoints", [])
    tech_stack = state.get("tech_stack", [])
    knowledge_context = state.get("knowledge_context", [])

    log.info("[vuln_hunt_node] Starting vuln hunt for %s (%d endpoints)", domain, len(endpoints))

    raw_findings: list[dict] = []

    # ── 1. nuclei ─────────────────────────────────────────────────────────────
    nuclei_results = await _run_nuclei(endpoints, state["scope"])
    raw_findings.extend(nuclei_results)

    # ── 2. ffuf (light param fuzzing on alive endpoints) ──────────────────────
    ffuf_results = await _run_ffuf(endpoints[:5])
    raw_findings.extend(ffuf_results)

    # ── 3. Burp active scan ─────────────────────────────────────────
    burp_scan_results = await _run_burp_active_scan(endpoints[:10], state["scope"])
    raw_findings.extend(burp_scan_results)

    # ── 4. Burp proxy history analysis ─────────────────────────────
    burp_proxy_results = await _get_burp_proxy_findings(domain, state["scope"])
    raw_findings.extend(burp_proxy_results)

    # ── 5. Collaborator payload (expose in tool_outputs for LLM) ─────────────
    collaborator_output: list[dict] = []
    collab = await _get_collaborator_payload(
        custom_data=f"pentra-{state['engagement_id'][:8]}",
        scope=state["scope"],
        domain=domain,
    )
    if collab:
        collaborator_output.append(collab)

    # ── 4. LLM synthesis ──────────────────────────────────────────────────────
    llm = LLMClient(base_url=_ollama_url(), model=state["llm_model"])
    classified: list[dict] = []
    for raw in raw_findings:
        try:
            classification = await llm.classify_finding(
                title=raw.get("title", "Potential Finding"),
                description=raw.get("description", ""),
                request=raw.get("request", ""),
                response=raw.get("response", ""),
            )
            finding = {**raw, **classification}
            classified.append(finding)
        except Exception as exc:
            log.warning("[vuln_hunt_node] classify_finding failed: %s", exc)
            classified.append(raw)

    # Deduplicate by title+url
    seen_keys: set[str] = set()
    deduped: list[dict] = []
    for f in classified:
        key = f"{f.get('title', '')}|{f.get('target_url', '')}"
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(f)

    # Refresh knowledge context using tech + finding classes
    vuln_classes = list({f.get("vuln_class", "") for f in deduped if f.get("vuln_class")})
    updated_knowledge: list[dict] = knowledge_context
    if vuln_classes:
        try:
            from pentra_knowledge.services.search import hybrid_search

            from app.db.base import _get_session_factory

            async with _get_session_factory()() as db:
                records = await hybrid_search(
                    query=f"{', '.join(vuln_classes)} exploitation techniques",
                    db=db,
                    vuln_class=vuln_classes if vuln_classes else None,
                    top_k=5,
                    min_quality_score=0.5,
                )
            updated_knowledge = [r.model_dump() for r in records]
        except Exception as exc:
            log.warning("[vuln_hunt_node] KB refresh failed: %s", exc)

    summary_msg = (
        f"**Vulnerability Hunt Complete** for `{domain}`\n\n"
        f"- Raw findings: {len(raw_findings)}\n"
        f"- After deduplication: {len(deduped)}\n"
        f"- High/Critical: {sum(1 for f in deduped if f.get('severity') in ('high', 'critical'))}\n\n"
        + (
            "**Findings:**\n"
            + "\n".join(
                f"- [{f.get('severity','?').upper()}] {f.get('title','?')} @ {f.get('target_url','?')}"
                for f in deduped[:10]
            )
            if deduped
            else "_No findings discovered._"
        )
    )

    return {
        "findings": deduped,
        "current_phase": "vuln_hunt",
        "phase_history": ["vuln_hunt"],
        "knowledge_context": updated_knowledge,
        "tool_outputs": collaborator_output,
        "messages": [AIMessage(content=summary_msg)],
    }


# ── Tool helpers ──────────────────────────────────────────────────────────────

async def _run_nuclei(endpoints: list[dict], scope: dict) -> list[dict]:
    """Run nuclei with non-destructive templates on in-scope endpoints.

    Runs two parallel nuclei passes:
    1. All templates against full HTTP URL targets.
    2. TCP/JS network templates only against ``hostname:port`` entries for
       every open service port discovered on the target host.  This ensures
       services like Redis, PostgreSQL, etc. are scanned even when the HTTP
       endpoint is unreachable.
    """
    import shutil
    from urllib.parse import urlparse

    if not endpoints:
        return []
    in_scope = scope.get("in_scope", [])

    url_targets: list[str] = [
        e["url"] for e in endpoints
        if e.get("url") and _is_in_scope(e["url"], in_scope)
    ][:20]
    if not url_targets:
        return []

    # Discover open service ports on each unique hostname
    COMMON_SERVICE_PORTS = [
        21, 22, 23, 25, 110, 143, 389, 443, 445, 1433, 1521,
        3306, 3389, 5432, 5672, 5900, 6379, 6380, 7001, 8080,
        8443, 8888, 9000, 9200, 9300, 11211, 27017, 28017,
    ]
    seen_hosts: set[str] = set()
    network_targets: list[str] = []
    for url in url_targets:
        host = urlparse(url).hostname or ""
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)
        open_ports = await _probe_open_ports(host, COMMON_SERVICE_PORTS)
        for port in open_ports:
            network_targets.append(f"{host}:{port}")

    nuclei_bin = shutil.which("nuclei") or "nuclei"
    log.info(
        "[vuln_hunt_node] nuclei=%s | http_targets=%s | net_targets=%s",
        nuclei_bin, url_targets, network_targets,
    )

    # Run sequentially — concurrent nuclei processes compete for CPU/templates and both timeout
    http_findings = await _nuclei_scan(nuclei_bin, url_targets, protocol_types=None)
    net_findings = await _nuclei_scan(nuclei_bin, network_targets, protocol_types=["tcp", "javascript"])
    findings = http_findings + net_findings
    log.info("[vuln_hunt_node] nuclei: http=%d net=%d total=%d", len(http_findings), len(net_findings), len(findings))
    return findings


async def _nuclei_scan(
    nuclei_bin: str,
    targets: list[str],
    protocol_types: list[str] | None,
    timeout: int = 300,
) -> list[dict]:
    """Internal helper: run one nuclei pass and return parsed findings."""
    if not targets:
        return []

    import tempfile

    cmd = [
        nuclei_bin,
        "-severity", "info,low,medium,high,critical",
        "-exclude-tags", "intrusive,dos",
        "-jsonl",
        "-silent",
        "-duc",   # disable update check — avoids lock conflicts on concurrent runs
    ]
    if protocol_types:
        cmd += ["-pt", ",".join(protocol_types)]

    # Write targets to a temp file — /dev/stdin is unreliable when nohup closes fd 0
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, prefix="nuclei-targets-") as tf:
        tf.write("\n".join(targets))
        targets_file = tf.name
    cmd += ["-list", targets_file]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        if stderr:
            log.debug("[vuln_hunt_node] nuclei stderr (%s): %s", protocol_types, stderr[:500].decode(errors="replace"))
        findings = _parse_nuclei_jsonl(stdout.decode())
        log.info("[vuln_hunt_node] _nuclei_scan(%s) → %d findings (exit=%s)", protocol_types, len(findings), proc.returncode)
        return findings
    except FileNotFoundError:
        log.warning("[vuln_hunt_node] nuclei not found — skipping")
        return []
    except Exception as exc:
        log.warning("[vuln_hunt_node] nuclei scan error (%s): %s", protocol_types, exc)
        return []
    finally:
        import os
        try:
            os.unlink(targets_file)
        except OSError:
            pass


async def _probe_open_ports(host: str, ports: list[int], timeout: float = 1.0) -> list[int]:
    """Return the subset of *ports* that accept a TCP connection on *host*."""
    open_ports: list[int] = []

    async def check(port: int) -> None:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            open_ports.append(port)
        except Exception:
            pass

    await asyncio.gather(*[check(p) for p in ports])
    log.debug("[vuln_hunt_node] open ports on %s: %s", host, sorted(open_ports))
    return open_ports



def _parse_nuclei_jsonl(output: str) -> list[dict]:
    results: list[dict] = []
    for line in output.splitlines():
        try:
            obj = json.loads(line)
            results.append({
                "title": obj.get("info", {}).get("name", "Nuclei Finding"),
                "description": obj.get("info", {}).get("description", ""),
                "severity": obj.get("info", {}).get("severity", "info"),
                "target_url": obj.get("matched-at", obj.get("host", "")),
                "vuln_class": _nuclei_tags_to_vuln_class(obj.get("info", {}).get("tags", [])),
                "request": obj.get("request", ""),
                "response": obj.get("response", ""),
                "source": "nuclei",
                "template_id": obj.get("template-id", ""),
            })
        except (json.JSONDecodeError, KeyError):
            continue
    return results


async def _run_ffuf(endpoints: list[dict]) -> list[dict]:
    """Light ffuf parameter discovery — only looks for interesting endpoints."""
    # Minimal ffuf run — just discover common API paths, no brute force
    findings: list[dict] = []
    for ep in endpoints[:3]:
        url = ep.get("url", "")
        if not url:
            continue
        try:
            proc = await asyncio.create_subprocess_exec(
                "ffuf",
                "-u", f"{url.rstrip('/')}/FUZZ",
                "-w", "/usr/share/wordlists/dirb/common.txt",
                "-mc", "200,201,301,302,403",
                "-t", "10",
                "-timeout", "5",
                "-json",
                "-recursion", "0",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            try:
                data = json.loads(stdout.decode())
                for r in data.get("results", []):
                    findings.append({
                        "title": f"Discovered endpoint: {r.get('url','')}",
                        "description": f"Status {r.get('status')}, Length {r.get('length')}",
                        "severity": "info",
                        "target_url": r.get("url", ""),
                        "vuln_class": "Information Disclosure",
                        "request": "",
                        "response": "",
                        "source": "ffuf",
                    })
            except json.JSONDecodeError:
                pass
        except FileNotFoundError:
            log.debug("[vuln_hunt_node] ffuf not found — skipping")
            break
        except Exception as exc:
            log.debug("[vuln_hunt_node] ffuf error for %s: %s", url, exc)
    return findings


async def _get_burp_proxy_findings(domain: str, scope: dict) -> list[dict]:
    """Pull Burp proxy history via BurpMCPClient; map to finding dicts."""
    burp_url, burp_enabled = _get_burp_config()
    if not burp_url:
        log.info(
            "[vuln_hunt_node] BURP_MCP_URL not set — Burp proxy history disabled. "
            "Set BURP_MCP_URL=http://127.0.0.1:9876 in .env to enable."
        )
        return []
    if not burp_enabled:
        log.info("[vuln_hunt_node] BURP_MCP_ENABLED=false — Burp proxy history disabled.")
        return []
    if not _BURP_AVAILABLE:
        log.warning("[vuln_hunt_node] pentra-tools Burp module not available — skipping proxy history")
        return []

    in_scope: list[str] = scope.get("in_scope", [])
    out_of_scope: list[str] = scope.get("out_of_scope", [])
    enforcer = ScopeEnforcer(in_scope=in_scope, out_of_scope=out_of_scope)
    try:
        enforcer.validate_or_raise(domain)
    except ScopeViolationError as exc:
        log.warning("[vuln_hunt_node] Burp proxy history skipped — scope: %s", exc)
        return []

    client = BurpMCPClient(base_url=burp_url)
    if not await client.health_check():
        log.info("[vuln_hunt_node] Burp not reachable — skipping proxy history")
        return []

    try:
        import re as _re
        escaped = _re.escape(domain)
        history = await client.get_proxy_history(filter_regex=escaped, limit=100)
        findings: list[dict] = []
        for entry in history:
            # Scope check each entry before processing
            try:
                enforcer.validate_or_raise(entry.url)
            except ScopeViolationError:
                continue
            if entry.request and entry.response:
                findings.append({
                    "title": f"Burp proxy capture: {entry.method} {entry.url}",
                    "description": (
                        f"Intercepted request/response pair from Burp proxy history. "
                        f"Status: {entry.response_status}"
                    ),
                    "severity": "info",
                    "target_url": entry.url,
                    "vuln_class": "Unknown",
                    "request": entry.request or "",
                    "response": entry.response or "",
                    "source": "burp_proxy_mcp",
                })
        log.info("[vuln_hunt_node] Burp proxy findings: %d entries", len(findings))
        return findings
    except (BurpConnectionError, Exception) as exc:
        log.warning("[vuln_hunt_node] Burp proxy history error: %s", exc)
        return []


async def _run_burp_active_scan(endpoints: list[dict], scope: dict) -> list[dict]:
    """Trigger Burp active scan probes and collect scanner issues (Pro only).

    Steps:
      1. Scope-check each endpoint before sending to Burp.
      2. Call ``trigger_active_scan()`` to probe via Burp HTTP engine.
      3. Fetch ``get_scan_results()`` to collect any issues found.
    """
    burp_url, burp_enabled = _get_burp_config()
    if not burp_url or not burp_enabled or not _BURP_AVAILABLE or not endpoints:
        return []

    in_scope: list[str] = scope.get("in_scope", [])
    out_of_scope: list[str] = scope.get("out_of_scope", [])
    enforcer = ScopeEnforcer(in_scope=in_scope, out_of_scope=out_of_scope)

    client = BurpMCPClient(base_url=burp_url)
    if not await client.health_check():
        log.info("[vuln_hunt_node] Burp not reachable — skipping active scan")
        return []

    probed_urls: list[str] = []
    for ep in endpoints:
        url = ep.get("url", "")
        if not url:
            continue
        # Scope check before every Burp call
        try:
            enforcer.validate_or_raise(url)
        except ScopeViolationError as exc:
            log.warning("[vuln_hunt_node] Active scan skipped for %s — scope: %s", url, exc)
            continue
        try:
            await client.trigger_active_scan(url=url, scope=in_scope)
            probed_urls.append(url)
            log.debug("[vuln_hunt_node] Burp scan probe sent: %s", url)
        except BurpConnectionError:
            log.info("[vuln_hunt_node] Burp disconnected during active scan")
            break
        except Exception as exc:
            log.warning("[vuln_hunt_node] trigger_active_scan error for %s: %s", url, exc)

    if not probed_urls:
        return []

    # Collect scanner issues (Pro-only — graceful fallback for Community)
    findings: list[dict] = []
    try:
        issues = await client.get_scan_results(limit=50)
        for issue in issues:
            # Scope check each result URL
            try:
                enforcer.validate_or_raise(issue.url)
            except ScopeViolationError:
                continue
            findings.append({
                "title": issue.name or issue.issue_type or "Burp Scanner Issue",
                "description": issue.detail or "",
                "severity": issue.severity.lower(),
                "target_url": issue.url,
                "vuln_class": issue.issue_type or "Misconfiguration",
                "request": "",
                "response": "",
                "source": "burp_scanner",
                "confidence": issue.confidence,
            })
        log.info("[vuln_hunt_node] Burp scanner issues: %d", len(findings))
    except BurpNotProError:
        log.info("[vuln_hunt_node] Burp scanner issues require Pro — skipping")
    except (BurpConnectionError, Exception) as exc:
        log.warning("[vuln_hunt_node] get_scan_results error: %s", exc)

    return findings


async def _get_collaborator_payload(
    custom_data: str,
    scope: dict,
    domain: str,
) -> dict | None:
    """Generate a Burp Collaborator OOB payload for SSRF/blind injection testing.

    The payload URL is returned as a tool_output dict so the LLM can reference
    it when constructing SSRF/XXE/header-injection payloads.
    Requires Burp Suite Pro.
    """
    burp_url, burp_enabled = _get_burp_config()
    if not burp_url or not burp_enabled or not _BURP_AVAILABLE:
        return None

    in_scope: list[str] = scope.get("in_scope", [])
    out_of_scope: list[str] = scope.get("out_of_scope", [])
    enforcer = ScopeEnforcer(in_scope=in_scope, out_of_scope=out_of_scope)
    try:
        enforcer.validate_or_raise(domain)
    except ScopeViolationError as exc:
        log.warning("[vuln_hunt_node] Collaborator skipped — scope: %s", exc)
        return None

    client = BurpMCPClient(base_url=burp_url)
    if not await client.health_check():
        return None

    try:
        payload = await client.generate_collaborator_payload(custom_data=custom_data)
        log.info("[vuln_hunt_node] Collaborator payload: %s", payload.payload)
        return {
            "tool": "burp_collaborator",
            "payload_url": payload.payload,
            "payload_id": payload.payload_id,
            "usage": (
                "Inject this URL as SSRF target, blind XSS callback, "
                "XXE external entity, or Host header value."
            ),
        }
    except BurpNotProError:
        log.info("[vuln_hunt_node] Collaborator requires Burp Pro — skipping")
        return None
    except (BurpConnectionError, Exception) as exc:
        log.warning("[vuln_hunt_node] generate_collaborator_payload error: %s", exc)
        return None


def _nuclei_tags_to_vuln_class(tags: list[str]) -> str:
    tag_map = {
        "sqli": "SQL Injection",
        "xss": "XSS",
        "ssrf": "SSRF",
        "idor": "IDOR",
        "rce": "RCE",
        "lfi": "LFI",
        "xxe": "XXE",
        "auth-bypass": "Authentication Bypass",
        "csrf": "CSRF",
        "redirect": "Open Redirect",
    }
    for tag in tags:
        vuln = tag_map.get(tag.lower())
        if vuln:
            return vuln
    return "Misconfiguration"


def _is_in_scope(url: str, in_scope: list[str]) -> bool:
    if not in_scope:
        return True
    for scope_entry in in_scope:
        clean = scope_entry.lstrip("*.")
        if clean in url:
            return True
    return False


def _ollama_url() -> str:
    return os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/") + "/v1"
