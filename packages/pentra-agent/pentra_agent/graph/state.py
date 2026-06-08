"""PentraState — the shared mutable state threaded through the LangGraph graph.

Rules:
- Fields that ACCUMULATE across nodes use Annotated reducers (operator.add, add_messages).
- Nodes return ONLY the fields they modify — never the full state.
- thread_id == engagement_id for checkpoint persistence.
"""

from __future__ import annotations

import operator
from typing import Annotated, Literal, TypedDict

from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages


# ── Sub-TypedDicts ────────────────────────────────────────────────────────────

class Target(TypedDict):
    domain: str                 # Primary target domain (e.g. "target.com")
    ip_ranges: list[str]        # CIDR ranges in scope
    base_urls: list[str]        # Known base URLs (e.g. ["https://target.com"])


class Scope(TypedDict):
    in_scope: list[str]         # Authorised targets: domains, IPs, CIDRs
    out_of_scope: list[str]     # Explicit exclusions within in-scope range


class Subdomain(TypedDict):
    host: str
    ip: str | None
    source: str                 # "subfinder", "httpx", etc.
    is_alive: bool
    status_code: int | None
    tech_stack: list[str]


class Port(TypedDict):
    host: str
    port: int
    protocol: str               # "tcp" | "udp"
    service: str                # e.g. "https", "ssh"
    version: str | None
    state: str                  # "open" | "filtered" | "closed"


class Endpoint(TypedDict):
    url: str
    method: str
    params: list[str]
    source: str                 # "katana", "burp_proxy", "ffuf"


class ProposedAction(TypedDict):
    action_type: str            # "run_tool", "test_vuln", "generate_payload"
    tool: str
    args: dict
    reason: str
    is_destructive: bool


# ── Main state ────────────────────────────────────────────────────────────────

class PentraState(TypedDict):
    """Full state for one engagement thread."""

    # ── Engagement context ─────────────────────────────────────────────
    engagement_id: str
    target: Target
    scope: Scope
    mode: Literal["semi_auto", "agentic"]
    llm_model: str                              # Ollama model tag
    opsec_mode: bool
    request_jitter_ms: int

    # ── Phase tracking ─────────────────────────────────────────────────
    current_phase: Literal[
        "planning", "recon", "vuln_hunt", "exploit_validation", "report", "done"
    ]
    phase_history: Annotated[list[str], operator.add]

    # ── Accumulated recon data (reducers append, never overwrite) ──────
    subdomains: Annotated[list[Subdomain], operator.add]
    open_ports: Annotated[list[Port], operator.add]
    tech_stack: Annotated[list[str], operator.add]
    endpoints: Annotated[list[Endpoint], operator.add]

    # ── Findings (agent-discovered or manual) ─────────────────────────
    findings: Annotated[list[dict], operator.add]

    # ── LLM reasoning ─────────────────────────────────────────────────
    pentest_plan: str
    current_hypothesis: str
    knowledge_context: list[dict]               # RAG results — replaced per phase, not accumulated

    # ── Human-in-the-loop ─────────────────────────────────────────────
    awaiting_approval: bool
    pending_action: ProposedAction | None
    user_decision: Literal["approve", "skip", "modify"] | None

    # ── Execution history ─────────────────────────────────────────────
    messages: Annotated[list[AnyMessage], add_messages]
    tool_outputs: Annotated[list[dict], operator.add]
    errors: Annotated[list[str], operator.add]

    # ── Recon metadata ────────────────────────────────────────────────
    rate_limit_info: dict  # {safe_rps, delay_ms, is_limited, notes}
    waf_info: dict         # {waf_type, is_blocking, bypass_strategies, safe_rps}
    osint_results: dict    # {ct_subdomains, h1_program, shodan}

    # ── Triage gate (Sprint 16) ───────────────────────────────────────
    # Populated by triage_node; report_node reads this instead of `findings`
    # to honour KILL / DOWNGRADE verdicts. Plain list — last-write-wins (no reducer).
    triaged_findings: list[dict]

    # ── DO NOT STOP routing (Sprint 17) ──────────────────────────────
    # Incremented by vuln_hunt_node each round; capped at MAX_ROUNDS=3 in router.
    hunt_rounds: int

    # ── Authenticated scan (Sprint 18.6) ─────────────────────────────
    # Optional auth credentials injected into all scan requests.
    # None = unauthenticated scan (default).
    # Use AuthCredentials from pentra_tools.auth.session_manager.
    auth_credentials: dict | None  # serialised AuthCredentials dict
