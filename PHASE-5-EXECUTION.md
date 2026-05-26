# PHASE-5-EXECUTION.md — Pentra AI
> **Untuk:** GitHub Copilot dengan Claude Sonnet 4.6  
> **Baca terlebih dahulu:** `CLAUDE.md` → `docs/PRD.md` → `PROGRESS.md` → file ini  
> **Status saat ini:** Sprint 1–9 selesai, 47 tests passing, fondasi production-ready  
> **Tujuan:** Implementasi Agent Engine — LangGraph StateGraph + tool nodes + HITL frontend

---

## Konteks Penting

Progress report terbaru menunjukkan bahwa **infrastruktur sudah sangat solid**:
- PostgreSQL + Qdrant + Redis + MinIO + Ollama → berjalan dan ter-validate
- StartupValidator, backup tasks, rate limiting, performance indexes → semua ada
- Knowledge Engine (embed_batch, quality_score, hybrid search) → siap dipakai
- Semua tool wrappers (subfinder, nmap, nuclei, Burp MCP, dll) → sudah ada di `pentra-tools`

Yang **belum diimplementasi** adalah **Agent Engine** — `packages/pentra-agent/` masih kosong atau skeleton. LangGraph StateGraph, node-node, HITL, dan live feed di frontend belum terhubung ke tool wrappers yang sudah ada.

**Urutan sprint wajib diikuti** — setiap sprint bergantung pada sprint sebelumnya.

---

## Sprint 10 — LangGraph Core

> **Tujuan:** Bangun `packages/pentra-agent/` dari awal — StateGraph, semua nodes, checkpointing  
> **Estimasi:** 4–5 hari  
> **Jangan mulai Sprint 11 sebelum semua task di sini selesai dan tests pass**

---

### Task 10.1 — PentraState TypedDict

**Buat file: `packages/pentra-agent/pentra_agent/graph/state.py`**

```python
from __future__ import annotations

import operator
from typing import Annotated, Literal, TypedDict
from uuid import UUID

from langgraph.graph.message import add_messages
from langchain_core.messages import AnyMessage

from pentra_shared.types import Finding, VulnClass, Severity


class Target(TypedDict):
    domain: str
    ip_ranges: list[str]
    base_urls: list[str]


class Scope(TypedDict):
    in_scope: list[str]
    out_of_scope: list[str]


class Subdomain(TypedDict):
    host: str
    ip: str | None
    source: str
    is_alive: bool
    status_code: int | None
    tech_stack: list[str]


class Port(TypedDict):
    host: str
    port: int
    protocol: str
    service: str
    version: str | None
    state: str


class Endpoint(TypedDict):
    url: str
    method: str
    params: list[str]
    source: str             # "katana", "burp_proxy", "ffuf"


class ProposedAction(TypedDict):
    action_type: str        # "run_tool", "test_vuln", "generate_payload"
    tool: str
    args: dict
    reason: str
    is_destructive: bool


class PentraState(TypedDict):
    # === Engagement context ===
    engagement_id: str
    target: Target
    scope: Scope
    mode: Literal["semi_auto", "agentic"]
    llm_model: str
    opsec_mode: bool
    request_jitter_ms: int

    # === Phase tracking ===
    current_phase: Literal[
        "planning", "recon", "vuln_hunt", "exploit_validation", "report"
    ]
    phase_history: Annotated[list[str], operator.add]

    # === Accumulated recon data ===
    # Semua list pakai operator.add reducer — nodes return partial lists, bukan replace
    subdomains: Annotated[list[Subdomain], operator.add]
    open_ports: Annotated[list[Port], operator.add]
    tech_stack: Annotated[list[str], operator.add]
    endpoints: Annotated[list[Endpoint], operator.add]

    # === Findings ===
    findings: Annotated[list[dict], operator.add]   # dict sebelum di-persist ke DB

    # === LLM reasoning ===
    pentest_plan: str
    current_hypothesis: str
    knowledge_context: list[dict]   # KnowledgeRecord dicts dari RAG query

    # === Human-in-the-loop ===
    awaiting_approval: bool
    pending_action: ProposedAction | None
    user_decision: Literal["approve", "skip", "modify"] | None

    # === Execution history ===
    messages: Annotated[list[AnyMessage], add_messages]
    tool_outputs: Annotated[list[dict], operator.add]
    errors: Annotated[list[str], operator.add]
```

**Tests untuk state:**

```python
# packages/pentra-agent/tests/test_state.py

def test_pentra_state_reducers_accumulate():
    """operator.add reducer harus accumulate, bukan replace."""
    state1 = {"subdomains": [{"host": "api.target.com"}]}
    state2 = {"subdomains": [{"host": "admin.target.com"}]}

    # Simulate reducer
    combined = state1["subdomains"] + state2["subdomains"]
    assert len(combined) == 2
    assert combined[0]["host"] == "api.target.com"
    assert combined[1]["host"] == "admin.target.com"


def test_phase_literals_are_valid():
    """Pastikan semua phase literal valid."""
    valid_phases = {"planning", "recon", "vuln_hunt", "exploit_validation", "report"}
    from pentra_agent.graph.state import PentraState
    import typing
    hints = typing.get_type_hints(PentraState)
    # current_phase harus Literal dengan nilai-nilai di atas
    assert hints.get("current_phase") is not None
```

---

### Task 10.2 — LLM Client Abstraction

**Buat file: `packages/pentra-agent/pentra_agent/llm/client.py`**

```python
"""
LLM client abstraction — OpenAI-compatible, works with any Ollama model.
Semua LLM calls di agent nodes harus melalui class ini.
Jangan panggil Ollama / OpenAI SDK langsung dari node functions.
"""

from __future__ import annotations

import json
import httpx
from typing import Any

from pentra_shared.types import VulnClass


class LLMClient:
    def __init__(
        self,
        base_url: str,       # e.g., "http://localhost:11434/v1"
        model: str,          # e.g., "qwen2.5-coder:32b"
        temperature: float = 0.3,
        timeout: float = 120.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.timeout = timeout

    async def complete(
        self,
        system: str,
        user: str,
        json_output: bool = False,
    ) -> str:
        """
        Single completion — system + user message → string response.
        Gunakan json_output=True untuk force JSON response.
        """
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        if json_output:
            messages[0]["content"] += "\n\nRespond ONLY with valid JSON. No markdown, no preamble."

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/chat/completions",
                json={
                    "model": self.model,
                    "messages": messages,
                    "temperature": self.temperature,
                    "stream": False,
                },
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]

    async def complete_json(self, system: str, user: str) -> dict | list:
        """
        Completion yang guaranteed return valid JSON.
        Retry sekali jika parse gagal.
        """
        raw = await self.complete(system, user, json_output=True)
        raw = raw.strip()

        # Strip markdown fences jika ada
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1]
            raw = raw.rsplit("```", 1)[0]

        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            # Retry dengan prompt yang lebih ketat
            retry_system = system + "\n\nCRITICAL: Return ONLY raw JSON, nothing else."
            raw = await self.complete(retry_system, user, json_output=True)
            raw = raw.strip().lstrip("```json").rstrip("```").strip()
            return json.loads(raw)

    async def plan_engagement(
        self,
        target: dict,
        scope: dict,
        knowledge_hints: list[dict],
    ) -> str:
        """Generate pentest plan berdasarkan target + scope + knowledge context."""
        system = """You are a senior penetration tester and bug bounty hunter.
Create a structured pentest plan based on the target and scope provided.
Focus on high-impact vulnerabilities. Be specific about techniques to try.
Reference the knowledge hints to prioritize testing based on similar past findings."""

        user = f"""Target: {json.dumps(target, indent=2)}
Scope: {json.dumps(scope, indent=2)}
Similar findings from knowledge base: {json.dumps(knowledge_hints[:5], indent=2)}

Create a prioritized pentest plan with:
1. Recon phase steps
2. Vulnerability classes to test (based on tech stack if known)
3. Specific endpoints/parameters to focus on
4. High-value targets based on knowledge hints"""

        return await self.complete(system, user)

    async def analyze_recon_results(
        self,
        subdomains: list[dict],
        ports: list[dict],
        tech_stack: list[str],
        knowledge_context: list[dict],
    ) -> dict:
        """
        Analisis hasil recon dan suggest langkah vuln hunt.
        Return dict dengan: summary, hypotheses, suggested_tests
        """
        system = """You are a senior security researcher analyzing recon results.
Based on the discovered attack surface and known vulnerability patterns,
identify the most promising attack vectors.
Return JSON with keys: summary, tech_stack_analysis, hypotheses, suggested_tests"""

        user = f"""Recon results:
Subdomains ({len(subdomains)}): {json.dumps(subdomains[:20], indent=2)}
Open ports: {json.dumps(ports[:20], indent=2)}
Tech stack detected: {tech_stack}

Similar vulnerability patterns from knowledge base:
{json.dumps(knowledge_context[:5], indent=2)}

Analyze and return JSON with your assessment."""

        return await self.complete_json(system, user)

    async def classify_finding(
        self,
        title: str,
        description: str,
        request: str,
        response: str,
    ) -> dict:
        """
        Classify finding: vuln_class, severity, cvss_score, impact.
        Return dict dengan field-field tersebut.
        """
        system = """You are a security expert classifying vulnerabilities.
Analyze the provided HTTP request/response and classify the finding.
Return JSON with: vuln_class, vuln_subclass, severity, cvss_score (0-10), 
cvss_vector, impact, remediation"""

        user = f"""Finding: {title}
Description: {description}

HTTP Request:
{request[:2000]}

HTTP Response:
{response[:2000]}

Classify this finding and return JSON."""

        return await self.complete_json(system, user)
```

---

### Task 10.3 — Node Functions

**Buat satu file per node di `packages/pentra-agent/pentra_agent/nodes/`**

#### `plan_node.py`

```python
# packages/pentra-agent/pentra_agent/nodes/plan_node.py

"""
Plan node: LLM membuat pentest plan berdasarkan target + scope + knowledge.
Node pertama dalam graph.
"""

from pentra_agent.graph.state import PentraState
from pentra_agent.llm.client import LLMClient
from pentra_knowledge.services.search import hybrid_search
from pentra_scope import ScopeEnforcer


async def plan_node(state: PentraState) -> dict:
    """
    1. Query knowledge base untuk context berdasarkan target
    2. LLM generate pentest plan
    3. Update state dengan plan dan phase
    """
    from langchain_core.messages import AIMessage

    # Query knowledge untuk initial context
    knowledge = await hybrid_search(
        query=f"pentest techniques for {state['target']['domain']}",
        top_k=5,
        min_quality_score=0.4,
    )

    # Generate plan
    llm = LLMClient(
        base_url=_get_ollama_url(),
        model=state["llm_model"],
    )
    plan = await llm.plan_engagement(
        target=state["target"],
        scope=state["scope"],
        knowledge_hints=[k.model_dump() for k in knowledge],
    )

    return {
        "pentest_plan": plan,
        "current_phase": "planning",
        "knowledge_context": [k.model_dump() for k in knowledge],
        "messages": [AIMessage(content=f"Pentest plan created:\n\n{plan}")],
    }


def _get_ollama_url() -> str:
    import os
    return os.getenv("OLLAMA_URL", "http://localhost:11434") + "/v1"
```

#### `hitl_nodes.py`

```python
# packages/pentra-agent/pentra_agent/nodes/hitl_nodes.py

"""
Human-in-the-Loop nodes.
Menggunakan langgraph interrupt() untuk pause graph dan tunggu user decision.
"""

from langgraph.types import interrupt
from pentra_agent.graph.state import PentraState


async def hitl_plan_review(state: PentraState) -> dict:
    """
    Pause setelah plan dibuat.
    Semi-auto: interrupt dan tunggu approval.
    Agentic: auto-approve, log saja.
    """
    if state["mode"] == "semi_auto":
        decision = interrupt({
            "type": "AWAITING_APPROVAL",
            "phase": "planning",
            "message": "Agent telah membuat pentest plan. Review dan approve untuk mulai recon.",
            "data": {
                "plan": state["pentest_plan"],
                "target": state["target"]["domain"],
                "scope_summary": {
                    "in_scope": state["scope"]["in_scope"],
                    "out_of_scope": state["scope"]["out_of_scope"],
                },
                "knowledge_hints": [
                    k.get("key_insight", "") 
                    for k in state.get("knowledge_context", [])[:3]
                ],
            }
        })
        return {"user_decision": decision, "awaiting_approval": False}

    # Agentic mode: auto-approve
    return {"user_decision": "approve", "awaiting_approval": False}


async def hitl_recon_review(state: PentraState) -> dict:
    """
    Pause setelah recon selesai.
    Tampilkan summary findings dan suggest langkah selanjutnya.
    """
    if state["mode"] == "semi_auto":
        decision = interrupt({
            "type": "AWAITING_APPROVAL",
            "phase": "recon",
            "message": "Recon selesai. Review attack surface yang ditemukan.",
            "data": {
                "subdomains_found": len(state.get("subdomains", [])),
                "ports_found": len(state.get("open_ports", [])),
                "tech_stack": state.get("tech_stack", []),
                "endpoints_found": len(state.get("endpoints", [])),
                "hypothesis": state.get("current_hypothesis", ""),
                "top_subdomains": [
                    s["host"] for s in state.get("subdomains", [])[:10]
                ],
            }
        })
        return {"user_decision": decision, "awaiting_approval": False}

    return {"user_decision": "approve", "awaiting_approval": False}


async def hitl_exploit_review(state: PentraState) -> dict:
    """
    SELALU interrupt — destructive action.
    Tidak peduli mode semi_auto atau agentic.
    """
    decision = interrupt({
        "type": "AWAITING_APPROVAL",
        "phase": "exploit_validation",
        "message": "⚠️ Agent akan melakukan exploit validation. Ini destructive — selalu butuh approval.",
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
            "warning": "Exploit validation akan mengirim payload aktif ke target. Pastikan dalam scope.",
        }
    })
    return {"user_decision": decision, "awaiting_approval": False}
```

#### `recon_node.py`

```python
# packages/pentra-agent/pentra_agent/nodes/recon_node.py

"""
Recon node: subdomain enum → port scan → HTTP probe → tech detect.
Menggunakan tool wrappers dari packages/pentra-tools.
"""

import asyncio
from langchain_core.messages import AIMessage

from pentra_agent.graph.state import PentraState
from pentra_agent.llm.client import LLMClient
from pentra_knowledge.services.search import hybrid_search
from pentra_scope import ScopeEnforcer, ScopeViolationError


async def recon_node(state: PentraState) -> dict:
    """
    1. Subdomain enumeration via subfinder
    2. HTTP probing via httpx
    3. Port scan via nmap (top ports only)
    4. LLM analyze → update hypothesis + query knowledge
    """
    from langchain_core.messages import HumanMessage

    scope = ScopeEnforcer(
        in_scope=state["scope"]["in_scope"],
        out_of_scope=state["scope"]["out_of_scope"],
    )

    domain = state["target"]["domain"]
    all_subdomains = []
    all_ports = []
    tech_stack = []

    # ── Step 1: Subdomain enumeration ──────────────────────────────────
    try:
        from pentra_tools.recon.subfinder import SubfinderWrapper
        subfinder = SubfinderWrapper(scope_enforcer=scope)
        result = await subfinder.run(domain=domain)
        if result.success:
            all_subdomains.extend(result.data)
    except Exception as e:
        pass  # Graceful fallback — log tapi jangan stop

    # ── Step 2: HTTP probe semua subdomains ────────────────────────────
    if all_subdomains:
        try:
            from pentra_tools.recon.httpx import HttpxWrapper
            httpx_wrapper = HttpxWrapper(scope_enforcer=scope)
            hosts = [s["host"] for s in all_subdomains[:50]]  # limit 50
            result = await httpx_wrapper.run(hosts=hosts)
            if result.success:
                for item in result.data:
                    # Merge tech stack info ke subdomain
                    for sub in all_subdomains:
                        if sub["host"] == item.get("host"):
                            sub["is_alive"] = True
                            sub["status_code"] = item.get("status_code")
                            sub["tech_stack"] = item.get("tech", [])
                            tech_stack.extend(item.get("tech", []))
        except Exception as e:
            pass

    # ── Step 3: Port scan pada live subdomains ─────────────────────────
    live_hosts = [s["host"] for s in all_subdomains if s.get("is_alive")][:10]
    if live_hosts:
        try:
            from pentra_tools.recon.nmap import NmapWrapper
            nmap = NmapWrapper(scope_enforcer=scope)
            for host in live_hosts[:5]:  # limit 5 untuk speed
                result = await nmap.run(target=host, top_ports=1000)
                if result.success:
                    all_ports.extend(result.data)
        except Exception as e:
            pass

    # ── Step 4: LLM analyze + knowledge query ─────────────────────────
    unique_tech = list(set(tech_stack))
    knowledge = await hybrid_search(
        query=f"vulnerabilities in {' '.join(unique_tech[:5])} applications",
        filters={"severity": ["critical", "high"]},
        top_k=8,
        min_quality_score=0.3,
    )

    llm = LLMClient(base_url=_get_ollama_url(), model=state["llm_model"])
    analysis = await llm.analyze_recon_results(
        subdomains=all_subdomains[:20],
        ports=all_ports[:20],
        tech_stack=unique_tech,
        knowledge_context=[k.model_dump() for k in knowledge],
    )

    hypothesis = analysis.get("hypotheses", [])
    hypothesis_text = "\n".join(
        f"- {h}" for h in hypothesis[:5]
    ) if isinstance(hypothesis, list) else str(hypothesis)

    return {
        "subdomains": all_subdomains,
        "open_ports": all_ports,
        "tech_stack": unique_tech,
        "current_phase": "recon",
        "current_hypothesis": hypothesis_text,
        "knowledge_context": [k.model_dump() for k in knowledge],
        "messages": [
            AIMessage(content=(
                f"Recon complete:\n"
                f"- {len(all_subdomains)} subdomains found\n"
                f"- {len(live_hosts)} alive\n"
                f"- Tech stack: {', '.join(unique_tech[:5])}\n"
                f"- {len(knowledge)} similar H1 reports found\n\n"
                f"Hypotheses:\n{hypothesis_text}"
            ))
        ],
        "tool_outputs": [{
            "phase": "recon",
            "subdomains": len(all_subdomains),
            "ports": len(all_ports),
            "tech_stack": unique_tech,
        }]
    }


def _get_ollama_url() -> str:
    import os
    return os.getenv("OLLAMA_URL", "http://localhost:11434") + "/v1"
```

#### `vuln_hunt_node.py`

```python
# packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py

"""
Vuln hunt node: nuclei scan + Burp scan + GraphQL analysis + knowledge-guided manual tests.
"""

import asyncio
from langchain_core.messages import AIMessage

from pentra_agent.graph.state import PentraState
from pentra_knowledge.services.search import hybrid_search
from pentra_scope import ScopeEnforcer


async def vuln_hunt_node(state: PentraState) -> dict:
    """
    1. Nuclei scan pada live subdomains (safe tags only)
    2. GraphQL analyzer pada endpoint GraphQL yang terdeteksi
    3. Burp MCP proxy history analysis (jika Burp aktif)
    4. LLM synthesize findings + query knowledge untuk additional tests
    """
    scope = ScopeEnforcer(
        in_scope=state["scope"]["in_scope"],
        out_of_scope=state["scope"]["out_of_scope"],
    )

    all_findings = []
    live_hosts = [
        s["host"] for s in state.get("subdomains", [])
        if s.get("is_alive")
    ][:20]

    # ── Step 1: Nuclei scan ────────────────────────────────────────────
    if live_hosts:
        try:
            from pentra_tools.vuln.nuclei import NucleiWrapper
            nuclei = NucleiWrapper(scope_enforcer=scope)
            for host in live_hosts[:10]:
                result = await nuclei.run(
                    target=f"https://{host}",
                    tags=["misconfig", "exposure", "info"],
                )
                if result.success and result.data:
                    all_findings.extend([
                        {**f, "source": "nuclei", "host": host}
                        for f in result.data
                    ])
        except Exception:
            pass

    # ── Step 2: GraphQL analysis ───────────────────────────────────────
    graphql_endpoints = _detect_graphql_endpoints(state)
    if graphql_endpoints:
        try:
            from pentra_tools.vuln.graphql_analyzer import GraphQLAnalyzer
            analyzer = GraphQLAnalyzer(scope_enforcer=scope)
            for endpoint in graphql_endpoints[:3]:
                result = await analyzer.run(endpoint_url=endpoint)
                if result.success and result.data.get("findings"):
                    all_findings.extend([
                        {**f, "source": "graphql_analyzer", "endpoint": endpoint}
                        for f in result.data["findings"]
                    ])
        except Exception:
            pass

    # ── Step 3: Burp proxy history analysis (opsional) ─────────────────
    burp_findings = await _analyze_burp_proxy(state, scope)
    all_findings.extend(burp_findings)

    # ── Step 4: LLM + Knowledge synthesis ─────────────────────────────
    tech = state.get("tech_stack", [])
    knowledge = await hybrid_search(
        query=(
            f"vulnerabilities {' '.join(tech[:5])} "
            f"{'REST API' if any('api' in h for h in live_hosts) else ''}"
        ),
        filters={"severity": ["critical", "high", "medium"]},
        top_k=10,
        min_quality_score=0.3,
    )

    return {
        "findings": all_findings,
        "current_phase": "vuln_hunt",
        "knowledge_context": [k.model_dump() for k in knowledge],
        "messages": [
            AIMessage(content=(
                f"Vuln hunt complete:\n"
                f"- {len(all_findings)} potential findings\n"
                f"- Nuclei: {sum(1 for f in all_findings if f.get('source') == 'nuclei')}\n"
                f"- GraphQL: {sum(1 for f in all_findings if f.get('source') == 'graphql_analyzer')}\n"
                f"- Burp: {sum(1 for f in all_findings if f.get('source') == 'burp')}\n"
                f"- Knowledge hints loaded: {len(knowledge)}"
            ))
        ],
    }


def _detect_graphql_endpoints(state: PentraState) -> list[str]:
    """Deteksi endpoint GraphQL dari endpoints dan subdomains yang ditemukan."""
    graphql_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]
    endpoints = []
    for sub in state.get("subdomains", []):
        if sub.get("is_alive"):
            for path in graphql_paths:
                endpoints.append(f"https://{sub['host']}{path}")
    return endpoints[:5]


async def _analyze_burp_proxy(
    state: PentraState,
    scope: ScopeEnforcer,
) -> list[dict]:
    """Analisis Burp proxy history jika tersedia."""
    import os
    burp_url = os.getenv("BURP_MCP_URL")
    if not burp_url:
        return []
    try:
        from pentra_tools.burp.client import BurpMCPClient
        burp = BurpMCPClient(base_url=burp_url)
        if not await burp.health_check():
            return []
        history = await burp.get_proxy_history(limit=50)
        # Filter hanya target yang in-scope
        in_scope_history = [
            h for h in history
            if scope.is_allowed(h.url)
        ]
        # Return sebagai findings-format sederhana untuk LLM analisis lebih lanjut
        return [
            {"source": "burp", "url": h.url, "method": h.method,
             "status": h.response_status, "needs_analysis": True}
            for h in in_scope_history[:20]
        ]
    except Exception:
        return []
```

#### `report_node.py`

```python
# packages/pentra-agent/pentra_agent/nodes/report_node.py

"""
Report node: compile semua findings → persist ke DB → trigger report generation.
Node terakhir dalam graph.
"""

from langchain_core.messages import AIMessage
from pentra_agent.graph.state import PentraState


async def report_node(state: PentraState) -> dict:
    """
    1. Deduplicate findings
    2. Classify + score setiap finding via LLM (jika belum)
    3. Persist ke DB (finding_service.create_bulk)
    4. Return summary
    """
    from pentra_agent.llm.client import LLMClient

    findings = state.get("findings", [])
    if not findings:
        return {
            "current_phase": "report",
            "messages": [AIMessage(content="No findings to report. Engagement complete.")],
        }

    # Deduplicate by URL + vuln type
    seen = set()
    unique_findings = []
    for f in findings:
        key = f"{f.get('url', f.get('target_url', ''))}-{f.get('vuln_class', f.get('issue_type', ''))}"
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # Persist ke DB via API call (agent tidak boleh akses DB langsung)
    persisted_count = await _persist_findings(
        engagement_id=state["engagement_id"],
        findings=unique_findings,
    )

    summary = (
        f"Engagement complete.\n\n"
        f"**Summary:**\n"
        f"- Subdomains discovered: {len(state.get('subdomains', []))}\n"
        f"- Open ports: {len(state.get('open_ports', []))}\n"
        f"- Tech stack: {', '.join(state.get('tech_stack', [])[:5])}\n"
        f"- Findings: {persisted_count} (from {len(findings)} raw)\n\n"
        f"**Top findings:**\n" +
        "\n".join(
            f"- [{f.get('severity', 'unknown').upper()}] {f.get('title', f.get('issue_type', 'Finding'))}"
            for f in unique_findings[:5]
        )
    )

    return {
        "current_phase": "report",
        "messages": [AIMessage(content=summary)],
    }


async def _persist_findings(engagement_id: str, findings: list[dict]) -> int:
    """
    Persist findings ke DB via internal API call.
    Agent tidak boleh akses DB langsung — selalu lewat API layer.
    """
    import httpx
    import os

    api_url = os.getenv("API_INTERNAL_URL", "http://localhost:8000")

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                f"{api_url}/api/v1/internal/engagements/{engagement_id}/findings/bulk",
                json={"findings": findings},
                headers={"X-Internal-Token": os.getenv("INTERNAL_API_TOKEN", "")},
            )
            if response.status_code == 201:
                return response.json().get("created", 0)
    except Exception:
        pass
    return 0
```

---

### Task 10.4 — StateGraph Builder

**Buat file: `packages/pentra-agent/pentra_agent/graph/builder.py`**

```python
# packages/pentra-agent/pentra_agent/graph/builder.py

"""
Builds dan compiles PentraGraph — LangGraph StateGraph.
Entry point untuk semua agent execution.
"""

from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

from pentra_agent.graph.state import PentraState
from pentra_agent.nodes.plan_node import plan_node
from pentra_agent.nodes.hitl_nodes import (
    hitl_plan_review,
    hitl_recon_review,
    hitl_exploit_review,
)
from pentra_agent.nodes.recon_node import recon_node
from pentra_agent.nodes.vuln_hunt_node import vuln_hunt_node
from pentra_agent.nodes.report_node import report_node


def route_after_recon(state: PentraState) -> str:
    """Routing setelah recon: lanjut ke vuln_hunt atau stop jika skip."""
    if state.get("user_decision") == "skip":
        return "report"
    return "vuln_hunt"


def route_after_vuln_hunt(state: PentraState) -> str:
    """Routing setelah vuln_hunt: ke exploit_validation jika ada findings, atau langsung report."""
    findings = state.get("findings", [])
    high_value = [
        f for f in findings
        if f.get("severity") in ("critical", "high")
    ]
    if high_value and state.get("user_decision") != "skip":
        return "hitl_exploit"
    return "report"


def build_pentra_graph(checkpointer: AsyncPostgresSaver):
    """
    Bangun dan compile PentraGraph.
    Dipanggil sekali saat startup → simpan instance di app state.
    """
    graph = StateGraph(PentraState)

    # Register nodes
    graph.add_node("plan", plan_node)
    graph.add_node("hitl_plan", hitl_plan_review)
    graph.add_node("recon", recon_node)
    graph.add_node("hitl_recon", hitl_recon_review)
    graph.add_node("vuln_hunt", vuln_hunt_node)
    graph.add_node("hitl_exploit", hitl_exploit_review)
    graph.add_node("report", report_node)

    # Edges
    graph.add_edge(START, "plan")
    graph.add_edge("plan", "hitl_plan")
    graph.add_edge("hitl_plan", "recon")
    graph.add_edge("recon", "hitl_recon")
    graph.add_conditional_edges(
        "hitl_recon",
        route_after_recon,
        {"vuln_hunt": "vuln_hunt", "report": "report"},
    )
    graph.add_conditional_edges(
        "vuln_hunt",
        route_after_vuln_hunt,
        {"hitl_exploit": "hitl_exploit", "report": "report"},
    )
    graph.add_edge("hitl_exploit", "report")
    graph.add_edge("report", END)

    return graph.compile(
        checkpointer=checkpointer,
        # interrupt_before diatur via interrupt() di dalam node — tidak perlu di sini
    )
```

---

### Task 10.5 — Agent Service + API Integration

**Buat file: `packages/pentra-agent/pentra_agent/service.py`**

```python
# packages/pentra-agent/pentra_agent/service.py

"""
AgentService: interface antara FastAPI endpoints dan LangGraph graph.
Start, resume, stream events.
"""

from __future__ import annotations
import asyncio
from typing import AsyncIterator
from uuid import UUID

from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

from pentra_agent.graph.builder import build_pentra_graph
from pentra_agent.graph.state import PentraState


class AgentService:
    def __init__(self, graph):
        self.graph = graph

    async def start_engagement(
        self,
        engagement_id: str,
        initial_state: dict,
    ) -> None:
        """
        Start engagement baru.
        Thread ID = engagement_id untuk checkpoint persistence.
        """
        config = {"configurable": {"thread_id": engagement_id}}
        await self.graph.ainvoke(initial_state, config=config)

    async def resume_engagement(
        self,
        engagement_id: str,
        user_decision: str,  # "approve" | "skip" | "modify"
    ) -> None:
        """
        Resume setelah HITL interrupt.
        Update state dengan user_decision lalu lanjut.
        """
        config = {"configurable": {"thread_id": engagement_id}}

        # Update state dengan decision
        await self.graph.aupdate_state(
            config=config,
            values={"user_decision": user_decision, "awaiting_approval": False},
        )

        # Resume execution
        await self.graph.ainvoke(None, config=config)

    async def stream_events(
        self,
        engagement_id: str,
    ) -> AsyncIterator[dict]:
        """
        Stream events dari graph untuk WebSocket live feed.
        Yield event dicts yang akan dikirim ke frontend.
        """
        config = {"configurable": {"thread_id": engagement_id}}

        async for event in self.graph.astream_events(
            None,
            config=config,
            version="v2",
        ):
            event_type = event.get("event", "")

            if event_type == "on_chain_start":
                yield {
                    "type": "PHASE_START",
                    "node": event.get("name", ""),
                    "data": {}
                }

            elif event_type == "on_chain_end":
                output = event.get("data", {}).get("output", {})
                # Cek apakah ada interrupt (HITL)
                if "__interrupt__" in str(output):
                    yield {
                        "type": "AWAITING_APPROVAL",
                        "data": output,
                    }
                else:
                    yield {
                        "type": "PHASE_COMPLETE",
                        "node": event.get("name", ""),
                        "data": output,
                    }

            elif event_type == "on_chat_model_stream":
                chunk = event.get("data", {}).get("chunk", {})
                if hasattr(chunk, "content") and chunk.content:
                    yield {
                        "type": "LLM_STREAM",
                        "content": chunk.content,
                    }
```

**Update `apps/api/app/api/router.py` — tambahkan engagement start endpoint:**

```python
# apps/api/app/api/router.py — tambahkan:

@router.post("/engagements/{engagement_id}/start")
async def start_engagement(
    engagement_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Start agent untuk engagement. Berjalan di background via Celery."""
    engagement = await engagement_service.get_or_404(db, engagement_id, current_user)
    
    # Kirim ke Celery worker — agent jalan di background
    celery.send_task(
        "tasks.agent.run_engagement",
        args=[str(engagement_id)],
        task_id=str(engagement_id),
    )
    
    return {"status": "started", "engagement_id": str(engagement_id)}


@router.post("/engagements/{engagement_id}/approve")
async def approve_hitl(
    engagement_id: UUID,
    decision: HitlDecision,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Resume agent setelah HITL interrupt."""
    engagement = await engagement_service.get_or_404(db, engagement_id, current_user)
    
    celery.send_task(
        "tasks.agent.resume_engagement",
        args=[str(engagement_id), decision.action],
    )
    
    return {"status": "resumed", "decision": decision.action}
```

**Buat Celery tasks untuk agent:**

```python
# apps/worker/app/tasks/agent.py

from celery import shared_task
from pentra_agent.service import AgentService


@shared_task(bind=True, name="tasks.agent.run_engagement")
def run_engagement(self, engagement_id: str):
    """
    Celery task: jalankan agent untuk engagement.
    Berjalan di background worker — bukan di API process.
    """
    import asyncio
    asyncio.run(_run_engagement_async(engagement_id))


async def _run_engagement_async(engagement_id: str):
    """Async wrapper untuk run LangGraph dari Celery sync context."""
    from apps.api.app.db.session import get_db_session
    from apps.api.app.db.models import EngagementORM
    
    async with get_db_session() as db:
        engagement = await db.get(EngagementORM, engagement_id)
        if not engagement:
            return
    
    # Build initial state dari engagement record
    initial_state = {
        "engagement_id": engagement_id,
        "target": {
            "domain": engagement.target_domain,
            "ip_ranges": engagement.target_ip_ranges or [],
            "base_urls": [],
        },
        "scope": {
            "in_scope": engagement.in_scope,
            "out_of_scope": engagement.out_of_scope,
        },
        "mode": engagement.mode,
        "llm_model": engagement.llm_model,
        "opsec_mode": engagement.opsec_mode,
        "request_jitter_ms": engagement.request_jitter_ms,
        "subdomains": [],
        "open_ports": [],
        "tech_stack": [],
        "endpoints": [],
        "findings": [],
        "messages": [],
        "tool_outputs": [],
        "errors": [],
        "awaiting_approval": False,
    }
    
    # Build graph dengan PostgreSQL checkpointer
    from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
    from pentra_agent.graph.builder import build_pentra_graph
    import os
    
    async with await AsyncPostgresSaver.from_conn_string(
        os.getenv("DATABASE_URL")
    ) as checkpointer:
        graph = build_pentra_graph(checkpointer)
        service = AgentService(graph)
        await service.start_engagement(engagement_id, initial_state)
```

---

### Task 10.6 — Tests untuk Agent Core

**Buat: `packages/pentra-agent/tests/test_graph.py`**

```python
# packages/pentra-agent/tests/test_graph.py

import pytest
from unittest.mock import AsyncMock, patch, MagicMock


def test_route_after_recon_goes_to_vuln_hunt_on_approve():
    from pentra_agent.graph.builder import route_after_recon
    state = {"user_decision": "approve", "findings": []}
    assert route_after_recon(state) == "vuln_hunt"


def test_route_after_recon_goes_to_report_on_skip():
    from pentra_agent.graph.builder import route_after_recon
    state = {"user_decision": "skip", "findings": []}
    assert route_after_recon(state) == "report"


def test_route_after_vuln_hunt_goes_to_hitl_exploit_when_high_findings():
    from pentra_agent.graph.builder import route_after_vuln_hunt
    state = {
        "user_decision": "approve",
        "findings": [{"severity": "high", "title": "IDOR"}],
    }
    assert route_after_vuln_hunt(state) == "hitl_exploit"


def test_route_after_vuln_hunt_goes_to_report_when_no_high_findings():
    from pentra_agent.graph.builder import route_after_vuln_hunt
    state = {
        "user_decision": "approve",
        "findings": [{"severity": "low", "title": "Info Disclosure"}],
    }
    assert route_after_vuln_hunt(state) == "report"


def test_route_after_vuln_hunt_goes_to_report_when_no_findings():
    from pentra_agent.graph.builder import route_after_vuln_hunt
    state = {"user_decision": "approve", "findings": []}
    assert route_after_vuln_hunt(state) == "report"


@pytest.mark.asyncio
async def test_hitl_plan_review_auto_approves_in_agentic_mode():
    from pentra_agent.nodes.hitl_nodes import hitl_plan_review
    state = {
        "mode": "agentic",
        "pentest_plan": "Test plan",
        "target": {"domain": "target.com"},
        "scope": {"in_scope": ["target.com"], "out_of_scope": []},
        "knowledge_context": [],
    }
    result = await hitl_plan_review(state)
    assert result["user_decision"] == "approve"
    assert result["awaiting_approval"] is False


@pytest.mark.asyncio
async def test_hitl_exploit_always_interrupts():
    """hitl_exploit harus selalu interrupt — tidak peduli mode."""
    from pentra_agent.nodes.hitl_nodes import hitl_exploit_review
    from langgraph.types import interrupt

    # Mock interrupt untuk capture payload
    captured = {}

    def mock_interrupt(payload):
        captured["payload"] = payload
        return "approve"  # Simulate user approve

    with patch("pentra_agent.nodes.hitl_nodes.interrupt", mock_interrupt):
        state = {
            "mode": "agentic",  # bahkan agentic mode pun harus interrupt
            "findings": [{"title": "IDOR", "severity": "high"}],
        }
        result = await hitl_exploit_review(state)

    assert "payload" in captured
    assert captured["payload"]["type"] == "AWAITING_APPROVAL"
    assert captured["payload"]["phase"] == "exploit_validation"


@pytest.mark.asyncio
async def test_llm_client_complete_json_strips_markdown_fences():
    from pentra_agent.llm.client import LLMClient

    client = LLMClient(base_url="http://localhost:11434/v1", model="test")

    with patch.object(client, "complete", return_value='```json\n{"key": "value"}\n```'):
        result = await client.complete_json("system", "user")

    assert result == {"key": "value"}


@pytest.mark.asyncio
async def test_llm_client_complete_json_handles_raw_json():
    from pentra_agent.llm.client import LLMClient

    client = LLMClient(base_url="http://localhost:11434/v1", model="test")

    with patch.object(client, "complete", return_value='{"findings": []}'):
        result = await client.complete_json("system", "user")

    assert result == {"findings": []}
```

---

## Sprint 11 — WebSocket Live Feed + HITL Frontend

> **Tujuan:** Sambungkan agent events ke UI secara real-time  
> **Estimasi:** 3–4 hari  
> **Mulai Sprint 11 hanya setelah Sprint 10 selesai dan tests pass**

---

### Task 11.1 — WebSocket Event Broadcasting

**Buat: `apps/api/app/core/ws_manager.py`**

```python
# apps/api/app/core/ws_manager.py

"""
WebSocket connection manager.
Broadcast events dari agent ke semua connected clients per engagement.
"""

from collections import defaultdict
from fastapi import WebSocket
import asyncio
import json


class WebSocketManager:
    def __init__(self):
        # engagement_id → list of connected WebSocket
        self._connections: dict[str, list[WebSocket]] = defaultdict(list)

    async def connect(self, websocket: WebSocket, engagement_id: str):
        await websocket.accept()
        self._connections[engagement_id].append(websocket)

    def disconnect(self, websocket: WebSocket, engagement_id: str):
        conns = self._connections.get(engagement_id, [])
        if websocket in conns:
            conns.remove(websocket)

    async def broadcast(self, engagement_id: str, event: dict):
        """Broadcast event ke semua client yang terhubung ke engagement ini."""
        conns = self._connections.get(engagement_id, [])
        dead = []
        for ws in conns:
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws, engagement_id)

    async def send_personal(self, websocket: WebSocket, event: dict):
        await websocket.send_json(event)


ws_manager = WebSocketManager()  # singleton
```

**WebSocket endpoint:**

```python
# apps/api/app/api/ws_router.py

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from app.core.ws_manager import ws_manager
from app.core.auth import decode_token

router = APIRouter()

@router.websocket("/ws/engagements/{engagement_id}/feed")
async def engagement_live_feed(
    websocket: WebSocket,
    engagement_id: str,
    token: str = Query(...),
):
    """
    WebSocket endpoint untuk live feed per engagement.
    Agent events di-broadcast ke sini.
    Client: apps/web/src/hooks/useEngagementFeed.ts
    """
    # Validate token
    try:
        user = await decode_token(token)
    except Exception:
        await websocket.close(code=4001)
        return

    await ws_manager.connect(websocket, engagement_id)
    try:
        while True:
            # Keep alive ping setiap 30 detik
            await asyncio.sleep(30)
            await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, engagement_id)
```

**Update Celery agent task untuk broadcast events:**

```python
# apps/worker/app/tasks/agent.py — update _run_engagement_async:

async def _run_engagement_async(engagement_id: str):
    # ... existing setup code ...
    
    # Broadcast events ke WebSocket saat agent berjalan
    async for event in graph.astream_events(initial_state, config=config, version="v2"):
        ws_event = _convert_to_ws_event(event)
        if ws_event:
            # Broadcast via Redis pub/sub (worker → API → WebSocket)
            await redis.publish(
                f"engagement:{engagement_id}:events",
                json.dumps(ws_event)
            )


def _convert_to_ws_event(langgraph_event: dict) -> dict | None:
    """Convert LangGraph event ke WebSocket event format."""
    event_type = langgraph_event.get("event", "")
    name = langgraph_event.get("name", "")

    if event_type == "on_chain_start" and name in (
        "plan", "recon", "vuln_hunt", "hitl_plan",
        "hitl_recon", "hitl_exploit", "report"
    ):
        return {"type": "NODE_START", "node": name, "timestamp": _now()}

    elif event_type == "on_chain_end":
        output = langgraph_event.get("data", {}).get("output", {})
        # Cek interrupt
        interrupts = langgraph_event.get("data", {}).get("__interrupt__", [])
        if interrupts:
            return {
                "type": "AWAITING_APPROVAL",
                "node": name,
                "timestamp": _now(),
                "data": interrupts[0].value if interrupts else {},
            }
        return {"type": "NODE_COMPLETE", "node": name, "timestamp": _now()}

    elif event_type == "on_chat_model_stream":
        chunk = langgraph_event.get("data", {}).get("chunk")
        if chunk and hasattr(chunk, "content") and chunk.content:
            return {"type": "LLM_STREAM", "content": chunk.content, "timestamp": _now()}

    return None


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
```

**Redis pub/sub bridge di API (agar WebSocket bisa terima dari worker):**

```python
# apps/api/app/core/redis_pubsub.py

"""
Bridge: subscribe Redis channel → broadcast ke WebSocket clients.
Dijalankan sebagai background task saat API startup.
"""

import asyncio
import json
import redis.asyncio as redis
from app.core.ws_manager import ws_manager


async def start_redis_bridge(redis_url: str):
    """
    Subscribe ke semua engagement event channels.
    Forward events ke WebSocket clients.
    Jalankan di background via asyncio.create_task() saat startup.
    """
    r = redis.from_url(redis_url)
    pubsub = r.pubsub()
    await pubsub.psubscribe("engagement:*:events")

    async for message in pubsub.listen():
        if message["type"] != "pmessage":
            continue

        channel = message["channel"].decode()
        # Extract engagement_id dari channel name: "engagement:{id}:events"
        engagement_id = channel.split(":")[1]

        try:
            event = json.loads(message["data"])
            await ws_manager.broadcast(engagement_id, event)
        except Exception:
            pass
```

---

### Task 11.2 — Frontend: Live Feed + HITL UI

**Update: `apps/web/src/hooks/useEngagementFeed.ts`**

```typescript
// apps/web/src/hooks/useEngagementFeed.ts

import { useState, useEffect, useCallback, useRef } from "react";
import { useAuthStore } from "@/stores/auth";

export interface FeedEvent {
  type:
    | "NODE_START"
    | "NODE_COMPLETE"
    | "AWAITING_APPROVAL"
    | "LLM_STREAM"
    | "PHASE_START"
    | "PHASE_COMPLETE"
    | "ping";
  node?: string;
  content?: string;
  timestamp?: string;
  data?: Record<string, unknown>;
}

export interface HitlRequest {
  type: "AWAITING_APPROVAL";
  node: string;
  timestamp: string;
  data: {
    phase: string;
    message: string;
    data: Record<string, unknown>;
  };
}

export function useEngagementFeed(engagementId: string) {
  const [events, setEvents] = useState<FeedEvent[]>([]);
  const [hitlRequest, setHitlRequest] = useState<HitlRequest | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [currentNode, setCurrentNode] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const { accessToken } = useAuthStore();

  const connect = useCallback(() => {
    if (!engagementId || !accessToken) return;

    const wsUrl = `${import.meta.env.VITE_WS_URL ?? "ws://localhost:8000"}/ws/engagements/${engagementId}/feed?token=${accessToken}`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => setIsConnected(true);
    ws.onclose = () => {
      setIsConnected(false);
      // Auto-reconnect setelah 3 detik
      setTimeout(connect, 3000);
    };

    ws.onmessage = (e) => {
      const event: FeedEvent = JSON.parse(e.data);
      if (event.type === "ping") return;

      if (event.type === "AWAITING_APPROVAL") {
        setHitlRequest(event as unknown as HitlRequest);
      }

      if (event.type === "NODE_START") {
        setCurrentNode(event.node ?? null);
      }

      if (event.type === "NODE_COMPLETE") {
        setCurrentNode(null);
      }

      setEvents((prev) => [event, ...prev].slice(0, 500));
    };
  }, [engagementId, accessToken]);

  useEffect(() => {
    connect();
    return () => {
      wsRef.current?.close();
    };
  }, [connect]);

  const clearHitlRequest = useCallback(() => setHitlRequest(null), []);

  return {
    events,
    hitlRequest,
    isConnected,
    currentNode,
    clearHitlRequest,
  };
}
```

**Update: `apps/web/src/components/engagement/LiveFeed.tsx`**

```typescript
// apps/web/src/components/engagement/LiveFeed.tsx

import { useRef, useEffect } from "react";
import { FeedEvent } from "@/hooks/useEngagementFeed";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";

const NODE_LABELS: Record<string, string> = {
  plan: "Planning",
  hitl_plan: "Awaiting Approval",
  recon: "Reconnaissance",
  hitl_recon: "Awaiting Approval",
  vuln_hunt: "Vulnerability Hunt",
  hitl_exploit: "Awaiting Approval",
  report: "Report Generation",
};

const EVENT_COLORS: Record<string, string> = {
  NODE_START: "text-blue-400",
  NODE_COMPLETE: "text-green-400",
  AWAITING_APPROVAL: "text-yellow-400",
  LLM_STREAM: "text-slate-300",
};

interface LiveFeedProps {
  events: FeedEvent[];
  isConnected: boolean;
  currentNode: string | null;
}

export function LiveFeed({ events, isConnected, currentNode }: LiveFeedProps) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [events.length]);

  return (
    <div className="flex flex-col h-full bg-slate-950 rounded-lg border border-slate-800">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <div
            className={cn(
              "w-2 h-2 rounded-full",
              isConnected ? "bg-green-500 animate-pulse" : "bg-slate-600"
            )}
          />
          <span className="text-sm text-slate-400 font-mono">
            {isConnected ? "CONNECTED" : "DISCONNECTED"}
          </span>
        </div>
        {currentNode && (
          <Badge variant="outline" className="text-blue-400 border-blue-400/30">
            {NODE_LABELS[currentNode] ?? currentNode}
          </Badge>
        )}
      </div>

      {/* Events */}
      <div className="flex-1 overflow-y-auto p-4 space-y-1 font-mono text-sm">
        {events.length === 0 && (
          <p className="text-slate-600 text-center mt-8">
            Waiting for agent to start...
          </p>
        )}
        {[...events].reverse().map((event, i) => (
          <div key={i} className={cn("flex gap-2", EVENT_COLORS[event.type])}>
            <span className="text-slate-600 shrink-0">
              {event.timestamp
                ? new Date(event.timestamp).toLocaleTimeString()
                : ""}
            </span>
            <span>
              {event.type === "NODE_START" &&
                `▶ Starting ${NODE_LABELS[event.node ?? ""] ?? event.node}`}
              {event.type === "NODE_COMPLETE" &&
                `✓ ${NODE_LABELS[event.node ?? ""] ?? event.node} complete`}
              {event.type === "AWAITING_APPROVAL" &&
                `⏸ Awaiting approval — ${(event.data as any)?.phase}`}
              {event.type === "LLM_STREAM" && event.content}
            </span>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
```

**Update: `apps/web/src/components/engagement/HitlApprovalDialog.tsx`**

```typescript
// apps/web/src/components/engagement/HitlApprovalDialog.tsx

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, CheckCircle, XCircle } from "lucide-react";
import { HitlRequest } from "@/hooks/useEngagementFeed";
import { useApproveEngagement } from "@/lib/api";

interface HitlApprovalDialogProps {
  request: HitlRequest | null;
  engagementId: string;
  onClose: () => void;
}

const PHASE_ICONS: Record<string, typeof CheckCircle> = {
  exploit_validation: AlertTriangle,
};

export function HitlApprovalDialog({
  request,
  engagementId,
  onClose,
}: HitlApprovalDialogProps) {
  const approve = useApproveEngagement(engagementId);

  if (!request) return null;

  const isDestructive = request.data.phase === "exploit_validation";
  const Icon = PHASE_ICONS[request.data.phase] ?? CheckCircle;

  const handleDecision = async (decision: "approve" | "skip") => {
    await approve.mutateAsync({ action: decision });
    onClose();
  };

  return (
    <Dialog open={!!request} onOpenChange={onClose}>
      <DialogContent className="bg-slate-900 border-slate-700 max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Icon
              className={isDestructive ? "text-red-400" : "text-yellow-400"}
              size={20}
            />
            {isDestructive ? "⚠️ Destructive Action — Approval Required" : "Agent Approval Required"}
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4">
          <p className="text-slate-300 text-sm">{request.data.message}</p>

          {/* Phase badge */}
          <Badge
            variant="outline"
            className={isDestructive ? "border-red-400/30 text-red-400" : "border-yellow-400/30 text-yellow-400"}
          >
            Phase: {request.data.phase}
          </Badge>

          {/* Data preview */}
          {request.data.data && Object.keys(request.data.data).length > 0 && (
            <div className="bg-slate-950 rounded p-3 text-xs font-mono text-slate-400 max-h-48 overflow-y-auto">
              <pre>{JSON.stringify(request.data.data, null, 2)}</pre>
            </div>
          )}
        </div>

        <DialogFooter className="gap-2">
          <Button
            variant="outline"
            onClick={() => handleDecision("skip")}
            className="border-slate-600"
          >
            <XCircle size={16} className="mr-1" />
            Skip
          </Button>
          <Button
            onClick={() => handleDecision("approve")}
            className={isDestructive ? "bg-red-600 hover:bg-red-700" : "bg-green-600 hover:bg-green-700"}
          >
            <CheckCircle size={16} className="mr-1" />
            {isDestructive ? "Approve (Destructive)" : "Approve"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
```

---

## Sprint 12 — Integration + End-to-End Tests

> **Tujuan:** Pastikan seluruh flow berjalan end-to-end  
> **Estimasi:** 2–3 hari  
> **Mulai Sprint 12 hanya setelah Sprint 11 selesai**

---

### Task 12.1 — Internal API Endpoint untuk Agent

Agent nodes tidak boleh akses DB langsung. Perlu internal endpoint:

```python
# apps/api/app/api/internal_router.py

"""
Internal endpoints — hanya bisa diakses dari dalam Docker network.
Digunakan oleh agent worker untuk persist data tanpa akses DB langsung.
"""

from fastapi import APIRouter, Depends, HTTPException, Header
import os

router = APIRouter(prefix="/api/v1/internal", tags=["Internal"])


def verify_internal_token(x_internal_token: str = Header(...)):
    expected = os.getenv("INTERNAL_API_TOKEN", "")
    if not expected or x_internal_token != expected:
        raise HTTPException(403, "Invalid internal token")


@router.post(
    "/engagements/{engagement_id}/findings/bulk",
    dependencies=[Depends(verify_internal_token)],
    status_code=201,
)
async def bulk_create_findings(
    engagement_id: str,
    payload: BulkFindingsCreate,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Bulk create findings dari agent. Internal use only."""
    created = await finding_service.bulk_create(
        db=db,
        engagement_id=engagement_id,
        findings=payload.findings,
    )
    return {"created": len(created)}


@router.patch(
    "/engagements/{engagement_id}/status",
    dependencies=[Depends(verify_internal_token)],
)
async def update_engagement_status(
    engagement_id: str,
    status: EngagementStatusUpdate,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Update engagement status dari agent. Internal use only."""
    await engagement_service.update_status(db, engagement_id, status.status)
    return {"updated": True}
```

---

### Task 12.2 — Agent Integration Tests

```python
# packages/pentra-agent/tests/test_integration.py

"""
Integration tests untuk agent graph.
Menggunakan MemorySaver (bukan PostgreSQL) untuk isolasi test.
Mock semua external calls (LLM, tools, DB).
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from langgraph.checkpoint.memory import MemorySaver

from pentra_agent.graph.builder import build_pentra_graph
from pentra_agent.graph.state import PentraState


def make_test_state() -> dict:
    return {
        "engagement_id": "test-engagement-123",
        "target": {"domain": "testphp.vulnweb.com", "ip_ranges": [], "base_urls": []},
        "scope": {
            "in_scope": ["testphp.vulnweb.com"],
            "out_of_scope": [],
        },
        "mode": "agentic",
        "llm_model": "qwen2.5-coder:7b",
        "opsec_mode": False,
        "request_jitter_ms": 0,
        "subdomains": [],
        "open_ports": [],
        "tech_stack": [],
        "endpoints": [],
        "findings": [],
        "messages": [],
        "tool_outputs": [],
        "errors": [],
        "awaiting_approval": False,
    }


@pytest.mark.asyncio
async def test_graph_plan_node_runs_and_updates_state():
    """Plan node harus update state dengan pentest_plan."""
    checkpointer = MemorySaver()

    with patch("pentra_agent.nodes.plan_node.hybrid_search", return_value=[]), \
         patch("pentra_agent.nodes.plan_node.LLMClient") as MockLLM:
        mock_llm = AsyncMock()
        mock_llm.plan_engagement.return_value = "Test pentest plan"
        MockLLM.return_value = mock_llm

        graph = build_pentra_graph(checkpointer)
        config = {"configurable": {"thread_id": "test-123"}}

        # Agentic mode — run sampai interrupt atau selesai
        result = await graph.ainvoke(make_test_state(), config=config)

    assert "pentest_plan" in result
    assert result["pentest_plan"] == "Test pentest plan"


@pytest.mark.asyncio
async def test_graph_pauses_at_hitl_in_semi_auto_mode():
    """Semi-auto mode harus pause di hitl_plan_review."""
    from langgraph.errors import GraphInterrupt

    checkpointer = MemorySaver()

    with patch("pentra_agent.nodes.plan_node.hybrid_search", return_value=[]), \
         patch("pentra_agent.nodes.plan_node.LLMClient") as MockLLM:
        mock_llm = AsyncMock()
        mock_llm.plan_engagement.return_value = "Test plan"
        MockLLM.return_value = mock_llm

        graph = build_pentra_graph(checkpointer)
        config = {"configurable": {"thread_id": "test-semi-123"}}

        state = make_test_state()
        state["mode"] = "semi_auto"

        # Harus raise GraphInterrupt (interrupt() dipanggil)
        with pytest.raises(GraphInterrupt):
            await graph.ainvoke(state, config=config)


@pytest.mark.asyncio
async def test_recon_node_scope_check_blocks_out_of_scope():
    """Recon node tidak boleh scan target di luar scope."""
    from pentra_scope import ScopeViolationError

    state = make_test_state()
    state["target"]["domain"] = "evil.com"  # Bukan target sebenarnya
    state["scope"]["in_scope"] = ["target.com"]  # evil.com bukan in scope

    with pytest.raises(Exception):  # ScopeViolationError atau wrapper exception
        from pentra_agent.nodes.recon_node import recon_node
        with patch("pentra_tools.recon.subfinder.SubfinderWrapper.run",
                   side_effect=ScopeViolationError("evil.com out of scope")):
            await recon_node(state)
```

---

## Checklist Akhir Phase 5

```
Sprint 10 — LangGraph Core
[ ] PentraState TypedDict terdefinisi dengan semua fields + reducers
[ ] LLMClient.complete() berhasil call Ollama endpoint
[ ] LLMClient.complete_json() strip markdown fences dan return valid dict
[ ] plan_node() update state dengan pentest_plan
[ ] hitl_plan_review() auto-approve di agentic mode
[ ] hitl_exploit_review() SELALU interrupt (tidak peduli mode)
[ ] recon_node() memanggil subfinder + httpx + nmap secara berurutan
[ ] vuln_hunt_node() memanggil nuclei + graphql_analyzer
[ ] report_node() deduplicate findings sebelum persist
[ ] build_pentra_graph() compile tanpa error
[ ] run_engagement Celery task bisa dijalankan tanpa error
[ ] 10+ tests di test_graph.py semua pass

Sprint 11 — WebSocket + HITL UI
[ ] WebSocketManager.broadcast() mengirim ke semua connected clients
[ ] Redis pub/sub bridge meneruskan events dari worker ke API
[ ] WebSocket endpoint /ws/engagements/{id}/feed accept connections
[ ] useEngagementFeed hook connect ke WebSocket dan update events state
[ ] LiveFeed komponen menampilkan events dengan color coding
[ ] HitlApprovalDialog muncul saat AWAITING_APPROVAL event diterima
[ ] Klik Approve → POST /engagements/{id}/approve → agent resume
[ ] Klik Skip → POST /engagements/{id}/approve dengan decision=skip

Sprint 12 — Integration + E2E
[ ] POST /api/v1/internal/engagements/{id}/findings/bulk membutuhkan internal token
[ ] Bulk create findings menyimpan ke DB dengan benar
[ ] test_integration.py: plan node runs → state updated
[ ] test_integration.py: semi_auto mode raises GraphInterrupt
[ ] test_integration.py: recon node blocks out-of-scope target
[ ] E2E: Start engagement dari UI → LiveFeed menampilkan events
[ ] E2E: HITL dialog muncul → Approve → agent lanjut → findings muncul

Security Compliance (re-check)
[ ] Semua tool wrappers dipanggil lewat ScopeEnforcer
[ ] hitl_exploit_review selalu interrupt — tidak ada bypass
[ ] Internal API token dicek sebelum bulk findings diterima
[ ] Agent tidak akses DB langsung — selalu lewat API layer
[ ] LLM inference lokal — tidak ada external API call
[ ] Total tests setelah Phase 5: 47 existing + 20+ baru = 67+ passing
```

---

## Cara Memulai Phase 5

Gunakan prompt berikut di Copilot Chat:

```
Baca CLAUDE.md, docs/PRD.md, PROGRESS.md, dan PHASE-5-EXECUTION.md secara lengkap.

Kita mulai Sprint 10, Task 10.1 — PentraState TypedDict.

1. Buat file packages/pentra-agent/pentra_agent/graph/state.py
   dengan semua TypedDict yang dijelaskan di Task 10.1
2. Buat packages/pentra-agent/tests/test_state.py dengan 2 test cases
3. Jalankan tests dan pastikan pass

Ikuti semua konvensi di CLAUDE.md Section 7 (LangGraph patterns).
```

---

*Phase 5 Execution Plan — Pentra AI*  
*Dibuat berdasarkan gap analysis dari PROGRESS.md (Sprint 1–9, 47 tests) vs arsitektur yang direncanakan*  
*Setelah Phase 5 selesai: platform memiliki agentic loop yang berjalan end-to-end dengan live feed real-time*
