# PENTRA AI — Product Requirements Document (PRD)
**Version:** 0.2 — Decisions Locked  
**Status:** Approved for Phase 1 Development  
**Classification:** Private / Confidential  
**Last Updated:** May 2026

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| v0.1 | May 2026 | Initial draft — all sections |
| v0.2 | May 2026 | All open decisions locked (O1–O7), repo structure defined, tech stack finalized |

---

## Table of Contents

1. [Product Overview](#1-product-overview)
2. [Target Users & Personas](#2-target-users--personas)
3. [Core Features — MoSCoW](#3-core-features--moscow)
4. [System Architecture](#4-system-architecture)
5. [Knowledge Engine — Detail Design](#5-knowledge-engine--detail-design)
6. [Agent Architecture — LangGraph](#6-agent-architecture--langgraph)
7. [Tool Integration Layer](#7-tool-integration-layer)
8. [Web UI & UX](#8-web-ui--ux)
9. [Data Model](#9-data-model)
10. [LLM Strategy](#10-llm-strategy)
11. [Auth & User Management](#11-auth--user-management)
12. [Security & Ethics Layer](#12-security--ethics-layer)
13. [Repository Structure](#13-repository-structure)
14. [Deployment & Infrastructure](#14-deployment--infrastructure)
15. [Development Roadmap](#15-development-roadmap)
16. [Decision Log](#16-decision-log)

---

## 1. Product Overview

### 1.1 Vision

> **"The first self-hosted AI security research platform that thinks like a seasoned bug bounty hunter — not a vulnerability scanner."**

Pentra AI adalah **AI Security Research Platform** yang menggabungkan:
- Kecerdasan LLM lokal (Qwen, DeepSeek, dan model lainnya)
- Knowledge dari puluhan ribu real-world bug bounty disclosures (HackerOne, Bugcrowd, writeups)
- Integrasi deep dengan tooling profesional (Burp Suite Pro via MCP)
- Orchestration multi-agent berbasis LangGraph yang stateful dan resumable

### 1.2 Problem Statement

| # | Problem | Impact |
|---|---------|--------|
| P1 | **Scanner Blindness** — tools existing hanya deteksi known vulns dari template; unique bugs (IDOR, business logic, auth bypass) tidak terdeteksi | Miss high-value findings |
| P2 | **Context Loss** — LLM tools kehilangan context setelah beberapa step; tidak ada memori lintas sesi | Redundant work, incomplete coverage |
| P3 | **Tool Fragmentation** — 10+ tools berbeda tanpa orchestration coherent; output tidak terkoneksi | Manual effort, analyst fatigue |
| P4 | **Knowledge Gap** — teknik unik tersebar di blog, writeup, H1 reports; tidak terstruktur dan tidak queryable | Junior/mid researcher miss patterns |
| P5 | **Privacy Concern** — cloud AI tools = data target keluar dari mesin lokal; tidak acceptable untuk professional engagement | NDA/compliance risk |

### 1.3 Positioning

```
             HIGH AI INTELLIGENCE
                     │
    Pentra AI ●      │
  (Smart + Fast)     │
                     │
LOW ─────────────────┼────────────────── HIGH
AUTOMATION           │               AUTOMATION
                     │   ● reNgine
         Burp Pro ●  │
                     │  ● Nuclei
                     │
             LOW AI INTELLIGENCE
```

Pentra AI adalah satu-satunya platform di kuadran **High AI + High Automation** yang sepenuhnya self-hosted.

### 1.4 Naming Convention

- Platform: **Pentra AI**
- Packages/tools: prefix `pentra-` (e.g., `pentra-scope`, `pentra-report`, `pentra-knowledge`)
- Naming bisa descriptive atau codename — fleksibel per komponen
- Repository: monorepo `pentra-ai`

---

## 2. Target Users & Personas

### Persona 1 — Solo Bug Bounty Hunter
| Atribut | Detail |
|---------|--------|
| Pengalaman | 2–5 tahun |
| Goals | Temukan high/critical bugs, maximize bounty per jam effort |
| Pain Points | Waktu terbatas, miss unique bugs, report writing lama, tool setup ribet |
| Butuh dari Pentra AI | Fast recon, smart technique suggestion per tech stack, H1-ready auto-report |

### Persona 2 — Penetration Tester Profesional
| Atribut | Detail |
|---------|--------|
| Pengalaman | 3–8 tahun |
| Goals | Deliver comprehensive pentest report dalam timeframe ketat (1–2 minggu) |
| Pain Points | Scope management, dokumentasi evidence, coverage, client report professional |
| Butuh dari Pentra AI | Scope enforcement, auto evidence capture, professional report, audit trail |

### Persona 3 — Security Researcher
| Atribut | Detail |
|---------|--------|
| Pengalaman | 5+ tahun |
| Goals | Discover novel vulnerability classes, publish research |
| Pain Points | Pattern recognition across large target, knowledge management, chaining vulns |
| Butuh dari Pentra AI | Knowledge engine query, pattern analysis, vulnerability chaining, data export |

### Persona 4 — Red Team Korporat
| Atribut | Detail |
|---------|--------|
| Pengalaman | 5+ tahun, team 3–6 orang |
| Goals | Simulate APT, test defense posture, full kill chain |
| Pain Points | Team coordination, OPSEC, multi-phase planning, blue team debrief evidence |
| Butuh dari Pentra AI | Multi-user RBAC, project management, immutable audit log |

---

## 3. Core Features — MoSCoW

### Must Have (MVP)
| ID | Feature | Deskripsi |
|----|---------|-----------|
| M1 | **Knowledge Engine** | H1 pipeline + vector DB (BGE-M3 + Qdrant) + RAG |
| M2 | **Project Management** | Workspace → Engagement → Target + scope |
| M3 | **Recon Module** | Subdomain, port, tech detection, crawling |
| M4 | **LLM Orchestrator** | LangGraph + Ollama (model-agnostic) |
| M5 | **Burp Suite MCP** | Proxy history, scanner, Repeater, Intruder, Collaborator |
| M6 | **Finding Management** | Store, categorize, severity (CVSS), status |
| M7 | **Basic Report** | Markdown export + evidence capture |
| M8 | **Scope Enforcer** | Hard boundary validator setiap LLM action |
| M9 | **Web UI** | React + Vite dashboard + WebSocket live feed |
| M10 | **Docker Deployment** | Single `docker compose up` |
| M11 | **Auth System** | Admin user + tambah user lain (RBAC minimal) |
| M12 | **KB Browser** | UI untuk browse dan query knowledge base |

### Should Have (v1.0)
| ID | Feature | Deskripsi |
|----|---------|-----------|
| S1 | **Multi-agent Mode** | LangGraph multi-node: Recon, Vuln, Exploit, Report agents |
| S2 | **Vector Memory** | Cross-session context persistence |
| S3 | **Dual Mode** | Semi-auto + fully agentic dalam satu platform |
| S4 | **Custom Nuclei Templates** | LLM-generated templates berdasarkan findings |
| S5 | **PDF Report** | Professional format, CVSS, executive summary |
| S6 | **HackerOne Integration** | BountyHub sync + auto-format draft submission |
| S7 | **Payload Generator** | Context-aware, tech-specific payloads via LLM |
| S8 | **Screenshot Capture** | Headless browser evidence capture |
| S9 | **Continuous Monitoring** | Scheduled scan + delta detection |
| S10 | **Notifications** | Slack/Discord/Telegram |
| S11 | **KB Auto-Update** | Cron scraper H1 + sumber lain |
| S12 | **KB Manual Inject** | Upload writeup/technique dari user |
| S13 | **Agent Self-Learn** | Findings dari engagement masuk KB (user approve) |

### Could Have (v2.0)
| ID | Feature | Deskripsi |
|----|---------|-----------|
| C1 | **Multi-platform BB** | Bugcrowd, Intigriti integration |
| C2 | **Full Team RBAC** | Admin, Tester, Auditor roles |
| C3 | **OPSEC Mode** | Rate limiting adaptif, traffic blending |
| C4 | **CVE Correlation** | Link findings ke NVD/CVE |
| C5 | **Exploit Chaining** | LLM suggest vuln chains dari findings |
| C6 | **API Schema Analysis** | OpenAPI/GraphQL introspection auto-analysis |
| C7 | **CI/CD Gate** | GitHub Actions security integration |

### Won't Have (saat ini)
| ID | Feature | Alasan |
|----|---------|--------|
| W1 | Post-exploitation / C2 | Di luar scope, beda threat model |
| W2 | Zero-day generation | Tidak etis tanpa disclosure |
| W3 | Cloud SaaS | Privacy-first, lokal dulu |
| W4 | Auto-submit laporan | Report selalu butuh human review |
| W5 | Engagement export/import | Ditunda — kebutuhan private saat ini |

---

## 4. System Architecture

### 4.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        PENTRA AI PLATFORM                            │
│                   (Self-hosted · Docker Compose)                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              WEB UI  (React + Vite + Tailwind + Shadcn)      │   │
│  │  Dashboard · Projects · Live Feed · Findings · KB · Reports  │   │
│  └──────────────────────────┬──────────────────────────────────┘   │
│                             │  WebSocket + REST API                   │
│  ┌──────────────────────────▼──────────────────────────────────┐   │
│  │               API GATEWAY  (FastAPI + Python)                 │   │
│  │          Auth (JWT) · Rate Limit · Logging · Scope Guard      │   │
│  └──────────┬──────────────────────────────────┬───────────────┘   │
│             │                                  │                      │
│  ┌──────────▼──────────────┐      ┌────────────▼──────────────┐    │
│  │      AGENT ENGINE        │      │     KNOWLEDGE ENGINE       │    │
│  │   (LangGraph + Ollama)   │      │                            │    │
│  │                          │      │  ┌──────────────────────┐  │    │
│  │  ┌────────────────────┐  │      │  │  Vector DB (Qdrant)   │  │    │
│  │  │   StateGraph        │  │◄─RAG─►  │  BGE-M3 Embeddings   │  │    │
│  │  │   Orchestrator      │  │      │  └──────────────────────┘  │    │
│  │  └──────────┬──────────┘  │      │  ┌──────────────────────┐  │    │
│  │             │             │      │  │  Ingestion Pipeline   │  │    │
│  │  ┌──────────▼──────────┐  │      │  │  H1 · Bugcrowd       │  │    │
│  │  │  Specialist Nodes    │  │      │  │  Writeups · Custom   │  │    │
│  │  │  Recon · Vuln        │  │      │  └──────────────────────┘  │    │
│  │  │  Exploit · Report    │  │      │  ┌──────────────────────┐  │    │
│  │  └──────────┬──────────┘  │      │  │  KB Browser API       │  │    │
│  │             │             │      │  │  (search, browse,     │  │    │
│  │  [HITL Gate]│             │      │  │   filter by class)    │  │    │
│  │  Pause → UI →│User approve │      │  └──────────────────────┘  │    │
│  └─────────────┼─────────────┘      └───────────────────────────┘    │
│                │                                                        │
│  ┌─────────────▼──────────────────────────────────────────────────┐  │
│  │                   TOOL INTEGRATION LAYER                         │  │
│  │  ┌─────────────┐  ┌──────────────────┐  ┌───────────────────┐  │  │
│  │  │ Burp Suite  │  │  OSS Wrappers     │  │  Custom (pentra-) │  │  │
│  │  │ Pro via MCP │  │  subfinder · nmap │  │  pentra-scope     │  │  │
│  │  │ Scanner     │  │  httpx · nuclei   │  │  pentra-payload   │  │  │
│  │  │ Proxy       │  │  ffuf · katana    │  │  pentra-report    │  │  │
│  │  │ Repeater    │  │  dalfox · sqlmap  │  │  pentra-dedup     │  │  │
│  │  │ Intruder    │  │  amass · naabu    │  │  pentra-chain     │  │  │
│  │  │ Collaborator│  └──────────────────┘  └───────────────────┘  │  │
│  │  └─────────────┘                                                 │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                         DATA LAYER                                │  │
│  │    PostgreSQL · Redis (Queue/Cache) · Qdrant (Vector) · MinIO    │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                      LLM LAYER (Ollama)                           │  │
│  │   Qwen2.5-Coder-32B · DeepSeek-R1-32B · BGE-M3 (embedding)      │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Tech Stack — Final

| Layer | Technology | Keputusan & Alasan |
|-------|-----------|---------------------|
| **Frontend** | React + Vite + Tailwind + Shadcn/ui | SPA/dashboard + heavy WebSocket — Vite lebih cocok dari Next.js untuk tool internal real-time |
| **Backend** | FastAPI (Python 3.11+) | Async native, typing kuat, ekosistem LLM/AI |
| **Agent Framework** | **LangGraph v1.2+** | Stateful graph, human-in-the-loop native, durable execution, fault tolerant — terbaik untuk pentest workflow |
| **LLM Runtime** | Ollama (OpenAI-compatible API) | Local, model-agnostic, semua model via satu endpoint |
| **Embedding Model** | **BGE-M3** (primary) | Hybrid search native (dense + sparse), 8192 token ctx, multilingual, 1.2GB — terbaik untuk RAG knowledge base |
| **Embedding Fallback** | nomic-embed-text | Lightweight (274MB) untuk mesin resource-terbatas |
| **Vector DB** | Qdrant | Self-hosted, hybrid search support, performa tinggi |
| **Task Queue** | Celery + Redis | Async tool execution, scheduling, retry |
| **Primary DB** | PostgreSQL | Relational, reliable, full-text search |
| **Object Storage** | MinIO | Screenshots & evidence, S3-compatible, self-hosted |
| **Reverse Proxy** | Nginx | SSL termination, static serving |
| **Containerization** | Docker Compose | Single command deploy |
| **Repo Management** | Monorepo (Turborepo) | Modular, shared types, satu clone semua service |
| **Burp Integration** | MCP — PortSwigger official | Official, Montoya API coverage, actively maintained |

---

## 5. Knowledge Engine — Detail Design

Knowledge Engine adalah komponen **paling diferensiasi** Pentra AI.

### 5.1 Philosophy

Tools pentest biasa hanya tahu common vulnerabilities dari template. Pentra AI Knowledge Engine menyimpan intelligence dari real-world findings:
- **Logic bugs** yang spesifik per aplikasi
- **Chained vulnerabilities** yang butuh multi-step thinking
- **Tech stack-specific patterns** dari ribuan reports
- **Business context** dari actual disclosures

### 5.2 Data Sources & Priority

| Source | Method | Volume Est. | Priority | Status |
|--------|--------|-------------|----------|--------|
| **reddelexc/h1-reports** | GitHub CSV | ~7,000 reports | P1 | Seed — mulai di sini |
| **H1 Hacktivity (public)** | GraphQL scraping | 50,000+ | P1 | Continuous update |
| **H1 REST API** | Official API | Structured meta | P1 | Supplementary |
| **Bugcrowd disclosures** | Web scraping | 10,000+ | P2 | v1.0 |
| **Intigriti Hall of Fame** | Web scraping | 5,000+ | P2 | v1.0 |
| **PayloadsAllThings** | GitHub API | Technique library | P1 | Import |
| **PortSwigger Research** | RSS + scraping | Articles | P2 | v1.0 |
| **Security writeup blogs** | RSS aggregation | 10,000+ | P2 | v1.0 |
| **NVD / CVE** | Official API | CVE correlation | P3 | v2.0 |
| **User custom inject** | Manual upload | User-specific | P1 | MVP |
| **Agent findings** | Internal auto-ingest | Continuous | P1 | MVP |

### 5.3 Pipeline Architecture

```
INGESTION
─────────
reddelexc CSV    ──┐
H1 GraphQL API    ─┤──► Raw Collector (async Python) ──► MinIO (raw storage)
H1 REST API       ─┤
User Upload       ─┘

PROCESSING
──────────
Raw Data ──► Parser & Extractor
                  │
                  ├── Structured fields (title, severity, tech_stack, etc.)
                  ├── LLM-assisted extraction:
                  │     key_insight, attack_technique, indicators, prerequisites
                  │     (via Qwen2.5-Coder-7B untuk efficiency)
                  └── Deduplication (hash + semantic similarity check)
                  │
                  ▼
         Structured Record ──► PostgreSQL (metadata + full text)
                  │
                  ▼
         BGE-M3 Embedding ──► Qdrant (dense + sparse vectors)

SERVING
───────
Agent Query ──► Hybrid Search (BGE-M3 dense + sparse + keyword FTS)
                    │
                    ▼
              Reranker (cross-encoder)
                    │
                    ▼
              Top-K Records ──► RAG inject ke LangGraph context
```

### 5.4 Knowledge Record Schema

```python
class KnowledgeRecord(BaseModel):
    # Identity
    id: UUID
    source: Literal["hackerone", "bugcrowd", "intigriti",
                     "writeup", "pentra_finding", "custom"]
    source_id: str
    source_url: str | None
    ingested_at: datetime
    updated_at: datetime

    # Vulnerability Classification
    title: str
    vuln_class: VulnClass       # Enum — lihat taxonomy di bawah
    vuln_subclass: str
    severity: Severity          # critical/high/medium/low/info
    cvss_score: float | None
    cvss_vector: str | None
    cve_id: str | None

    # Target Context
    program: str
    tech_stack: list[str]       # ["Ruby on Rails", "AWS S3", ...]
    platform_type: list[str]    # ["web", "api", "mobile", "cloud"]
    endpoint_pattern: str       # "/api/v{n}/users/{id}/*"
    http_method: list[str]
    auth_required: bool

    # Attack Intelligence
    attack_technique: str           # Human-readable summary
    attack_steps: list[str]         # Step-by-step reproduction
    payload_pattern: str | None
    indicators: list[str]           # Sinyal kehadiran bug ini
    prerequisites: list[str]        # Kondisi yang harus true
    what_tools_missed: str | None   # Kenapa scanner tidak deteksi

    # Chain & Impact
    chained_with: list[str]         # Vuln class yang sering digabung
    impact: str
    impact_category: list[str]      # ["account_takeover", "data_exfil", ...]
    bounty_usd: int | None

    # Learning
    key_insight: str                # "Aha moment" — 1-3 kalimat
    unique_factor: str              # Apa yang membuat ini non-obvious
    pentra_tags: list[str]

    # Embedding (BGE-M3)
    embedding_dense: list[float]    # Dense vector
    embedding_sparse: dict          # Sparse vector (lexical)
    embedding_model: str            # "bge-m3"
    embedding_version: int
```

### 5.5 VulnClass Taxonomy

```
ACCESS_CONTROL      → IDOR, BOLA, BFLA, PRIVILEGE_ESCALATION
INJECTION           → SQLi, XSS (Stored/Reflected/DOM/mXSS), XXE, SSTI, CMDi
AUTH                → AUTH_BYPASS, SESSION, OAUTH_MISCONFIG, JWT_ISSUES
SERVER_SIDE         → SSRF, PATH_TRAVERSAL, RCE, DESERIALIZATION
BUSINESS_LOGIC      → RACE_CONDITION, MASS_ASSIGNMENT, PARAM_POLLUTION, WORKFLOW_BYPASS
INFO_DISCLOSURE     → API_KEY_LEAK, PII_EXPOSURE, DEBUG_INFO, SOURCE_CODE
INFRASTRUCTURE      → SUBDOMAIN_TAKEOVER, CACHE_POISONING, CLOUD_MISCONFIG, CORS
GRAPHQL             → INTROSPECTION, QUERY_DEPTH, BATCH_ABUSE, FIELD_SUGGESTION
CRYPTOGRAPHY        → WEAK_ALGO, PADDING_ORACLE, TIMING_ATTACK
```

### 5.6 KB Browser — UI Design

```
┌─────────────────────────────────────────────────────────────┐
│  KNOWLEDGE BASE                         [+ Add Knowledge]   │
├─────────────────────────────────────────────────────────────┤
│  Search: [____________________________] [🔍 Search]          │
│                                                              │
│  Filter: Vuln Class ▼  Tech Stack ▼  Severity ▼  Source ▼  │
├──────────────────────────┬──────────────────────────────────┤
│  IDOR                 847 │  Result 1: IDOR on /api/v1/...  │
│  XSS                  623 │  Program: Shopify               │
│  Auth Bypass          412 │  Severity: High · $5,000        │
│  Business Logic       389 │  Stack: Rails, PostgreSQL       │
│  SSRF                 301 │                                  │
│  Mass Assignment      287 │  Key Insight:                   │
│  Race Condition       201 │  Numeric user ID exposed in     │
│  ...                      │  URL path. Auth check missing   │
│                           │  on object-level for v1 API.    │
│  By Tech Stack:           │                                  │
│  Ruby on Rails       1203 │  Attack Steps:                  │
│  Django               891 │  1. Auth as user A              │
│  Laravel              743 │  2. GET /api/v1/users/{id}      │
│  Express              612 │  3. Change id to user B's       │
│  Spring Boot          489 │  4. Response returns B's data   │
│                           │                                  │
│  By Program:              │  [View Full] [Add to Engagement]│
│  HackerOne            342 │                                  │
│  Shopify              218 │  Result 2: ...                  │
└──────────────────────────┴──────────────────────────────────┘
```

### 5.7 Knowledge Update Strategy

**Otomatis (Scheduled via Celery Beat):**
- Harian: scrape H1 Hacktivity untuk reports baru yang di-disclose
- Mingguan: scrape Bugcrowd, Intigriti, blog RSS feeds
- Monitor program: track program tertentu yang diminati user

**Manual (User-triggered):**
- Upload writeup: PDF, Markdown, atau URL
- Paste raw text dari report/blog
- Import JSON/CSV bulk
- Annotate dan approve agent findings

**Self-learning dari Engagement:**
- Setiap confirmed finding → ditawarkan untuk masuk KB
- User review dan annotate sebelum disimpan
- Technique berhasil → booster weight di retrieval ranking

---

## 6. Agent Architecture — LangGraph

LangGraph dipilih sebagai agent framework karena:
1. **Stateful** — pentest session persist across pause/resume
2. **Human-in-the-loop native** — pause di titik manapun, user approve, lanjut
3. **Durable execution** — agent resume dari state terakhir jika terjadi failure
4. **Graph-based** — conditional branching sesuai findings (temukan XSS → branch ke XSS validation node)
5. **Production-grade** — dipakai Klarna, LinkedIn, Replit, Elastic

### 6.1 Pentra AI StateGraph

```python
class PentraState(TypedDict):
    # Engagement context
    engagement_id: str
    target: Target
    scope: Scope
    mode: Literal["semi_auto", "agentic"]

    # Current phase
    current_phase: Literal["recon", "vuln_hunt", "exploit_val", "report"]
    phase_complete: bool

    # Accumulated data
    subdomains: list[Subdomain]
    open_ports: list[Port]
    tech_stack: list[str]
    endpoints: list[Endpoint]
    findings: list[Finding]

    # LLM reasoning
    pentest_plan: str
    current_hypothesis: str
    knowledge_context: list[KnowledgeRecord]  # RAG results

    # Human-in-the-loop
    awaiting_approval: bool
    pending_action: Action | None
    user_decision: Literal["approve", "skip", "modify"] | None

    # Execution history
    action_history: list[Action]
    tool_outputs: list[ToolOutput]
    messages: list[AnyMessage]
```

### 6.2 Graph Structure

```
START
  │
  ▼
[plan_engagement]          ← LLM buat pentest plan
  │
  ▼
[hitl_plan_review]         ← PAUSE jika semi_auto → user approve
  │
  ▼
┌─[recon_node]─────────────────────────────────────────────┐
│  subfinder → nmap → httpx → katana → tech fingerprint    │
│  → LLM analisis → Query Knowledge Engine (RAG)           │
│  → Generate hypotheses berdasarkan tech stack + KB       │
└──────────────────────────────────────┬───────────────────┘
                                       │
                              [hitl_recon_review]  ← PAUSE jika semi_auto
                                       │
                                       ▼
┌─[vuln_hunt_node]──────────────────────────────────────────┐
│  Burp MCP scan → Nuclei → Custom checks                   │
│  → LLM analyze per finding → KB similarity search        │
│  → Suggest manual tests berdasarkan KB patterns          │
└──────────────────────────────────────┬────────────────────┘
                                       │
                        [conditional_branch]
                        /              |              \
               has_findings      no_findings      needs_more_recon
                    │                 │                   │
                    ▼                 ▼                   │
      [exploit_validation_node]  [report_empty]      [recon_node]◄──┘
      Test payload → Confirm
      impact → Document evidence
                    │
           [hitl_exploit_review]  ← PAUSE selalu — destructive action
                    │
                    ▼
            [report_node]
            Generate draft (MD/PDF)
            → H1 format jika diminta
                    │
                    ▼
                  END
```

### 6.3 Human-in-the-Loop Implementation

```python
# Setiap HITL node menggunakan interrupt() dari LangGraph
def hitl_plan_review(state: PentraState):
    if state["mode"] == "semi_auto":
        # Pause eksekusi, kirim state ke UI via WebSocket
        ws_manager.broadcast({
            "type": "AWAITING_APPROVAL",
            "data": {
                "plan": state["pentest_plan"],
                "proposed_next": "Begin reconnaissance phase"
            }
        })
        # LangGraph interrupt — resume saat user respond
        interrupt("Awaiting user approval for pentest plan")

    return state  # agentic mode: langsung lanjut

# Di API endpoint:
@router.post("/engagement/{id}/approve")
async def approve_action(id: str, decision: Decision):
    # Resume LangGraph dari checkpoint
    await graph.aupdate_state(
        config={"configurable": {"thread_id": id}},
        values={"user_decision": decision.action}
    )
    await graph.ainvoke(None, config=...)
```

### 6.4 Knowledge RAG dalam Agent Loop

```python
async def query_knowledge_for_context(state: PentraState) -> list[KnowledgeRecord]:
    """
    Dipanggil setelah setiap phase untuk contextualize LLM reasoning.
    """
    query = build_query(
        tech_stack=state["tech_stack"],
        endpoints=state["endpoints"],
        current_hypothesis=state["current_hypothesis"]
    )

    results = await knowledge_engine.hybrid_search(
        query=query,
        filters={
            "tech_stack": state["tech_stack"],
            "severity": ["critical", "high"],
        },
        top_k=8
    )

    return results  # Inject ke LLM context sebagai "Known similar findings"
```

---

## 7. Tool Integration Layer

### 7.1 Burp Suite Pro via MCP

| Capability | Penggunaan di Pentra AI |
|-----------|------------------------|
| **Proxy History** | LLM analisis traffic pattern, discover undocumented endpoints |
| **Active Scanner** | Trigger scan post-recon, analisis findings di LangGraph |
| **Repeater via MCP** | LLM test modified request, iterate payload |
| **Intruder via MCP** | Structured fuzzing dikontrol agent |
| **Collaborator** | Deteksi SSRF, blind XSS, OOB interactions |
| **Sitemap** | Attack surface map awal untuk agent planning |

### 7.2 OSS Tool Wrappers

Setiap tool di-wrap dalam Python async class:
- Input validation + scope check sebelum eksekusi
- Output parsing → structured format ke PentraState
- Error handling + retry + timeout
- Rate limiting
- Real-time streaming ke WebSocket

| Tool | Fungsi | Output |
|------|--------|--------|
| subfinder | Subdomain enum | `{subdomain, source}` |
| amass | Deep OSINT subdomain | `{subdomain, ip, asn}` |
| nmap / naabu | Port scan | `{host, port, service, version}` |
| httpx | HTTP probe + tech detect | `{url, status, tech, title}` |
| nuclei | Template vuln scan | `{template_id, severity, matched, evidence}` |
| katana | Web crawl + endpoints | `{url, method, params, forms}` |
| ffuf / feroxbuster | Directory fuzzing | `{url, status, size}` |
| dalfox | XSS scan | `{url, param, payload, poc}` |
| ghauri / sqlmap | SQLi test | `{url, param, type, dbms}` |

### 7.3 Custom pentra-* Packages

| Package | Fungsi | Phase |
|---------|--------|-------|
| `pentra-scope` | Scope definition, validator, enforcer | MVP |
| `pentra-payload` | Context-aware payload gen via LLM | v1.0 |
| `pentra-report` | MD → PDF, H1 format builder | MVP |
| `pentra-dedup` | Cross-tool finding deduplication | MVP |
| `pentra-chain` | Vulnerability chaining suggester | v1.0 |
| `pentra-screenshot` | Headless Chromium evidence capture | v1.0 |
| `pentra-monitor` | Continuous scan scheduler + delta | v1.0 |

---

## 8. Web UI & UX

### 8.1 Stack: React + Vite + Tailwind + Shadcn/ui

Dipilih karena:
- **SPA + heavy WebSocket** — Pentra AI adalah internal tool, tidak butuh SSR/SEO
- **Vite** lebih cepat untuk dashboard real-time vs Next.js
- **Shadcn/ui** — composable, accessible, dark mode ready
- **Tailwind** — utility-first, konsisten dengan security tool aesthetic

### 8.2 Pages

| Page | Fungsi Utama | Route |
|------|-------------|-------|
| **Dashboard** | Overview engagements, recent findings, stats | `/` |
| **Workspaces** | Manage workspace per client/personal | `/workspaces` |
| **Engagement** | Setup, scope, mode, launch | `/engagements/:id` |
| **Live Feed** | Real-time agent log via WebSocket | `/engagements/:id/live` |
| **Recon** | Subdomain tree, port map, tech fingerprint viz | `/engagements/:id/recon` |
| **Findings** | List, filter, sort, severity, evidence | `/engagements/:id/findings` |
| **Knowledge Base** | Browse, search, filter, view details | `/knowledge` |
| **Reports** | Generate, preview, export | `/engagements/:id/reports` |
| **Settings** | LLM model, tool paths, API keys, notifications | `/settings` |
| **Users** | Manage users (admin only) | `/admin/users` |

### 8.3 Live Feed Design

```
┌──────────────────────────────────────────────────────────────┐
│  LIVE FEED — engagement: "target.com recon"    [⏸] [■ Stop] │
├──────────────────────────────────────────────────────────────┤
│  [14:32:01] 🔍 Recon Agent — starting subdomain enum         │
│  [14:32:02]  ↳ subfinder -d target.com -all -silent         │
│  [14:32:15]  ↳ ✓ Found 47 subdomains                        │
│  [14:32:15] 🔍 Running httpx on 47 subdomains...             │
│  [14:32:28]  ↳ ✓ 32 alive · 8 interesting                   │
│  [14:32:29] 🤖 LLM analyzing results...                      │
│  [14:32:31]  ↳ Detected Rails app on api.target.com          │
│  [14:32:31] 📚 Querying knowledge base...                     │
│  [14:32:32]  ↳ Found 8 similar H1 reports (Rails IDOR/Auth) │
│  [14:32:32]  ↳ Insight: "Check /api/v1/users/{id} for IDOR" │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  💡 Agent Suggestion                                  │   │
│  │  Based on Rails + REST API + numeric IDs found:      │   │
│  │  → Test IDOR on /api/v1/users/{id}/settings          │   │
│  │  → Check mass assignment on POST /api/v1/users       │   │
│  │  → Verify auth enforcement on v1 vs v2 endpoints     │   │
│  │                                                      │   │
│  │  Similar H1 reports: Shopify $5k · GitLab $3k        │   │
│  │                                                      │   │
│  │  [✓ Approve & Continue]  [✗ Skip]  [✏ Modify]        │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

### 8.4 UI Design Principles

- **Dark mode default** — sesuai target audience
- **Real-time first** — semua agent activity stream via WebSocket
- **Human in the loop** — approval UI tidak boleh blocking, mudah dismiss
- **Evidence-centric** — setiap finding link ke screenshot, raw req/res, timeline
- **Keyboard-friendly** — shortcut untuk approve/skip/stop (Space, Esc, S)

---

## 9. Data Model

### 9.1 Entity Relationships

```
User (admin/member)
  └── manages Workspace (1..*)
        └── Engagement (1..*)
              ├── Target (1..*)
              │     └── ScanJob (1..*)
              │           └── ToolOutput (1..*)
              ├── Finding (0..*)
              │     ├── Evidence (screenshot, req/res, poc)
              │     └── KnowledgeRef → KnowledgeRecord
              └── Report (0..*)

KnowledgeRecord (global, shared across all engagements)
AuditLog (append-only, per engagement)
```

### 9.2 Key Schemas

```python
class Engagement(BaseModel):
    id: UUID
    workspace_id: UUID
    name: str
    mode: Literal["semi_auto", "agentic"]
    status: Literal["planning", "active", "paused", "completed", "archived"]
    in_scope: list[str]       # domains, IPs, CIDRs
    out_of_scope: list[str]
    llm_model: str            # selected model
    langgraph_thread_id: str  # for state persistence/resume
    started_at: datetime | None
    completed_at: datetime | None

class Finding(BaseModel):
    id: UUID
    engagement_id: UUID
    title: str
    vuln_class: VulnClass
    severity: Severity
    cvss_score: float | None
    target_url: str
    http_method: str
    request_raw: str
    response_raw: str
    screenshot_path: str | None
    reproduction_steps: list[str]
    knowledge_refs: list[UUID]
    status: Literal["new", "confirmed", "false_positive", "duplicate", "reported"]
    discovered_by: str        # agent node name or "manual"
    discovered_at: datetime

class AuditLog(BaseModel):
    id: UUID
    engagement_id: UUID
    timestamp: datetime
    agent: str
    action_type: str
    action_detail: dict
    scope_validated: bool
    user_approved: bool | None  # None jika agentic mode
```

---

## 10. LLM Strategy

### 10.1 Model-Agnostic via OpenAI-Compatible API

```python
class LLMClient:
    """Abstraction layer — works with any OpenAI-compatible endpoint."""
    def __init__(self, base_url: str, model: str, api_key: str = "ollama"):
        self.client = AsyncOpenAI(base_url=base_url, api_key=api_key)
        self.model = model
```

User bisa pilih model apapun dari Settings UI. Platform tidak hardcode ke model tertentu.

### 10.2 Recommended Models

| Model | Size | VRAM (Q4) | Keunggulan | Best For |
|-------|------|-----------|-----------|----------|
| **Qwen2.5-Coder-32B** | 32B | ~20GB | SOTA coding + 128K context | Default — dev, code analysis, payload gen |
| **DeepSeek-R1-32B** | 32B | ~20GB | Chain-of-thought reasoning dalam | Planning, vuln analysis, chaining |
| **Qwen2.5-72B** | 72B | ~40GB | Lebih kuat semua task | High-end setup, multi-GPU |
| **Llama-3.3-70B** | 70B | ~40GB | Strong reasoning, open weight | Alternative high-end |
| **Qwen2.5-Coder-7B** | 7B | ~5GB | Cepat, resource ringan | Testing, low-end, LLM extraction pipeline |

### 10.3 Model Routing

```python
MODEL_ROUTING = {
    "planning":           "deepseek-r1:32b",      # deep reasoning
    "code_analysis":      "qwen2.5-coder:32b",    # code understanding
    "payload_generation": "qwen2.5-coder:32b",    # exploit craft
    "kb_extraction":      "qwen2.5-coder:7b",     # bulk processing
    "report_writing":     "qwen2.5:32b",           # natural language
    "quick_classify":     "qwen2.5-coder:7b",     # fast decisions
    "embedding":          "bge-m3",                # BGE-M3 via Ollama
}
```

---

## 11. Auth & User Management

### 11.1 Design

- **Single Admin** — user pertama yang register otomatis jadi admin
- **Admin dapat tambah user** — via Settings > Users
- **Roles minimal:**
  - `admin` — full access, user management, settings
  - `operator` — bisa create/run engagement, view semua findings
  - `viewer` — read-only, download report saja
- **Auth mechanism:** JWT token (access + refresh) via FastAPI
- **Session:** stored in PostgreSQL, expire setelah inactivity
- **Password:** bcrypt hashing, no external OAuth di MVP

### 11.2 User Management UI

```
Settings → Users
┌────────────────────────────────────────────────┐
│  USERS                          [+ Add User]   │
├────────────────────────────────────────────────┤
│  admin@pentra.local   admin    [active]        │
│  alice@pentra.local   operator [active] [Edit] │
│  bob@pentra.local     viewer   [active] [Edit] │
└────────────────────────────────────────────────┘
```

---

## 12. Security & Ethics Layer

### 12.1 Scope Enforcer — Non-Negotiable

Setiap action yang akan dieksekusi agent **harus melewati** `pentra-scope` validator:

```python
class ScopeEnforcer:
    """
    Hard gate — setiap tool call dan LLM action divalidasi.
    Return False = action di-block, user di-notifikasi.
    """
    def validate(self, action: Action, scope: Scope) -> ValidationResult:
        target = extract_target(action)

        if not self.is_in_scope(target, scope.in_scope):
            return ValidationResult(allowed=False, reason="OUT_OF_SCOPE")

        if self.is_explicitly_excluded(target, scope.out_of_scope):
            return ValidationResult(allowed=False, reason="EXPLICITLY_EXCLUDED")

        if action.is_destructive and not action.user_approved:
            return ValidationResult(allowed=False, reason="REQUIRES_APPROVAL")

        return ValidationResult(allowed=True)
```

### 12.2 Ethics Guardrails

1. Pentra AI hanya berjalan dengan **explicit scope input** — tidak ada scan tanpa definisi target
2. Semua data target tersimpan **lokal** — tidak ada sync cloud tanpa explicit user action
3. Audit log **append-only** — tidak bisa diedit atau dihapus
4. LLM inference **sepenuhnya lokal** via Ollama — tidak ada data keluar ke API eksternal
5. **Kill switch** — satu klik stop semua agents kapanpun
6. **Destructive actions** (eksploitasi aktif) selalu butuh user approval, bahkan di agentic mode

### 12.3 Legal Disclaimer

Pentra AI dirancang untuk:
- Authorized penetration testing dengan explicit written permission
- Bug bounty hunting dalam scope program terdaftar
- Security research pada sistem milik sendiri atau test environment

Penggunaan di luar konteks ini adalah tanggung jawab penuh pengguna.

---

## 13. Repository Structure

### 13.1 Monorepo Layout

```
pentra-ai/                              ← Root monorepo (Turborepo)
├── apps/
│   ├── web/                            ← React + Vite frontend
│   │   ├── src/
│   │   │   ├── pages/                  ← Route-based pages
│   │   │   ├── components/             ← Shared UI components
│   │   │   ├── hooks/                  ← Custom React hooks
│   │   │   ├── stores/                 ← State management (Zustand)
│   │   │   └── lib/                    ← API client, WS client, utils
│   │   ├── package.json
│   │   └── vite.config.ts
│   │
│   ├── api/                            ← FastAPI backend
│   │   ├── app/
│   │   │   ├── api/                    ← Route handlers
│   │   │   ├── core/                   ← Config, auth, middleware
│   │   │   ├── models/                 ← SQLAlchemy models
│   │   │   ├── schemas/                ← Pydantic schemas
│   │   │   └── services/               ← Business logic
│   │   └── pyproject.toml
│   │
│   └── worker/                         ← Celery workers
│       ├── tasks/
│       │   ├── knowledge_update.py     ← Scraping + ingestion tasks
│       │   ├── scan_scheduler.py       ← Continuous monitoring
│       │   └── report_gen.py           ← Async report generation
│       └── pyproject.toml
│
├── packages/
│   ├── pentra-knowledge/               ← Knowledge Engine service
│   │   ├── ingestion/                  ← Scrapers, parsers
│   │   ├── processing/                 ← LLM extraction, dedup
│   │   ├── storage/                    ← Qdrant + PostgreSQL layer
│   │   ├── retrieval/                  ← Hybrid search, reranker
│   │   └── api/                        ← Internal FastAPI router
│   │
│   ├── pentra-agent/                   ← LangGraph agent definitions
│   │   ├── graph/                      ← StateGraph, nodes, edges
│   │   ├── nodes/                      ← Recon, Vuln, Exploit, Report
│   │   ├── hitl/                       ← Human-in-the-loop handlers
│   │   └── prompts/                    ← System prompts per node
│   │
│   ├── pentra-tools/                   ← Tool wrappers
│   │   ├── burp/                       ← Burp Suite MCP client
│   │   ├── recon/                      ← subfinder, nmap, httpx, katana
│   │   ├── vuln/                       ← nuclei, dalfox, sqlmap
│   │   └── base.py                     ← AsyncToolWrapper base class
│   │
│   ├── pentra-scope/                   ← Scope enforcer
│   │   ├── validator.py
│   │   ├── models.py
│   │   └── exceptions.py
│   │
│   ├── pentra-report/                  ← Report generator
│   │   ├── templates/                  ← Jinja2 MD + PDF templates
│   │   ├── formatters/                 ← H1, Bugcrowd, generic format
│   │   └── generator.py
│   │
│   └── pentra-shared/                  ← Shared types & utils
│       ├── types/                      ← Pydantic models (shared)
│       ├── constants/                  ← VulnClass, Severity enums
│       └── utils/                      ← Common helpers
│
├── infra/
│   ├── docker/
│   │   ├── Dockerfile.api
│   │   ├── Dockerfile.web
│   │   └── Dockerfile.worker
│   ├── docker-compose.yml
│   ├── docker-compose.dev.yml
│   └── nginx/
│       └── nginx.conf
│
├── docs/
│   ├── PRD.md                          ← This document
│   ├── ARCHITECTURE.md
│   └── SETUP.md
│
├── scripts/
│   ├── seed_knowledge.py               ← Import initial H1 dataset
│   └── setup.sh                        ← First-run setup
│
├── turbo.json                          ← Turborepo config
├── package.json                        ← Root package (workspaces)
└── .env.example
```

---

## 14. Deployment & Infrastructure

### 14.1 Docker Compose

```yaml
services:
  nginx:
    image: nginx:alpine
    ports: ["443:443", "80:80"]
    volumes: [./infra/nginx/nginx.conf:/etc/nginx/nginx.conf, ./certs:/certs]

  web:
    build: {context: ., dockerfile: infra/docker/Dockerfile.web}
    environment: [VITE_API_URL=http://api:8000]

  api:
    build: {context: ., dockerfile: infra/docker/Dockerfile.api}
    environment:
      - DATABASE_URL=postgresql://pentra:${POSTGRES_PASSWORD}@db:5432/pentra
      - REDIS_URL=redis://redis:6379
      - QDRANT_URL=http://qdrant:6333
      - MINIO_URL=http://minio:9000
      - OLLAMA_URL=${OLLAMA_URL:-http://host.docker.internal:11434}
      - SECRET_KEY=${SECRET_KEY}

  worker:
    build: {context: ., dockerfile: infra/docker/Dockerfile.worker}
    command: celery -A app.worker worker -l info -Q default,knowledge,reports
    deploy: {replicas: 2}

  beat:
    build: {context: ., dockerfile: infra/docker/Dockerfile.worker}
    command: celery -A app.worker beat -l info

  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: pentra
      POSTGRES_USER: pentra
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes: [postgres_data:/var/lib/postgresql/data]

  redis:
    image: redis:7-alpine
    volumes: [redis_data:/data]

  qdrant:
    image: qdrant/qdrant:latest
    volumes: [qdrant_data:/qdrant/storage]

  minio:
    image: minio/minio:latest
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: ${MINIO_USER}
      MINIO_ROOT_PASSWORD: ${MINIO_PASSWORD}
    volumes: [minio_data:/data]

  # Ollama — opsional jika sudah running di host
  # ollama:
  #   image: ollama/ollama:latest
  #   runtime: nvidia   # uncomment jika GPU
  #   volumes: [ollama_data:/root/.ollama]
```

### 14.2 Hardware Requirements

| Tier | Spec | Model Support |
|------|------|---------------|
| **Minimum** | 16GB RAM, 8-core, no GPU | 7B model only — slow |
| **Recommended** | 32GB RAM, RTX 3090 24GB | 32B Q4 — comfortable |
| **Optimal** | 64GB RAM, RTX 4090 24GB | 32B full + headroom |
| **High-end** | 128GB RAM, 2× A100 80GB | 70B model production |

### 14.3 Storage Requirements

| Component | Size |
|-----------|------|
| LLM model 32B (Q4) | ~20GB |
| BGE-M3 embedding | ~1.2GB |
| nomic-embed-text (fallback) | ~274MB |
| Qdrant vectors (50K records) | ~2GB |
| PostgreSQL | ~1GB initial |
| MinIO (evidence, screenshots) | ~50GB+ |
| Knowledge raw data | ~5GB |
| **Total minimum** | **~80GB** |

---

## 15. Development Roadmap

### Phase 1 — Knowledge Foundation ← START HERE
**Duration:** 6–8 minggu  
**Goal:** Knowledge Engine live, data H1 terkumpul dan queryable

| Task | Package | Priority |
|------|---------|----------|
| Setup monorepo (Turborepo) | root | P1 |
| Import seed dataset (reddelexc CSV) | pentra-knowledge | P1 |
| Build parser & field extractor | pentra-knowledge | P1 |
| LLM extraction pipeline (key_insight, technique) | pentra-knowledge | P1 |
| BGE-M3 embedding via Ollama | pentra-knowledge | P1 |
| Qdrant setup + collection + indexing | pentra-knowledge | P1 |
| Hybrid search API (FastAPI) | pentra-knowledge | P1 |
| H1 GraphQL scraper (continuous) | worker | P1 |
| Manual knowledge inject API | pentra-knowledge | P1 |
| Basic CLI query interface | scripts | P2 |
| KB Browser UI (read-only) | web | P2 |

**Deliverable:** `pentra-knowledge` service running, 7,000+ seed records queryable via API + basic UI

---

### Phase 2 — Core Agent + Burp
**Duration:** 6–8 minggu  
**Goal:** LangGraph agent bisa orchestrate tools, Burp MCP connected

| Task | Package | Priority |
|------|---------|----------|
| LLM client abstraction (Ollama) | pentra-agent | P1 |
| LangGraph StateGraph setup | pentra-agent | P1 |
| Recon node (subfinder, nmap, httpx) | pentra-tools | P1 |
| pentra-scope enforcer | pentra-scope | P1 |
| Burp MCP connection + wrapper | pentra-tools/burp | P1 |
| Agent → Knowledge RAG integration | pentra-agent | P1 |
| HITL mechanism (WebSocket notify) | pentra-agent + api | P1 |
| PostgreSQL schema + migrations | api | P1 |
| Celery workers setup | worker | P1 |
| WebSocket real-time streaming | api | P1 |

**Deliverable:** CLI/API-driven agent yang bisa recon + query knowledge + HITL approval

---

### Phase 3 — Web UI + Project Management
**Duration:** 4–6 minggu  
**Goal:** Platform fully usable via browser

| Task | Package | Priority |
|------|---------|----------|
| React + Vite scaffold | web | P1 |
| Auth (JWT) — login, register admin | api + web | P1 |
| Dashboard + Engagement CRUD | web | P1 |
| Scope definition UI | web | P1 |
| Live Feed (WebSocket + HITL UI) | web | P1 |
| Findings list + detail + evidence | web | P1 |
| KB Browser (search + filter + view) | web | P1 |
| Basic Markdown report download | pentra-report | P2 |
| User management (admin) | web + api | P2 |

**Deliverable:** Pentra AI fully usable via browser end-to-end

---

### Phase 4 — Full Platform MVP
**Duration:** 4–6 minggu  
**Goal:** Production-ready dengan semua M-features + key S-features

| Task | Package | Priority |
|------|---------|----------|
| Full multi-node LangGraph (Vuln, Exploit, Report agents) | pentra-agent | P1 |
| Agentic mode (auto dengan safeguards) | pentra-agent | P1 |
| Nuclei integration + custom template gen | pentra-tools | P1 |
| PDF report (pentra-report) | pentra-report | P1 |
| H1 draft format output | pentra-report | P1 |
| Screenshot capture (headless Chromium) | pentra-tools | P1 |
| KB auto-update (Celery cron) | worker | P1 |
| KB self-learning dari findings | pentra-knowledge | P2 |
| Docker Compose full stack tested | infra | P1 |

**Deliverable:** Pentra AI v0.1 — end-to-end self-hosted AI pentest platform

---

## 16. Decision Log

### All Decisions — Final

| # | Decision | Choice | Rationale |
|---|---------|--------|-----------|
| D1 | Tool naming | `pentra-*` prefix | Consistent, identifiable, fleksibel |
| D2 | KB seed data | reddelexc dataset → build scraper | Start cepat, lalu continuous update |
| D3 | LLM model | Model-agnostic (OpenAI-compat) + recommend Qwen/DeepSeek 32B | Flexibility + privacy |
| D4 | Lisensi | Private (sementara) | IP protection selama development |
| D5 | KB update | Otomatis (cron) + manual + self-learn dari findings | Comprehensive, user-controlled |
| D6 | Deployment | Self-hosted lokal — privacy-first | Data tidak keluar mesin |
| D7 | Phase 1 | Knowledge Engine | Foundation paling kritis |
| D8 | Burp integration | Official PortSwigger MCP server | Official, maintained, full coverage |
| D9 | Repo structure | Monorepo (Turborepo) | Modular, maintainable, shared types |
| D10 | Frontend | React + Vite | SPA + heavy WebSocket = Vite > Next.js |
| D11 | Agent framework | **LangGraph v1.2+** | Stateful, HITL native, durable, production-proven |
| D12 | Embedding model | **BGE-M3** (primary) + nomic-embed-text (fallback) | Hybrid search native, terbaik untuk knowledge RAG |
| D13 | Auth system | Single admin + add users | Simple, multi-user tanpa over-engineering |
| D14 | KB Browser | Ada di UI — dedicated page | User harus bisa explore dan belajar dari KB |
| D15 | Engagement export | Ditunda — kebutuhan private saat ini | Revisit di v2.0 |

### Open Items (Future Discussion)

| # | Item | Target Version |
|---|------|----------------|
| F1 | Engagement export/import format | v2.0 |
| F2 | Team collaboration features | v2.0 |
| F3 | OPSEC mode detail design | v2.0 |
| F4 | Mobile app testing integration | v2.0 |
| F5 | Public open-source release strategy | TBD |

---

*Pentra AI PRD v0.2 — All Phase 1 decisions locked. Ready for technical spec and development.*

*Next step: Technical Specification Document — Phase 1: Knowledge Engine*
