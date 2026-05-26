# Pentra AI — Architecture Overview

> Privacy-first, self-hosted AI Security Research Platform.
> All LLM inference is local via Ollama — no data leaves the machine.

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Browser (SPA)                            │
│                React 18 + Vite + Tailwind + Shadcn/ui           │
│         http://localhost:5173  │  WebSocket live feed           │
└──────────────────────┬──────────────────────────────────────────┘
                       │ HTTP / WebSocket
┌──────────────────────▼──────────────────────────────────────────┐
│                    FastAPI (apps/api)                           │
│              Python 3.11+  │  SQLAlchemy 2 async               │
│                      :8000                                       │
│   ┌──────────────┬────────────────┬────────────────────────┐    │
│   │  Auth        │  Engagements   │  Knowledge Inject      │    │
│   │  JWT HS256   │  Findings      │  Payload Generator     │    │
│   │  /api/v1/    │  HITL Approve  │  Reports               │    │
│   └──────────────┴────────────────┴────────────────────────┘    │
└───────┬───────────────────────────┬─────────────────────────────┘
        │                           │
        │ SQLAlchemy async          │ httpx / Qdrant SDK
        ▼                           ▼
┌───────────────┐         ┌──────────────────┐
│ PostgreSQL 16 │         │   Qdrant          │
│  (metadata,   │         │  (dense + sparse  │
│   findings,   │         │   knowledge       │
│   audit logs) │         │   vectors)        │
└───────────────┘         └──────────────────┘
        │                           │
┌───────▼──────────────────────────────────────────────────────────┐
│                  Celery Worker (apps/worker)                      │
│                Python + Redis broker                              │
│   ┌────────────────┬─────────────────┬────────────────────────┐  │
│   │ embed_pending  │ h1_scraper      │ backup_postgresql       │  │
│   │ (BGE-M3 batch) │ (GraphQL + CSV) │ backup_qdrant          │  │
│   └────────────────┴─────────────────┴────────────────────────┘  │
└──────────────────────────────┬───────────────────────────────────┘
                               │ httpx
                    ┌──────────▼──────────┐
                    │     Ollama           │
                    │   (host machine)     │
                    │  bge-m3             │
                    │  qwen2.5-coder:*    │
                    │  deepseek-r1:*      │
                    └─────────────────────┘
```

---

## Component Map

| Component | Path | Role |
|-----------|------|------|
| **Frontend** | `apps/web/` | React SPA — engagement management, KB browser, HITL decisions, live feed |
| **API** | `apps/api/` | FastAPI REST + WebSocket server. Thin routing → service layer |
| **Worker** | `apps/worker/` | Celery async tasks: embedding, scraping, backups |
| **Knowledge Engine** | `packages/pentra-knowledge/` | BGE-M3 embedding, Qdrant upsert, hybrid search, LLM extraction |
| **Agent Engine** | `packages/pentra-agent/` | LangGraph StateGraph, HITL interrupt nodes (Phase 2) |
| **Tools** | `packages/pentra-tools/` | Async wrappers: subfinder, nmap, nuclei, ffuf, Burp MCP |
| **Scope Enforcer** | `packages/pentra-scope/` | Validates every target against engagement in-scope/out-of-scope before tool execution |
| **Report** | `packages/pentra-report/` | Markdown/PDF report generator |
| **Shared Types** | `packages/pentra-shared/` | Pydantic v2 models: `KnowledgeRecord`, `VulnClass`, `Severity`, etc. |
| **PostgreSQL** | Docker `db` | Primary relational store — workspaces, engagements, findings, audit logs |
| **Redis** | Docker `redis` | Celery broker + result backend |
| **Qdrant** | Docker `qdrant` | Vector DB — dense (1024-dim BGE-M3) + sparse (SPLADE-style) |
| **MinIO** | Docker `minio` | S3-compatible object storage — screenshots, evidence, daily backups |
| **Ollama** | Host machine | Local LLM inference server — all models accessed via OpenAI-compatible API |

---

## Knowledge Engine Pipeline

```
Raw Source (H1 CSV / GraphQL scrape / URL / file upload / manual)
         │
         ▼
   CSV/HTML Parser
         │
         ▼
   LLM Extraction (qwen2.5-coder:7b)
   → title, vuln_class, attack_technique,
     key_insight, indicators, attack_steps,
     pentra_tags
         │
         ▼
   PostgreSQL: knowledge_records row
   quality_score = calculate_quality_score()
         │
         ▼
   Celery: embed_pending_records task
         │
         ▼
   BGE-M3 via Ollama → dense[1024] + sparse{}
         │
         ▼
   Qdrant upsert (dense + sparse vectors + metadata payload)
         │
         ▼
   hybrid_search() ← query from agent or UI
   RRF fusion (dense + sparse) + quality_score boost
         │
         ▼
   KnowledgeRecord[] injected into LangGraph PentraState
```

---

## LangGraph Agent Flow (Phase 2)

```
START
  │
  ▼
plan_engagement_node         ← deepseek-r1:32b reasoning
  │
  ▼
hitl_plan_review             ← interrupt() if mode=semi_auto
  │
  ▼
recon_node                   ← subfinder + nmap + tech detect
  │  knowledge context injected here
  ▼
hitl_recon_review            ← interrupt() if mode=semi_auto
  │
  ▼
vuln_hunt_node               ← nuclei + ffuf + Burp active scan
  │                             all via pentra-tools wrappers
  ▼
hitl_exploit_review          ← ALWAYS interrupt() — approval required
  │
  ▼
report_node                  ← pentra-report Markdown/PDF
  │
  ▼
END
```

**HITL Resume Flow:**
1. Agent calls `interrupt({"type": "APPROVAL_REQUIRED", ...})`
2. LangGraph checkpoints state to PostgreSQL (via `AsyncPostgresSaver`)
3. WebSocket pushes `HITL_REQUIRED` event to frontend
4. User clicks Approve/Skip/Modify in the UI
5. Frontend sends `POST /api/v1/engagements/{id}/approve`
6. API calls `graph.ainvoke(None, config={"configurable": {"thread_id": id}})`
7. Agent resumes from the checkpoint

---

## Data Flow: Security Finding

```
Agent discovers potential vulnerability
         │
         ▼
pentra-scope validates target ∈ in_scope
         │ (raises ScopeViolationError if out of scope)
         ▼
Tool wrapper executes (e.g., nuclei, Burp repeater)
         │
         ▼
LLM analyzes response + KB context
         │
         ▼
Finding stored in PostgreSQL (findings table)
AuditLog written (audit_logs — append-only)
WebSocket event pushed to frontend
         │
         ▼
HITL interrupt → user reviews → approve/skip
         │
         ▼
report_node generates markdown report
```

---

## Database Schema (Key Tables)

```sql
workspaces        -- groups engagements per team/project
  id, name, owner_id, created_at

engagements       -- a single security engagement
  id, workspace_id, name, mode, status,
  in_scope[], out_of_scope[], llm_model,
  opsec_mode, request_jitter_ms,
  langgraph_thread_id

findings          -- confirmed vulnerabilities
  id, engagement_id, title, vuln_class,
  severity, cvss_score, target_url,
  request_raw, response_raw,
  reproduction_steps[], status

audit_logs        -- append-only agent action log
  id, engagement_id, actor, action,
  detail (jsonb), created_at

knowledge_records -- BGE-M3 indexed security knowledge
  id, source, title, vuln_class, severity,
  attack_technique, key_insight, indicators[],
  tech_stack[], quality_score,
  is_embedded, embedding_model

monitoring_alerts -- live security monitoring events
  id, engagement_id, alert_type, message,
  severity, is_read
```

---

## Security Properties

| Property | Implementation |
|----------|---------------|
| **Privacy** | 100% local LLM inference via Ollama — no data sent to external APIs |
| **Scope enforcement** | `pentra-scope` ScopeEnforcer validates every tool call before execution |
| **HITL for destructive actions** | `interrupt()` required before any exploit/modify action |
| **Audit trail** | Every agent action written to append-only `audit_logs` table |
| **Input validation** | Pydantic v2 on all API inputs |
| **Auth** | JWT HS256 with short-lived access tokens + refresh rotation |
| **Secrets** | All credentials via environment variables — never hardcoded |
| **Rate limiting** | Tool wrappers enforce per-tool timeouts and concurrency limits |

---

## Monorepo Structure (Turborepo)

```
pentra-ai/
├── apps/
│   ├── web/             React SPA (Vite, Tailwind, Shadcn/ui)
│   ├── api/             FastAPI backend
│   └── worker/          Celery workers
├── packages/
│   ├── pentra-knowledge/ Knowledge engine (embedding + search + extraction)
│   ├── pentra-agent/    LangGraph agent (Phase 2)
│   ├── pentra-tools/    Security tool wrappers
│   ├── pentra-scope/    Scope enforcement
│   ├── pentra-report/   Report generation
│   └── pentra-shared/   Shared Pydantic types
├── infra/
│   └── docker-compose.yml
└── docs/
    ├── PRD.md           Product Requirements Document
    ├── SETUP.md         This setup guide
    └── ARCHITECTURE.md  This document
```

---

## Technology Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| LLM runtime | Ollama | Privacy-first; OpenAI-compatible API; supports all required models |
| Embedding | BGE-M3 | State-of-the-art multilingual; produces both dense + sparse vectors |
| Vector DB | Qdrant | Native hybrid search (dense + sparse); production-grade; Docker-native |
| Agent framework | LangGraph | Native HITL interrupt pattern; PostgreSQL checkpointing; active maintenance |
| Web framework | FastAPI | Async-native; automatic OpenAPI docs; Pydantic integration |
| Frontend | Vite + React | Fast HMR; desktop-first security tooling; no SSR complexity |
| Package manager | uv (Python), pnpm (TS) | Speed and workspace support |
| Task queue | Celery + Redis | Battle-tested; rich scheduling; Flower monitoring |
