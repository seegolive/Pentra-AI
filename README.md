# Pentra AI

> The first self-hosted AI Security Research Platform that thinks like a seasoned bug bounty hunter — not a vulnerability scanner.

![Status](https://img.shields.io/badge/status-v1.0.0_stable-brightgreen)
![Tests](https://img.shields.io/badge/tests-556_passing-brightgreen)
![E2E](https://img.shields.io/badge/playwright-90_e2e-brightgreen)
![KB](https://img.shields.io/badge/knowledge_base-8%2C341_reports-blue)
![LLM](https://img.shields.io/badge/LLM-local_ollama-purple)
![Python](https://img.shields.io/badge/python-3.11+-green)
![License](https://img.shields.io/badge/license-private-red)

---

## What is Pentra AI?

Pentra AI is a **self-hosted AI Security Research Platform** built for penetration testers, bug bounty hunters, security researchers, and red teams. It combines:

- **Local LLM inference** via Ollama (Qwen2.5-Coder, DeepSeek-R1, pentra-ft fine-tune) — target data never leaves your machine
- **Knowledge from 8,341 real HackerOne public disclosures** — RAG-powered technique suggestions based on what actually works
- **Burp Suite Pro integration** via official PortSwigger MCP — deep web analysis as a first-class citizen
- **LangGraph multi-agent orchestration** — stateful, resumable pentest sessions with human-in-the-loop approval
- **Full web UI** — React dashboard with real-time live feed, finding management, knowledge browser, attack surface map, and report generation
- **Fine-tuned LLM (pentra-ft)** — Qwen2.5-Coder-7B trained on 8,309 H1 disclosures, validated superior to baseline on MSSQL/ASP.NET targets

Pentra AI is not a vulnerability scanner. It is an **AI research companion** that finds the bugs scanners miss.

---

## Current Status — v1.0.0

| Metric | Value |
|--------|-------|
| **Unit tests** | **556 passing** (225 pentra-tools + 156 pentra-agent + 25 pentra-knowledge + 27 apps/worker + 123 apps/api) |
| **E2E tests (Playwright)** | **90 passing** across 8 spec files |
| **Knowledge base** | **8,341 HackerOne reports** (embedded with BGE-M3, hybrid search) |
| **Agent capabilities** | SQLi, XSS, CORS, GraphQL, race condition, JWT alg:none, SSRF, IDOR, subdomain takeover, second-order SQLi |
| **Burp MCP** | Connected — proxy history analysis, active scan trigger, Collaborator |
| **Fine-tuned LLM** | pentra-ft (Qwen2.5-Coder-7B Q4_K_M, 4.4GB) — 8 confirmed vs 6 baseline on real targets |

---

## Why Pentra AI?

| Problem | How Pentra AI Solves It |
|---------|------------------------|
| Scanners miss IDOR, business logic, auth bypass | Knowledge Engine — RAG from 8,341 real H1 reports, suggests techniques per tech stack |
| LLM tools lose context between steps | LangGraph stateful sessions — persist across pause/resume via PostgreSQL checkpoints |
| 10+ tools with no coherent orchestration | Multi-agent pipeline — Recon → Triage → Vuln Hunt → Exploit Validation → Report |
| Senior researcher knowledge not accessible | "Similar bugs found at Shopify, GitLab, Uber" — grounded in real disclosures |
| Cloud AI = data leaves your machine | 100% local — Ollama LLM, self-hosted Qdrant, MinIO storage |
| No context on known CVEs | Automatic CVE enrichment via NVD API — correlates findings with public vulnerabilities |
| Manual surface tracking | Continuous monitoring — periodic recon snapshots with delta alerts |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                  WEB UI (React 18 + Vite + Tailwind + Shadcn/ui)     │
│  Dashboard · Live Feed · Findings · KB Browser · Reports             │
│  Attack Surface Map · Monitoring · API Vault · GF Patterns           │
│  Scan Wizard · Notification System · Admin Panel                     │
└──────────────────────────────┬───────────────────────────────────────┘
                               │ REST + WebSocket
┌──────────────────────────────▼───────────────────────────────────────┐
│                  API GATEWAY (FastAPI async)                         │
│  auth · setup · engagement · findings · knowledge · monitoring       │
│  report · h1 · admin · worker_health · internal (agent ↔ api)        │
└────────┬─────────────────────────────────────┬───────────────────────┘
         │ Celery tasks (Redis broker)         │ SQLAlchemy async
         │                                     │
┌────────▼────────────────┐      ┌─────────────▼────────────────────┐
│  CELERY WORKER          │      │  PERSISTENCE LAYER               │
│  (apps/worker)          │      │  PostgreSQL 16                   │
│  H1 scraper · KB embed  │      │    Engagements · Findings        │
│  Scan scheduler         │      │    KB records · Audit log        │
│  Monitoring snapshots   │      │    LangGraph checkpoints         │
└────────┬────────────────┘      │  Redis — Celery broker/backend   │
         │                       │  MinIO — screenshots · evidence  │
         │                       └──────────────────────────────────┘
         │
┌────────▼──────────────────────────────────────────────────────────┐
│  AGENT ENGINE (pentra-agent — LangGraph v1.2+)                    │
│                                                                   │
│  Nodes (StateGraph):                                              │
│    plan_node → recon_node → crawler_node → osint_node             │
│    → triage_node → vuln_hunt_node → report_node                   │
│                                                                   │
│  HITL interrupts: plan · recon · triage · vuln_hunt · report      │
│  Memory: per-engagement learnings (PostgreSQL)                    │
│  Arsenal: playbooks · scan_presets · incremental scanning         │
└────────┬───────────────────────────────┬──────────────────────────┘
         │                               │
┌────────▼──────────────┐   ┌───────────▼──────────────────────────┐
│  TOOL LAYER           │   │  KNOWLEDGE ENGINE (pentra-knowledge) │
│  (pentra-tools)       │   │  BGE-M3 + Qdrant (hybrid search)     │
│                       │   │  8,341 H1 Reports indexed            │
│  Recon:               │   │  NVD CVE enrichment                  │
│   subfinder · httpx   │   │  H1 program scope sync               │
│   nmap · katana       │   └──────────────────────────────────────┘
│   WAF profiler        │
│   rate limit detect   │   ┌──────────────────────────────────────┐
│   takeover detect     │   │  PAYLOAD ENGINE (pentra-payload)     │
│  Vuln:                │   │  Context-aware payload generation    │
│   nuclei · dalfox     │   │  Mutation engine                     │
│   sqlmap · ffuf       │   │  Auth bypass · SQLi · XSS payloads   │
│   gf patterns         │   └──────────────────────────────────────┘
│   cors/jwt/ssrf/      │
│   graphql/race-cond/  │
│   business-logic      │
│  Burp Suite Pro (MCP):│
│   proxy history       │
│   active scan         │
│   Collaborator OOB    │
│  Crawlers:            │
│   JS crawler          │
│   screenshot capture  │
└────────┬──────────────┘
         │
┌────────▼──────────────────────────────────────────────────────────┐
│  LLM LAYER (Ollama — fully local, no data leaves machine)         │
│  qwen2.5-coder:32b   — default reasoning + payload generation     │
│  deepseek-r1:32b     — deep reasoning (plan, triage)              │
│  qwen3:8b            — fast extraction (bulk KB processing)       │
│  bge-m3              — hybrid embedding (dense 1024 + sparse)     │
│  pentra-ft           — fine-tuned Qwen2.5-Coder-7B on 8,309 H1    │
└───────────────────────────────────────────────────────────────────┘
```

---

## Repository Structure

```
pentra-ai/                          ← Monorepo (Turborepo + uv workspaces)
├── apps/
│   ├── web/                        ← React + Vite frontend (Shadcn/ui)
│   ├── api/                        ← FastAPI backend (async, SQLAlchemy 2)
│   └── worker/                     ← Celery workers (tasks, H1 scraping, scheduling)
├── packages/
│   ├── pentra-knowledge/           ← Knowledge Engine (H1 pipeline, BGE-M3, Qdrant RAG)
│   ├── pentra-agent/               ← LangGraph agent orchestration (HITL, state, nodes)
│   ├── pentra-tools/               ← Tool wrappers (Burp MCP, nmap, nuclei, ffuf, dalfox…)
│   ├── pentra-scope/               ← Scope enforcer (all tool calls validated)
│   ├── pentra-report/              ← Report generator (Markdown, HTML, PDF, H1 format)
│   └── pentra-shared/              ← Shared Pydantic types & enums
├── infra/
│   ├── docker/                     ← Dockerfiles per service
│   └── docker-compose.yml
├── docs/
│   └── PRD.md                      ← Full Product Requirements Document
├── scripts/
│   ├── seed_knowledge.py           ← Import H1 dataset
│   └── setup.sh                    ← First-run setup
├── CLAUDE.md                       ← AI coding instructions (Claude Code)
└── PROGRESS.md                     ← Sprint-by-sprint development log
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18 + Vite 5 + Tailwind CSS 3 + Shadcn/ui |
| Backend | FastAPI + Python 3.11+ + SQLAlchemy 2 (async) |
| Agent Framework | LangGraph v1.2+ (StateGraph + AsyncPostgresSaver) |
| LLM Runtime | Ollama (OpenAI-compatible local API) |
| Fine-tuned LLM | pentra-ft — Qwen2.5-Coder-7B trained on 8,309 H1 disclosures |
| Embedding Model | BGE-M3 (hybrid: dense 1024-dim + sparse SPLADE) |
| Vector DB | Qdrant (hybrid search — dense + sparse) |
| Task Queue | Celery + Redis |
| Primary DB | PostgreSQL 16 (also LangGraph checkpoint store) |
| Object Storage | MinIO (screenshots, evidence) |
| Burp Integration | PortSwigger official MCP extension (v2025+) |
| Containerization | Docker Compose |
| Package Manager | uv (Python) · pnpm (TypeScript) |
| Build System | Turborepo |

---

## Features

### Agent Pipeline

The core of Pentra AI — a stateful LangGraph graph that runs the full pentest lifecycle:

1. **Plan** — LLM analyzes scope, suggests attack phases, queries knowledge base
2. **Recon** — subfinder, httpx, nmap, katana, JS crawler, tech detection
3. **Triage** — two-stage verification (HTTP re-probe + LLM gate), deduplication
4. **Vuln Hunt** — RAG-guided technique selection, nuclei, dalfox, sqlmap, gf, Burp
5. **Exploit** — payload generation, CVE correlation, Burp Collaborator
6. **Report** — Markdown, HTML, PDF, H1-format JSON, LLM executive summary

Every phase has a **Human-in-the-Loop (HITL)** checkpoint in semi-auto mode. The graph state persists to PostgreSQL so you can pause, resume, or modify mid-engagement.

### Knowledge Engine

- **8,341 HackerOne public reports** indexed with BGE-M3 hybrid embeddings
- **Hybrid search** — dense cosine similarity + sparse lexical (SPLADE-style)
- **LLM-extracted fields** — `key_insight`, `attack_technique`, `indicators` per report
- **CVE enrichment** — automatic NVD API correlation for known vulnerabilities
- **H1 scope import** — `GET /api/v1/h1/programs/{handle}/scope` fetches live bug bounty scope

### Security Tools

| Tool | Purpose |
|------|---------|
| subfinder | Subdomain enumeration |
| httpx | HTTP probing + tech detection |
| nmap | Port scan + service fingerprint |
| katana + JS crawler | Endpoint discovery + JS analysis |
| nuclei | Template-based vuln scan |
| dalfox | XSS detection + exploitation |
| sqlmap | SQLi detection + exploitation |
| ffuf | Directory/parameter fuzzing |
| gf | Grep For patterns (secrets, params) |
| Burp Suite Pro | Full web proxy + active scan + Collaborator |

### Web UI Highlights

- **Live Feed** — real-time WebSocket stream of agent events per engagement
- **Attack Surface Map** — visual subdomain/port/tech stack with subscan trigger
- **Finding Management** — severity badges, CVSS scores, HTTP request/response viewer
- **Knowledge Browser** — search 8,341 H1 reports by tech stack, vuln class, keyword
- **Report Viewer** — inline Markdown preview + download (MD, HTML, PDF, H1, H1 Executive)
- **API Vault** — discovered API endpoints with parameter analysis
- **GF Patterns** — grep-for secrets/params/endpoints viewer
- **Monitoring Panel** — continuous monitoring alerts, snapshot diff (new/removed hosts), schedule config
- **Scan Wizard** — step-by-step engagement creation with H1 scope import
- **Notification System** — real-time alerts for new findings

### Continuous Monitoring

Set up periodic recon re-runs per engagement:
- Configurable interval (6h, 12h, 24h, 48h, 72h, weekly)
- Automatic delta detection (new subdomains, new ports, new endpoints, tech changes)
- Alert feed with read/unread state
- Snapshot diff viewer comparing any two recon runs

---

## Quick Start

### Prerequisites

| Requirement | Notes |
|-------------|-------|
| Docker + Docker Compose | All services except Ollama |
| Ollama | Runs on host (GPU recommended) |
| Burp Suite Professional 2025.x+ | With MCP Server extension from BApp Store |
| NVIDIA GPU (recommended) | RTX 3090+ (24GB VRAM) for 32B models |

### 1. Pull LLM models

```bash
ollama pull bge-m3                  # Embedding model (required)
ollama pull qwen2.5-coder:32b       # Default reasoning LLM
ollama pull deepseek-r1:32b         # Deep reasoning LLM
ollama pull qwen3:8b                # Fast extraction LLM
```

### 2. Install Burp MCP Extension

1. Open Burp Suite Professional
2. **Extensions → BApp Store → "MCP Server"** (PortSwigger official)
3. Install + enable → MCP server binds to `http://127.0.0.1:9876`
4. Set `BURP_MCP_URL=http://172.31.192.1:9876` in `.env` (WSL2 host IP)

### 3. Clone and configure

```bash
git clone https://github.com/seegolive/pentra-ai.git
cd pentra-ai

cp .env.example .env
# Edit .env — minimum required:
#   POSTGRES_PASSWORD=strong-password
#   SECRET_KEY=32-char-random-string
#   BURP_MCP_URL=http://<your-host-ip>:9876
```

### 4. Start services

```bash
docker compose up -d
```

| Service | URL |
|---------|-----|
| Web UI | `https://localhost` |
| API | `http://localhost:8000` |
| API Docs | `http://localhost:8000/docs` |
| Qdrant Dashboard | `http://localhost:6333/dashboard` |
| MinIO Console | `http://localhost:9001` |

### 5. Seed the Knowledge Base

```bash
docker compose exec api uv run python scripts/seed_knowledge.py
```

Imports ~8,300 HackerOne public reports, extracts insights via LLM, generates BGE-M3 embeddings, and indexes into Qdrant. ETA: 2–4 hours with GPU.

### 6. Create your first engagement

1. Open `https://localhost` → Register (first user = admin)
2. **New Workspace → New Engagement**
3. Define scope — paste domains/IPs, or use "Import H1 Scope" for bug bounty programs
4. Select mode: **Semi-auto** (recommended) or **Agentic**
5. Select LLM model
6. Click **Launch**

---

## Operation Modes

### Semi-Automatic (Recommended)

Agent proposes each action and waits for your approval before executing.

```
Agent → "Found Rails app on api.target.com
         Based on 12 similar H1 reports, I suggest testing mass assignment on
         POST /api/v1/users (H1 $4,200 Shopify, H1 $2,800 Airbnb)
         Proposed: send modified request with extra fields"

You → [Approve] [Skip] [Modify]
```

### Fully Agentic

Agent executes the full pipeline autonomously within scope. Rate limiting and scope enforcement always active. Destructive actions (active exploitation) always pause for approval regardless of mode.

---

## Hardware Requirements

| Tier | Spec | For |
|------|------|-----|
| Minimum | 16GB RAM, 8-core CPU | 7B model (pentra-ft / qwen3:8b) |
| Recommended | 32GB RAM, RTX 3090 (24GB VRAM) | 32B Q4 — daily use |
| Optimal | 64GB RAM, RTX 4090 (24GB VRAM) | 32B full precision |
| High-end | 128GB RAM, 2× A100 | 70B model |

---

## Development

```bash
# Install all dependencies
uv sync                            # Python (all packages)
pnpm install                       # TypeScript (frontend)

# Start dev servers
turbo dev                          # All services with hot reload

# Individual services
cd apps/api && uv run fastapi dev app/main.py --port 8000
cd apps/web && pnpm dev            # Vite on :5173

# Run all tests
turbo test

# Per-package tests
cd apps/api && uv run pytest -q               # 98 tests
cd packages/pentra-tools && uv run pytest -q  # 225 tests
cd packages/pentra-agent && uv run pytest -q  # 156 tests

# Database migrations
cd apps/api && uv run alembic upgrade head
cd apps/api && uv run alembic revision --autogenerate -m "description"

# Code quality
cd apps/api && uv run ruff check . && uv run ruff format . && uv run mypy .
cd apps/web && pnpm lint && pnpm type-check
```

---

## Development Progress

### Completed

| Phase | Description | Status |
|-------|-------------|--------|
| **Phase 1 — Knowledge Engine** | H1 pipeline, BGE-M3 embeddings, Qdrant hybrid search, RAG API, KB Browser UI | ✅ Complete |
| **Phase 2 — Agent Engine** | LangGraph StateGraph, HITL approval, Burp MCP integration, scope enforcer, all tool wrappers, 17 sprint iterations | ✅ Complete |
| **Phase 3 — Web UI** | React dashboard, live feed, findings, KB browser, reports, attack surface map, monitoring, API vault | ✅ Complete |
| **Phase 4 — Full MVP** | Multi-agent, CVE correlation, fine-tuned LLM, PDF reports, H1 submission format, continuous monitoring | ✅ Complete |

### Sprint History (Selected)

| Sprint | Milestone |
|--------|-----------|
| Sprint 1–12 | Core knowledge engine, agent graph, tool wrappers, scope enforcer |
| Sprint 13–17 | HITL, Burp MCP, DO-NOT-STOP routing, frontend BLOK 1–6 |
| Sprint 18–19 | CVE enrichment, report generation (MD/HTML/PDF/H1), H1 scope import |
| Sprint 20–24 | Attack surface map, monitoring panel, snapshot diff, alert system |
| Sprint 25–29 | Workspace isolation, admin panel, rate limiting, pentra-ft fine-tuning |
| Sprint 30–32 | UI polish, design system tokens, scan wizard, GF patterns, trends charts |
| Sprint 33 | Code review follow-up: cross-worker cancel, rate limit tiers, schedule persistence |
| Sprint 34 | Report endpoint security audit: auth added, settings attrs fixed |
| Sprint 35 | NameError fix (monitoring router), 26 new tests for internal + monitoring endpoints |

### Current Metrics

```
Unit tests:     531 (0 failed) — pentra-tools 225, pentra-agent 156,
                                 apps/api 98, apps/worker 27, pentra-knowledge 25
Playwright E2E: 90 (0 failed) — 8 spec files
Knowledge base: 8,341 HackerOne reports (BGE-M3 embedded, Qdrant indexed)
API endpoints:  Full CRUD for engagements, findings, KB, reports, monitoring
Git tag:        v1.0.0 (main branch)
```

See `PROGRESS.md` for the complete sprint-by-sprint log.

---

## Security & Ethics

Pentra AI is built for **authorized security testing only**.

- All LLM inference is local — target data never leaves your machine
- Every tool call is validated against the defined engagement scope before execution
- Audit log is append-only — full traceability of all agent actions
- Destructive actions (active exploitation) always require explicit user approval
- Kill switch (`/stop`) halts all running agent tasks immediately
- Rate limiting per client — scan-heavy endpoints capped at 5 req/min
- Internal agent API uses shared-secret token, not exposed to end users

**Only use Pentra AI against systems you own or have explicit written permission to test.**

---

## For AI Coding Assistants

This repository includes complete instructions for AI coding agents:

- **`CLAUDE.md`** — loaded automatically by Claude Code on every session
- **`PROGRESS.md`** — complete sprint history and current development state
- **`docs/PRD.md`** — full Product Requirements Document with decision log

If you are an AI assistant reading this: start with `CLAUDE.md`, then `docs/PRD.md`, then `PROGRESS.md` for current context.

---

## License

Private — All rights reserved.

---

*Pentra AI — Built for researchers, by researchers.*
