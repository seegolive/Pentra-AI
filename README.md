# Pentra AI

> The first self-hosted AI Security Research Platform that thinks like a seasoned bug bounty hunter — not a vulnerability scanner.

![Status](https://img.shields.io/badge/status-active_development-orange)
![Phase](https://img.shields.io/badge/phase-1_knowledge_engine-blue)
![License](https://img.shields.io/badge/license-private-red)
![Python](https://img.shields.io/badge/python-3.11+-green)
![LLM](https://img.shields.io/badge/LLM-ollama_local-purple)

---

## What is Pentra AI?

Pentra AI is a **self-hosted AI Security Research Platform** built for penetration testers, bug bounty hunters, security researchers, and red teams. It combines:

- **Local LLM inference** via Ollama (Qwen, DeepSeek, and any OpenAI-compatible model) — data never leaves your machine
- **Knowledge from 50,000+ real HackerOne/Bugcrowd public disclosures** — RAG-powered technique suggestions based on what actually works
- **Burp Suite Pro integration** via official PortSwigger MCP — deep web analysis as a first-class citizen
- **LangGraph multi-agent orchestration** — stateful, resumable pentest sessions with human-in-the-loop approval
- **Full web UI** — React dashboard with real-time live feed, finding management, knowledge browser, and report generation

Pentra AI is not a vulnerability scanner. It is an **AI research companion** that helps you find the bugs that scanners miss.

---

## Why Pentra AI?

| Problem | How Pentra AI Solves It |
|---------|------------------------|
| Scanners miss IDOR, business logic, auth bypass | Knowledge Engine — learns from 50K+ real H1 reports, suggests techniques based on tech stack |
| LLM tools lose context between steps | LangGraph stateful sessions — persist across pause/resume, cross-session memory |
| 10+ tools with no coherent orchestration | Multi-agent pipeline — Recon → Vuln Hunt → Exploit Validation → Report, all connected |
| Senior researcher knowledge not accessible | RAG-powered technique suggestion — "similar bugs found at Shopify, GitLab, Uber" |
| Cloud AI = data leaves your machine | 100% local — Ollama LLM, self-hosted vector DB, MinIO storage |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│              WEB UI (React + Vite)                   │
│   Dashboard · Live Feed · Findings · KB · Reports   │
└─────────────────────┬───────────────────────────────┘
                      │ WebSocket + REST
┌─────────────────────▼───────────────────────────────┐
│              API GATEWAY (FastAPI)                   │
└──────────┬──────────────────────────┬───────────────┘
           │                          │
┌──────────▼──────────┐  ┌───────────▼───────────────┐
│    AGENT ENGINE      │  │    KNOWLEDGE ENGINE        │
│    (LangGraph)       │◄─┤    BGE-M3 + Qdrant        │
│                      │  │    H1/Bugcrowd RAG        │
│  Recon → Vuln Hunt   │  └───────────────────────────┘
│  → Exploit → Report  │
│  [HITL approval]     │
└──────────┬───────────┘
           │
┌──────────▼───────────────────────────────────────┐
│              TOOL INTEGRATION LAYER               │
│  Burp Suite Pro (MCP) · nmap · nuclei · ffuf     │
│  subfinder · httpx · dalfox · sqlmap · katana    │
└──────────────────────────────────────────────────┘
           │
┌──────────▼───────────────────────────────────────┐
│              LLM LAYER (Ollama)                   │
│  Qwen2.5-Coder-32B · DeepSeek-R1-32B · BGE-M3   │
└──────────────────────────────────────────────────┘
```

---

## Repository Structure

```
pentra-ai/                          ← Monorepo (Turborepo)
├── apps/
│   ├── web/                        ← React + Vite frontend
│   ├── api/                        ← FastAPI backend
│   └── worker/                     ← Celery workers (tasks, scraping)
├── packages/
│   ├── pentra-knowledge/           ← Knowledge Engine (H1 pipeline, RAG)
│   ├── pentra-agent/               ← LangGraph agent orchestration
│   ├── pentra-tools/               ← Tool wrappers (Burp, nmap, nuclei…)
│   ├── pentra-scope/               ← Scope enforcer
│   ├── pentra-report/              ← Report generator (MD, PDF, H1 format)
│   └── pentra-shared/              ← Shared Pydantic types & enums
├── infra/
│   ├── docker/                     ← Dockerfiles per service
│   └── docker-compose.yml
├── docs/
│   └── PRD.md                      ← Full Product Requirements Document
├── scripts/
│   ├── seed_knowledge.py           ← Import initial H1 dataset
│   └── setup.sh                    ← First-run setup
└── CLAUDE.md                       ← AI coding instructions (Copilot/Claude Code)
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18 + Vite 5 + Tailwind CSS + Shadcn/ui |
| Backend | FastAPI + Python 3.11+ + SQLAlchemy 2 (async) |
| Agent Framework | LangGraph v1.2+ |
| LLM Runtime | Ollama (OpenAI-compatible API) |
| Embedding Model | BGE-M3 (hybrid: dense + sparse) |
| Vector DB | Qdrant |
| Task Queue | Celery + Redis |
| Primary DB | PostgreSQL 16 |
| Object Storage | MinIO (screenshots, evidence) |
| Burp Integration | PortSwigger official MCP extension |
| Containerization | Docker Compose |
| Package Manager | uv (Python) · pnpm (TypeScript) |

---

## Quick Start

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Docker + Docker Compose | Latest | For all services |
| Ollama | Latest | Runs on host machine |
| Burp Suite Professional | 2025.x+ | With MCP extension installed |
| GPU (recommended) | RTX 3090+ (24GB VRAM) | For 32B models |

### 1. Install Ollama and pull models

```bash
# Install Ollama: https://ollama.ai
ollama pull bge-m3                  # Embedding model (required)
ollama pull qwen2.5-coder:32b       # Default LLM
ollama pull deepseek-r1:32b         # Reasoning LLM
ollama pull qwen2.5-coder:7b        # Fast LLM (for bulk extraction)
```

### 2. Install Burp Suite MCP Extension

1. Open Burp Suite Professional
2. Go to **Extensions → BApp Store**
3. Search for **"MCP Server"** (by PortSwigger)
4. Install and enable — MCP server starts on `http://127.0.0.1:9876`

### 3. Clone and configure

```bash
git clone https://github.com/your-org/pentra-ai.git
cd pentra-ai

# Copy environment config
cp .env.example .env

# Edit .env — minimum required changes:
# POSTGRES_PASSWORD=your-strong-password
# SECRET_KEY=your-32-char-secret-key
```

### 4. Start services

```bash
docker compose up -d
```

Services started:
- Web UI: `https://localhost`
- API: `http://localhost:8000`
- Qdrant UI: `http://localhost:6333/dashboard`
- MinIO Console: `http://localhost:9001`

### 5. Seed the Knowledge Base

```bash
# Import initial HackerOne dataset (~7,000 public reports)
docker compose exec api uv run python scripts/seed_knowledge.py

# This will:
# 1. Download reddelexc/hackerone-reports dataset
# 2. Parse and structure all records
# 3. Extract key_insight and attack_technique via LLM
# 4. Generate BGE-M3 embeddings
# 5. Index into Qdrant for hybrid search
# ETA: ~2-4 hours depending on GPU
```

### 6. Create your first engagement

1. Open `https://localhost`
2. Register admin account (first user = admin)
3. Create **New Workspace** → **New Engagement**
4. Define scope (domains, IP ranges)
5. Select mode: **Semi-auto** (recommended) or **Agentic**
6. Select LLM model
7. Click **Launch**

---

## Operation Modes

### Semi-Automatic (Recommended)

Agent suggests each action and waits for your approval before executing. You stay in control at every step.

```
Agent: "Found Rails app on api.target.com
        Based on 8 similar H1 reports, I suggest testing IDOR on /api/v1/users/{id}
        Similar bugs: Shopify ($5,000) · GitLab ($3,000)"

You: [Approve] → Agent executes → shows results → suggests next step
```

### Fully Agentic

Agent executes the full pentest pipeline autonomously. Scope enforcement and rate limiting are always active. Destructive actions (active exploitation) always pause for approval regardless of mode.

---

## Hardware Requirements

| Tier | Spec | Recommended For |
|------|------|----------------|
| Minimum | 16GB RAM, 8-core CPU | 7B model only, slow |
| Recommended | 32GB RAM, RTX 3090 (24GB VRAM) | 32B Q4 — daily use |
| Optimal | 64GB RAM, RTX 4090 (24GB VRAM) | 32B full precision |
| High-end | 128GB RAM, 2× A100 | 70B model |

---

## Development

```bash
# Install dependencies
uv sync                          # Python (all packages)
pnpm install                     # TypeScript (frontend)

# Start dev servers
turbo dev                        # All services with hot reload

# Individual services
cd apps/api && uv run fastapi dev app/main.py --port 8000
cd apps/web && pnpm dev

# Run tests
turbo test                       # All
cd packages/pentra-knowledge && uv run pytest

# Database migrations
cd apps/api && uv run alembic upgrade head
cd apps/api && uv run alembic revision --autogenerate -m "description"

# Linting & formatting
turbo lint
cd apps/api && uv run ruff check . && uv run ruff format .
cd apps/web && pnpm lint && pnpm type-check
```

---

## Development Roadmap

| Phase | Status | Goal |
|-------|--------|------|
| **Phase 1 — Knowledge Engine** | 🔄 Active | H1 pipeline, BGE-M3, Qdrant, RAG API, KB Browser |
| **Phase 2 — Core Agent + Burp** | ⏳ Pending | LangGraph, Ollama, Burp MCP, scope enforcer |
| **Phase 3 — Web UI** | ⏳ Pending | React dashboard, live feed, findings, reports |
| **Phase 4 — Full MVP** | ⏳ Pending | Multi-agent, agentic mode, PDF reports, H1 integration |

See `docs/PRD.md` for complete product requirements, architecture decisions, and detailed roadmap.

---

## Security & Ethics

Pentra AI is built for **authorized security testing only**.

- All LLM inference is local — target data never leaves your machine
- Every agent action is validated against the defined engagement scope
- Audit log is append-only — full traceability of all actions
- Destructive actions always require explicit user approval
- Kill switch available at any time from the UI

**Only use Pentra AI against systems you own or have explicit written permission to test.**

---

## For AI Coding Assistants

This repository includes full instructions for AI coding agents:

- **`CLAUDE.md`** — loaded automatically by Claude Sonnet 4.6 (GitHub Copilot) and Claude Code
- **`.github/copilot-instructions.md`** — always-on Copilot context
- **`.github/instructions/*.instructions.md`** — path-specific instructions per package

If you are an AI assistant reading this: start with `CLAUDE.md`, then `docs/PRD.md`.

---

## License

Private — All rights reserved.

---

*Pentra AI — Built for researchers, by researchers.*
