# Changelog

All notable changes to Pentra AI are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [1.0.0] — 2026-06-04

### Phase 2 — Agent Engine (Complete)

#### Added
- LangGraph `StateGraph` with `AsyncPostgresSaver` checkpointing (`pentra-agent`)
- Human-in-the-loop (HITL) interrupt pattern via `langgraph.types.interrupt()`
- Agent nodes: `plan`, `hitl_plan`, `recon`, `hitl_recon`, `vuln_hunt`, `hitl_exploit`, `report`
- `hunt_rounds` loop with `route_after_triage()` — DO-NOT-STOP routing (6/6 tests passing)
- Scope enforcer (`pentra-scope`) — validates every tool target before execution
- Tool wrappers: subfinder, nmap, nuclei, ffuf, httpx (`pentra-tools`)
- Burp Suite MCP integration (`pentra-tools/burp`) — proxy history, Repeater, active scan
- Audit log on every agent action (`audit_logs` table, append-only)
- WebSocket live feed with Redis bridge — `NODE_START`, `NODE_COMPLETE`, `LLM_STREAM`, `AWAITING_APPROVAL`, `FINDINGS_UPDATED` events
- `GET /api/v1/findings/recent` endpoint — cross-engagement recent findings
- `GET /api/v1/version` endpoint — API version + build info
- `POST /api/v1/auth/change-password` endpoint

#### Frontend — Block 6 (Complete)
- Dashboard page with stat cards, recent engagements, recent findings
- Engagement Detail: Live Feed with LLM stream token grouping (collapsible)
- Engagement Detail: breadcrumb with workspace name + Engagements link
- Engagement Detail: tab counters (Findings N, Monitoring N, Live Feed N)
- `EmptyState` and `LoadingSpinner` shared components
- `ErrorBoundary` + `Toaster` system (Zustand-backed, auto-dismiss 5s)
- API error interceptor — 5xx responses trigger toast notification
- Settings page: profile display, change-password form, system info panel
- Version stamp in sidebar footer

---

## [0.9.0] — 2026-05-20

### Phase 1 — Knowledge Engine (Complete)

#### Added
- Monorepo scaffold: Turborepo + `uv` workspaces + `pnpm` workspaces
- `pentra-shared` — core Pydantic types: `VulnClass`, `Severity`, `KnowledgeRecord`
- `pentra-knowledge` — PostgreSQL schema + Alembic migrations
- Seed data importer — reddelexc CSV format (HackerOne public disclosures)
- LLM extraction pipeline — `key_insight`, `technique`, `indicators` via Ollama
- BGE-M3 embedding via Ollama — dense + sparse vectors
- Qdrant collection setup — hybrid (dense + sparse) indexing
- Hybrid search service — cosine + SPLADE-style keyword matching, top-K results
- FastAPI router — `GET /api/v1/knowledge/search`, `GET /api/v1/knowledge/{id}`, list endpoint
- Celery worker — H1 GraphQL scraper (3 000+ records), manual inject API
- Knowledge Browser UI — search, filter by vuln_class/severity/tech_stack, detail drawer

#### Infrastructure
- Docker Compose: PostgreSQL 16, Redis, Qdrant, MinIO, API, Worker, Web
- Alembic migration pipeline
- `ruff` linting + formatting, `mypy` strict type checking
- `pytest` + `pytest-asyncio` — 51/51 tests passing

---

## [0.1.0] — 2026-04-01

### Initial scaffold

#### Added
- Repository structure: `apps/`, `packages/`, `infra/`, `docs/`, `scripts/`
- `apps/api` — FastAPI 0.111 skeleton with CORS, JWT auth, health check
- `apps/web` — React 18 + Vite 5 + Tailwind + Shadcn/ui skeleton
- `apps/worker` — Celery 5 + Redis skeleton
- `infra/docker-compose.yml` — all services defined
- `docs/PRD.md` — Product Requirements Document
- `CLAUDE.md` — project intelligence file
