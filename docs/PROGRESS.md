# Pentra AI — Development Progress Report

> **Date:** 22 Mei 2026  
> **Status:** MVP Complete ✅  
> **Platform:** Self-hosted AI Security Research Platform

---

## Ringkasan Eksekutif

Pentra AI adalah platform orkestrasi AI untuk penetration testing berbasis LLM lokal (Ollama). Seluruh fase MVP telah selesai dikerjakan, mencakup Knowledge Engine, Agent Engine, Frontend, Tool Wrappers, Infrastructure, Auth, dan laporan otomatis.

---

## Arsitektur Sistem

```
pentra-ai/
├── apps/
│   ├── web/              React 19 + Vite + Tailwind + Shadcn/ui (port 5174)
│   ├── api/              FastAPI + Python 3.12 + SQLAlchemy 2 async (port 8000)
│   └── worker/           Celery + Redis (task queue)
├── packages/
│   ├── pentra-knowledge/ Knowledge Engine — pipeline RAG, Qdrant
│   ├── pentra-agent/     LangGraph v1.2 — StateGraph + HITL
│   ├── pentra-tools/     Tool wrappers: subfinder, nmap, nuclei, httpx, Burp
│   ├── pentra-scope/     Scope enforcer — validasi setiap tool call
│   ├── pentra-report/    Report generator: MD, HTML, PDF, H1
│   └── pentra-shared/    Shared Pydantic models, enums, constants
└── infra/
    ├── docker/           Dockerfiles per service
    └── docker-compose.yml
```

---

## Phase 1 — Knowledge Engine ✅

**Tujuan:** Membangun basis pengetahuan dari laporan HackerOne/Bugcrowd sebagai konteks RAG untuk agent.

| Komponen | Status | Detail |
|----------|--------|--------|
| `pentra-shared` Pydantic types | ✅ | `VulnClass`, `Severity`, `KnowledgeRecord`, enums |
| PostgreSQL schema + Alembic | ✅ | Tabel `knowledge_records`, relasi, index |
| Seed data importer | ✅ | Format CSV reddelexc (H1 public disclosures) |
| LLM extraction pipeline | ✅ | `key_insight`, `technique`, `indicators` via Ollama |
| BGE-M3 embedding | ✅ | Via Ollama `http://localhost:11434` |
| Qdrant hybrid search | ✅ | Dense (1024-dim) + sparse (SPLADE), **1.500 points terindeks** |
| FastAPI router | ✅ | `GET /search`, `GET /list`, `GET /{id}` |
| Celery H1 scraper task | ✅ | Worker task `knowledge_update` |

---

## Phase 2 — Agent Engine (Backend + Frontend) ✅

**Tujuan:** LangGraph multi-agent dengan HITL (Human-in-the-Loop) dan live streaming ke UI.

### Backend

| Komponen | Status | Detail |
|----------|--------|--------|
| LangGraph `StateGraph` | ✅ | 7 node: plan → hitl_plan → recon → hitl_recon → vuln_hunt → hitl_exploit → report |
| `AsyncPostgresSaver` | ✅ | Checkpoint ke PostgreSQL, thread_id = engagement_id |
| HITL `interrupt()` | ✅ | Pause graph, resume via `POST /approve` |
| `PentraState` TypedDict | ✅ | Semua field dengan reducer untuk list accumulation |
| REST API engagements | ✅ | CRUD workspace/engagement, start, approve, findings |
| WebSocket live feed | ✅ | `/ws/engagements/{id}/feed` — streaming `astream_events` |
| Audit log | ✅ | Tabel `audit_logs` (append-only), setiap aksi tercatat |

### Frontend

| Komponen | Status | Detail |
|----------|--------|--------|
| Workspaces page | ✅ | Create, list, navigate ke engagements |
| Engagements page | ✅ | Create engagement, list, filter by workspace |
| Engagement Detail | ✅ | Live Feed tab, Findings tab, Reports tab |
| HITL Approval dialog | ✅ | Modal saat agent butuh persetujuan, Approve/Skip |
| WebSocket hook | ✅ | `useEngagementFeed` — auto-reconnect, event buffer |
| Knowledge Browser | ✅ | Search + filter (severity, vuln_class, tech) + detail modal |

---

## Phase 3 — Tools + Infrastructure ✅

### Tool Wrappers (`packages/pentra-tools/`)

| Tool | Status | Detail |
|------|--------|--------|
| `SubfinderWrapper` | ✅ | Passive subdomain enum, JSON + plaintext parser |
| `NmapWrapper` | ✅ | Port scan + service detection, timeout handling |
| `NucleiWrapper` | ✅ | Template-based vuln scan, safe tags only (misconfig/exposure/info) |
| `HttpxWrapper` | ✅ | HTTP probing, tech detection, status codes |
| `BurpMCPClient` | ✅ | Proxy history, repeater, active scan via MCP protocol |
| Scope gate (semua wrapper) | ✅ | `scope.validate_or_raise()` baris pertama setiap `run()` |
| Rate limiter | ✅ | Token-bucket, konfigurasi per wrapper |

### Integrasi ke Agent Nodes

```python
# recon_node: SubfinderWrapper → HttpxWrapper → NmapWrapper
# vuln_hunt_node: NucleiWrapper (safe tags, graceful fallback jika tools tidak tersedia)
```

### Report Generator (`packages/pentra-report/`)

| Format | Status | Detail |
|--------|--------|--------|
| Markdown | ✅ | Scope, executive summary table, per-finding sections |
| HTML | ✅ | Standalone, embedded CSS, severity color cards |
| PDF | ✅ | Via WeasyPrint 68.1, professional layout |
| HackerOne | ✅ | Per-finding submission format (title, steps, impact) |

**Endpoint:** `GET /api/v1/engagements/{id}/report?format=markdown|html|pdf|h1`

### Docker Compose (Full Stack)

```yaml
services:
  db:      PostgreSQL 16-alpine
  redis:   Redis 7-alpine  
  qdrant:  Qdrant (vector DB)
  minio:   MinIO (S3-compatible, evidence storage)
  api:     FastAPI (Dockerfile.api multi-stage)
  worker:  Celery (Dockerfile.worker + nmap/curl)
  web:     React SPA (Dockerfile.web + nginx)
```

- Semua service dengan healthcheck dan `condition: service_healthy`
- Ollama berjalan di host machine: `http://host.docker.internal:11434`
- nginx: SPA routing (`try_files`), security headers, gzip, 1-year static cache

---

## Phase 3 — Auth System ✅

### Backend

| Komponen | Status | Detail |
|----------|--------|--------|
| `UserORM` model | ✅ | id, username, email, hashed_password, is_active, is_admin |
| Alembic migration | ✅ | `add_users_table_and_finding_description` — applied |
| Password hashing | ✅ | `bcrypt` direct (bukan passlib — incompatible dengan bcrypt 5.0) |
| JWT HS256 | ✅ | `python-jose`, access token (8h) + refresh token (30d) |
| `get_current_user` dep | ✅ | HTTPBearer + decode JWT + DB lookup |
| Auth endpoints | ✅ | `POST /register`, `POST /login`, `POST /refresh`, `GET /me` |
| Auth gate di semua endpoints | ✅ | Semua workspace/engagement/findings endpoint require JWT |

### Frontend

| Komponen | Status | Detail |
|----------|--------|--------|
| Zustand auth store | ✅ | `persist` ke localStorage, `accessToken`, `refreshToken`, `user` |
| Axios interceptors | ✅ | Auto-inject `Bearer` token, auto-logout on 401 |
| `LoginPage` | ✅ | Form sign-in, error handling, dark theme |
| `ProtectedRoute` | ✅ | Redirect ke `/login` jika belum auth |
| `AppShell` | ✅ | User avatar + sign-out button di sidebar |
| Route protection | ✅ | Semua route di-wrap `<ProtectedRoute> → <AppShell>` |

---

## Testing ✅

**22 tests — 22 passed (0 failed)**

```
packages/pentra-tools/tests/
├── test_scope_enforcer.py   — 12 tests
│   ├── Exact domain match/block
│   ├── Explicit exclusion (out_of_scope)
│   ├── Wildcard subdomain (*.target.com)
│   ├── URL stripping (scheme, port, path)
│   ├── CIDR matching (10.0.0.0/8)
│   └── is_allowed() boolean API
└── test_wrappers.py         — 10 tests
    ├── Subfinder: scope block, JSON parse, plaintext fallback, empty output
    ├── Nmap: scope block, ToolResult structure
    └── Nuclei: scope block, empty output, JSON finding parse
```

**Bug fix ditemukan lewat tests:**
> `pentra_scope/validator.py` — CIDR notation `10.0.0.0/8` ikut di-strip slash-nya sebelum CIDR check → IP dalam range salah dianggap out-of-scope. Fixed dengan cek `_is_cidr()` sebelum strip path.

---

## Security Compliance

| Rule | Status |
|------|--------|
| Scope check sebelum setiap tool call | ✅ |
| No hardcoded credentials | ✅ |
| SQLAlchemy ORM only (no raw SQL) | ✅ |
| Pydantic v2 validation semua API input/output | ✅ |
| LangGraph `interrupt()` untuk destructive actions | ✅ |
| Audit log setiap agent action | ✅ |
| JWT HS256, secret via env var | ✅ |
| LLM inference lokal (Ollama) | ✅ |
| OWASP: no SQL injection, no hardcoded secrets, input validation | ✅ |

---

## Stack Teknologi Final

| Layer | Teknologi | Versi |
|-------|-----------|-------|
| Frontend | React + Vite + Tailwind + TanStack Query + Zustand | React 19, Vite 8 |
| Backend | FastAPI + SQLAlchemy async | Python 3.12 |
| Agent | LangGraph + AsyncPostgresSaver | v1.2 |
| LLM | Ollama (qwen2.5-coder:32b default) | Local |
| Embedding | BGE-M3 via Ollama | 1024-dim dense + sparse |
| Vector DB | Qdrant hybrid search | 1.500 points |
| Auth | JWT HS256 + bcrypt | python-jose + bcrypt 5.0 |
| Report | Jinja2 + WeasyPrint + Markdown | WeasyPrint 68.1 |
| Queue | Celery + Redis | — |
| Storage | PostgreSQL 16 + MinIO | — |
| Container | Docker Compose | 7 services |
| Package manager | uv (Python) + pnpm (TypeScript) | — |

---

## Cara Menjalankan

```bash
# Development (tanpa Docker)
cd apps/api && uv run uvicorn app.main:app --port 8000 --reload
cd apps/web && pnpm dev

# Login default
username: admin
password: pentra123

# Full stack dengan Docker
docker compose up -d

# Run tests
cd packages/pentra-tools && uv run pytest tests/ -v

# Generate report
curl http://localhost:8000/api/v1/engagements/{id}/report?format=pdf \
  -H "Authorization: Bearer $TOKEN" --output report.pdf
```

---

## Roadmap Post-MVP

| Item | Prioritas |
|------|-----------|
| Burp Suite MCP integration testing (Burp Pro required) | High |
| Celery worker health monitoring UI | Medium |
| Multi-user workspace isolation | Medium |
| Knowledge base auto-update scheduler | Medium |
| nuclei template auto-update | Low |
| Rate limiting di API layer (FastAPI middleware) | Low |
| E2E tests (Playwright) untuk frontend auth flow | Low |
