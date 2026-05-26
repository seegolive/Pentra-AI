# Pentra AI — Development Progress Report

> **Date:** 22 Mei 2026  
> **Status:** MVP + Sprint 1–3 Post-MVP Complete ✅  
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

**Total: 84 tests — 84 passed (0 failed)**

```
packages/pentra-tools/tests/
├── test_scope_enforcer.py   — 12 tests
│   ├── Exact domain match/block
│   ├── Explicit exclusion (out_of_scope)
│   ├── Wildcard subdomain (*.target.com)
│   ├── URL stripping (scheme, port, path)
│   ├── CIDR matching (10.0.0.0/8)
│   └── is_allowed() boolean API
├── test_wrappers.py         — 10 tests
│   ├── Subfinder: scope block, JSON parse, plaintext fallback, empty output
│   ├── Nmap: scope block, ToolResult structure
│   └── Nuclei: scope block, empty output, JSON finding parse
├── test_burp_mcp.py         — 24 tests (Sprint 1.1)
│   ├── health_check, proxy_history, sitemap, send_to_repeater
│   ├── trigger_active_scan, get_scan_results, collaborator
│   └── Connection error, timeout, filter_regex handling
└── test_tool_wrappers_sprint2.py — 15 tests (Sprint 2.1)
    ├── AmassWrapper: scope block, passive mode, JSON parse
    ├── KatanaWrapper: scope block, depth param, endpoint dedup
    ├── FfufWrapper: scope block, wordlist required, hit parse
    ├── DalfoxWrapper: scope block, XSS result parse
    └── SqlmapWrapper: scope block, safe-mode flag, injection parse

packages/pentra-knowledge/tests/
├── test_search.py           — 3 tests
│   ├── hybrid_search returns relevant results (RRF merge)
│   ├── hybrid_search returns [] on no hits
│   └── hybrid_search respects top_k cap
└── test_from_finding.py     — 6 tests (Sprint 3.5)
    ├── KB record created with correct fields from finding
    ├── Deduplication by source_id
    ├── Creates new record when not duplicate
    ├── Tags merged with defaults
    ├── Empty key_insight preserved
    └── Search text includes key fields

apps/api/tests/
├── test_workspace_isolation.py — 5 tests (Sprint 2.3 + 3.5)
│   ├── List returns only owned workspaces
│   ├── Admin sees all workspaces
│   ├── User B cannot access User A's workspace
│   ├── Workspace created with correct owner_id
│   └── Null owner excluded from list
└── test_rate_limit.py       — 9 tests (Sprint 3.4 + 3.5)
    ├── Extract key from valid JWT
    ├── Fallback to IP without Authorization header
    ├── Fallback to IP with bad token
    ├── Uses X-Forwarded-For when present
    ├── Sliding window allows under limit
    ├── Sliding window blocks at limit
    ├── Redis error fails open (request allowed)
    ├── Expensive endpoint detection
    └── Expensive endpoint uses lower limit (10/min)
```

**Bug fix ditemukan lewat tests:**
> `pentra_scope/validator.py` — CIDR notation `10.0.0.0/8` ikut di-strip slash-nya sebelum CIDR check → IP dalam range salah dianggap out-of-scope. Fixed dengan cek `_is_cidr()` sebelum strip path.  
> `pentra_knowledge/tests/test_search.py` — Mock lama menggunakan `client.search` tapi implementasi sudah menggunakan `client.query_points` (dengan `.points` attribute). Fixed ke mock yang benar.

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
| Rate Limiting | Redis sliding window middleware | Sprint 3.4 |
| Payload Engine | `pentra-payload` package + Ollama | Sprint 3.1 |
| Monitoring | Celery daily delta detection task | Sprint 3.2 |
| Notifications | Slack webhook + Telegram Bot API | Sprint 3.3 |
| Package manager | uv (Python) + pnpm (TypeScript) | — |

---

## Sprint 1–3 Post-MVP ✅

> **Dokumen referensi:** `PHASE-2-EXECUTION.md`  
> Semua sprint telah selesai dieksekusi per 22 Mei 2026.

### Sprint 1 — Make it Real ✅

| Task | Deskripsi | Status |
|------|-----------|--------|
| 1.1 | Burp Suite MCP End-to-End (client, models, exceptions, 24 tests) | ✅ |
| 1.2 | Agentic Mode full auto (bypass HITL, audit log per aksi) | ✅ |
| 1.3 | Screenshot & Evidence Capture (Playwright + MinIO upload) | ✅ |
| 1.4 | KB Expansion (RSS ingestion, H1 payloads scraper, Celery beat) | ✅ |

### Sprint 2 — Complete the Arsenal ✅

| Task | Deskripsi | Status |
|------|-----------|--------|
| 2.1 | Tool wrappers baru: amass, katana, ffuf, dalfox, sqlmap (61 tests pass) | ✅ |
| 2.2 | KB Self-Learning dari findings (SubmitToKBModal + POST /kb/from-finding) | ✅ |
| 2.3 | Workspace isolation (owner_id FK + Alembic migration + filter query) | ✅ |
| 2.4 | KB Manual Inject UI (3 tab: URL scrape / File upload / Raw text) | ✅ |

### Sprint 3 — Production Hardening ✅

| Task | Deskripsi | Status |
|------|-----------|--------|
| 3.1 | Payload Generator (`packages/pentra-payload` + `POST /api/v1/payloads/generate` + PayloadPanel UI) | ✅ |
| 3.2 | Continuous Monitoring (ReconSnapshotORM + MonitoringAlertORM + delta detection Celery daily task) | ✅ |
| 3.3 | Notifications (Slack incoming webhook + Telegram Bot API, async httpx) | ✅ |
| 3.4 | Rate Limiting (Redis sliding window middleware, 200/min default, 10/min expensive endpoints) | ✅ |
| 3.5 | Tests: 23 test baru (workspace isolation, rate limit, KB from-finding), total 84 pass | ✅ |

**File baru Sprint 3:**
```
packages/pentra-payload/
├── pyproject.toml
└── pentra_payload/
    ├── __init__.py
    ├── models.py         ← PayloadContext, Payload Pydantic models
    └── generator.py      ← PayloadGenerator (LLM + RAG → JSON array)

apps/api/app/core/middleware/
└── rate_limit.py         ← RateLimitMiddleware (Redis sliding window)

apps/worker/app/tasks/
├── monitoring.py         ← run_all_engagement_monitors, delta detection
└── notifications.py      ← send_monitoring_alerts, Slack + Telegram

apps/api/tests/
├── test_workspace_isolation.py  — 5 tests
└── test_rate_limit.py           — 9 tests

packages/pentra-knowledge/tests/
└── test_from_finding.py         — 6 tests
```

---

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

## Roadmap Berikutnya

| Item | Prioritas | Catatan |
|------|-----------|---------|
| E2E tests (Playwright) untuk frontend auth flow | High | Belum ada UI test |
| Burp Suite MCP integration testing dengan Burp Pro aktif | High | Butuh lisensi Burp Pro |
| Monitoring dashboard UI (alert list + snapshot diff view) | Medium | Backend sudah siap |
| Celery worker health monitoring UI | Medium | — |
| Knowledge base auto-update scheduler (RSS + H1 daily) | Medium | Task sudah ada, perlu jadwal prod |
| nuclei template auto-update | Low | — |
