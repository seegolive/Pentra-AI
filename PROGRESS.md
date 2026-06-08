# Pentra AI — Development Progress

> **Tanggal Update:** 4 Juni 2026 (sesi 2)
> **Status:** Sprint 1–16.x In Progress 🔄 | **170 tests passing** (51 api · 38 agent · 81 tools) | Smoke: 30/35
> **Alembic Head:** `a28fd25517b3` | **Migrations:** 13

---

## Status Keseluruhan

| Phase | Sprint | Status | Keterangan |
|-------|--------|--------|------------|
| Phase 1 — Knowledge Engine | Sprint 0 (baseline) | ✅ | DB schema, seed importer, LLM extraction, BGE-M3, Qdrant, FastAPI router |
| Phase 2 — Agent Engine | Sprint 1–2 | ✅ | LangGraph StateGraph, HITL interrupt, WebSocket live feed, tool wrappers |
| Phase 3 — Frontend + Auth | Sprint 2–3 | ✅ | React SPA, JWT auth, workspace isolation, KB browser, HITL UI |
| Phase 4 — Arsenal + Hardening | Sprint 3–6 | ✅ | Payload engine, monitoring, notifications, rate limiting, export/import, OPSEC mode |
| Phase 5 — Foundation Hardening | Sprint 7 | ✅ | StartupValidator, performance indexes, secret scanning, backup tasks, lock files |
| Phase 6 — KB Scale-Up | Sprint 8 | ✅ | `embed_batch`, `upsert_batch_to_qdrant`, `quality_score`, search boost |
| Phase 7 — API & Docs | Sprint 9 | ✅ | OpenAPI docs semua endpoints, SETUP.md, ARCHITECTURE.md |
| Phase 8 — Agent Engine Rebuild | Sprint 10 | ✅ | PentraState redesign, LLMClient, nodes/ per-file, Burp MCP aktif |
| **Phase 9 — Agent Integration** | **Sprint 11.1** | ✅ | AgentService rewrite, Celery stream events, Redis pub/sub, 4 tests |
| **Phase 9 — Hardening** | **Sprint 11.2–11.3** | ✅ | Bug fixes, nuclei tempfile, INTERNAL_API_TOKEN, 18 findings persisted |
| **Phase 10 — Burp MCP + Worker** | **Sprint 12** | ✅ | Burp MCP WSL2 NAT fix, worker pyproject fix, SSE path + Host header fix |
| **Phase 11 — Frontend HITL** | **Sprint 13** | ✅ | FindingsTable, ReportViewer, HITL approval modal, live feed |
| **Phase 12 — Intelligence Upgrade** | **Sprint 14** | ✅ | EngagementLearning, ReAct loop, CVSS v3.1 auto-scoring |
| **Phase 13 — Architecture Upgrade** | **Sprint 15** | ✅ | RateLimitDetector, VulnerabilityCorrelator, Attack Playbooks, ChainSummarizer, OSINT Node |
| **Phase 14 — BugHunter Enhancement** | **Sprint 16** | 🔄 | Triage Gate (16.1), Anomaly Detection (16.4), Developer Psychology (16.5) |

---

## Arsitektur Sistem

```
Browser (React 18 + Vite + Tailwind + Shadcn/ui)
         │ HTTP + WebSocket
         ▼
FastAPI (apps/api) — port 8000
         │                    │
    PostgreSQL           Qdrant (vectors)
    (metadata +          (dense + sparse
     audit logs)          knowledge)
         │
Celery Worker (apps/worker)
         │ httpx
      Ollama (host machine)
      bge-m3 | qwen2.5-coder:* | deepseek-r1:*
```

**Packages:**

| Package | Peran |
|---------|-------|
| `pentra-knowledge` | Embedding, Qdrant upsert/search, LLM extraction |
| `pentra-agent` | LangGraph StateGraph + HITL nodes |
| `pentra-tools` | Async wrappers: subfinder, nmap, nuclei, ffuf, Burp MCP |
| `pentra-scope` | ScopeEnforcer — validasi setiap tool call |
| `pentra-payload` | Payload generator (LLM + RAG) |
| `pentra-report` | MD / HTML / PDF / H1 report generator |
| `pentra-shared` | Pydantic v2 types: KnowledgeRecord, VulnClass, Severity |

---

## Database Schema (PostgreSQL)

| Tabel | Keterangan |
|-------|------------|
| `users` | Operator accounts (bcrypt + JWT HS256) |
| `workspaces` | Grup engagement per project/team |
| `engagements` | Satu security engagement — scope, mode, status, thread_id |
| `findings` | Confirmed vulnerabilities — severity, CVSS, CVE, request/response |
| `audit_logs` | Append-only log setiap aksi agent (engagement_id, actor, action) |
| `monitoring_alerts` | Live security monitoring events, is_read flag |
| `recon_snapshots` | Snapshot attack surface per engagement untuk diff |
| `knowledge_records` | KB records — BGE-M3 indexed, quality_score, is_embedded |

---

## Sprint 1–3 — Foundation & Arsenal ✅

### Sprint 1 — Make it Real
| Task | Detail |
|------|--------|
| Burp Suite MCP client | `BurpMCPClient` + 24 tests (proxy history, repeater, active scan) |
| Agentic mode (full auto) | Bypass HITL, audit log setiap aksi otomatis |
| Screenshot & evidence | Playwright + MinIO upload |
| KB expansion | RSS ingestion + H1 payloads scraper + Celery beat |

### Sprint 2 — Complete the Arsenal
| Task | Detail |
|------|--------|
| Tool wrappers baru | `AmassWrapper`, `KatanaWrapper`, `FfufWrapper`, `DalfoxWrapper`, `SqlmapWrapper` |
| KB self-learning | `SubmitToKBModal` + `POST /kb/from-finding` — confirmed findings → knowledge base |
| Workspace isolation | `owner_id` FK di workspaces, query filter per user |
| KB manual inject UI | 3 tab: URL scrape / file upload / raw text |

### Sprint 3 — Production Hardening
| Task | Detail |
|------|--------|
| Payload Generator | `packages/pentra-payload` + `POST /api/v1/payloads/generate` + PayloadPanel UI |
| Continuous Monitoring | `ReconSnapshotORM` + `MonitoringAlertORM` + delta detection Celery daily task |
| Notifications | Slack incoming webhook + Telegram Bot API |
| Rate Limiting | Redis sliding window middleware — 200/min default, 10/min expensive endpoints |

---

## Sprint 4–6 — Operational Completeness ✅

### Sprint 4
| Task | Detail |
|------|--------|
| E2E Tests Playwright | `auth.spec.ts` (4), `engagement.spec.ts` (3), `hitl.spec.ts` (3) |
| Monitoring Dashboard | AlertTimeline + SnapshotDiff + MonitoringSchedule, backend `/monitoring/*` |
| KB Volume Expansion | Admin panel `/admin`, bulk import endpoint, Bugcrowd scraper |
| Setup Wizard | 4-step `/setup` page + `GET/POST /api/v1/setup/*` |
| User Management UI | `/admin/users` — CRUD: create, toggle active/admin, reset password, delete |

### Sprint 5
| Task | Detail |
|------|--------|
| Nuclei template auto-update | Celery Beat task tiap minggu (`nuclei -update-templates`) |
| CVE Correlation | NVD API v2.0, `cve_ids` + `cve_data` di Finding, badge link di UI |
| GraphQL Attack Surface | `GraphQLAnalyzer` — introspection, depth bypass, batching, field suggestion, alias flood |
| H1 Program Scope Sync | `H1ProgramSync` + `GET /api/v1/h1/programs/{handle}/scope`, auto-fill di form |

### Sprint 6
| Task | Detail |
|------|--------|
| Worker Health UI | `GET /api/v1/admin/worker/health`, WorkerHealthPage auto-refresh 10s |
| Engagement Export/Import | JSON bundle export + import ke workspace lain |
| OPSEC Mode | `opsec_mode` + `request_jitter_ms` — jitter sebelum setiap tool exec |

---

## Sprint 7 — Foundation Hardening ✅

### 7.1 — Migration Fix + StartupValidator

**Problem ditemukan:** Tiga migrasi (`aa834f32e5ed`, `f91810040c15`, `fe72005d78b2`) crash di DB baru karena `op.drop_index()` / `op.drop_table()` untuk LangGraph checkpoint tables yang belum pernah dibuat.

**Fix:** Semua operasi drop diganti `op.execute("DROP ... IF EXISTS ...")`.

**Baru:** `apps/api/app/core/startup.py` — `StartupValidator` dijalankan di `lifespan()`:

| Check | Behaviour |
|-------|-----------|
| Env vars wajib | `sys.exit(1)` jika kosong |
| PostgreSQL (`SELECT 1` + cek head migration) | `sys.exit(1)` jika gagal |
| Redis (ping) | `sys.exit(1)` jika gagal |
| Qdrant (`GET /healthz`) | `sys.exit(1)` jika gagal |
| Ollama (`GET /api/tags`, cek model) | Warning saja jika model tidak ada |
| Burp MCP (opsional) | Warning saja |

### 7.2 — Performance Indexes (migration `1861c1b0307a`)

| Index | Tabel | Kolom |
|-------|-------|-------|
| `ix_audit_logs_engagement_id` | audit_logs | engagement_id |
| `ix_engagements_workspace_id` | engagements | workspace_id |
| `ix_findings_engagement_id` | findings | engagement_id |
| `ix_findings_engagement_severity` | findings | (engagement_id, severity) |
| `ix_findings_engagement_status` | findings | (engagement_id, status) |
| `ix_audit_logs_engagement_created` | audit_logs | (engagement_id, created_at) |
| `ix_monitoring_alerts_engagement_read` | monitoring_alerts | (engagement_id, is_read) |

### 7.3 — Security Scanning + Pre-commit

- `.gitleaks.toml` — allowlist `.env.example`, `docs/*.md`, lock files, placeholder credentials
- `.pre-commit-config.yaml` — gitleaks v8.18.4 + ruff lint/format + check-yaml/toml/json + detect-private-key
- `.gitignore` diperluas — `.env*`, `__pycache__/`, `.venv/`, `infra/data/`, log files

### 7.4 — Automated Backup Tasks (`apps/worker/app/tasks/backup.py`)

```
backup_postgresql  (tiap 24 jam)
  pg_dump → gzip → MinIO: backups/postgresql/{timestamp}.sql.gz
  Retain: 7 terbaru

backup_qdrant  (tiap 24 jam + 30 menit offset)
  Qdrant snapshot API → download → MinIO: backups/qdrant/{timestamp}_{name}
  Hapus snapshot dari Qdrant setelah upload
  Retain: 7 terbaru
```

### 7.5 — Lock Files

`uv lock` untuk 8 packages: `apps/api`, `pentra-agent`, `pentra-knowledge`, `pentra-payload`, `pentra-report`, `pentra-scope`, `pentra-shared`, `pentra-tools`.

---

## Sprint 8 — KB Scale-Up ✅

### 8.2 — Batch Embedding Pipeline

**`embed_batch()`** di `pentra_knowledge/services/embedding.py`:
```python
async def embed_batch(
    texts: list[str],
    batch_size: int = 32,
    max_concurrent: int = 8,
) -> list[EmbeddingResult]
```
- `asyncio.Semaphore(8)` — batas concurrent Ollama calls
- Proses dalam window 32 → `asyncio.gather()` per window
- Return order dijamin sesuai input

**`upsert_batch_to_qdrant()`** di `pentra_knowledge/services/search.py`:
```python
async def upsert_batch_to_qdrant(
    records: list[tuple[UUID, EmbeddingResult, dict]],
    batch_size: int = 100,
) -> int  # total records upserted
```
- 100 `PointStruct` per Qdrant call
- Input: `(record_id, EmbeddingResult, payload_dict)`

### 8.3 — Quality Score

**`KnowledgeRecord.quality_score`** (`packages/pentra-shared/pentra_shared/types/knowledge.py`):
```python
quality_score: float = Field(default=0.0, ge=0.0, le=1.0)

def calculate_quality_score(self) -> float: ...
```

Bobot scoring:

| Field | Bobot |
|-------|-------|
| `key_insight` (populated) | +0.20 |
| `attack_technique` (populated) | +0.20 |
| `indicators` (non-empty list) | +0.15 |
| `attack_steps` (non-empty list) | +0.15 |
| `what_tools_missed` (populated) | +0.10 |
| `tech_stack` (non-empty list) | +0.10 |
| `bounty_usd >= 5000` | +0.10 |
| `bounty_usd >= 1` (< 5000) | +0.05 |
| `chained_with` (non-empty list) | +0.05 |
| `cvss_score` (populated) | +0.05 |
| **Max total** | **1.00** |

**Migration `5270364c5870`** — sekaligus memperbaiki bug: tabel `knowledge_records` hilang karena migration `aa834f32e5ed` meng-DROP table tanpa recreate. Migration ini CREATE TABLE lengkap + `quality_score` column + 9 indexes.

**`hybrid_search()`** mendapat dua parameter baru:
```python
min_quality_score: float | None = None   # filter Qdrant payload
quality_boost: float = 0.1               # re-rank: rrf + boost × quality_score
```

**Backfill script:** `apps/api/scripts/backfill_quality_scores.py` — iterasi batch 500, hitung ulang, update DB. Idempotent.

---

## Sprint 9 — API & Documentation ✅

### 9.1 — FastAPI OpenAPI Documentation

`summary=` + `description=` ditambahkan ke **semua endpoint** di 8 router files:

| Router | Endpoint Count |
|--------|---------------|
| `router.py` | 14 (workspaces, engagements, findings, export/import, KB inject, payloads) |
| `auth_router.py` | 4 (register, login, refresh, me) |
| `monitoring_router.py` | 5 (alerts, mark read, mark all read, snapshots, diff) |
| `admin_router.py` | 7 (stats, list/create/update/delete users, reset password, bulk import) |
| `report_router.py` | 1 (generate report) |
| `h1_router.py` | 1 (H1 program scope) |
| `setup_router.py` | 2 (status, initialize) |
| `worker_health_router.py` | 1 (worker health) |
| **Total** | **35 endpoints** |

Swagger UI: `http://localhost:8000/docs` | ReDoc: `http://localhost:8000/redoc`

### 9.2 — Documentation Files

**`docs/SETUP.md`:**
- Prerequisites table (Docker, Ollama, Python 3.11+, Node.js, uv)
- Step-by-step 8 langkah: clone → .env → Docker infra → Ollama models → migrations → first-run → worker → frontend → seed KB
- Environment variables reference table (13 vars)
- Troubleshooting section

**`docs/ARCHITECTURE.md`:**
- ASCII component diagram
- Component map table (semua packages + infra services)
- Knowledge Engine pipeline diagram
- LangGraph agent flow (Phase 2 preview)
- Data flow: finding → scope check → tool → LLM → DB → HITL → report
- DB schema key tables
- Security properties table
- Technology decisions dengan rationale

---

## Sprint 10 — Agent Engine Rebuild + Burp MCP Aktif ✅

### 10.1 — PentraState TypedDict Redesign

File: `packages/pentra-agent/pentra_agent/graph/state.py`

6 sub-TypedDicts baru:

| TypedDict | Field Utama |
|-----------|-------------|
| `Target` | `domain`, `ip_ranges`, `base_urls` |
| `Scope` | `in_scope`, `out_of_scope` |
| `Subdomain` | `host`, `ip`, `source`, `is_alive`, `status_code`, `tech_stack` |
| `Port` | `host`, `port`, `protocol`, `service`, `version`, `state` |
| `Endpoint` | `url`, `method`, `params`, `source` |
| `ProposedAction` | `action_type`, `tool`, `args`, `reason`, `is_destructive` |

Field dengan `Annotated[list[T], operator.add]` reducer: `phase_history`, `subdomains`, `open_ports`, `tech_stack`, `endpoints`, `findings`, `messages`, `tool_outputs`, `errors`.

Field yang di-replace (bukan diakumulasi): `knowledge_context`, `pentest_plan`, `current_hypothesis`, `pending_action`, `user_decision`.

### 10.2 — LLMClient

File: `packages/pentra-agent/pentra_agent/llm/client.py`

| Method | Kegunaan |
|--------|----------|
| `complete(system, user, json_output)` | Low-level chat completion |
| `complete_json(system, user)` | Strip markdown fence + retry on parse fail |
| `plan_engagement(target, scope, knowledge_hints)` | Generate structured pentest plan |
| `analyze_recon_results(subdomains, ports, tech_stack, kb)` | Analisis attack surface → JSON |
| `classify_finding(title, desc, request, response)` | Vuln class + severity + CVSS → JSON |

### 10.3 — Nodes Per-File

Semua node dipecah ke `packages/pentra-agent/pentra_agent/nodes/`:

| File | Node | Isi |
|------|------|-----|
| `plan_node.py` | `plan_node` | Query KB → `LLMClient.plan_engagement()` → pentest plan |
| `hitl_nodes.py` | `hitl_plan_review`, `hitl_recon_review`, `hitl_exploit_review` | HITL: semi_auto interrupt / agentic auto-approve + audit log. `hitl_exploit_review` **selalu** interrupt tanpa mode check |
| `recon_node.py` | `recon_node` | subfinder → httpx probe → nmap → **Burp sitemap + proxy history** → KB → LLM analyze |
| `vuln_hunt_node.py` | `vuln_hunt_node` | nuclei → ffuf → **Burp active scan** → **Burp proxy MCP** → **Collaborator payload** → LLM classify |
| `report_node.py` | `report_node` | Deduplicate findings → persist via internal API → markdown report |

### 10.4 — builder.py Redesign

File: `packages/pentra-agent/pentra_agent/graph/builder.py`

**Routing functions baru:**

```python
def route_after_recon(state) -> str:
    """skip → report, approve → vuln_hunt"""

def route_after_vuln_hunt(state) -> str:
    """high/critical findings → hitl_exploit, else → report"""
```

**Edge baru:**
- `hitl_recon` → conditional `route_after_recon` (dulu direct edge ke `vuln_hunt`)
- Routing keys diubah: `has_findings`/`no_findings` → `hitl_exploit`/`report`
- Import dari `nodes/` bukan `graph/nodes.py`

### 10.5 — Celery Agent Task

File: `apps/worker/app/tasks/agent.py`

```
run_engagement(engagement_id)
  └── asyncio.run(_run_engagement_async)
        ├── Load EngagementORM dari PostgreSQL
        ├── Build PentraState initial dict
        ├── AsyncPostgresSaver.from_conn_string(DATABASE_URL)
        └── AgentService(graph).start_engagement()
```

Retry: max 3×, backoff 60 detik, `acks_late=True`, queue `agent`.

`AgentService` diperluas dengan dua alias: `start_engagement()` + `resume_engagement()`; constructor baru menerima kwarg `graph=` agar worker bisa pass pre-built graph.

### 10.6 — Burp MCP Aktif di recon + vuln_hunt

**Burp Suite Pro tervalidasi:** `BURP_MCP_URL=http://host.docker.internal:9876`, 24 Burp tests pass.

#### `recon_node.py` — `_fetch_burp_endpoints()`

| Step | Detail |
|------|--------|
| Scope check | `ScopeEnforcer.validate_or_raise(domain)` sebelum setiap call |
| Health check | `BurpMCPClient.health_check()` — jika false, graceful return `[], []` |
| Sitemap | `get_sitemap(url_prefix=https://{domain})` → setiap entry di-scope-check |
| Proxy history | `get_proxy_history(filter_regex=domain, limit=200)` → dedup terhadap sitemap |
| Tech detection | Scan response headers dari history (`x-powered-by`, `server`, `x-generator`, dll.) |
| Merge | Endpoint Burp di-merge ke state (dedup by url+method), tech stack digabung |

#### `vuln_hunt_node.py` — Tiga fungsi Burp baru

| Fungsi | Burp Tool | Detail |
|--------|-----------|--------|
| `_get_burp_proxy_findings()` | `get_proxy_history()` | Pull 100 request/response pair untuk domain, kirim ke LLM classify |
| `_run_burp_active_scan()` | `trigger_active_scan()` + `get_scan_results()` | Probe via Burp HTTP engine per endpoint, fetch scanner issues (Pro only, graceful fallback) |
| `_get_collaborator_payload()` | `generate_collaborator_payload()` | OOB payload untuk SSRF/XXE/blind XSS, disimpan di `tool_outputs` bukan findings |

Pipeline baru: **nuclei → ffuf → Burp active scan → Burp proxy history → Collaborator → LLM**

Semua fungsi Burp: `validate_or_raise()` dulu → `BurpNotProError` ditangkap gracefully → `BurpConnectionError` ditangkap gracefully.

---

## Test Suite — Sprint 10 (pentra-agent, 11 tests)

| Test | Kategori |
|------|----------|
| `test_route_after_recon_goes_to_vuln_hunt_on_approve` | Routing |
| `test_route_after_recon_goes_to_report_on_skip` | Routing |
| `test_route_after_vuln_hunt_goes_to_hitl_exploit_when_high_findings` | Routing |
| `test_route_after_vuln_hunt_goes_to_report_when_no_high_findings` | Routing |
| `test_route_after_vuln_hunt_goes_to_report_when_no_findings` | Routing |
| `test_hitl_plan_review_auto_approves_in_agentic_mode` | HITL |
| `test_hitl_exploit_always_interrupts` | HITL |
| `test_llm_client_complete_json_strips_markdown_fences` | LLMClient |
| `test_llm_client_complete_json_handles_raw_json` | LLMClient |
| `test_pentra_state_reducers_accumulate` | State |
| `test_phase_literals_are_valid` | State |

---

## Sprint 11.1 — AgentService + Celery End-to-End ✅

### 11.1a — `packages/pentra-agent/pentra_agent/service.py` Rewrite

| Method / Helper | Keterangan |
|-----------------|------------|
| `_langgraph_to_ws_event(lg_event)` | Module-level helper: `on_chain_start` → `NODE_START`, `on_chain_end + __interrupt__` → `AWAITING_APPROVAL`, `on_chain_end + findings` → `FINDINGS_UPDATED`, `on_chat_model_stream` → `LLM_STREAM`. Node tidak dikenal → `None`. |
| `AgentService.__init__(graph)` | Simplified — terima compiled graph langsung |
| `AgentService.create(database_url)` | Async factory: strip `asyncpg` prefix → `AsyncPostgresSaver` → `setup()` → `build_pentra_graph()` → return instance |
| `start(engagement_id, initial_state)` | `ainvoke(initial_state, config)` — fire-and-forget |
| `resume(engagement_id, user_decision)` | `aupdate_state(config=, values={user_decision, awaiting_approval=False})` → `ainvoke(None, config)` |
| `stream_events_during_start(id, state)` | `astream_events(initial_state, version="v2")` → filter & yield WS events |
| `stream_events(engagement_id)` | `astream_events(None, version="v2")` — follow running engagement (Sprint 12) |
| `get_current_state(engagement_id)` | Sync wrapper via `asyncio.run(aget_state)` |

**Tracked nodes** (diforward ke client): `plan`, `hitl_plan`, `recon`, `hitl_recon`, `vuln_hunt`, `hitl_exploit`, `report`

### 11.1b — `apps/worker/app/tasks/agent.py` Rewrite

| Fungsi | Keterangan |
|--------|------------|
| `run_engagement(engagement_id)` | `max_retries=0` (stateful), `acks_late=True`, queue `agent` |
| `resume_engagement(engagement_id, user_decision)` | **Baru** — HITL resume dari UI |
| `_run_async(engagement_id)` | Load ORM → set `status="active"` → publish `ENGAGEMENT_STARTED` → `async with AsyncPostgresSaver` → stream events → publish tiap event ke Redis |
| `_resume_async(engagement_id, user_decision)` | **Baru** — publish `AGENT_RESUMED` → `service.resume()` |
| `_publish_event(engagement_id, event)` | `redis.from_url().publish(f"engagement:{id}:events", json)` |
| `_extract_domain(in_scope)` | Extract domain utama dari list scope (skip CIDR, strip wildcard `*.`) |
| `_build_initial_state(engagement)` | Fix field ORM: `in_scope`, `out_of_scope`, `llm_model` (bukan `scope_in_scope` / `target_domain`) |

**Status flow:** `planning` → `active` saat task mulai; `failed` + `AGENT_ERROR` event saat exception.

**Redis channel:** `engagement:{engagement_id}:events`

### 11.1c — Test Suite Sprint 11.1 (4 tests baru)

File: `packages/pentra-agent/tests/test_service.py`

| Test | Kategori |
|------|----------|
| `test_agent_service_resume_updates_state_and_continues` | `resume()` — `aupdate_state` + `ainvoke` dipanggil dengan args benar |
| `test_langgraph_to_ws_event_converts_node_start` | `on_chain_start` → `NODE_START` dengan `node` + `timestamp` |
| `test_langgraph_to_ws_event_returns_none_for_unknown_nodes` | Node internal → `None` |
| `test_langgraph_to_ws_event_detects_interrupt` | `on_chain_end + __interrupt__` → `AWAITING_APPROVAL` |

---

## Sprint 11.2 — Bug Fixes & Hardening ✅

### 11.2a — StartupValidator Fix (`apps/api/app/core/startup.py`)

| Bug | Fix |
|-----|-----|
| `MigrationContext.configure()` returns `None` dengan asyncpg | Ganti dengan direct SQL: `SELECT version_num FROM alembic_version_api LIMIT 1` |
| `UnboundLocalError: cannot access local variable 'text'` | `from sqlalchemy import text` duplikat di dalam try block → hapus import lokal |
| Wrong alembic table name | Table adalah `alembic_version_api` (set via `version_table=` di `env.py`), bukan default `alembic_version` |

Startup kini clean: `✅ Pentra AI startup validation passed`

### 11.2b — `hybrid_search()` Kwarg Fix

| File | Bug | Fix |
|------|-----|-----|
| `pentra-agent/nodes/recon_node.py` | `hybrid_search(filters={...})` — `filters` bukan kwarg valid | Ganti ke `tech_stack=`, tambah `db=` parameter |
| `pentra-agent/nodes/vuln_hunt_node.py` | Same | Ganti ke `vuln_class=`, tambah `db=` |

`hybrid_search()` signature: `tech_stack=`, `vuln_class=`, `db=`, `top_k=`, `min_quality_score=`.

### 11.2c — Orphaned File Removal

`packages/pentra-agent/pentra_agent/graph/nodes.py` — file duplikat orphaned dari sebelum refactor ke `nodes/` directory. `builder.py` sudah import dari `nodes/*.py` individual. File dihapus.

### 11.2d — Internal API Endpoint (`apps/api/app/api/internal_router.py`) — NEW FILE

`report_node.py` memanggil `POST /internal/findings/bulk` untuk persist findings — endpoint tidak ada.

| Detail | Nilai |
|--------|-------|
| Endpoint | `POST /internal/findings/bulk` |
| Auth | `X-Internal-Token` header = `INTERNAL_API_TOKEN` env var |
| Logic | Skip duplicates by `(title, target_url)`, persist `FindingORM` rows |
| Return | `{created: N, skipped: N, engagement_id: "..."}` |
| Wrong token | HTTP 401 |

Ditambahkan ke `app/main.py` via `app.include_router(internal_router)`.

### 11.2e — `INTERNAL_API_TOKEN` + `FindingORM` Columns

| Change | File |
|--------|------|
| `internal_api_token` field di Settings | `apps/api/app/core/config.py` |
| Token 64-char hex di `.env` | `apps/api/.env` |
| `impact: Mapped[str \| None]` + `remediation: Mapped[str \| None]` di ORM | `apps/api/app/db/models.py` |
| Migration `cc62ee2cd0df` — ADD COLUMN impact, remediation | `alembic/versions/cc62ee2cd0df_*.py` |

### 11.2f — `.env` → `os.environ` Fix

pydantic-settings membaca `.env` ke settings object tapi **TIDAK** mengisi `os.environ`. Agent nodes (`report_node.py` dll.) pakai `os.getenv()` langsung.

Fix: `load_dotenv(dotenv_path=str(_API_DIR / ".env"), override=False)` di `apps/api/app/main.py`.

### 11.2g — Smoke Tests Update

| Test | Status | Keterangan |
|------|--------|------------|
| ST-01: Admin login + JWT | ✅ | |
| ST-02: Workspace + Engagement | ✅ | |
| ST-03: WebSocket connect | ✅ | |
| ST-04: `AWAITING_APPROVAL` (planning) | ✅ | |
| ST-05: `POST /approve` resume | ✅ | |
| ST-06: Recon + HITL recon | ✅ | 1 subdomain found |
| ST-07: vuln_hunt phase | ✅ | 59 raw findings → 18 deduped (nuclei tempfile fix) |
| ST-08: report_node + findings persist | ✅ | 18 findings via `POST /internal/findings/bulk` 201 |

---

## Sprint 11.3 — vuln_hunt_node Bug Fixes ✅

### 11.3a — Root Cause: nuclei `/dev/stdin` Unusable Under nohup

API server berjalan via `nohup` sehingga fd 0 (stdin) diredirect ke `/dev/null`. Nuclei menggunakan
`-list /dev/stdin` untuk membaca target list dari stdin sebagai **file**, bukan dari fd 0. Di WSL2/Linux
dengan nohup, `/dev/stdin` tidak bisa dibuka sebagai file biasa → nuclei exit dengan kode 1.

Error di log:
```
[FTL] Could not create runner: could not create input provider: could not open targets file:
      open /dev/stdin: no such device or address
```

**Fix**: Tulis targets ke `tempfile.NamedTemporaryFile` dan pass `-list /path/to/tempfile`. File temp di-cleanup di `finally` block.

### 11.3b — Bug Chain Lengkap yang Ditemukan

| Bug | Symptom | Fix |
|-----|---------|-----|
| Concurrent nuclei conflict | Dua proses compete untuk `.templates-config.json` → keduanya exit <1s | Tambah `-duc` flag |
| CPU contention paralel | HTTP scan jenuhkan CPU → net scan timeout | Ubah `asyncio.gather` → sequential |
| `/dev/stdin` tidak tersedia | Nuclei exit=1 dengan `no such device or address` | Tulis target ke temp file |

### 11.3c — File yang Diubah

| File | Perubahan |
|------|-----------|
| `packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py` | `_nuclei_scan`: targets ditulis ke `NamedTemporaryFile`, `-duc` flag ditambah |
| `packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py` | `_run_nuclei`: ubah `asyncio.gather` → sequential (http scan dulu, lalu net scan) |

### 11.3d — Hasil Verifikasi (Engagement v15)

Engagement ID: `360a7c97-4fce-48b3-8325-02215fa97401`

| Metric | Hasil |
|--------|-------|
| HTTP scan (all templates) | 30 findings |
| Net scan (tcp/javascript, 4 ports) | 29 findings |
| Total raw findings | 59 |
| Setelah LLM dedup/classify | 18 findings |
| `POST /internal/findings/bulk` | 201 Created |
| Findings persisted | 18 (7 HIGH, 9 MEDIUM, 2 LOW) |
| Sample findings | `exposed-redis`, CVE-2025-46817, CVE-2025-46818, CVE-2025-46819 |

### 11.3e — Smoke Tests Final Status

| Test | Status | Keterangan |
|------|--------|------------|
| ST-01: Admin login + JWT | ✅ | |
| ST-02: Workspace + Engagement | ✅ | |
| ST-03: WebSocket connect | ✅ | |
| ST-04: `AWAITING_APPROVAL` (planning) | ✅ | |
| ST-05: `POST /approve` resume | ✅ | |
| ST-06: Recon + HITL recon | ✅ | 1 subdomain found |
| ST-07: vuln_hunt → nuclei findings | ✅ | 59 raw → 18 deduped |
| ST-08: report_node + findings persist | ✅ | 18 findings via bulk endpoint |

---

## Sprint 12 — Burp MCP WSL2 Connectivity + Worker Fixes ✅

> **Tanggal:** 26 Mei 2026 | **Tests:** 15/15 agent, 47 api, 81 tools

### 12.1 — Worker `pyproject.toml` Path Fix

`apps/worker/pyproject.toml` menggunakan `{ workspace = true }` tapi tidak ada root `[tool.uv.workspace]`.

| Change | Detail |
|--------|--------|
| Sebelum | `pentra-knowledge = { workspace = true }` |
| Sesudah | `pentra-knowledge = { path = "../../packages/pentra-knowledge", editable = true }` |

Fix: sama dengan pola di `apps/api/pyproject.toml`.

### 12.2 — Celery Worker Startup Fix

Command yang salah: `celery -A app.celery_app` → tidak ada module `app.celery_app`.

**Correct command:**
```bash
cd apps/worker && uv run celery -A app.worker:celery_app worker -l info -Q default,knowledge
```

Worker berjalan: `celery@DESKTOP-6ALGDJS ready`, Redis `redis://localhost:6379/0`, queues: `default` + `knowledge`.

### 12.3 — Burp MCP WSL2 NAT Connectivity

**Root cause**: Burp MCP default bind ke `127.0.0.1:9876`. WSL2 NAT networking tidak bisa reach `127.0.0.1` Windows dari WSL2.

**Diagnosis perjalanan:**
| Issue | Detail |
|-------|--------|
| Port 9876 → `svchost.exe` | Windows system service sudah pakai port 9876 — tidak bisa dibebaskan |
| Burp bind ke `172.31.192.1:9876` | Meski host diubah ke `0.0.0.0`, old process hold port |
| HTTP 403 di semua Origin | Burp MCP cek Host header — `172.31.192.1` ditolak |

**Solusi final:**
1. Ganti Burp MCP port ke **9877** (Advanced Options)
2. Burp berhasil bind ke `0.0.0.0:9877`
3. Fix Python client: SSE path `/sse` → `/` (root), inject `Host: localhost:<port>`

### 12.4 — `BurpMCPClient` Fix (`packages/pentra-tools/pentra_tools/burp/client.py`)

| Bug | Fix |
|-----|-----|
| SSE path salah: `{base_url}/sse` | PortSwigger MCP pakai root `/`, bukan `/sse` |
| Host header `172.31.192.1:9877` → 403 | Inject `Host: localhost:<port>` via `sse_client(headers=...)` |

```python
# Sebelum
self._sse_url = f"{self.base_url}/sse"
# ...
async with sse_client(self._sse_url) as (read, write):

# Sesudah
from urllib.parse import urlparse
self._sse_url = self.base_url  # root path
parsed = urlparse(self.base_url)
port = parsed.port or (443 if parsed.scheme == "https" else 80)
self._host_header = f"localhost:{port}"
# ...
async with sse_client(self._sse_url, headers={"Host": self._host_header}) as (read, write):
```

**Hasil:** `BurpMCPClient.health_check()` → `True` ✅

### 12.5 — BURP-MCP-FIX: INFO Logging + ENV Helpers

| Change | File |
|--------|------|
| `_get_burp_config()` helper (URL + enabled flag) | `vuln_hunt_node.py`, `recon_node.py` |
| Log INFO saat Burp disabled (bukan DEBUG tersembunyi) | Both nodes |
| `BURP_MCP_ENABLED=true` ditambah ke `.env` | `apps/api/.env` |
| Burp setup instructions + mirrored networking note | `apps/api/.env.example` |
| CLAUDE.md Section 12 update | Burp env var notes |

### 12.6 — `.wslconfig` Update

`/mnt/c/Users/user/.wslconfig` diupdate ke `networkingMode=mirrored` (efektif setelah `wsl --shutdown`).
Setelah restart WSL2: gunakan `BURP_MCP_URL=http://localhost:9877`.
Untuk saat ini (NAT): `BURP_MCP_URL=http://172.31.192.1:9877` + Host header injection.

### 12.7 — Smoke Tests Sprint 12

| Test | Status | Keterangan |
|------|--------|------------|
| Celery worker start | ✅ | Redis connected, 2 queues ready |
| `BurpMCPClient.health_check()` | ✅ | Connected ke `172.31.192.1:9877` |
| 15 pentra-agent tests | ✅ | All pass |
| API health | ✅ | `{"status":"ok"}` |

---

## Security Tool Binaries — Status

Semua wrapper di `packages/pentra-tools/pentra_tools/wrappers/` sudah implement. Binary belum terinstall di sistem.

| Tool | Wrapper | Binary | Install |
|------|---------|--------|---------|
| subfinder | ✅ | ❌ | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| httpx (pd) | ✅ | ❌ | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| nmap | ✅ | ✅ | installed via `sudo apt-get install -y nmap` |
| nuclei | ✅ | ✅ | `/home/mdilab/go/bin/nuclei` (v3.8.0), templates at `/home/mdilab/nuclei-templates` |
| ffuf | ✅ | ❌ | `go install github.com/ffuf/ffuf/v2@latest` |
| dalfox | ✅ | ❌ | `go install github.com/hahwul/dalfox/v2@latest` |
| sqlmap | ✅ | ✅ | installed via `sudo apt-get install -y sqlmap` |
| katana | ✅ | ❌ | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| amass | ✅ | ❌ | `go install github.com/owasp-amass/amass/v4/...@master` |

> **Prerequisite:** Go belum terinstall — `sudo snap install go --classic`

---

## Test Suite — apps/api (47 tests)

### `test_engagement_export.py` (13 tests)
| Test | Kategori |
|------|----------|
| `test_export_bundle_schema_construction` | Schema |
| `test_export_bundle_with_findings` | Schema |
| `test_import_request_schema` | Schema |
| `test_import_request_new_name_optional` | Schema |
| `test_import_access_control_owner_allowed` | Auth |
| `test_import_access_control_non_owner_denied` | Auth |
| `test_import_access_control_admin_allowed` | Auth |
| `test_export_handler_returns_404_for_missing_engagement` | Handler |
| `test_export_handler_returns_bundle` | Handler |
| `test_import_handler_returns_404_for_missing_workspace` | Handler |
| `test_import_handler_returns_403_for_non_owner` | Handler |
| `test_import_handler_creates_new_uuid` | Handler |
| `test_import_with_custom_name` | Handler |

### `test_rate_limit.py` (9 tests)
| Test | Kategori |
|------|----------|
| `test_extract_key_from_valid_jwt` | Key extraction |
| `test_extract_key_falls_back_to_ip_without_auth` | Key extraction |
| `test_extract_key_falls_back_to_ip_with_bad_token` | Key extraction |
| `test_extract_key_uses_x_forwarded_for` | Key extraction |
| `test_sliding_window_allows_under_limit` | Sliding window |
| `test_sliding_window_blocks_at_limit` | Sliding window |
| `test_sliding_window_fails_open_on_redis_error` | Resilience |
| `test_expensive_endpoint_detection` | Config |
| `test_expensive_endpoint_uses_lower_limit` | Config |

### `test_worker_health.py` (17 tests)
| Test | Kategori |
|------|----------|
| `test_parse_worker_extracts_hostname/pid/concurrency/queues` | Parser |
| `test_parse_worker_counts_active/reserved_tasks` | Parser |
| `test_parse_active_task_extracts_id_and_name/worker/timestamp` | Parser |
| `test_parse_active_task_handles_missing_time_start` | Edge case |
| `test_safe_inspect_returns_empty_on_exception` | Resilience |
| `test_safe_inspect_returns_data_when_workers_online` | Happy path |
| `test_safe_inspect_handles_none_stats` | Edge case |
| `test_worker_health_response_healthy_true/false` | Schema |
| `test_worker_health_response_includes_active_tasks` | Schema |
| `test_get_worker_health_returns_healthy/unhealthy` | Handler |
| `test_get_worker_health_scheduled_tasks_count` | Handler |
| `test_get_worker_health_checked_at_is_iso_format` | Handler |

### `test_workspace_isolation.py` (5 tests)
| Test | Kategori |
|------|----------|
| `test_list_workspaces_returns_only_owned` | Isolation |
| `test_admin_can_see_all_workspaces` | Admin |
| `test_user_cannot_access_other_user_workspace` | Auth |
| `test_workspace_created_with_owner_id` | Creation |
| `test_workspace_filter_excludes_null_owner` | Filter |

### `test_engagement_export.py` — 1 extra duplicate
Lihat baris paling bawah pytest output: test terakhir di-run ulang (pytest artifact, count = 47 bukan 46).

---

## File Struktur Akhir (Key Files)

```
pentra-ai/
├── apps/
│   ├── api/
│   │   ├── app/
│   │   │   ├── core/
│   │   │   │   ├── config.py          ← ApiSettings (pydantic-settings)
│   │   │   │   ├── startup.py         ← StartupValidator [Sprint 7.1]
│   │   │   │   └── middleware/
│   │   │   │       └── rate_limit.py  ← Redis sliding window
│   │   │   ├── api/
│   │   │   │   ├── router.py          ← Main router (14 endpoints, documented)
│   │   │   │   ├── auth_router.py     ← JWT auth
│   │   │   │   ├── admin_router.py    ← Admin + user mgmt
│   │   │   │   ├── monitoring_router.py ← Alerts + snapshots
│   │   │   │   ├── report_router.py   ← Report generation
│   │   │   │   ├── h1_router.py       ← H1 scope sync
│   │   │   │   ├── setup_router.py    ← First-run setup
│   │   │   │   └── worker_health_router.py ← Celery health
│   │   │   └── db/
│   │   │       └── models.py          ← ORM (9 tables, indexed FKs)
│   │   ├── alembic/versions/          ← 10 migrations
│   │   ├── scripts/
│   │   │   └── backfill_quality_scores.py ← [Sprint 8.3]
│   │   └── tests/                     ← 47 tests
│   ├── web/
│   │   └── src/
│   │       ├── pages/                 ← 10+ pages
│   │       ├── components/            ← Shared UI components
│   │       └── lib/                   ← api.ts, types.ts, stores
│   └── worker/
│       └── app/tasks/
│           ├── backup.py              ← [Sprint 7.4]
│           ├── monitoring.py
│           ├── notifications.py
│           ├── knowledge_update.py
│           └── agent.py               ← run_engagement + resume_engagement [Sprint 11.1]
├── packages/
│   ├── pentra-knowledge/
│   │   └── pentra_knowledge/
│   │       ├── services/
│   │       │   ├── embedding.py       ← embed() + embed_batch() [Sprint 8.2]
│   │       │   └── search.py          ← hybrid_search() + upsert_batch_to_qdrant() [Sprint 8.2, 8.3]
│   │       └── db/
│   │           └── models.py          ← quality_score column [Sprint 8.3]
│   ├── pentra-shared/
│   │   └── pentra_shared/types/
│   │       └── knowledge.py           ← quality_score + calculate_quality_score() [Sprint 8.3]
│   ├── pentra-agent/
│   │   └── pentra_agent/
│   │       ├── llm/
│   │       │   └── client.py          ← LLMClient [Sprint 10.2]
│   │       ├── nodes/
│   │       │   ├── plan_node.py       ← [Sprint 10.3]
│   │       │   ├── hitl_nodes.py      ← [Sprint 10.3]
│   │       │   ├── recon_node.py      ← + Burp sitemap/history [Sprint 10.6]
│   │       │   ├── vuln_hunt_node.py  ← + Burp active scan + Collab [Sprint 10.6]
│   │       │   └── report_node.py     ← [Sprint 10.3]
│   │       ├── service.py             ← AgentService rewrite [Sprint 11.1]
│   │       └── graph/
│   │           ├── state.py           ← PentraState redesign [Sprint 10.1]
│   │           └── builder.py         ← route_after_recon, new imports [Sprint 10.4]
│   ├── pentra-tools/                  ← Tool wrappers + scope gate
│   ├── pentra-payload/                ← Payload generator
│   ├── pentra-report/                 ← MD/HTML/PDF/H1 reports
│   └── pentra-scope/                  ← ScopeEnforcer
├── docs/
│   ├── PRD.md                         ← Product Requirements Document
│   ├── SETUP.md                       ← Setup guide [Sprint 9.2]
│   └── ARCHITECTURE.md                ← Architecture overview [Sprint 9.2]
├── infra/
│   └── docker-compose.yml             ← 7 services + healthchecks
├── .gitleaks.toml                     ← [Sprint 7.3]
├── .pre-commit-config.yaml            ← [Sprint 7.3]
├── CLAUDE.md                          ← Project intelligence (auto-loaded)
└── SPRINT-7-8-9-REPORT.md            ← Detail report sprint ini
```

---

## Security Compliance

| Rule | Status |
|------|--------|
| Scope check sebelum setiap tool call | ✅ |
| No hardcoded credentials — semua via env var | ✅ |
| SQLAlchemy ORM only — no raw SQL | ✅ |
| Pydantic v2 validation semua API input/output | ✅ |
| LangGraph `interrupt()` untuk destructive actions | ✅ |
| Audit log setiap agent action (append-only) | ✅ |
| JWT HS256, secret via `SECRET_KEY` env var | ✅ |
| LLM inference lokal (Ollama) — no external AI API | ✅ |
| Rate limiting (Redis sliding window) | ✅ |
| Pre-commit secret scanning (gitleaks) | ✅ |
| Automated daily backups (PostgreSQL + Qdrant → MinIO) | ✅ |

---

## Quick Start

```bash
# 1. Infrastruktur
docker compose -f infra/docker-compose.yml up -d

# 2. Models Ollama (host machine)
ollama pull bge-m3 && ollama pull qwen2.5-coder:7b

# 3. Migrasi DB
cd apps/api
DATABASE_URL="postgresql+asyncpg://pentra:pentra@localhost:5432/pentra" \
  uv run alembic upgrade head

# 4. API server
uv run fastapi dev app/main.py --port 8000

# 5. Frontend
cd apps/web && pnpm dev   # http://localhost:5173

# 6. First run → setup admin
curl -X POST http://localhost:8000/api/v1/setup/initialize \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin@localhost","password":"changeme"}'

# 7. Tests
cd apps/api && uv run pytest tests/ -q
```

---

## Sprint 13 — HITL Frontend & Live Feed ✅

> Real-time engagement dashboard, approval flow, FindingsTable, ReportViewer.

| Task | Status | Detail |
|------|--------|--------|
| `FindingsTable.tsx` | ✅ | Severity badge + status pill + paginated table di `EngagementDetailPage` |
| `ReportViewer.tsx` | ✅ | Render markdown report dari `report_node` output |
| HITL approval modal | ✅ | WebSocket event `AWAITING_APPROVAL` → modal + Approve/Skip/Modify |
| Live feed WebSocket | ✅ | `useEngagementFeed` hook — per-engagement event stream |
| CVE badge in findings | ✅ | Link ke NVD per CVE ID |
| OPSEC mode toggle | ✅ | UI toggle + jitter config di engagement form |

---

## Sprint 14 — Intelligence Upgrade ✅

> Tanggal: 3 Juni 2026 | Alembic Head: `c8551619e47f`

### ✅ Task 14.1 — EngagementLearning (Cross-Engagement Self-Learning)

**Goal:** Agent belajar dari engagement sebelumnya — v12 lebih pintar dari v11.

**File yang dibuat/diubah:**

| File | Perubahan |
|---|---|
| `apps/api/app/db/models.py` | Tambah `EngagementLearningORM` — 12 kolom: `tech_stack`, `effective_tools`, `failed_tools`, `high_value_endpoints`, `findings_count`, `high_critical_count` (JSONB) |
| `apps/api/app/services/learning.py` | `save_engagement_learning()` + `query_similar_learnings()` |
| `apps/api/app/services/__init__.py` | Init file |
| `apps/api/alembic/versions/fe25c4ad4fac_add_engagement_learnings.py` | Migration: CREATE TABLE `engagement_learnings` + index |
| `apps/api/alembic/env.py` | Import `EngagementLearningORM` |
| `packages/pentra-agent/pentra_agent/nodes/report_node.py` | Step 3: `_save_learning()` helper fire-and-forget setelah findings persist |
| `packages/pentra-agent/pentra_agent/nodes/plan_node.py` | Query `query_similar_learnings(tech_stack)` → inject ke LLM prompt sebagai `prior_learnings` |
| `packages/pentra-agent/pentra_agent/llm/client.py` | `plan_engagement()` terima `prior_learnings: list[dict] \| None` |

**Flow:**
1. `report_node` selesai → `_save_learning()` derivasi `effective_tools` dari finding source, `high_value_endpoints` dari confirmed findings, simpan ke DB
2. Engagement baru `plan_node` → `query_similar_learnings(tech_stack)` JSONB `&&` overlap → top-3 by `high_critical_count DESC`
3. LLM plan enriched: *"Dari ASP.NET engagement sebelumnya: nuclei sqli produktif, /products?cat= injectable, 3 HIGH findings"*

---

### ✅ Task 14.2 — ReAct Reasoning Loop

**Goal:** LLM verbalize reasoning sebelum setiap injection test — audit trail + precision.

**File yang dibuat/diubah:**

| File | Perubahan |
|---|---|
| `packages/pentra-agent/pentra_agent/llm/client.py` | `ReActOutput` dataclass + `parse_react_output()` + `react_step()` method |
| `packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py` | ReAct block sebelum `craft_exploit_payloads()` per kandidat; `write_audit_log` tiap Thought |

**ReAct loop per kandidat:**
```
Observation: URL + param + baseline response (400 chars)
   ↓
LLMClient.react_step()
   ↓
Thought: "This /products?cat=1 param looks injectable — integer ID, no WAF detected"
Action: test_injection  (atau skip_candidate)
   ↓
audit_logs: action="react_thought", detail={thought, action, url, param}
   ↓
craft_exploit_payloads() → hanya jika action == test_injection
```

**Audit log format:**
```json
{
  "actor": "agent/vuln_hunt",
  "action": "react_thought",
  "detail": {
    "thought": "Integer param with no sanitization — SQLi candidate",
    "action": "test_injection",
    "url": "http://testaspnet.vulnweb.com/listproducts.aspx",
    "param": "cat"
  }
}
```

---

### ✅ Task 14.3 — CVSS v3.1 Auto-Calculator

**Goal:** Setiap finding mendapat CVSS v3.1 score + vector string valid — H1-submission ready.

**File yang dibuat/diubah:**

| File | Perubahan |
|---|---|
| `packages/pentra-shared/pentra_shared/utils/cvss.py` | 40+ CVSS entries, `calculate_cvss()`, `normalise_vuln_class()`, `_ALIASES` map |
| `packages/pentra-shared/pentra_shared/utils/__init__.py` | Init file |
| `apps/api/app/db/models.py` | `FindingORM.cvss_vector: Mapped[str \| None]` — setelah `cvss_score` |
| `apps/api/alembic/versions/c8551619e47f_add_cvss_vector_to_findings.py` | Migration: ADD COLUMN `cvss_vector VARCHAR(200)` |
| `apps/api/app/api/schemas.py` | `FindingResponse.cvss_vector: str \| None = None` |
| `apps/api/app/api/internal_router.py` | `FindingPayload.cvss_vector` + `FindingORM(cvss_vector=f.cvss_vector)` |
| `packages/pentra-agent/pentra_agent/nodes/report_node.py` | Step 1b: CVSS enrichment loop per finding, auto-detect `auth_required` dari request headers |
| `apps/web/src/lib/types.ts` | `Finding.cvss_vector?: string \| null`, tambah `impact?`, `remediation?` |
| `apps/web/src/components/findings/FindingsTable.tsx` | `ExpandedDetail`: CVSS Vector block (10px monospace, break-all) + Impact + Remediation |

**CVSS auto-enrichment logic (report_node.py):**
```python
request_raw = (finding.get("request") or "").lower()
auth_required = "cookie:" in request_raw or "authorization:" in request_raw
score, vector = calculate_cvss(vuln_class, auth_required=auth_required)
if finding.get("cvss_score") is None:   # preserve LLM score if set
    finding["cvss_score"] = score
finding["cvss_vector"] = vector          # always write vector
```

**CVSS score table (sample):**

| Vuln Class | Auth | Score | Vector |
|---|---|---|---|
| SQL Injection | No | 9.8 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| SQL Injection | Yes | 8.8 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| XSS (Reflected) | No | 6.1 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` |
| Stored XSS | No | 8.2 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N` |
| IDOR | Yes | 8.1 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` |
| RCE | No | 10.0 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| SSRF | No | 9.8 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Path Traversal | No | 7.5 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |

Full coverage: SQL_INJECTION, XSS, STORED_XSS, IDOR, SSRF, PATH_TRAVERSAL, COMMAND_INJECTION, RCE, SSTI, OPEN_REDIRECT, XXE, CSRF, BROKEN_AUTH, ACCOUNT_TAKEOVER, MASS_ASSIGNMENT, INSECURE_DESERIALIZATION, INFORMATION_DISCLOSURE, MISCONFIGURATION, BUSINESS_LOGIC, RACE_CONDITION, OAUTH_MISCONFIGURATION, JWT_VULNERABILITY, HOST_HEADER_INJECTION.

---

## Database Migrations — Full History

```
bbd52d203d8e  Initial schema (workspaces, engagements, findings, audit_logs)
6133ff6cb342  Users table + finding description
aa834f32e5ed  Workspace owner_id
1861c1b0307a  Performance indexes (7 indexes)
5270364c5870  quality_score → knowledge_records
0686d9d188a5  ReconSnapshot + MonitoringAlert
fe72005d78b2  CVE fields → findings
a3c91b7d0e22  opsec_mode → engagements
f91810040c15  is_read → monitoring_alerts
cc62ee2cd0df  impact + remediation → findings
fe25c4ad4fac  engagement_learnings table         ← Sprint 14.1
c8551619e47f  cvss_vector → findings             ← Sprint 14.3  [HEAD]
```

---

## E2E Test History

| Run | Target | Status | Findings |
|---|---|---|---|
| E2E-v1 … v8 | testaspnet.vulnweb.com | Iterative fixes | Pipeline bugs found + fixed |
| E2E-v9 | testaspnet.vulnweb.com | ✅ | nuclei SQLi confirmed |
| E2E-v10-HttpNuclei | testaspnet.vulnweb.com | ✅ | HTTP fallback fix, multi-finding pipeline |
| E2E-v11-BurpLive | testaspnet.vulnweb.com | ✅ | 18 findings, Burp MCP live |
| E2E-v12+ | testaspnet.vulnweb.com | 🔜 | First run with EngagementLearning + CVSS enrichment |

---

## Sprint 15 — Architecture Upgrade ✅

> Selesai: 4 Juni 2026 | 12 tests baru | Migration: `a28fd25517b3`

### ✅ Task 15.1 — RateLimitDetector
- `packages/pentra-tools/pentra_tools/recon/rate_limit_detector.py`
- `probe_rate_limit()` deteksi HTTP 429, `X-RateLimit-*` headers, timing variance
- Output `safe_rps` → di-feed ke ffuf/katana/nuclei sebelum scanning
- Integrasi di `recon_node.py` — `rate_limit_info` disimpan di `PentraState`
- 3 tests: `test_detects_429`, `test_detects_ratelimit_headers`, `test_no_rate_limit`

### ✅ Task 15.2 — VulnerabilityCorrelator
- `correlate_findings()` di `report_node.py` — LLM identify attack chains
- Contoh chains: SSRF→RCE, XSS+CSRF→ATO, IDOR+PII→critical data breach
- `chains` JSONB field ditambahkan ke `FindingORM`
- Migration `a28fd25517b3` applied — DB head updated
- Graceful fallback: LLM error → findings dikembalikan tanpa chains

### ✅ Task 15.3 — Attack Playbooks
- `packages/pentra-agent/pentra_agent/playbooks/` — `__init__`, `base`, `registry`
- 5 playbooks: `sqli_error`, `xss_reflected`, `idor`, `ssrf`, `path_traversal`
- `get_playbook_for_context(tech_stack, url, param)` → sorted by relevance + priority
- Integrasi di `vuln_hunt_node` — max 2 playbooks per parameter candidate
- 4 tests: SQLi match, XSS match, empty context, `run_playbook` result

### ✅ Task 15.4 — ChainSummarizer
- `packages/pentra-agent/pentra_agent/llm/summarizer.py`
- `maybe_summarize()` trigger saat `len(messages) > 40`
- Keeps 10 pesan terbaru verbatim, compress sisanya ke 1 `SystemMessage`
- Integrasi di `recon_node` dan `vuln_hunt_node`
- 2 tests: threshold not triggered, compress to summary + recent

### ✅ Task 15.5 — OSINT Node
- `packages/pentra-agent/pentra_agent/nodes/osint_node.py`
- Sources: crt.sh certificate transparency + HackerOne program lookup + Shodan (opsional)
- Passive only — zero traffic ke target
- `builder.py`: `START → osint → plan → hitl_plan → recon → ...`
- `PentraState.osint_results` field untuk simpan hasil
- 3 tests: crt.sh response, graceful on failure, subdomain enrichment

### Bugs Fixed di Sprint 15
| # | Bug | Fix |
|---|-----|-----|
| 9 | `hitl_exploit_review` bypass interrupt di agentic mode | Removed auto-approve — always `interrupt()` |
| 10 | `calculate_cvss('RCE')` → 9.8 bukan 10.0 | Vector S:C (scope changed) → 10.0 |

---

## Sprint 16 — BugHunter Enhancement 🔄

> Dimulai: 4 Juni 2026 (sesi 2) | **+11 tests** (38 agent total) | Adopsi Claude-BugHunter best practices

### ✅ Task 16.1 — Triage Gate Node (7-Question Gate)
- `packages/pentra-agent/pentra_agent/nodes/triage_node.py` — baru
- 7-Question framework: Reproducible / In-scope / Real impact / Novel / Chainable / Evidenced / Not-duplicate
- Verdict per finding: **PASS** / **DOWNGRADE** / **KILL** / **CHAIN_REQUIRED**
- KILL → finding di-drop sebelum persist ke DB
- DOWNGRADE → severity diturunkan sesuai LLM assessment
- `triaged_findings: list[dict]` ditambah ke `PentraState` (no reducer — last write wins)
- Graph diupdate: `vuln_hunt → triage → (hitl_exploit | report)`
- `report_node` membaca `triaged_findings` bila ada, fallback ke `findings`
- Graceful fallback: LLM error → finding tetap dipertahankan
- 3 tests: PASS / KILL / DOWNGRADE verdict

### ✅ Task 16.3 — FindingsTable Attack Chains UI (verifikasi)
- Dikonfirmasi sudah fully implemented dari sprint sebelumnya
- `ChainInfo` interface: `name`, `scenario`, `upgraded_severity`, `business_impact`, `chain_size`
- `chains?: ChainInfo[] | null` pada `Finding` type
- Attack Chains section di `ExpandedDetail` (guard: `chains.length > 0`)
- `tsc --noEmit` → 0 errors

### ✅ Task 16.4 — Anomaly Detection (Enhancement E)
- `detect_anomalies(baseline_body, test_body, test_payload)` ditambah ke `vuln_hunt_node.py`
- 4 anomaly types:
  - `SIZE_ANOMALY` — response ≥500 bytes beda + >30% baseline
  - `ERROR_DISCLOSURE` — SQL/trace keyword baru di test (tidak ada di baseline)
  - `REFLECTION` — payload ter-reflect di test tapi tidak di baseline
  - `EMPTY_RESPONSE` — baseline >100 bytes, test <20 bytes
- Diintegrasikan ke payload loop: anomalies di-append ke `detection_hint` → dikirim ke `analyze_exploit_response`
- 8 tests: no anomaly, size, error disclosure, baseline dedup, reflection, no-false-reflection, empty, multiple

### ✅ Task 16.5 — Developer Psychology Heuristics (Enhancement D)
- `DEVELOPER_PSYCHOLOGY_HEURISTICS` constant ditambah ke `vuln_hunt_node.py`
- 8 heuristics: API versioning, frontend trust, integer ID → IDOR, admin endpoints,
  debug endpoints, copy-paste auth bypass, function-level auth, verbose errors
- Diinjeksi ke ReAct `observation` string setiap candidate test
- LLM menerima context tentang di mana developer biasa membuat kesalahan
- 3 tests: non-empty constant, key patterns coverage, injection in observation

### Pending Tasks Sprint 16
- `[ ]` **Task 16.2** — DO NOT STOP routing: jika ada `CHAIN_REQUIRED` findings, re-enter vuln_hunt
- `[ ]` **Task 16.6** — Enterprise Attack Matrix: M365/Okta/VPN surface detection node

---

## Competitive Position (Updated 4 Juni 2026 — sesi 2)

| Aspek | Pentra AI | PentAGI | HexStrike AI |
|---|---|---|---|
| Local LLM (privacy-first) | ✅ Ollama | ❌ Cloud | ❌ External AI |
| Burp Pro MCP (27 tools) | ✅ First-class | ❌ | Partial |
| H1 Knowledge RAG | ✅ BGE-M3 + Qdrant | ❌ | ❌ |
| HITL stateful + resumable | ✅ LangGraph checkpoint | Partial | ❌ |
| Self-learning antar engagement | ✅ Sprint 14.1 | ❌ | ❌ |
| ReAct reasoning + audit trail | ✅ Sprint 14.2 | ✅ | ❌ |
| CVSS v3.1 auto-scoring | ✅ Sprint 14.3 | ❌ | Partial |
| RateLimit-aware scanning | ✅ Sprint 15.1 | ❌ | ❌ |
| Attack chain correlation | ✅ Sprint 15.2 | ❌ | ❌ |
| Structured attack playbooks | ✅ Sprint 15.3 | ❌ | Partial |
| Context summarization | ✅ Sprint 15.4 | ❌ | ❌ |
| Passive OSINT pre-recon | ✅ Sprint 15.5 | ❌ | ❌ |
| **7-Question Triage Gate** | ✅ Sprint 16.1 | ❌ | ❌ |
| **Anomaly detection (baseline diff)** | ✅ Sprint 16.4 | ❌ | Partial |
| **Developer psychology heuristics** | ✅ Sprint 16.5 | ❌ | ❌ |
| HTTPS→HTTP fallback | ✅ | ❓ | ❓ |
| OPSEC mode + jitter | ✅ | ❌ | ❌ |
| Web UI (React full) | ✅ | ✅ | ❌ CLI |
| Bug bounty H1 format auto | ✅ | ❌ | ❌ |

---

## Smoke Test Scorecard (4 Juni 2026)

```
BLOK 1 — Infrastruktur & API          ✅ 4/4
BLOK 2 — Workspace & Engagement       ✅ 3/3
BLOK 3 — Knowledge Base               ✅ 3/3
BLOK 4 — Agent Pipeline               ✅ 6/6
BLOK 5 — Report Generation            ✅ 2/2
BLOK 6 — Frontend UI                  ⏳ 0/5  (manual — requires pnpm dev)
BLOK 7 — Monitoring & Admin           ✅ 3/3
BLOK 8 — Security & Scope             ✅ 3/3
BLOK 9 — Unit Tests                   ✅ 2/2
BLOK 10 — Export/Import               ✅ 2/2
BLOK 11 — Celery Worker               ✅ 2/2
────────────────────────────────────
TOTAL                                 30/35
```

## Unit Test History

| Selesai | pentra-tools | pentra-agent | apps/api | Total |
|---------|-------------|--------------|----------|-------|
| Sprint 14 (Juni 3) | 81 | 15 | 47 | 143 |
| Sprint 15 (Juni 4, sesi 1) | 84 (+3) | 24 (+9) | 51 (+4) | 159 (+16) |
| Sprint 16 (Juni 4, sesi 2) | 84 | 38 (+14) | 51 | 170 (+11) |

---

## Remaining Work

### Sprint 16 — Tasks Belum Selesai
- `[ ]` **Task 16.2** — DO NOT STOP routing (chain loop): setelah triage, jika ada finding `CHAIN_REQUIRED`, re-enter vuln_hunt
- `[ ]` **Task 16.6** — Enterprise Attack Matrix node (M365, Okta, VPN surface detection)

### Frontend (BLOK 6 — manual)
Jalankan `cd apps/web && pnpm dev`, buka browser, test:
- ST-6.1 Login flow
- ST-6.2 Engagement create + live feed WebSocket
- ST-6.3 FindingsTable + HITL approval modal
- ST-6.4 ReportViewer (Markdown + H1 export)
- ST-6.5 KB Browser (search + filter + detail)

### E2E-v16 Run
Full engagement pada live target dengan fitur Sprint 16 aktif:
- Verify `[triage]` KILL/DOWNGRADE di log setelah vuln_hunt
- Verify `ANOMALY SIGNALS:` muncul di log saat error keyword terdeteksi
- Verify `Developer Psychology` heuristics masuk observation di log
- Verify `triaged_findings` berbeda dari `findings` (filtered)

---

## Quick Start

```bash
# Start API (port 8001)
cd apps/api
nohup uv run uvicorn app.main:app --host 0.0.0.0 --port 8001 &>/tmp/api-server.log &

# Start Frontend (port 5173)
cd apps/web && pnpm dev

# Run migrations
cd apps/api && uv run alembic upgrade head

# Auth
curl -sX POST http://localhost:8001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Pentra@2026!"}'

# Watch logs
tail -f /tmp/api-server.log | grep -E "CONFIRMED|react_thought|CVSS|learning|ReAct"
```
