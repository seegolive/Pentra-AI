# Sprint Report — Sprint 7, 8, 9 Completion

**Tanggal:** 25 Mei 2026  
**Status:** Sprint 7 ✅ | Sprint 8 ✅ | Sprint 9 ✅  
**Test Suite:** 47 passing, 1 warning  
**Alembic Head:** `5270364c5870`  
**Total Migrations:** 9

---

## Ringkasan Eksekutif

Sesi ini menyelesaikan tiga sprint penuh — **Foundation Hardening (7)**, **KB Scale-Up (8)**, dan **API & Docs (9)** — dari kondisi sprint 7 yang masih terblokir migrasi hingga seluruh task checklist Phase 1 selesai.

---

## Sprint 7 — Foundation Hardening ✅

### 7.1 Migration Fix + StartupValidator

**Problem:** Tiga migrasi Alembic (`aa834f32e5ed`, `f91810040c15`, `fe72005d78b2`) gagal pada DB baru karena `op.drop_index()` / `op.drop_table()` untuk LangGraph checkpoint tables yang belum pernah ada.

**Fix:** Semua operasi drop diganti dengan `op.execute("DROP ... IF EXISTS ...")`. Cache `__pycache__` dibersihkan.

**Ditambahkan:** `apps/api/app/core/startup.py` — `StartupValidator` yang dijalankan di `lifespan()` sebelum server naik:
- Validasi environment variables wajib
- Koneksi ke PostgreSQL (`SELECT 1` + cek head migration)
- Ping ke Redis
- HTTP `/healthz` ke Qdrant
- HTTP `/api/tags` ke Ollama (warning jika model tidak ditemukan)
- Ping ke Burp MCP (warning-only, opsional)

```
Startup → validate_all() → sys.exit(1) jika ada error kritis
```

### 7.2 Performance Indexes

Migration `1861c1b0307a` menambah 7 indexes:

| Index | Table | Columns |
|-------|-------|---------|
| `ix_audit_logs_engagement_id` | audit_logs | engagement_id |
| `ix_engagements_workspace_id` | engagements | workspace_id |
| `ix_findings_engagement_id` | findings | engagement_id |
| `ix_findings_engagement_severity` | findings | (engagement_id, severity) |
| `ix_findings_engagement_status` | findings | (engagement_id, status) |
| `ix_audit_logs_engagement_created` | audit_logs | (engagement_id, created_at) |
| `ix_monitoring_alerts_engagement_read` | monitoring_alerts | (engagement_id, is_read) |

### 7.3 Security Scanning + Pre-commit

**File baru:**
- `.gitleaks.toml` — allowlist paths (`.env.example`, `docs/*.md`, lock files) + allowlist regex untuk placeholder credentials
- `.pre-commit-config.yaml` — hooks: gitleaks v8.18.4, ruff lint + format, standard safety checks (trailing whitespace, merge conflict markers, private key detection, large file guard)
- `.gitignore` diperluas — `.env*`, `__pycache__/`, `.venv/`, `infra/data/`, log files

### 7.4 Automated Backup Tasks

**File baru:** `apps/worker/app/tasks/backup.py`

Dua Celery beat tasks:

**`backup_postgresql`** (setiap 24 jam):
```
pg_dump → gzip → MinIO: backups/postgresql/{timestamp}.sql.gz
Retain: 7 backup terbaru (file lama otomatis dihapus)
```

**`backup_qdrant`** (setiap 24 jam + 30 menit offset):
```
Qdrant snapshot API → download → MinIO: backups/qdrant/{timestamp}_{name}
Hapus snapshot dari Qdrant setelah upload
Retain: 7 backup terbaru
```

Dependency baru: `miniopy-async>=1.21` di `apps/worker/pyproject.toml`.

### 7.5 Lock Files

`uv lock` dijalankan untuk 8 Python packages:

| Package | File |
|---------|------|
| apps/api | `apps/api/uv.lock` |
| pentra-agent | `packages/pentra-agent/uv.lock` |
| pentra-knowledge | `packages/pentra-knowledge/uv.lock` |
| pentra-payload | `packages/pentra-payload/uv.lock` |
| pentra-report | `packages/pentra-report/uv.lock` |
| pentra-scope | `packages/pentra-scope/uv.lock` |
| pentra-shared | `packages/pentra-shared/uv.lock` |
| pentra-tools | `packages/pentra-tools/uv.lock` |

> `apps/worker` dilewati karena workspace member issue (uv tidak mendukung cross-workspace dependency dalam mode ini).

---

## Sprint 8 — KB Scale-Up ✅

### 8.2 Batch Embedding Pipeline

**`packages/pentra-knowledge/pentra_knowledge/services/embedding.py`**

Ditambahkan `embed_batch()`:

```python
async def embed_batch(
    texts: list[str],
    batch_size: int = 32,
    max_concurrent: int = 8,
) -> list[EmbeddingResult]:
```

- Proses teks dalam window `batch_size=32`
- `asyncio.Semaphore(8)` membatasi concurrent Ollama calls
- `asyncio.gather()` per window → paralel dalam batas semaphore
- Return order dijamin sesuai input

**`packages/pentra-knowledge/pentra_knowledge/services/search.py`**

Ditambahkan `upsert_batch_to_qdrant()`:

```python
async def upsert_batch_to_qdrant(
    records: list[tuple[UUID, EmbeddingResult, dict]],
    batch_size: int = 100,
) -> int:
```

- Upsert 100 `PointStruct` per Qdrant call
- Input: list of `(record_id, EmbeddingResult, payload_dict)`
- Return: total records yang berhasil di-upsert

Kedua fungsi di-export dari `pentra_knowledge/__init__.py`.

### 8.3 Quality Score

#### Schema Changes

**`packages/pentra-shared/pentra_shared/types/knowledge.py`** — `KnowledgeRecord`:

```python
quality_score: float = Field(default=0.0, ge=0.0, le=1.0)

def calculate_quality_score(self) -> float:
    ...
```

Bobot scoring:

| Field | Bobot |
|-------|-------|
| `key_insight` | +0.20 |
| `attack_technique` | +0.20 |
| `indicators` | +0.15 |
| `attack_steps` | +0.15 |
| `what_tools_missed` | +0.10 |
| `tech_stack` | +0.10 |
| `bounty_usd >= 5000` | +0.10 |
| `bounty_usd >= 1` | +0.05 |
| `chained_with` | +0.05 |
| `cvss_score` | +0.05 |

**`packages/pentra-knowledge/pentra_knowledge/db/models.py`** — `KnowledgeRecordORM`:

```python
quality_score: Mapped[float] = mapped_column(
    Float, nullable=False, default=0.0, index=True,
    comment="Completeness score 0.0–1.0 — used to boost retrieval rank",
)
```

#### Migration `5270364c5870`

Migration ini sekaligus memperbaiki bug besar: tabel `knowledge_records` hilang dari DB karena migration `aa834f32e5ed` sebelumnya melakukan `DROP TABLE IF EXISTS knowledge_records` dalam upgrade (hasil autogenerate yang salah) tanpa recreate.

Migration `5270364c5870` di-rewrite menjadi `CREATE TABLE knowledge_records` lengkap dengan semua kolom + `quality_score` + 9 indexes.

```
DB sebelum: knowledge_records ❌ tidak ada
DB sesudah: knowledge_records ✅ + quality_score column + ix_knowledge_records_quality_score
```

#### Hybrid Search Update

`hybrid_search()` di `search.py` mendapat dua parameter baru:

```python
async def hybrid_search(
    ...
    min_quality_score: float | None = None,  # filter Qdrant payload
    quality_boost: float = 0.1,              # re-rank weight
) -> list[KnowledgeRecord]:
```

Re-ranking formula:
```
final_score = rrf_score + quality_boost × quality_score
```

#### Backfill Script

`apps/api/scripts/backfill_quality_scores.py`:
- Iterasi semua `knowledge_records` dalam batch 500
- Hitung `calculate_quality_score()` per record
- Update DB
- Idempotent (aman dijalankan berulang kali)

```bash
DATABASE_URL="postgresql+asyncpg://..." uv run python scripts/backfill_quality_scores.py
```

---

## Sprint 9 — API & Documentation ✅

### 9.1 FastAPI OpenAPI Documentation

`summary=` dan `description=` ditambahkan ke **semua 30+ endpoint** di 8 router files:

| Router | Endpoints |
|--------|-----------|
| `router.py` | 14 endpoints (workspaces, engagements, findings, export/import, knowledge inject, payload) |
| `auth_router.py` | 4 endpoints (register, login, refresh, me) |
| `monitoring_router.py` | 5 endpoints (list alerts, mark read, mark all read, list snapshots, diff snapshots) |
| `admin_router.py` | 7 endpoints (stats, list users, create user, update user, delete user, reset password, bulk import) |
| `report_router.py` | 1 endpoint (generate report) |
| `h1_router.py` | 1 endpoint (H1 program scope) |
| `setup_router.py` | 2 endpoints (status, initialize) |
| `worker_health_router.py` | 1 endpoint (worker health) |

Dokumentasi tersedia di:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

### 9.2 Documentation Files

**`docs/SETUP.md`** — Setup guide lengkap:
- Prerequisites table (Docker, Ollama, Python, Node.js, uv)
- Step-by-step: clone → configure `.env` → Docker infra → Ollama models → migrations → first-run → worker → frontend → seed KB
- Environment variables reference table
- Troubleshooting section (StartupValidator, migration failures, Qdrant collection, worker broker)

**`docs/ARCHITECTURE.md`** — Architecture overview:
- ASCII diagram: Browser → API → PostgreSQL/Qdrant/Worker → Ollama
- Component map table (semua packages + infra services)
- Knowledge Engine pipeline diagram
- LangGraph agent flow (Phase 2 preview)
- Data flow: security finding → scope check → tool → LLM → DB → HITL → report
- DB schema (key tables)
- Security properties table
- Technology decisions table (dengan rationale)

---

## State Database Saat Ini

```
Tabel aktif di PostgreSQL:
  workspaces, engagements, findings, audit_logs,
  monitoring_alerts, recon_snapshots, users,
  knowledge_records ← recreated in migration 5270364c5870

Alembic version: 5270364c5870 (head)
Total migrations: 9
```

---

## File yang Dimodifikasi / Dibuat

### Baru
| File | Keterangan |
|------|------------|
| `apps/api/app/core/startup.py` | StartupValidator |
| `apps/api/alembic/versions/1861c1b0307a_add_performance_indexes.py` | 7 performance indexes |
| `apps/api/alembic/versions/5270364c5870_add_quality_score_to_knowledge_records.py` | Recreate knowledge_records + quality_score |
| `apps/api/scripts/backfill_quality_scores.py` | Backfill quality_score ke semua rows |
| `apps/worker/app/tasks/backup.py` | PostgreSQL + Qdrant backup tasks |
| `docs/SETUP.md` | Setup guide lengkap |
| `docs/ARCHITECTURE.md` | Architecture overview |
| `.gitleaks.toml` | Secret scanning config |
| `.pre-commit-config.yaml` | Pre-commit hooks |
| 8× `uv.lock` | Lock files per Python package |

### Dimodifikasi
| File | Perubahan |
|------|-----------|
| `packages/pentra-shared/pentra_shared/types/knowledge.py` | `quality_score` field + `calculate_quality_score()` |
| `packages/pentra-knowledge/pentra_knowledge/db/models.py` | `quality_score` column |
| `packages/pentra-knowledge/pentra_knowledge/services/embedding.py` | `embed_batch()` |
| `packages/pentra-knowledge/pentra_knowledge/services/search.py` | `upsert_batch_to_qdrant()`, `min_quality_score` + `quality_boost` di `hybrid_search()` |
| `packages/pentra-knowledge/pentra_knowledge/__init__.py` | Export fungsi baru |
| `apps/api/app/core/config.py` | Fields: qdrant, minio, ollama_embedding, burp_mcp |
| `apps/api/app/main.py` | `StartupValidator` di `lifespan()` |
| `apps/api/app/db/models.py` | `index=True` di FK columns |
| `apps/api/app/api/router.py` | `summary` + `description` semua endpoints |
| `apps/api/app/api/auth_router.py` | `summary` + `description` |
| `apps/api/app/api/monitoring_router.py` | `summary` + `description` |
| `apps/api/app/api/admin_router.py` | `summary` + `description` |
| `apps/api/app/api/report_router.py` | `summary` + `description` |
| `apps/api/app/api/h1_router.py` | `summary` + `description` |
| `apps/api/app/api/setup_router.py` | `summary` + `description` |
| `apps/api/app/api/worker_health_router.py` | `summary` + `description` |
| `apps/worker/app/core/config.py` | Fields + beat schedule untuk backup |
| `apps/worker/pyproject.toml` | `miniopy-async>=1.21` |
| `.gitignore` | Expanded patterns |
| `PROGRESS.md` | Status diupdate |

---

## Test Suite

```
47 passed, 1 warning in 0.38s
```

1 warning: `datetime.utcnow()` deprecated di `router.py:310` (tidak mempengaruhi fungsi).

---

## Next Steps (Phase 2 — Agent Engine)

Setelah Phase 1 Knowledge Engine selesai seluruhnya, next sprint:

1. **Sprint 10 — Agent Graph**: Implementasi `packages/pentra-agent/` — `PentraState`, node-node LangGraph (`plan`, `recon`, `vuln_hunt`, `report`), edge routing
2. **Sprint 11 — Tool Wrappers**: `packages/pentra-tools/` — `subfinder`, `nmap`, `nuclei`, `ffuf`, Burp MCP client
3. **Sprint 12 — HITL Frontend**: UI component untuk approval flow, live feed WebSocket consumer, engagement dashboard real-time
