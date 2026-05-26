# PHASE-4-EXECUTION.md — Pentra AI
> **Untuk:** GitHub Copilot dengan Claude Sonnet 4.6  
> **Baca terlebih dahulu:** `CLAUDE.md` → `docs/PRD.md` → `PROGRESS.md` → file ini  
> **Status saat ini:** Sprint 1–6 selesai, 153 tests passing, semua fitur core berjalan  
> **Tujuan:** Platform maturity — siap digunakan di real engagement secara profesional

---

## Status Lengkap Sebelum Mulai

```
✅ Knowledge Engine         — BGE-M3, Qdrant hybrid, pipeline RAG
✅ LangGraph Agent          — 7 nodes, semi-auto + agentic mode, HITL
✅ Tool Wrappers            — subfinder, nmap, nuclei, httpx, Burp MCP,
                              amass, katana, ffuf, dalfox, sqlmap,
                              graphql_analyzer (13 tools total)
✅ Report Generator         — MD, HTML, PDF, H1 format
✅ Auth + User Management   — JWT, bcrypt, admin/operator/viewer, CRUD UI
✅ Docker Compose           — 7 services, healthcheck, nginx
✅ Rate Limiting            — Redis sliding window middleware
✅ Payload Generator        — pentra-payload, context-aware via LLM
✅ Continuous Monitoring    — delta detection, Celery daily task + UI
✅ Notifications            — Slack webhook + Telegram Bot
✅ KB Self-Learning         — finding → knowledge pipeline
✅ KB Manual Inject         — URL, file upload, raw text
✅ Workspace Isolation      — row-level, owner_id FK
✅ Screenshot Capture       — Playwright + MinIO
✅ Setup Wizard             — 4-step first-run wizard
✅ Admin Panel              — KB stats, bulk import, user management
✅ CVE Correlation          — NVD API v2.0, badge di UI
✅ GraphQL Analyzer         — 5 test vectors, terintegrasi ke vuln_hunt
✅ HackerOne Program Sync   — import scope dari H1 program handle
✅ Worker Health UI         — auto-refresh, cards, active task table
✅ Engagement Export/Import — JSON bundle, access control
✅ OPSEC Mode               — request jitter, toggle di UI
✅ E2E Tests                — Playwright auth + engagement + HITL
✅ Tests                    — 153 passing, 0 failed
```

## Yang Masih Kurang (Gap Final)

```
❌ Migration belum di-apply           — `a3c91b7d0e22` pending (HIGH)
❌ Burp Pro live test                 — kode ada, validasi real belum
❌ KB record volume                   — 1.500 records, target 50.000+
❌ API documentation (OpenAPI)        — belum dikurasi untuk external use
❌ Performance hardening              — tidak ada benchmark, query N+1 risk
❌ Secret scanning / security audit   — tidak ada automated secret check
❌ Log aggregation                    — tidak ada centralized logging
❌ Backup strategy                    — PostgreSQL + Qdrant tidak ada backup
❌ HTTPS default                      — nginx ada tapi self-signed cert only
❌ Environment config validation      — startup tidak validasi env vars
❌ Dependency pinning                 — pyproject.toml pakai `>=`, bukan pinned
```

---

## Sprint 7 — Foundation Hardening

> **Prioritas:** Hal-hal yang bisa menyebabkan kegagalan di production  
> **Estimasi:** 3–5 hari  
> **Urutan wajib diikuti**

---

### Task 7.1 — Apply Pending Migration + Startup Validation

**Konteks:**  
Migration `a3c91b7d0e22_add_opsec_mode_to_engagements.py` belum di-apply. Jika DB sudah berjalan, OPSEC mode tidak akan berfungsi. Selain itu, aplikasi tidak memvalidasi environment variables saat startup — error muncul random saat runtime.

**Step 1 — Apply migration:**

```bash
# Jalankan dari apps/api
uv run alembic upgrade head

# Verifikasi
uv run alembic current
# Output: a3c91b7d0e22 (head)

# Verifikasi kolom ada di DB
psql $DATABASE_URL -c "\d engagements"
# Harus ada: opsec_mode boolean, request_jitter_ms integer
```

**Step 2 — Buat startup validator:**

```python
# apps/api/app/core/startup.py

"""
Validasi semua environment variables dan dependencies
saat aplikasi startup. Gagal dengan pesan jelas jika ada yang missing.
"""

import sys
import httpx
from app.core.config import settings

class StartupValidator:
    errors: list[str] = []
    warnings: list[str] = []

    async def validate_all(self):
        await self._validate_env_vars()
        await self._validate_database()
        await self._validate_redis()
        await self._validate_qdrant()
        await self._validate_ollama()
        await self._validate_minio()
        self._validate_burp_optional()

        if self.errors:
            print("\n❌ STARTUP FAILED — Missing required configuration:\n")
            for err in self.errors:
                print(f"  • {err}")
            print("\nCheck your .env file and try again.\n")
            sys.exit(1)

        if self.warnings:
            print("\n⚠️  Startup warnings (non-fatal):\n")
            for warn in self.warnings:
                print(f"  • {warn}")

        print("\n✅ Pentra AI startup validation passed\n")

    async def _validate_env_vars(self):
        required = [
            "DATABASE_URL", "REDIS_URL", "QDRANT_URL",
            "MINIO_URL", "OLLAMA_URL", "SECRET_KEY",
        ]
        for var in required:
            if not getattr(settings, var.lower(), None):
                self.errors.append(f"Missing required env var: {var}")

        # SECRET_KEY harus minimal 32 karakter
        if settings.secret_key and len(settings.secret_key) < 32:
            self.errors.append(
                "SECRET_KEY terlalu pendek — minimum 32 karakter"
            )

        # SECRET_KEY jangan pakai default
        if settings.secret_key in ["changeme", "secret", "pentra"]:
            self.errors.append(
                "SECRET_KEY menggunakan nilai default — ganti di .env"
            )

    async def _validate_database(self):
        try:
            async with get_db_session() as db:
                await db.execute(text("SELECT 1"))
        except Exception as e:
            self.errors.append(f"Database tidak bisa diakses: {e}")

    async def _validate_redis(self):
        try:
            r = await redis.from_url(settings.redis_url)
            await r.ping()
            await r.aclose()
        except Exception as e:
            self.errors.append(f"Redis tidak bisa diakses: {e}")

    async def _validate_qdrant(self):
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{settings.qdrant_url}/healthz", timeout=5
                )
                if resp.status_code != 200:
                    self.errors.append("Qdrant health check gagal")
        except Exception as e:
            self.errors.append(f"Qdrant tidak bisa diakses: {e}")

    async def _validate_ollama(self):
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{settings.ollama_url}/api/tags", timeout=10
                )
                models = [m["name"] for m in resp.json().get("models", [])]

                if settings.ollama_model_embedding not in models:
                    self.warnings.append(
                        f"Embedding model '{settings.ollama_model_embedding}' "
                        f"tidak ditemukan di Ollama. Jalankan: "
                        f"ollama pull {settings.ollama_model_embedding}"
                    )
                if settings.ollama_model_default not in models:
                    self.warnings.append(
                        f"Default LLM '{settings.ollama_model_default}' "
                        f"tidak ditemukan di Ollama."
                    )
        except Exception as e:
            self.errors.append(f"Ollama tidak bisa diakses: {e}")

    async def _validate_minio(self):
        try:
            # Cek bucket 'evidence' ada
            from app.core.minio import minio_client
            buckets = await minio_client.list_buckets()
            if "evidence" not in [b.name for b in buckets]:
                # Auto-create bucket
                await minio_client.make_bucket("evidence")
        except Exception as e:
            self.errors.append(f"MinIO tidak bisa diakses: {e}")

    def _validate_burp_optional(self):
        if not settings.burp_mcp_url:
            self.warnings.append(
                "BURP_MCP_URL tidak dikonfigurasi — "
                "Burp Suite integration tidak akan tersedia"
            )

# Panggil di app startup
# apps/api/app/main.py

@app.on_event("startup")
async def on_startup():
    validator = StartupValidator()
    await validator.validate_all()

    # Apply pending migrations otomatis
    alembic_cfg = Config("alembic.ini")
    command.upgrade(alembic_cfg, "head")
```

---

### Task 7.2 — Performance: Hilangkan N+1 Queries

**Konteks:**  
List endpoints (workspaces, engagements, findings) kemungkinan besar punya N+1 query problem — untuk setiap item di list, ada query tambahan ke tabel relasi. Ini akan lambat saat data bertambah.

**Audit semua list endpoints:**

```python
# Pattern yang harus dicari dan diperbaiki:

# ❌ N+1 — jangan lakukan ini:
engagements = await db.execute(select(EngagementORM))
for eng in engagements.scalars():
    eng.findings_count = await db.execute(
        select(func.count()).where(FindingORM.engagement_id == eng.id)
    )

# ✅ Gunakan selectinload atau joinedload:
from sqlalchemy.orm import selectinload

result = await db.execute(
    select(EngagementORM)
    .options(selectinload(EngagementORM.findings))
    .where(EngagementORM.workspace_id == workspace_id)
)

# ✅ Atau gunakan subquery untuk count:
findings_count = (
    select(func.count(FindingORM.id))
    .where(FindingORM.engagement_id == EngagementORM.id)
    .scalar_subquery()
)
result = await db.execute(
    select(EngagementORM, findings_count.label("findings_count"))
)
```

**File yang harus diaudit (cek semua `select()` yang di-loop):**

```
apps/api/app/services/workspace_service.py
apps/api/app/services/engagement_service.py
apps/api/app/services/finding_service.py
apps/api/app/services/knowledge_service.py
```

**Tambahkan database indexes yang missing:**

```python
# Buat migration baru untuk indexes:
# uv run alembic revision --autogenerate -m "add_performance_indexes"

# Indexes yang harus ada:
# findings: (engagement_id, severity) — filter by engagement + sort by severity
# findings: (engagement_id, status)   — filter confirmed findings
# audit_logs: (engagement_id, timestamp) — timeline queries
# knowledge_records: (vuln_class, severity) — KB browser filter
# monitoring_alerts: (engagement_id, is_read) — unread count
```

**Buat migration:**

```bash
uv run alembic revision -m "add_performance_indexes"
# Edit file migration yang baru dibuat, tambahkan:
# op.create_index('ix_findings_engagement_severity', 'findings', ['engagement_id', 'severity'])
# op.create_index('ix_findings_engagement_status', 'findings', ['engagement_id', 'status'])
# dst...
uv run alembic upgrade head
```

---

### Task 7.3 — Secret Scanning + Security Audit

**Konteks:**  
Tidak ada automated check untuk hardcoded secrets. Sebelum repo dibagikan atau open-sourced, ini critical.

**Install dan setup gitleaks:**

```bash
# Tambahkan ke Dockerfile.api atau sebagai CI step
# Install gitleaks
curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/main/scripts/install.sh | sh

# Scan seluruh repo
gitleaks detect --source . --verbose

# Scan git history
gitleaks detect --source . --log-opts="--all" --verbose
```

**Buat `.gitleaks.toml` di root:**

```toml
# .gitleaks.toml
title = "Pentra AI Gitleaks Config"

[allowlist]
  description = "Global allowlist"
  paths = [
    ".env.example",      # File contoh boleh punya placeholder
    "PROGRESS.md",       # Tidak ada secret di dokumen progress
    "docs/PRD.md",
  ]
  regexes = [
    "pentra123",         # Default dev password di docs
    "changeme",          # Placeholder di .env.example
    "your-strong-password",
  ]
```

**Tambahkan pre-commit hook:**

```bash
# .pre-commit-config.yaml (buat di root repo)
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.4.0
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.10.0
    hooks:
      - id: mypy
        additional_dependencies: [types-all]
```

**Setup pre-commit:**

```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files  # Jalankan sekali untuk baseline
```

---

### Task 7.4 — Backup Strategy

**Konteks:**  
Tidak ada backup untuk PostgreSQL dan Qdrant. Jika disk corrupt atau container mati, semua data hilang.

**Buat Celery task untuk backup harian:**

```python
# apps/worker/app/tasks/backup.py

import asyncio
import subprocess
from datetime import datetime
from pathlib import Path

async def backup_postgresql():
    """
    pg_dump database ke MinIO.
    Schedule: setiap hari jam 01:00.
    Retain: 7 backup terakhir.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = f"/tmp/pentra_backup_{timestamp}.sql.gz"

    # Dump dan compress
    dump_cmd = (
        f"pg_dump {settings.database_url} | gzip > {backup_file}"
    )
    result = subprocess.run(dump_cmd, shell=True, capture_output=True)
    
    if result.returncode != 0:
        raise RuntimeError(f"pg_dump failed: {result.stderr.decode()}")

    # Upload ke MinIO bucket 'backups'
    await minio_client.fput_object(
        bucket_name="backups",
        object_name=f"postgresql/{timestamp}.sql.gz",
        file_path=backup_file,
    )

    # Hapus backup lama (retain 7)
    await _cleanup_old_backups("backups", "postgresql/", keep=7)

    Path(backup_file).unlink(missing_ok=True)
    return {"status": "success", "file": f"postgresql/{timestamp}.sql.gz"}


async def backup_qdrant():
    """
    Snapshot Qdrant collection ke MinIO.
    Qdrant punya built-in snapshot API.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Buat snapshot via Qdrant REST API
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{settings.qdrant_url}/collections/knowledge/snapshots"
        )
        snapshot_name = resp.json()["result"]["name"]

        # Download snapshot
        snapshot_resp = await client.get(
            f"{settings.qdrant_url}/collections/knowledge/snapshots/{snapshot_name}",
            timeout=120,
        )

    # Upload ke MinIO
    await minio_client.put_object(
        bucket_name="backups",
        object_name=f"qdrant/{timestamp}_{snapshot_name}",
        data=snapshot_resp.content,
        length=len(snapshot_resp.content),
    )

    await _cleanup_old_backups("backups", "qdrant/", keep=7)
    return {"status": "success", "snapshot": snapshot_name}


async def _cleanup_old_backups(bucket: str, prefix: str, keep: int):
    """Hapus backup lama, pertahankan N backup terbaru."""
    objects = await minio_client.list_objects(bucket, prefix=prefix)
    sorted_objects = sorted(objects, key=lambda o: o.last_modified, reverse=True)
    
    for obj in sorted_objects[keep:]:
        await minio_client.remove_object(bucket, obj.object_name)
```

**Tambahkan ke Celery Beat schedule:**

```python
# apps/worker/app/celeryconfig.py
beat_schedule = {
    # ... existing ...
    "backup-postgresql-daily": {
        "task": "tasks.backup.backup_postgresql",
        "schedule": crontab(hour=1, minute=0),
    },
    "backup-qdrant-daily": {
        "task": "tasks.backup.backup_qdrant",
        "schedule": crontab(hour=1, minute=30),
    },
}
```

**Tambahkan UI backup status di Admin panel:**

```typescript
// apps/web/src/pages/AdminPage.tsx
// Tambahkan section "Backup Status":
// - Last PostgreSQL backup: "2 jam yang lalu" + size
// - Last Qdrant backup: "2 jam yang lalu" + size
// - Button: [Trigger Manual Backup] → POST /api/v1/admin/backup/trigger
// - Table: 7 backup terakhir dengan timestamp + ukuran + download link
```

---

### Task 7.5 — Dependency Pinning + Lock Files

**Konteks:**  
`pyproject.toml` menggunakan versi dengan `>=` yang bisa menyebabkan build non-deterministic dan breaking changes tiba-tiba.

**Untuk semua Python packages:**

```bash
# Generate lock files dengan uv
cd apps/api && uv lock
cd apps/worker && uv lock
cd packages/pentra-knowledge && uv lock
cd packages/pentra-agent && uv lock
cd packages/pentra-tools && uv lock
cd packages/pentra-scope && uv lock
cd packages/pentra-report && uv lock
cd packages/pentra-payload && uv lock
cd packages/pentra-shared && uv lock

# Commit semua uv.lock files ke git
git add */uv.lock
git commit -m "chore: pin all Python dependencies via uv lock"
```

**Untuk frontend:**

```bash
# pnpm sudah generate pnpm-lock.yaml — pastikan di-commit dan tidak di .gitignore
cd apps/web
pnpm install --frozen-lockfile  # Test bahwa lockfile valid
```

**Update Dockerfiles untuk gunakan lock files:**

```dockerfile
# infra/docker/Dockerfile.api — update:
# Sebelum:
RUN uv pip install -e .

# Sesudah (deterministic):
COPY uv.lock .
RUN uv sync --frozen --no-dev
```

---

## Sprint 8 — Knowledge Base Scale-Up

> **Prioritas:** Perbesar knowledge base dari 1.500 ke 25.000+ records  
> **Estimasi:** 2–3 hari (sebagian berjalan otomatis)  
> **Ini adalah sprint yang paling berdampak pada kualitas intelligence Pentra AI**

---

### Task 8.1 — Jalankan Bulk Import H1 + PayloadsAllThings

**Step 1 — Trigger H1 GraphQL bulk import via Admin UI:**

```
1. Buka http://localhost:5174/admin
2. Section "Knowledge Base Management"
3. Klik [Trigger H1 Import] dengan max_records: 5000
4. Monitor progress di Worker Health UI (/admin/workers)
5. Target: 5.000+ records dari H1 Hacktivity
```

**Atau via CLI:**

```bash
# Trigger Celery task langsung
cd apps/worker
uv run celery -A app.worker call tasks.knowledge_update \
  --args='[{"source": "h1_graphql", "max_pages": 200}]'

# Monitor
uv run celery -A app.worker inspect active
uv run celery -A app.worker events  # Real-time event stream
```

**Step 2 — Import PayloadsAllThings:**

```bash
# Jika task sudah ada dari Sprint 1.4:
uv run celery -A app.worker call tasks.payloads_all_things

# Jika belum ada, buat terlebih dahulu:
# apps/worker/tasks/payloads_all_things.py (lihat PHASE-2-EXECUTION.md Task 1.4)
```

**Step 3 — Monitor Qdrant record count:**

```bash
# Cek jumlah records di Qdrant
curl http://localhost:6333/collections/knowledge | jq '.result.points_count'

# Target setelah bulk import:
# H1 GraphQL (200 pages × ~25 reports) : ~5.000 records
# PayloadsAllThings                     : ~2.000 records
# RSS feeds (jika sudah berjalan)       : ~1.000 records
# Existing seed                         : ~1.500 records
# ─────────────────────────────────────
# Total target                          : ~10.000+ records
```

---

### Task 8.2 — Optimasi Embedding Pipeline

**Konteks:**  
Embedding pipeline saat ini memproses satu per satu. Untuk 10.000+ records, ini akan sangat lambat. Perlu batch processing.

**Update embedding service:**

```python
# packages/pentra-knowledge/pentra_knowledge/services/embedding.py

class EmbeddingService:
    
    async def embed_batch(
        self,
        texts: list[str],
        batch_size: int = 32,
    ) -> list[list[float]]:
        """
        Embed banyak teks sekaligus dalam batch.
        Lebih efisien dari embed satu per satu.
        BGE-M3 via Ollama tidak support true batch,
        tapi kita bisa jalankan concurrently dengan semaphore.
        """
        semaphore = asyncio.Semaphore(8)  # Max 8 concurrent requests ke Ollama
        
        async def embed_one(text: str) -> list[float]:
            async with semaphore:
                return await self.embed(text)
        
        # Proses dalam batch untuk hindari memory spike
        all_embeddings = []
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            embeddings = await asyncio.gather(*[embed_one(t) for t in batch])
            all_embeddings.extend(embeddings)
            
            # Log progress
            print(f"Embedded {min(i + batch_size, len(texts))}/{len(texts)} records")
        
        return all_embeddings
    
    async def upsert_batch_to_qdrant(
        self,
        records: list[KnowledgeRecord],
        batch_size: int = 100,
    ) -> int:
        """
        Upsert banyak records ke Qdrant sekaligus.
        Qdrant support batch upsert natively — jauh lebih cepat dari satu per satu.
        """
        from qdrant_client.models import PointStruct
        
        total_upserted = 0
        
        for i in range(0, len(records), batch_size):
            batch = records[i:i + batch_size]
            
            # Embed semua teks di batch sekaligus
            texts = [r.to_search_text() for r in batch]
            embeddings = await self.embed_batch(texts)
            
            points = [
                PointStruct(
                    id=str(record.id),
                    vector={"dense": embedding},
                    payload=record.model_dump(exclude={"embedding_dense"})
                )
                for record, embedding in zip(batch, embeddings)
            ]
            
            await self.qdrant_client.upsert(
                collection_name="knowledge",
                points=points,
            )
            
            total_upserted += len(batch)
            print(f"Upserted {total_upserted}/{len(records)} records to Qdrant")
        
        return total_upserted
```

---

### Task 8.3 — Knowledge Quality Scoring

**Konteks:**  
Tidak semua knowledge records punya kualitas yang sama. Record dari H1 dengan bounty tinggi dan detail lengkap lebih valuable dari record yang parsial. Perlu scoring untuk prioritaskan retrieval.

**Tambahkan field `quality_score` ke KnowledgeRecord:**

```python
# packages/pentra-shared/pentra_shared/types/knowledge.py — tambahkan:

class KnowledgeRecord(BaseModel):
    # ... existing fields ...
    quality_score: float = 0.0  # 0.0 - 1.0, diisi saat ingestion
    
    def calculate_quality_score(self) -> float:
        """
        Hitung quality score berdasarkan kelengkapan fields.
        Dipakai untuk boost retrieval — records berkualitas tinggi
        muncul lebih atas di search results.
        """
        score = 0.0
        
        # Fields yang ada berkontribusi ke score
        if self.key_insight:            score += 0.20
        if self.attack_technique:       score += 0.20
        if self.indicators:             score += 0.15
        if self.attack_steps:           score += 0.15
        if self.what_tools_missed:      score += 0.10
        if self.tech_stack:             score += 0.10
        if self.bounty_usd and self.bounty_usd > 0:
            # Bounty tinggi = report detail = quality tinggi
            if self.bounty_usd >= 5000:   score += 0.10
            elif self.bounty_usd >= 1000:  score += 0.05
        if self.chained_with:          score += 0.05
        if self.cvss_score:            score += 0.05  # Ada severity assessment
        
        return min(score, 1.0)
```

**Update search untuk pakai quality score sebagai secondary ranking:**

```python
# packages/pentra-knowledge/pentra_knowledge/services/search.py

async def hybrid_search(
    query: str,
    filters: dict | None = None,
    top_k: int = 8,
    min_quality_score: float = 0.3,  # Filter record berkualitas rendah
) -> list[KnowledgeRecord]:
    
    # ... existing search logic ...
    
    # Filter berdasarkan quality score
    if filters is None:
        filters = {}
    filters["quality_score"] = {"gte": min_quality_score}
    
    # Sort results: semantic score × quality_score (boost)
    results = sorted(
        raw_results,
        key=lambda r: r.score * (0.7 + 0.3 * r.payload.get("quality_score", 0)),
        reverse=True
    )
    
    return results[:top_k]
```

**Backfill quality scores untuk records yang sudah ada:**

```bash
# Script untuk update quality_score semua records yang ada
cd apps/api
uv run python scripts/backfill_quality_scores.py
```

```python
# scripts/backfill_quality_scores.py

"""
Hitung dan update quality_score untuk semua knowledge records yang ada.
Jalankan sekali setelah deploy.
"""

async def backfill():
    async with get_db_session() as db:
        result = await db.execute(select(KnowledgeRecordORM))
        records = result.scalars().all()
        
        print(f"Backfilling quality scores for {len(records)} records...")
        
        for i, orm_record in enumerate(records):
            record = KnowledgeRecord.model_validate(orm_record)
            score = record.calculate_quality_score()
            orm_record.quality_score = score
            
            if i % 100 == 0:
                await db.commit()
                print(f"  {i}/{len(records)} done")
        
        await db.commit()
        print(f"Done. Quality scores updated for {len(records)} records.")

asyncio.run(backfill())
```

---

## Sprint 9 — API Documentation + Developer Experience

> **Prioritas:** Memudahkan pengguna baru memahami API  
> **Estimasi:** 2–3 hari

---

### Task 9.1 — OpenAPI Documentation

**Konteks:**  
FastAPI sudah generate OpenAPI spec secara otomatis di `/docs`. Tapi belum dikurasi — tidak ada deskripsi yang berguna, tidak ada contoh request/response.

**Update semua router dengan deskripsi yang proper:**

```python
# apps/api/app/api/v1/engagements.py — contoh pattern:

router = APIRouter(
    prefix="/api/v1/engagements",
    tags=["Engagements"],
)

@router.post(
    "/",
    response_model=EngagementResponse,
    status_code=201,
    summary="Create new engagement",
    description="""
    Create a new security engagement (pentest session) within a workspace.
    
    **Modes:**
    - `semi_auto`: Agent suggests each action and waits for human approval
    - `agentic`: Agent runs autonomously, only pauses for destructive actions
    
    **Scope format:**
    - Domains: `example.com`, `*.example.com`
    - IP addresses: `192.168.1.1`
    - CIDR ranges: `10.0.0.0/24`
    - URLs: `https://example.com/api/*`
    """,
    responses={
        201: {"description": "Engagement created successfully"},
        400: {"description": "Invalid scope format"},
        403: {"description": "Not authorized to create engagement in this workspace"},
    }
)
async def create_engagement(
    data: EngagementCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EngagementResponse:
    ...
```

**Update Pydantic schemas dengan field descriptions dan examples:**

```python
# packages/pentra-shared/pentra_shared/types/engagement.py

class EngagementCreate(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Shopify Bug Bounty - Q3 2026",
                "workspace_id": "550e8400-e29b-41d4-a716-446655440000",
                "mode": "semi_auto",
                "in_scope": ["*.shopify.com", "*.myshopify.com"],
                "out_of_scope": ["community.shopify.com"],
                "llm_model": "qwen2.5-coder:32b",
                "opsec_mode": False,
            }
        }
    )
    
    name: str = Field(
        ...,
        description="Nama engagement (tampil di dashboard)",
        min_length=3,
        max_length=200,
        examples=["Shopify Bug Bounty", "Client Pentest Q3 2026"],
    )
    workspace_id: UUID = Field(
        ...,
        description="UUID workspace tempat engagement dibuat",
    )
    mode: Literal["semi_auto", "agentic"] = Field(
        default="semi_auto",
        description=(
            "semi_auto: agent pause tiap langkah, butuh approval. "
            "agentic: agent auto, hanya pause untuk destructive action."
        ),
    )
    in_scope: list[str] = Field(
        ...,
        description="Daftar domain/IP/CIDR yang boleh di-test",
        min_length=1,
        examples=[["*.target.com", "10.0.0.0/24"]],
    )
    out_of_scope: list[str] = Field(
        default=[],
        description="Daftar domain/IP yang TIDAK boleh di-test",
        examples=[["admin.target.com", "payment.target.com"]],
    )
```

**Konfigurasi OpenAPI metadata di main.py:**

```python
# apps/api/app/main.py

app = FastAPI(
    title="Pentra AI API",
    description="""
## Pentra AI — AI Security Research Platform

Self-hosted AI platform untuk penetration testing dan bug bounty hunting.

### Authentication
Semua endpoint (kecuali `/auth/login`, `/setup/*`) membutuhkan JWT token.
Sertakan di header: `Authorization: Bearer <token>`

### Rate Limiting  
- Standard endpoints: 200 requests/jam per user
- Expensive endpoints (`/engagements/*/start`, `/knowledge/search`): 10 requests/menit

### LLM Models
Platform menggunakan Ollama. Model yang direkomendasikan:
- `qwen2.5-coder:32b` — default, code analysis + payload generation
- `deepseek-r1:32b` — deep reasoning, pentest planning
- `bge-m3` — embedding (wajib ada)
    """,
    version="1.0.0",
    contact={
        "name": "Pentra AI",
        "url": "https://github.com/your-org/pentra-ai",
    },
    license_info={"name": "Private"},
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[
        {"name": "Auth", "description": "Authentication dan user management"},
        {"name": "Workspaces", "description": "Workspace management"},
        {"name": "Engagements", "description": "Pentest engagement lifecycle"},
        {"name": "Findings", "description": "Vulnerability findings management"},
        {"name": "Knowledge", "description": "Knowledge base — search dan inject"},
        {"name": "Reports", "description": "Report generation"},
        {"name": "Admin", "description": "Admin-only operations"},
        {"name": "Setup", "description": "First-run setup wizard"},
    ],
)
```

---

### Task 9.2 — SETUP.md dan CONTRIBUTING.md

**Buat `docs/SETUP.md` — panduan setup lengkap:**

```markdown
# Pentra AI — Setup Guide

## Prerequisites
...
## Installation Steps  
...
## Troubleshooting
...
## Hardware Recommendations
...
```

**Buat `docs/CONTRIBUTING.md` — panduan kontribusi:**

```markdown
# Contributing to Pentra AI

## Development Setup
...
## Code Standards
...
## Testing Requirements
...
## PR Process
...
```

**Buat `docs/ARCHITECTURE.md` — dokumentasi arsitektur:**

```markdown
# Pentra AI Architecture

## System Overview
...
## Agent Graph
...
## Knowledge Engine
...
## Tool Integration Layer
...
## Data Flow
...
```

---

## Checklist Akhir Phase 4

```
Sprint 7 — Foundation Hardening
[ ] uv run alembic upgrade head berhasil (migration a3c91b7d0e22 applied)
[ ] opsec_mode dan request_jitter_ms kolom ada di tabel engagements
[ ] StartupValidator berjalan saat `docker compose up`
[ ] Startup exit dengan pesan jelas jika DATABASE_URL missing
[ ] Startup warn jika bge-m3 tidak ada di Ollama
[ ] Tidak ada N+1 query di list endpoints (verified dengan SQLAlchemy echo)
[ ] Migration performance indexes berhasil di-apply
[ ] gitleaks scan tidak menemukan secret di repo
[ ] .pre-commit-config.yaml terinstall dan berjalan
[ ] uv.lock files ada untuk semua Python packages dan di-commit
[ ] pnpm-lock.yaml valid dan di-commit
[ ] Celery task backup_postgresql berjalan tanpa error
[ ] Celery task backup_qdrant berjalan tanpa error
[ ] Backup terlihat di MinIO bucket 'backups'
[ ] UI backup status di Admin panel menampilkan last backup time

Sprint 8 — Knowledge Base Scale-Up
[ ] Qdrant record count > 5.000 setelah H1 bulk import
[ ] Qdrant record count > 8.000 setelah PayloadsAllThings import
[ ] embed_batch() memproses 100 records lebih cepat dari embed satu per satu
[ ] upsert_batch_to_qdrant() berhasil upsert 100 records dalam satu call
[ ] quality_score field ada di KnowledgeRecord schema
[ ] Semua records existing punya quality_score > 0 setelah backfill
[ ] Search results diurutkan berdasarkan semantic score × quality boost
[ ] min_quality_score=0.3 filter records yang parsial

Sprint 9 — API Documentation
[ ] /docs menampilkan semua endpoint dengan deskripsi yang berguna
[ ] /redoc bisa diakses dan readable
[ ] Semua endpoint punya summary dan description
[ ] Semua Pydantic schemas punya field descriptions dan examples
[ ] docs/SETUP.md lengkap dan teruji (setup fresh mengikuti panduan berhasil)
[ ] docs/ARCHITECTURE.md mendeskripsikan semua komponen utama

Final Checks
[ ] docker compose up -d → semua 7 services healthy dalam 2 menit
[ ] Setup wizard berjalan dari awal sampai dashboard
[ ] Engagement bisa dibuat dan agent bisa distart
[ ] KB search return relevant results
[ ] Report bisa di-download dalam format PDF
[ ] Semua 153 existing tests masih pass
[ ] Tidak ada regresi dari perubahan Sprint 7–9
```

---

## Gap yang Masih Sengaja Ditunda (v2.0)

```
⏸ Bugcrowd / Intigriti full API integration   — H1 sudah cukup untuk MVP
⏸ CI/CD pipeline (GitHub Actions)             — setup lokal dulu
⏸ Multi-GPU LLM routing                       — hardware dependent
⏸ Mobile app testing integration              — beda scope produk
⏸ Public open-source release                  — lisensi masih private
⏸ Team plan / billing                         — SaaS feature, bukan priority
```

---

## Cara Memulai Phase 4

Gunakan prompt ini di Copilot Chat:

```
Baca CLAUDE.md, docs/PRD.md, PROGRESS.md, dan PHASE-4-EXECUTION.md secara lengkap.

Kita mulai Sprint 7, Task 7.1 — Apply pending migration dan buat startup validator.

1. Jalankan: uv run alembic upgrade head (dari apps/api)
2. Verifikasi kolom opsec_mode ada di tabel engagements
3. Buat apps/api/app/core/startup.py dengan class StartupValidator
4. Integrasikan ke apps/api/app/main.py di on_event("startup")
5. Test dengan DATABASE_URL yang salah — harus exit dengan pesan jelas

Ikuti semua konvensi yang ada di CLAUDE.md.
```

---

*Phase 4 Execution Plan — Pentra AI*  
*Dibuat berdasarkan gap analysis dari PROGRESS.md (Sprint 1–6 complete, 153 tests) vs PRD v0.2*  
*Setelah Phase 4 selesai: Pentra AI siap untuk digunakan secara profesional di real engagement*
