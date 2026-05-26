# Pentra AI — Setup Guide

Complete guide for setting up Pentra AI locally from scratch.

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Docker + Docker Compose | ≥ 24 | Runs PostgreSQL, Redis, Qdrant, MinIO |
| Ollama | latest | Must run **on the host** (not in Docker) |
| Python | 3.11+ | For running scripts / dev server outside Docker |
| Node.js + pnpm | Node 18+, pnpm 8+ | Frontend dev server |
| uv | 0.4+ | Python package manager (`pip install uv`) |

---

## Step 1 — Clone & Configure Environment

```bash
git clone https://github.com/your-org/pentra-ai.git
cd pentra-ai

# Copy API env file
cp apps/api/.env.example apps/api/.env

# Edit the env file — minimum required changes:
#   SECRET_KEY  →  generate with: python3 -c "import secrets; print(secrets.token_hex(32))"
#   All other defaults work for local development
nano apps/api/.env
```

---

## Step 2 — Start Infrastructure (Docker)

```bash
# Start PostgreSQL, Redis, Qdrant, MinIO
docker compose -f infra/docker-compose.yml up -d db redis qdrant minio

# Verify all services are healthy
docker compose -f infra/docker-compose.yml ps
```

Expected output: all 4 services show `healthy` or `running`.

---

## Step 3 — Install Ollama & Pull Models

Ollama must run on the **host machine** (not inside Docker) so it can use your GPU.

```bash
# Install Ollama (Linux)
curl -fsSL https://ollama.ai/install.sh | sh

# Start Ollama service
ollama serve &

# Pull required models
ollama pull bge-m3              # Embedding model (required)
ollama pull qwen2.5-coder:7b   # Fast/extraction LLM (required for knowledge pipeline)

# Optional — heavier models for full agent capability
ollama pull qwen2.5-coder:32b  # Default reasoning LLM
ollama pull deepseek-r1:32b    # Deep reasoning LLM
```

> **Minimum viable setup**: `bge-m3` + `qwen2.5-coder:7b` gives you the knowledge engine.  
> Full agent functionality requires at least `qwen2.5-coder:32b`.

---

## Step 4 — Run Database Migrations

```bash
cd apps/api
uv sync                         # Install Python dependencies

# Run all Alembic migrations
DATABASE_URL="postgresql+asyncpg://pentra:pentra@localhost:5432/pentra" \
  uv run alembic upgrade head
```

---

## Step 5 — First-Run Setup

Start the API server:

```bash
cd apps/api
uv run fastapi dev app/main.py --port 8000
```

On first boot, Pentra AI will:
1. Run `StartupValidator` — connects to DB, Redis, Qdrant, and Ollama.
2. Create the Qdrant `knowledge` collection if it doesn't exist.

Then complete the admin setup via API:

```bash
curl -s -X POST http://localhost:8000/api/v1/setup/initialize \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin@localhost","password":"your-secure-password"}'
```

Or use the UI (Step 7) which redirects to `/setup` automatically on first run.

---

## Step 6 — Start the Worker

```bash
cd apps/worker

# Install dependencies (worker uses uv pip due to workspace structure)
uv pip install -r requirements.txt

# Start Celery worker
uv run celery -A app.worker worker -l info -Q default,knowledge

# (Optional) Start Celery Beat for scheduled tasks
uv run celery -A app.worker beat -l info
```

---

## Step 7 — Start the Frontend

```bash
cd apps/web
pnpm install
pnpm dev        # Vite dev server on http://localhost:5173
```

Open `http://localhost:5173` in your browser. On first run you'll be redirected to the setup wizard.

---

## Step 8 — Seed the Knowledge Base (Optional)

Import the initial HackerOne public disclosure dataset:

```bash
cd apps/api

# From the reddelexc CSV export format
DATABASE_URL="postgresql+asyncpg://pentra:pentra@localhost:5432/pentra" \
  uv run python scripts/seed_knowledge.py \
  --source h1_csv \
  --path /path/to/h1_reports.csv

# Backfill quality scores after import
DATABASE_URL="postgresql+asyncpg://pentra:pentra@localhost:5432/pentra" \
  uv run python scripts/backfill_quality_scores.py
```

---

## All-in-One with Docker Compose

A full `docker compose up` workflow is coming in a future release. For now, run Ollama on the host and use Docker only for infrastructure services.

```bash
# Infrastructure only
docker compose -f infra/docker-compose.yml up -d

# API, Worker, and Web run locally during development
```

---

## Environment Variables Reference

See `apps/api/.env.example` for the full list. Key variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql+asyncpg://pentra:pentra@localhost:5432/pentra` | PostgreSQL async URL |
| `REDIS_URL` | `redis://localhost:6379/0` | Celery broker + result backend |
| `QDRANT_URL` | `http://localhost:6333` | Qdrant vector DB |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama inference server |
| `OLLAMA_MODEL_EMBEDDING` | `bge-m3` | BGE-M3 embedding model name |
| `OLLAMA_MODEL_DEFAULT` | `qwen2.5-coder:32b` | Primary LLM for agent reasoning |
| `OLLAMA_MODEL_FAST` | `qwen2.5-coder:7b` | Fast LLM for bulk extraction |
| `OLLAMA_MODEL_REASONING` | `deepseek-r1:32b` | Deep reasoning LLM |
| `SECRET_KEY` | — | **Must change!** JWT signing key (min 32 chars) |
| `MINIO_URL` | `http://localhost:9000` | Object storage (evidence, backups) |

---

## Troubleshooting

### StartupValidator fails on Ollama
```
Ollama is not reachable at http://localhost:11434
```
Run `ollama serve` before starting the API, or update `OLLAMA_URL` in `.env`.

### Migration fails: relation does not exist
```bash
# Clear pycache and retry
find apps/api/alembic -name "*.pyc" -delete
cd apps/api && DATABASE_URL="..." uv run alembic upgrade head
```

### Qdrant collection already exists
The `ensure_collection_exists()` function is idempotent — it checks before creating. If you see a collection schema mismatch, drop and recreate:
```bash
curl -X DELETE http://localhost:6333/collections/knowledge
# Then restart the API
```

### Worker can't connect to broker
Ensure Redis is running: `docker compose -f infra/docker-compose.yml up -d redis`
