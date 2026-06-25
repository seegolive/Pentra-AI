"""Constants for Pentra AI — centralised reference values.

All tuneable configuration lives in environment variables (see apps/api/.env.example).
This module contains static, code-level constants that never change at runtime.
"""

# ── Embedding ─────────────────────────────────────────────────────────────────

EMBEDDING_MODEL_PRIMARY = "bge-m3"
EMBEDDING_MODEL_FALLBACK = "nomic-embed-text"

# BGE-M3 dense vector dimension
EMBEDDING_DENSE_DIM = 1024

# Maximum token context for BGE-M3 (model supports up to 8192)
EMBEDDING_MAX_TOKENS = 8192

# ── Qdrant ────────────────────────────────────────────────────────────────────

QDRANT_COLLECTION_KNOWLEDGE = "knowledge"

# Default number of results returned by hybrid search
KNOWLEDGE_SEARCH_DEFAULT_TOP_K = 8
KNOWLEDGE_SEARCH_MAX_TOP_K = 50

# ── LLM Model Tags (defaults — overridden by env vars) ───────────────────────

OLLAMA_MODEL_DEFAULT = "qwen2.5:32b"
OLLAMA_MODEL_REASONING = "qwen2.5:32b"
OLLAMA_MODEL_FAST = "qwen2.5:7b"
OLLAMA_MODEL_EMBEDDING = "bge-m3"

# ── LangGraph ─────────────────────────────────────────────────────────────────

# Engagement phases — matches PentraState.current_phase
PHASE_PLANNING = "planning"
PHASE_RECON = "recon"
PHASE_VULN_HUNT = "vuln_hunt"
PHASE_EXPLOIT_VALIDATION = "exploit_validation"
PHASE_REPORT = "report"

PHASES_ORDERED = [
    PHASE_PLANNING,
    PHASE_RECON,
    PHASE_VULN_HUNT,
    PHASE_EXPLOIT_VALIDATION,
    PHASE_REPORT,
]

# ── Knowledge Ingestion ───────────────────────────────────────────────────────

# reddelexc/h1-reports CSV column names
H1_CSV_COLUMN_MAP = {
    "id": "source_id",
    "title": "title",
    "severity": "severity",
    "weakness": "vuln_subclass",
    "url": "source_url",
    "disclosed_at": "ingested_at",
    "reporter": "program",
}

# Minimum score threshold for Qdrant search results
KNOWLEDGE_MIN_SCORE = 0.60

# ── Celery Queues ─────────────────────────────────────────────────────────────

QUEUE_DEFAULT = "default"
QUEUE_KNOWLEDGE = "knowledge"
QUEUE_TOOLS = "tools"

# ── MinIO ─────────────────────────────────────────────────────────────────────

MINIO_BUCKET_EVIDENCE = "evidence"
MINIO_BUCKET_REPORTS = "reports"
MINIO_BUCKET_RAW_KB = "raw-knowledge"

# ── Auth ──────────────────────────────────────────────────────────────────────

ACCESS_TOKEN_EXPIRE_MINUTES = 480
REFRESH_TOKEN_EXPIRE_DAYS = 30

# ── API ───────────────────────────────────────────────────────────────────────

API_V1_PREFIX = "/api/v1"
WS_PREFIX = "/ws"

# Pagination defaults
DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100
