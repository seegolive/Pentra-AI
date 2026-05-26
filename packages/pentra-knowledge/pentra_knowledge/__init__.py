"""pentra-knowledge — Knowledge Engine for Pentra AI.

Ingests, processes, embeds, and serves knowledge from real-world bug bounty
reports to power RAG-based technique suggestions for the LangGraph agent.

Pipeline:
    Raw source (H1 CSV / GraphQL / upload)
    → Parser + LLM extraction (qwen2.5-coder:7b)
    → PostgreSQL (metadata + full text)
    → BGE-M3 embedding via Ollama
    → Qdrant (dense + sparse vectors)
    → Hybrid search (semantic + lexical + metadata filter)
    → RAG context injected into LangGraph PentraState
"""

__version__ = "0.1.0"

from pentra_knowledge.services.embedding import embed, embed_batch, build_embedding_text
from pentra_knowledge.services.search import (
    hybrid_search,
    upsert_to_qdrant,
    upsert_batch_to_qdrant,
    ensure_collection_exists,
)

__all__ = [
    "embed",
    "embed_batch",
    "build_embedding_text",
    "hybrid_search",
    "upsert_to_qdrant",
    "upsert_batch_to_qdrant",
    "ensure_collection_exists",
]
