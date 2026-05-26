"""BGE-M3 embedding via Ollama.

BGE-M3 produces a single 1024-dim dense vector when called through the Ollama
/api/embeddings endpoint.  Sparse (SPLADE-style) weights are approximated by
term-frequency over the tokenised input for now and will be replaced with true
SPLADE sparse vectors once the Ollama BGE-M3 sparse endpoint is available.
"""

import re
from collections import Counter
from math import log
from functools import lru_cache

import httpx

from pentra_knowledge.config import get_settings


class EmbeddingResult:
    """Container for BGE-M3 dense and sparse vectors."""

    __slots__ = ("dense", "sparse", "model")

    def __init__(
        self,
        dense: list[float],
        sparse: dict[str, float],
        model: str,
    ) -> None:
        self.dense = dense
        self.sparse = sparse
        self.model = model


@lru_cache(maxsize=1)
def _get_client() -> httpx.AsyncClient:
    settings = get_settings()
    return httpx.AsyncClient(base_url=settings.ollama_url, timeout=120.0)


def _build_sparse_vector(text: str) -> dict[str, float]:
    """Approximate sparse weights using TF×log(1 + len(text)/freq).

    This is a lightweight stand-in until a native SPLADE output is available
    from BGE-M3 through Ollama.  The Qdrant collection stores these under the
    'sparse' named vector config.
    """
    tokens = re.findall(r"[a-z0-9]+", text.lower())
    if not tokens:
        return {}
    counts = Counter(tokens)
    total = len(tokens)
    return {
        token: round(count / total * log(1 + total / count), 6)
        for token, count in counts.items()
        if len(token) >= 2  # skip single-character noise
    }


async def embed(text: str) -> EmbeddingResult:
    """Produce a BGE-M3 embedding for ``text`` via Ollama.

    Returns both a dense vector (1024-dim) and an approximate sparse vector.
    Raises ``httpx.HTTPStatusError`` on Ollama API errors.
    """
    settings = get_settings()
    client = _get_client()

    # Truncate to keep within BGE-M3's 8192-token window (~32 KB of text)
    truncated = text[:32_000]

    response = await client.post(
        "/api/embeddings",
        json={"model": settings.ollama_model_embedding, "prompt": truncated},
    )
    response.raise_for_status()
    payload = response.json()

    dense: list[float] = payload["embedding"]
    sparse = _build_sparse_vector(truncated)

    return EmbeddingResult(dense=dense, sparse=sparse, model=settings.ollama_model_embedding)


async def embed_batch(
    texts: list[str],
    batch_size: int = 32,
    max_concurrent: int = 8,
) -> list[EmbeddingResult]:
    """Embed many texts concurrently, respecting Ollama load limits.

    Processes ``texts`` in windows of ``batch_size`` with at most
    ``max_concurrent`` simultaneous Ollama requests to avoid overloading
    the local inference server.

    Args:
        texts: Input strings to embed.
        batch_size: Number of texts processed per window.
        max_concurrent: Max in-flight Ollama calls at one time.

    Returns:
        List of ``EmbeddingResult`` in the same order as ``texts``.
    """
    import asyncio

    semaphore = asyncio.Semaphore(max_concurrent)

    async def _embed_one(text: str) -> EmbeddingResult:
        async with semaphore:
            return await embed(text)

    all_results: list[EmbeddingResult] = []
    for i in range(0, len(texts), batch_size):
        batch = texts[i : i + batch_size]
        results = await asyncio.gather(*[_embed_one(t) for t in batch])
        all_results.extend(results)
    return all_results


def build_embedding_text(record: dict) -> str:
    """Build the text blob that will be embedded for a knowledge record.

    Combines the most semantically rich fields so BGE-M3 captures both
    the vulnerability class context and the attack technique detail.
    """
    parts = [
        record.get("title", ""),
        record.get("vuln_class", ""),
        record.get("attack_technique", ""),
        record.get("key_insight", ""),
        record.get("unique_factor", ""),
        " ".join(record.get("indicators", [])),
        " ".join(record.get("tech_stack", [])),
        " ".join(record.get("prerequisites", [])),
        record.get("what_tools_missed", "") or "",
    ]
    return "\n".join(p for p in parts if p).strip()
