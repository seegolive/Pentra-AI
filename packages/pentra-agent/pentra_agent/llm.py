"""LLM client wrapper — thin abstraction over the Ollama OpenAI-compatible API.

All LLM calls in pentra-agent go through this module so the model tag can
be swapped per-engagement without touching node logic.
"""

from __future__ import annotations

import os

import httpx


class OllamaClient:
    """Simple async Ollama chat completion client (OpenAI-compatible endpoint)."""

    def __init__(self, model: str, base_url: str | None = None) -> None:
        self.model = model
        self.base_url = (base_url or os.getenv("OLLAMA_URL", "http://localhost:11434")).rstrip("/")

    async def chat(self, messages: list[dict], *, temperature: float = 0.3) -> str:
        """Send a chat completion request and return the assistant message content."""
        url = f"{self.base_url}/v1/chat/completions"
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "stream": False,
        }
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]
