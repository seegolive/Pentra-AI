"""Context-aware payload generator using LLM + RAG knowledge records."""

from __future__ import annotations

import json
import logging

import httpx

from pentra_payload.models import Payload, PayloadContext

log = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are an expert penetration tester. Generate targeted security test payloads.
For each payload, provide:
- The exact payload string
- A brief rationale explaining why it might succeed
- A severity hint if it works (critical/high/medium/low/info)
- Whether the payload needs URL encoding

Respond ONLY with a valid JSON array. No markdown, no explanation outside JSON.
Format:
[
  {
    "value": "<payload>",
    "rationale": "<why>",
    "severity_hint": "high",
    "requires_encoding": false
  }
]
"""

_USER_TEMPLATE = """\
Target context:
- URL: {target_url}
- Parameter: {parameter_name} (position: {parameter_position}, method: {http_method})
- Current value: {parameter_value}
- Vulnerability class: {vuln_class}
- Tech stack: {tech_stack}
{additional_context}

Relevant patterns from knowledge base:
{knowledge_context}

Generate exactly {count} payloads for this parameter. Tailor them to the tech stack and vuln class.
"""


class PayloadGenerator:
    """Context-aware payload generator.

    Uses local Ollama LLM combined with RAG knowledge records to produce
    targeted payloads for a specific parameter + vulnerability class.
    """

    def __init__(self, ollama_url: str, model: str) -> None:
        self._ollama_url = ollama_url.rstrip("/")
        self._model = model

    async def generate(
        self,
        context: PayloadContext,
        knowledge_records: list[dict],
        count: int = 10,
    ) -> list[Payload]:
        """Generate payloads for the given context.

        Args:
            context: Target parameter and vulnerability context.
            knowledge_records: Raw KB record dicts (from RAG search results).
            count: How many payloads to generate (capped at 50).

        Returns:
            List of Payload objects.
        """
        count = min(count, 50)
        knowledge_context = self._format_knowledge(knowledge_records)

        user_message = _USER_TEMPLATE.format(
            target_url=context.target_url,
            parameter_name=context.parameter_name,
            parameter_position=context.parameter_position,
            http_method=context.http_method,
            parameter_value=context.parameter_value,
            vuln_class=context.vuln_class.value,
            tech_stack=", ".join(context.tech_stack) if context.tech_stack else "unknown",
            additional_context=(
                f"\nAdditional context: {context.additional_context}"
                if context.additional_context
                else ""
            ),
            knowledge_context=knowledge_context,
            count=count,
        )

        raw = await self._call_llm(user_message)
        return self._parse_response(raw, count)

    def _format_knowledge(self, records: list[dict]) -> str:
        if not records:
            return "(No knowledge base records available)"
        lines = []
        for i, rec in enumerate(records[:8], 1):  # cap at 8 records
            lines.append(
                f"{i}. [{rec.get('vuln_class', 'unknown')}] {rec.get('title', '')}"
                f"\n   Technique: {rec.get('attack_technique', '')}"
                f"\n   Insight: {rec.get('key_insight', '')}"
            )
        return "\n\n".join(lines)

    async def _call_llm(self, user_message: str) -> str:
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            "stream": False,
            "options": {"temperature": 0.7, "num_predict": 2048},
        }
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(f"{self._ollama_url}/api/chat", json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data["message"]["content"]

    def _parse_response(self, raw: str, expected_count: int) -> list[Payload]:
        """Extract JSON array from LLM response and validate into Payload objects."""
        # Strip markdown code fences if present
        text = raw.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[-1]
            text = text.rsplit("```", 1)[0]
        text = text.strip()

        # Find JSON array bounds
        start = text.find("[")
        end = text.rfind("]")
        if start == -1 or end == -1:
            log.warning("LLM response did not contain a JSON array")
            return []

        try:
            items = json.loads(text[start : end + 1])
        except json.JSONDecodeError as exc:
            log.warning("Failed to parse LLM payload JSON: %s", exc)
            return []

        payloads: list[Payload] = []
        for item in items[:expected_count]:
            try:
                payloads.append(
                    Payload(
                        value=str(item.get("value", "")),
                        rationale=str(item.get("rationale", "")),
                        severity_hint=item.get("severity_hint", "medium"),
                        requires_encoding=bool(item.get("requires_encoding", False)),
                    )
                )
            except Exception as exc:  # noqa: BLE001
                log.debug("Skipping invalid payload item: %s", exc)

        return payloads
