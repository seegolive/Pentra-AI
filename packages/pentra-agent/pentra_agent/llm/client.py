"""LLM client abstraction — OpenAI-compatible, works with any Ollama model.

All LLM calls in agent nodes must go through this class.
Do not call Ollama / OpenAI SDK directly from node functions.
"""

from __future__ import annotations

import json
import logging

import httpx

log = logging.getLogger(__name__)


class LLMClient:
    def __init__(
        self,
        base_url: str,          # e.g. "http://localhost:11434/v1"
        model: str,             # e.g. "qwen2.5-coder:32b"
        temperature: float = 0.3,
        timeout: float = 600.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.timeout = timeout

    # ── Low-level primitives ──────────────────────────────────────────────────

    async def complete(
        self,
        system: str,
        user: str,
        json_output: bool = False,
    ) -> str:
        """Single system+user completion → string response.

        Pass ``json_output=True`` to instruct the model to reply with raw JSON.
        """
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        if json_output:
            messages[0]["content"] += (
                "\n\nRespond ONLY with valid JSON. No markdown, no preamble."
            )

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/chat/completions",
                json={
                    "model": self.model,
                    "messages": messages,
                    "temperature": self.temperature,
                    "stream": False,
                },
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]

    async def complete_json(self, system: str, user: str) -> dict | list:
        """Completion that guarantees valid JSON output.

        Strips markdown fences if present; retries once with a stricter prompt
        if the first response fails to parse.
        """
        raw = await self.complete(system, user, json_output=True)
        raw = raw.strip()

        # Strip ```json ... ``` fences if present
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1]
            raw = raw.rsplit("```", 1)[0]

        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            # One retry with a tighter constraint
            retry_system = system + "\n\nCRITICAL: Return ONLY raw JSON, nothing else."
            raw = await self.complete(retry_system, user, json_output=True)
            raw = raw.strip().lstrip("```json").rstrip("```").strip()
            return json.loads(raw)

    # ── Domain-specific helpers ───────────────────────────────────────────────

    async def plan_engagement(
        self,
        target: dict,
        scope: dict,
        knowledge_hints: list[dict],
    ) -> str:
        """Generate a structured pentest plan from target + scope + KB hints."""
        system = (
            "You are a senior penetration tester and bug bounty hunter.\n"
            "Create a structured pentest plan based on the target and scope provided.\n"
            "Focus on high-impact vulnerabilities. Be specific about techniques to try.\n"
            "Reference the knowledge hints to prioritize testing based on similar past findings."
        )
        user = (
            f"Target: {json.dumps(target, indent=2)}\n"
            f"Scope: {json.dumps(scope, indent=2)}\n"
            f"Similar findings from knowledge base: {json.dumps(knowledge_hints[:5], indent=2)}\n\n"
            "Create a prioritized pentest plan with:\n"
            "1. Recon phase steps\n"
            "2. Vulnerability classes to test (based on tech stack if known)\n"
            "3. Specific endpoints/parameters to focus on\n"
            "4. High-value targets based on knowledge hints"
        )
        return await self.complete(system, user)

    async def analyze_recon_results(
        self,
        subdomains: list[dict],
        ports: list[dict],
        tech_stack: list[str],
        knowledge_context: list[dict],
    ) -> dict:
        """Analyse recon results and suggest vuln-hunt steps.

        Returns a dict with keys: summary, tech_stack_analysis, hypotheses,
        suggested_tests.
        """
        system = (
            "You are a senior security researcher analyzing recon results.\n"
            "Based on the discovered attack surface and known vulnerability patterns,\n"
            "identify the most promising attack vectors.\n"
            "Return JSON with keys: summary, tech_stack_analysis, hypotheses, suggested_tests"
        )
        user = (
            f"Recon results:\n"
            f"Subdomains ({len(subdomains)}): {json.dumps(subdomains[:20], indent=2)}\n"
            f"Open ports: {json.dumps(ports[:20], indent=2)}\n"
            f"Tech stack detected: {tech_stack}\n\n"
            f"Similar vulnerability patterns from knowledge base:\n"
            f"{json.dumps(knowledge_context[:5], indent=2)}\n\n"
            "Analyze and return JSON with your assessment."
        )
        return await self.complete_json(system, user)

    async def classify_finding(
        self,
        title: str,
        description: str,
        request: str,
        response: str,
    ) -> dict:
        """Classify a finding: vuln_class, severity, cvss_score, impact.

        Returns a dict with: vuln_class, vuln_subclass, severity, cvss_score,
        cvss_vector, impact, remediation.
        """
        system = (
            "You are a security expert classifying vulnerabilities.\n"
            "Analyze the provided HTTP request/response and classify the finding.\n"
            "Return JSON with: vuln_class, vuln_subclass, severity, cvss_score (0-10),\n"
            "cvss_vector, impact, remediation"
        )
        user = (
            f"Finding: {title}\n"
            f"Description: {description}\n\n"
            f"HTTP Request:\n{request[:2000]}\n\n"
            f"HTTP Response:\n{response[:2000]}\n\n"
            "Classify this finding and return JSON."
        )
        return await self.complete_json(system, user)
