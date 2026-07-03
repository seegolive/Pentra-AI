"""Located Memory — Task 18.10 (TermiAgent-inspired).

Provides a persistent, structured memory store for the vuln_hunt loop.
Prevents context forgetting by tracking:
  - Confirmed findings per URL/param (skip re-testing confirmed vulns)
  - Failed payloads per URL/param (avoid repeating dead-end attempts)
  - Tested candidates (prevent duplicate testing across hunt rounds)
  - Effective techniques (promote what worked on similar endpoints)

Used in two ways:
  1. Skip gate — before testing a candidate, check if already confirmed or useless
  2. Observation enrichment — inject compact memory summary into ReAct observation

Memory is scoped to one engagement run (not persisted to DB in this sprint).
It lives inside _run_llm_burp_active_testing and is passed into _test_one.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

# Key = (url, param_name)
_CandidateKey = tuple[str, str]


@dataclass
class LocatedMemory:
    """In-memory store tracking what happened to each URL/param combination.

    Thread-safe assumption: asyncio single-threaded event loop — no real concurrency
    on this dict; asyncio.gather cooperates, not preempts.
    """

    # Candidates that already have a confirmed finding — skip re-testing
    confirmed: dict[_CandidateKey, dict] = field(default_factory=dict)

    # Payloads that produced no anomaly for a given candidate — skip reuse
    # Key: (url, param_name), Value: set of payload strings
    failed_payloads: dict[_CandidateKey, set[str]] = field(default_factory=dict)

    # Candidates that were fully tested (no finding) — skip in future rounds
    exhausted: set[_CandidateKey] = field(default_factory=set)

    # Payloads that WORKED — prioritise on similar params next round
    # Key: vuln_class (e.g. "SQL Injection"), Value: list of effective payloads
    effective_payloads: dict[str, list[str]] = field(default_factory=dict)

    # Full react_history for LLM context (shared across candidates)
    react_history: list[dict] = field(default_factory=list)

    def mark_confirmed(self, url: str, param: str, finding: dict) -> None:
        key = (url, param)
        self.confirmed[key] = finding
        vuln_class = finding.get("vuln_class", "unknown")
        payload = finding.get("payload", "")
        if vuln_class and payload:
            self.effective_payloads.setdefault(vuln_class, [])
            if payload not in self.effective_payloads[vuln_class]:
                self.effective_payloads[vuln_class].append(payload)
        log.debug("[memory] Confirmed: %s[%s] → %s", url, param, vuln_class)

    def mark_failed_payload(self, url: str, param: str, payload: str) -> None:
        key = (url, param)
        self.failed_payloads.setdefault(key, set()).add(payload)

    def mark_exhausted(self, url: str, param: str) -> None:
        self.exhausted.add((url, param))

    def is_confirmed(self, url: str, param: str) -> bool:
        return (url, param) in self.confirmed

    def is_exhausted(self, url: str, param: str) -> bool:
        return (url, param) in self.exhausted

    def was_payload_tried(self, url: str, param: str, payload: str) -> bool:
        return payload in self.failed_payloads.get((url, param), set())

    def get_effective_payloads(self, vuln_class: str) -> list[str]:
        """Return payloads that confirmed a finding of this vuln_class before."""
        return list(self.effective_payloads.get(vuln_class, []))[:3]

    def add_react_step(self, url: str, param: str, thought: str, action: str) -> None:
        """Append a ReAct step to the rolling history."""
        self.react_history.append({
            "url": url,
            "param": param,
            "thought": thought,
            "action": action,
        })
        # Keep last 15 steps — enough context without overloading LLM
        if len(self.react_history) > 15:
            self.react_history = self.react_history[-15:]

    def observation_prefix(self, url: str, param: str) -> str:
        """Return a compact memory summary to prepend to every ReAct observation.

        This is the core of "no context forgetting" — the LLM sees what was
        already discovered so it can make better skip/test decisions.
        """
        lines: list[str] = []

        # ── Confirmed findings ────────────────────────────────────────────────
        if self.confirmed:
            lines.append(f"CONFIRMED FINDINGS SO FAR ({len(self.confirmed)}):")
            for (u, p), f in list(self.confirmed.items())[:5]:
                sev = f.get("severity", "?").upper()
                vc = f.get("vuln_class", "?")
                lines.append(f"  [{sev}] {vc} @ {u} param={p!r}")
            lines.append("")

        # ── Current candidate status ──────────────────────────────────────────
        key = (url, param)
        tried = self.failed_payloads.get(key, set())
        if tried:
            lines.append(f"ALREADY TRIED on {param!r} (no anomaly): {len(tried)} payloads — avoid repeating these.")
            lines.append("")

        # ── Effective payloads from similar tests ─────────────────────────────
        if self.effective_payloads:
            lines.append("PAYLOADS THAT WORKED this engagement:")
            for vc, payloads in list(self.effective_payloads.items())[:3]:
                lines.append(f"  {vc}: {payloads[0]!r}")
            lines.append("")

        # ── Exhausted candidates ──────────────────────────────────────────────
        if self.exhausted:
            lines.append(f"EXHAUSTED (tested, no finding): {len(self.exhausted)} candidate(s)")
            lines.append("")

        return "\n".join(lines) if lines else ""

    @property
    def stats(self) -> dict:
        return {
            "confirmed": len(self.confirmed),
            "exhausted": len(self.exhausted),
            "effective_payload_classes": list(self.effective_payloads.keys()),
        }

    # ── Redis serialisation ───────────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Serialise to a JSON-safe dict for Redis storage."""
        return {
            "confirmed": {
                f"{url}|||{param}": finding
                for (url, param), finding in self.confirmed.items()
            },
            "failed_payloads": {
                f"{url}|||{param}": list(payloads)
                for (url, param), payloads in self.failed_payloads.items()
            },
            "exhausted": [f"{url}|||{param}" for url, param in self.exhausted],
            "effective_payloads": self.effective_payloads,
            "react_history": self.react_history,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "LocatedMemory":
        """Deserialise from a dict stored in Redis."""
        def _split(key: str) -> tuple[str, str]:
            parts = key.split("|||", 1)
            return (parts[0], parts[1]) if len(parts) == 2 else (parts[0], "")

        instance = cls()
        instance.confirmed = {
            _split(k): v for k, v in data.get("confirmed", {}).items()
        }
        instance.failed_payloads = {
            _split(k): set(v) for k, v in data.get("failed_payloads", {}).items()
        }
        instance.exhausted = {_split(k) for k in data.get("exhausted", [])}
        instance.effective_payloads = data.get("effective_payloads", {})
        instance.react_history = data.get("react_history", [])
        return instance
