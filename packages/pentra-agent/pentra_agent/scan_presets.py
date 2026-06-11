"""Scan Engine Presets — Task 18.11 (reNgine pattern).

Named scan configurations that control:
  - Which tools to run (nuclei, ffuf, burp_scan, soap_xxe, etc.)
  - Concurrency (candidates tested in parallel)
  - Payload pacing (inter-request delay)
  - Timeout limits per tool
  - Max candidates tested
  - Crawl depth

Usage:
    from pentra_agent.scan_presets import ScanPreset, get_preset

    preset = get_preset("full")      # full, fast, stealth, quick
    preset.apply_to_env()            # writes env vars used by vuln_hunt_node

Or in live_scan.py:
    --preset fast                    # CLI flag
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Literal

PresetName = Literal["full", "fast", "stealth", "quick", "authenticated", "pentra-ft"]


@dataclass
class ScanPreset:
    """A named scan configuration controlling speed, depth, and tool selection.

    Attributes:
        name:               Preset identifier.
        description:        Human-readable description.
        concurrent_candidates: Number of injection candidates tested in parallel.
        payload_pacing_s:   Delay between payloads in seconds (anti-DoS).
        nuclei_timeout_s:   Max seconds before nuclei is killed.
        max_candidates:     Cap on candidates to test (higher = slower but more coverage).
        crawl_pages:        How many pages to crawl via Burp.
        run_nuclei:         Whether to run nuclei.
        run_ffuf:           Whether to run ffuf directory brute-force.
        run_burp_scan:      Whether to trigger Burp active scanner.
        run_soap_xxe:       Whether to probe for SOAP/WSDL + XXE.
        run_csrf_check:     Whether to run passive CSRF checks.
        max_payloads_per_candidate: Cap on payloads sent per candidate (higher = slower).
        use_collaborator:   Whether to use Burp Collaborator for blind OOB.
    """
    name: PresetName
    description: str
    concurrent_candidates: int = 3
    payload_pacing_s: float = 0.15
    nuclei_timeout_s: int = 180
    max_candidates: int = 20
    crawl_pages: int = 49
    run_nuclei: bool = True
    run_ffuf: bool = True
    run_burp_scan: bool = True
    run_soap_xxe: bool = True
    run_csrf_check: bool = True
    max_payloads_per_candidate: int = 4
    use_collaborator: bool = True
    llm_model: str = ""  # Override LLM model; empty = use settings.OLLAMA_MODEL_DEFAULT

    def apply_to_env(self) -> None:
        """Write preset values into environment variables consumed by vuln_hunt_node."""
        os.environ["PENTRA_CONCURRENT_CANDIDATES"] = str(self.concurrent_candidates)
        os.environ["PENTRA_PAYLOAD_PACING"] = str(self.payload_pacing_s)
        os.environ["PENTRA_NUCLEI_TIMEOUT"] = str(self.nuclei_timeout_s)
        os.environ["PENTRA_MAX_CANDIDATES"] = str(self.max_candidates)
        os.environ["PENTRA_CRAWL_PAGES"] = str(self.crawl_pages)
        os.environ["PENTRA_RUN_NUCLEI"] = "true" if self.run_nuclei else "false"
        os.environ["PENTRA_RUN_FFUF"] = "true" if self.run_ffuf else "false"
        os.environ["PENTRA_RUN_BURP_SCAN"] = "true" if self.run_burp_scan else "false"
        os.environ["PENTRA_RUN_SOAP_XXE"] = "true" if self.run_soap_xxe else "false"
        os.environ["PENTRA_RUN_CSRF_CHECK"] = "true" if self.run_csrf_check else "false"
        os.environ["PENTRA_MAX_PAYLOADS"] = str(self.max_payloads_per_candidate)
        os.environ["PENTRA_USE_COLLABORATOR"] = "true" if self.use_collaborator else "false"
        if self.llm_model:
            os.environ["PENTRA_LLM_MODEL"] = self.llm_model

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "concurrent_candidates": self.concurrent_candidates,
            "payload_pacing_s": self.payload_pacing_s,
            "nuclei_timeout_s": self.nuclei_timeout_s,
            "max_candidates": self.max_candidates,
            "crawl_pages": self.crawl_pages,
            "run_nuclei": self.run_nuclei,
            "run_ffuf": self.run_ffuf,
            "run_burp_scan": self.run_burp_scan,
            "run_soap_xxe": self.run_soap_xxe,
            "run_csrf_check": self.run_csrf_check,
            "max_payloads_per_candidate": self.max_payloads_per_candidate,
            "use_collaborator": self.use_collaborator,
        }


# ── Built-in presets ──────────────────────────────────────────────────────────

PRESETS: dict[PresetName, ScanPreset] = {
    "full": ScanPreset(
        name="full",
        description=(
            "Full scan — maximum coverage. Runs all tools, deep crawl, high concurrency. "
            "Best for thorough engagements where time is not a constraint. ~40-60 min."
        ),
        concurrent_candidates=3,
        payload_pacing_s=0.15,
        nuclei_timeout_s=300,
        max_candidates=30,
        crawl_pages=80,
        run_nuclei=True,
        run_ffuf=True,
        run_burp_scan=True,
        run_soap_xxe=True,
        run_csrf_check=True,
        max_payloads_per_candidate=6,
        use_collaborator=True,
    ),

    "fast": ScanPreset(
        name="fast",
        description=(
            "Fast scan — speed over coverage. Skips ffuf + SOAP/XXE, reduced crawl, "
            "capped candidates. Good for quick initial assessment. ~10-15 min."
        ),
        concurrent_candidates=5,
        payload_pacing_s=0.05,
        nuclei_timeout_s=120,
        max_candidates=15,
        crawl_pages=20,
        run_nuclei=True,
        run_ffuf=False,
        run_burp_scan=True,
        run_soap_xxe=False,
        run_csrf_check=False,
        max_payloads_per_candidate=3,
        use_collaborator=True,
    ),

    "stealth": ScanPreset(
        name="stealth",
        description=(
            "Stealth scan — minimal noise, slow pacing. Disables active scanner and "
            "nuclei (too loud). Only passive + LLM-driven testing. Ideal when WAF is "
            "present or engagement requires low-profile assessment. ~60-90 min."
        ),
        concurrent_candidates=1,
        payload_pacing_s=1.0,
        nuclei_timeout_s=60,
        max_candidates=10,
        crawl_pages=20,
        run_nuclei=False,
        run_ffuf=False,
        run_burp_scan=False,
        run_soap_xxe=False,
        run_csrf_check=True,
        max_payloads_per_candidate=2,
        use_collaborator=False,  # OOB might trigger IDS
    ),

    "quick": ScanPreset(
        name="quick",
        description=(
            "Quick scan — fastest possible, minimal payloads. "
            "LLM candidates + arsenal only, no nuclei/ffuf/SOAP. ~5-8 min. "
            "Good for CI/CD integration or smoke-testing a target."
        ),
        concurrent_candidates=5,
        payload_pacing_s=0.05,
        nuclei_timeout_s=60,
        max_candidates=10,
        crawl_pages=10,
        run_nuclei=False,
        run_ffuf=False,
        run_burp_scan=False,
        run_soap_xxe=False,
        run_csrf_check=False,
        max_payloads_per_candidate=2,
        use_collaborator=False,
    ),

    "authenticated": ScanPreset(
        name="authenticated",
        description=(
            "Authenticated scan — full coverage with session. Same as 'full' but "
            "designed for use with --auth-* flags. Includes IDOR testing with "
            "higher payload cap for ID enumeration. ~50-70 min."
        ),
        concurrent_candidates=3,
        payload_pacing_s=0.2,
        nuclei_timeout_s=300,
        max_candidates=30,
        crawl_pages=80,
        run_nuclei=True,
        run_ffuf=True,
        run_burp_scan=True,
        run_soap_xxe=True,
        run_csrf_check=True,
        max_payloads_per_candidate=8,   # more IDOR variants
        use_collaborator=True,
    ),

    "pentra-ft": ScanPreset(
        name="pentra-ft",
        description=(
            "Fine-tuned scan — uses pentra-ft (LoRA-tuned Qwen2.5-Coder-7B) as the "
            "reasoning LLM. Trained on 8,309 H1 disclosures + confirmed findings. "
            "Best payload generation quality for common vuln classes. ~10-15 min."
        ),
        concurrent_candidates=4,
        payload_pacing_s=0.1,
        nuclei_timeout_s=120,
        max_candidates=20,
        crawl_pages=25,
        run_nuclei=True,
        run_ffuf=False,
        run_burp_scan=True,
        run_soap_xxe=False,
        run_csrf_check=True,
        max_payloads_per_candidate=5,
        use_collaborator=True,
        llm_model="pentra-ft",  # LoRA-tuned model in Ollama
    ),
}


def get_preset(name: str) -> ScanPreset:
    """Return a named preset. Raises ValueError for unknown names."""
    if name not in PRESETS:
        available = ", ".join(PRESETS.keys())
        raise ValueError(f"Unknown preset {name!r}. Available: {available}")
    return PRESETS[name]


def list_presets() -> list[dict]:
    """Return all presets as a list of dicts (for API/CLI display)."""
    return [p.as_dict() for p in PRESETS.values()]
