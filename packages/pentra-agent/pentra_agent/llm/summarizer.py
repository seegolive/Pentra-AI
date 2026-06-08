# packages/pentra-agent/pentra_agent/llm/summarizer.py

"""
ChainSummarizer — compress message history saat mendekati context limit.
Dipanggil otomatis oleh agent nodes jika len(messages) > SUMMARIZE_THRESHOLD.

Strategy:
- Pertahankan 10 pesan terakhir verbatim (context terkini)
- Compress semua pesan sebelumnya menjadi 1 summary pesan
- Summary wajib preserve: semua findings, confirmed vulns, scope, decisions
- Compress: verbose tool outputs, repetitive recon data
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from langchain_core.messages import AnyMessage, SystemMessage

if TYPE_CHECKING:
    from pentra_agent.llm.client import LLMClient

log = logging.getLogger(__name__)

SUMMARIZE_THRESHOLD = 40   # Trigger compression after N messages
KEEP_RECENT = 10           # Number of recent messages kept verbatim
MAX_SUMMARY_CHARS = 2000   # Max character length for the compressed summary


async def maybe_summarize(
    messages: list[AnyMessage],
    llm: "LLMClient",
) -> list[AnyMessage]:
    """Compress messages if count exceeds SUMMARIZE_THRESHOLD.

    Returns messages unchanged if below threshold.
    On LLM failure, returns original messages (non-fatal).
    """
    if len(messages) <= SUMMARIZE_THRESHOLD:
        return messages

    recent = messages[-KEEP_RECENT:]
    older = messages[:-KEEP_RECENT]

    log.info(
        "[summarizer] Compressing %d messages (keeping %d recent)",
        len(older),
        len(recent),
    )

    older_text = "\n\n".join(
        f"[{type(m).__name__}]: {getattr(m, 'content', str(m))[:500]}"
        for m in older
        if hasattr(m, "content")
    )

    try:
        summary = await llm.complete(
            system="""You are summarizing a penetration testing session history.

CRITICAL RULES:
1. PRESERVE ALL: confirmed vulnerabilities, CVE IDs, CVSS scores, URLs, parameters
2. PRESERVE ALL: scope decisions, HITL approvals, rejected techniques
3. PRESERVE ALL: key findings with severity levels
4. COMPRESS: verbose tool outputs, raw HTTP responses, repeated status messages
5. FORMAT: Use bullet points, be concise but complete

Output format:
## Confirmed Findings
- [list all confirmed vulns with URL and severity]

## Key Decisions
- [list HITL approvals, skipped tests, scope clarifications]

## Recon Summary
- [brief summary of discovered assets]

## Current State
- [what phase, what's been tested, what's pending]""",
            user=f"Summarize this penetration testing session:\n\n{older_text[:6000]}",
        )
    except Exception as exc:
        log.warning("[summarizer] Summarization failed: %s — keeping original", exc)
        return messages

    if len(summary) > MAX_SUMMARY_CHARS:
        summary = summary[:MAX_SUMMARY_CHARS] + "\n... [truncated]"

    summary_msg = SystemMessage(
        content=(
            f"[COMPRESSED SESSION HISTORY — {len(older)} messages summarized]\n\n"
            f"{summary}"
        )
    )

    compressed = [summary_msg] + list(recent)
    log.info(
        "[summarizer] Compressed %d → %d messages",
        len(messages),
        len(compressed),
    )
    return compressed
