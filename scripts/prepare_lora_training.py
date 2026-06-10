#!/usr/bin/env python3
"""prepare_lora_training.py — Fine-tuning Dataset Preparation (Sprint 24)

Exports confirmed/active findings + KB records as JSONL training data
for LoRA fine-tuning of Ollama-hosted LLMs (qwen2.5:7b / qwen2.5:32b).

Two data sources:
  1. findings table  — real pentest findings from completed scans
  2. knowledge_records — 8,309 H1 public disclosures with techniques/payloads

Output format: OpenAI chat JSONL (compatible with Ollama LoRA training)
  {"messages": [
    {"role": "system",    "content": "<pentest system prompt>"},
    {"role": "user",      "content": "<observation>"},
    {"role": "assistant", "content": "<thought + action>"}
  ]}

Usage:
    cd /home/mdilab/projects/Pentra-AI/apps/api
    uv run python ../../scripts/prepare_lora_training.py

Output:
    /tmp/pentra_finetune.jsonl     — combined training JSONL
    /tmp/pentra_finetune_stats.txt — dataset statistics
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────

OUTPUT_JSONL = Path("/tmp/pentra_finetune.jsonl")
OUTPUT_STATS = Path("/tmp/pentra_finetune_stats.txt")
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://pentra:pentra@localhost:5432/pentra",
)
MAX_KB_RECORDS = int(os.getenv("MAX_KB_RECORDS", "2000"))  # cap to avoid huge files

_SYSTEM_PROMPT = (
    "You are an expert penetration tester using the ReAct (Reason+Act) framework. "
    "You analyze web application HTTP traffic to identify and confirm vulnerabilities. "
    "For each step, output:\n"
    "Thought: [Your reasoning about the current situation]\n"
    "Action: [test_injection | skip_candidate | report_finding]\n"
    "Action Input: [JSON parameters for the action]"
)

# ── Helpers ───────────────────────────────────────────────────────────────────


def make_record(system: str, user: str, assistant: str, meta: dict) -> dict:
    return {
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "_metadata": meta,
    }


def finding_to_record(row: dict) -> dict | None:
    """Convert a findings row to a training record."""
    vuln_class = row.get("vuln_class") or ""
    severity = row.get("severity") or "medium"
    url = row.get("target_url") or ""
    title = row.get("title") or vuln_class
    description = row.get("description") or ""
    request_raw = (row.get("request_raw") or "")[:500]
    response_raw = (row.get("response_raw") or "")[:300]
    remediation = row.get("remediation") or "Apply security best practices."

    if not (vuln_class and url):
        return None

    user_content = (
        f"Target URL: {url}\n"
        f"Vulnerability class: {vuln_class}\n"
        f"Severity: {severity}\n"
    )
    if request_raw:
        user_content += f"HTTP Request snippet:\n{request_raw}\n"
    if response_raw:
        user_content += f"HTTP Response snippet:\n{response_raw}\n"
    user_content += "Analyze this finding and explain the exploitation approach."

    action_input = json.dumps({
        "vuln_class": vuln_class,
        "severity": severity,
        "url": url,
        "remediation": remediation[:200],
    })
    assistant_content = (
        f"Thought: This appears to be a {severity} severity {vuln_class} vulnerability "
        f"at {url}. {description[:300] if description else ''}\n"
        f"Action: report_finding\n"
        f"Action Input: {action_input}"
    )

    return make_record(
        system=_SYSTEM_PROMPT,
        user=user_content,
        assistant=assistant_content,
        meta={"source": "findings", "vuln_class": vuln_class, "severity": severity, "url": url},
    )


def kb_record_to_training(row: dict) -> dict | None:
    """Convert a knowledge_records row to a training record."""
    vuln_class = row.get("vuln_class") or ""
    tech_stack = row.get("tech_stack") or []
    key_insight = row.get("key_insight") or ""
    technique = row.get("attack_technique") or row.get("attack_steps") or ""
    payload_pattern = row.get("payload_pattern") or ""
    severity = row.get("severity") or "medium"
    title = row.get("title") or vuln_class

    if not (vuln_class and (key_insight or technique)):
        return None

    tech_str = ", ".join(tech_stack) if tech_stack else "web application"
    user_content = (
        f"Tech stack: {tech_str}\n"
        f"Vulnerability type: {vuln_class}\n"
        f"Severity: {severity}\n"
        f"Context: Testing {title}\n"
        f"What technique and payload patterns should I use?"
    )

    kb_action_input = json.dumps({
        "vuln_class": vuln_class,
        "technique": technique[:200] if technique else key_insight[:200],
        "payload_pattern": payload_pattern[:200] if payload_pattern else "see technique",
    })
    assistant_content = (
        f"Thought: Based on historical H1 disclosures for {vuln_class} on {tech_str}, "
        f"the most effective approach is: {key_insight[:400] if key_insight else technique[:400]}\n"
        f"Action: test_injection\n"
        f"Action Input: {kb_action_input}"
    )

    return make_record(
        system=_SYSTEM_PROMPT,
        user=user_content,
        assistant=assistant_content,
        meta={
            "source": "knowledge_records",
            "vuln_class": vuln_class,
            "severity": severity,
            "tech_stack": tech_stack,
        },
    )


# ── Main ──────────────────────────────────────────────────────────────────────


async def main() -> None:
    print("=== Pentra AI — LoRA Fine-tuning Dataset Preparation ===")
    print(f"Database: {DATABASE_URL[:50]}...")
    print(f"Output:   {OUTPUT_JSONL}")
    print()

    try:
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy import text
    except ImportError:
        print("❌ sqlalchemy not available. Run from apps/api directory.")
        sys.exit(1)

    engine = create_async_engine(DATABASE_URL)
    records: list[dict] = []
    stats: dict[str, int] = {}

    async with engine.connect() as conn:
        # ── Source 1: findings ────────────────────────────────────────────────
        print("📂 Source 1: findings table")
        r = await conn.execute(text(
            "SELECT id, engagement_id, title, vuln_class, severity, target_url, "
            "request_raw, response_raw, description, remediation, status "
            "FROM findings ORDER BY discovered_at DESC"
        ))
        rows = [dict(zip(r.keys(), row)) for row in r.fetchall()]
        print(f"   {len(rows)} findings found")

        findings_added = 0
        for row in rows:
            rec = finding_to_record(row)
            if rec:
                records.append(rec)
                findings_added += 1
        stats["findings"] = findings_added
        print(f"   ✅ {findings_added} training records from findings")

        # ── Source 2: knowledge_records ───────────────────────────────────────
        print(f"\n📂 Source 2: knowledge_records (max {MAX_KB_RECORDS})")
        r2 = await conn.execute(text(
            "SELECT vuln_class, tech_stack, key_insight, attack_technique, attack_steps, "
            "payload_pattern, indicators, severity, title "
            "FROM knowledge_records "
            "WHERE key_insight IS NOT NULL AND key_insight != '' "
            "ORDER BY quality_score DESC NULLS LAST "
            f"LIMIT {MAX_KB_RECORDS}"
        ))
        kb_rows = [dict(zip(r2.keys(), row)) for row in r2.fetchall()]
        print(f"   {len(kb_rows)} KB records with key_insight")

        kb_added = 0
        for row in kb_rows:
            rec = kb_record_to_training(row)
            if rec:
                records.append(rec)
                kb_added += 1
        stats["knowledge_records"] = kb_added
        print(f"   ✅ {kb_added} training records from KB")

        # ── Source 3: engagement_learnings ────────────────────────────────────
        print("\n📂 Source 3: engagement_learnings")
        r3 = await conn.execute(text(
            "SELECT tech_stack, effective_tools, effective_techniques, "
            "high_value_endpoints, findings_count "
            "FROM engagement_learnings"
        ))
        learning_rows = [dict(zip(r3.keys(), row)) for row in r3.fetchall()]
        print(f"   {len(learning_rows)} engagement learnings")

        learnings_added = 0
        for row in learning_rows:
            tech = row.get("tech_stack") or []
            tools_raw = row.get("effective_tools") or []
            techs_raw = row.get("effective_techniques") or []
            # Normalize to list of strings
            tools = [str(x) for x in tools_raw] if tools_raw else []
            techniques = [str(x) for x in techs_raw] if techs_raw else []
            tech = [str(x) for x in tech] if tech else []
            if not (tech and (tools or techniques)):
                continue
            user_content = (
                f"Tech stack: {', '.join(tech)}\n"
                f"Starting a new pentest engagement. What tools and techniques "
                f"are most effective for this target?"
            )
            assistant_content = (
                f"Thought: Based on learnings from previous engagements on similar "
                f"tech stacks, I should prioritize:\n"
                f"Effective tools: {', '.join(tools[:5]) if tools else 'nuclei, ffuf'}\n"
                f"Effective techniques: {', '.join(techniques[:5]) if techniques else 'injection, auth bypass'}\n"
                f"Action: test_injection\n"
                f"Action Input: {json.dumps({'priority_tools': tools[:3] if tools else [], 'priority_techniques': techniques[:3] if techniques else []})}"
            )
            records.append(make_record(
                system=_SYSTEM_PROMPT,
                user=user_content,
                assistant=assistant_content,
                meta={"source": "engagement_learnings", "tech_stack": tech},
            ))
            learnings_added += 1
        stats["engagement_learnings"] = learnings_added
        print(f"   ✅ {learnings_added} training records from learnings")

    # ── Write output ──────────────────────────────────────────────────────────
    print(f"\n📝 Writing {len(records)} total records to {OUTPUT_JSONL}")
    with open(OUTPUT_JSONL, "w") as f:
        for rec in records:
            # Strip _metadata from final output (not needed for training)
            out = {k: v for k, v in rec.items() if k != "_metadata"}
            f.write(json.dumps(out, ensure_ascii=False) + "\n")

    # ── Stats ─────────────────────────────────────────────────────────────────
    total = len(records)
    stats_text = (
        f"Pentra AI LoRA Training Dataset\n"
        f"Generated: {datetime.now().isoformat()}\n"
        f"{'='*50}\n"
        f"Total records: {total}\n"
        f"  from findings:             {stats.get('findings', 0)}\n"
        f"  from knowledge_records:    {stats.get('knowledge_records', 0)}\n"
        f"  from engagement_learnings: {stats.get('engagement_learnings', 0)}\n"
        f"{'='*50}\n"
        f"Output file: {OUTPUT_JSONL}\n"
        f"File size:   {OUTPUT_JSONL.stat().st_size / 1024:.1f} KB\n"
        f"\nNext steps:\n"
        f"  1. Review sample: head -1 {OUTPUT_JSONL} | python3 -m json.tool\n"
        f"  2. LoRA training: ollama create pentra-ft -f Modelfile  (after setup)\n"
        f"  3. Min records for useful LoRA: ~500 (currently {total})\n"
    )
    OUTPUT_STATS.write_text(stats_text)
    print(stats_text)

    if total < 100:
        print("⚠️  WARNING: < 100 records — run more scans first for better fine-tuning quality")
    elif total < 500:
        print(f"ℹ️  {total} records — functional but more data = better results")
        print("   Tip: Run more scans to generate confirmed findings")
    else:
        print(f"✅ {total} records — good dataset for LoRA fine-tuning")


if __name__ == "__main__":
    asyncio.run(main())
