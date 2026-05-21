---
applyTo: "packages/pentra-agent/**"
---

# Agent Engine — Copilot Instructions

You are working inside `packages/pentra-agent/` — the LangGraph orchestration layer.
Do not start this package until Phase 1 (Knowledge Engine) is complete.

## Pattern Rules

- All nodes are `async def node_name(state: PentraState) -> dict`
- Nodes return ONLY the state fields they modify (partial update, not full state)
- Always import `ScopeEnforcer` from `pentra-scope` and validate at node entry
- Use `interrupt()` for ALL human-in-the-loop pause points — never blocking
- Thread ID always equals `engagement_id` for checkpoint persistence
- Use `AsyncPostgresSaver` for checkpointing (connects to the same PostgreSQL)

## Node Output Convention

```python
# Return only modified fields
async def recon_node(state: PentraState) -> dict:
    # ... do work ...
    return {
        "subdomains": new_subdomains,         # list — uses operator.add reducer
        "messages": [AIMessage(content=...)]  # uses add_messages reducer
        # DO NOT return unchanged fields
    }
```

## Prompt Files

All LLM system prompts live in `packages/pentra-agent/prompts/`.
One file per node: `recon_prompt.py`, `vuln_hunt_prompt.py`, `report_prompt.py`.
Prompts are Python strings — use f-strings for dynamic content.
Include security researcher framing — not "assistant" framing.

## HITL Events Sent to WebSocket

```python
# Standard event shape broadcast to /ws/engagements/{id}/feed
{
    "type": "AWAITING_APPROVAL",    # or "AGENT_LOG", "FINDING_DISCOVERED", "PHASE_COMPLETE"
    "engagement_id": "uuid",
    "phase": "recon",
    "timestamp": "2026-05-21T14:32:01Z",
    "data": {
        "summary": "Found 47 subdomains. Rails app detected on api.target.com.",
        "knowledge_hints": ["IDOR common on Rails APIs", "Check /api/v1/users/{id}"],
        "proposed_next": "Run vulnerability scan on api.target.com"
    }
}
```
