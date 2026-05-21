# Pentra AI — GitHub Copilot Instructions

This is **Pentra AI**, a self-hosted AI Security Research Platform.
Read `CLAUDE.md` at the repo root for the complete project intelligence.

## Quick Context

- **Monorepo** (Turborepo): `apps/` for runnable services, `packages/` for shared modules
- **Backend**: FastAPI + Python 3.11 + SQLAlchemy 2 async — all `async def`
- **Frontend**: React 18 + Vite 5 + Tailwind + Shadcn/ui — SPA, no SSR
- **Agent**: LangGraph v1.2 — StateGraph + HITL interrupt pattern
- **LLM**: Ollama (OpenAI-compatible) — model selected via `settings.OLLAMA_MODEL_*`
- **Embedding**: BGE-M3 via Ollama — Qdrant hybrid search (dense + sparse)
- **Package manager**: `uv` for Python, `pnpm` for TypeScript

## Active Phase

**Phase 1: Knowledge Engine** — work inside `packages/pentra-knowledge/` and `apps/worker/`.
Do not implement agent or UI code until Phase 1 tasks in CLAUDE.md Section 15 are checked.

## Non-Negotiable Rules

1. Scope check (`pentra-scope`) before every tool execution
2. All secrets via environment variables — never hardcoded
3. SQLAlchemy ORM only — no raw SQL
4. Pydantic v2 schemas on all API inputs/outputs
5. LangGraph `interrupt()` for human-in-the-loop — never blocking calls
6. Audit log every agent action (`audit_logs` table, append-only)
7. All LLM inference via Ollama — never call external AI APIs as default
