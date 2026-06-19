# PHASE-6-EXECUTION.md — Pentra AI
> **Untuk:** GitHub Copilot dengan Claude Sonnet 4.6  
> **Baca terlebih dahulu:** `CLAUDE.md` → `docs/PRD.md` → `PROGRESS.md` → file ini  
> **Status saat ini:** Sprint 1–10 selesai, 82 tests passing  
> **Tujuan:** Sprint 11 + 12 — tool wrappers aktif di agent nodes + HITL frontend real-time

---

## Konteks: Apa yang Sudah Ada di Sprint 10

```
✅ PentraState TypedDict        — state.py dengan semua reducers
✅ LLMClient                    — complete(), complete_json(), plan/analyze methods
✅ plan_node.py                 — query knowledge + generate plan
✅ hitl_nodes.py                — hitl_plan, hitl_recon, hitl_exploit
✅ recon_node.py                — subfinder + httpx + nmap + Burp sitemap/history
✅ vuln_hunt_node.py            — nuclei + graphql + Burp active scan + Collaborator
✅ report_node.py               — deduplicate + persist findings
✅ builder.py                   — StateGraph + conditional routing
✅ BurpMCPClient                — 24 tests, tervalidasi dengan Burp Pro aktif
✅ 11 agent tests               — routing, HITL behavior, LLMClient JSON parsing
```

## Yang Masih Kurang

```
❌ Sprint 11 — Tool wrappers belum aktif di agent nodes (subfinder, nmap, nuclei, dll
               dipanggil tapi hasilnya belum benar-benar dipakai secara integrated)
❌ Sprint 11 — OPSEC jitter belum terintegrasi ke agent execution flow
❌ Sprint 11 — Celery task run_engagement belum bisa dijalankan end-to-end
❌ Sprint 12 — WebSocket live feed belum terkoneksi ke agent events
❌ Sprint 12 — HITL approval dialog belum terhubung ke resume agent
❌ Sprint 12 — Live engagement dashboard belum ada
❌ Sprint 12 — Internal API untuk bulk findings belum ada
```

---

## Sprint 11 — Tool Integration dalam Agent Nodes

> **Tujuan:** Semua tool wrappers benar-benar berjalan di dalam agent nodes,  
> OPSEC jitter aktif, dan Celery task bisa dijalankan end-to-end  
> **Estimasi:** 3–4 hari  
> **Mulai dari Task 11.1, urutan wajib diikuti**

---

### Task 11.1 — AgentService + Celery Task End-to-End

**Konteks:**  
`run_engagement` Celery task sudah ada di `apps/worker/app/tasks/agent.py` tapi belum bisa dijalankan end-to-end karena `AgentService` belum punya proper setup untuk `AsyncPostgresSaver`.

**Buat / update `packages/pentra-agent/pentra_agent/service.py`:**

```python
# packages/pentra-agent/pentra_agent/service.py

from __future__ import annotations
import json
import asyncio
from typing import AsyncIterator

from pentra_agent.graph.builder import build_pentra_graph


class AgentService:
    """
    Interface antara FastAPI/Celery dan LangGraph graph.
    Jangan instantiate langsung — gunakan create() factory method.
    """

    def __init__(self, graph):
        self.graph = graph

    @classmethod
    async def create(cls, database_url: str) -> "AgentService":
        """
        Factory method — setup AsyncPostgresSaver dan compile graph.
        Dipanggil sekali per Celery task execution.
        """
        from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

        async with await AsyncPostgresSaver.from_conn_string(database_url) as checkpointer:
            # Setup tables jika belum ada
            await checkpointer.setup()
            graph = build_pentra_graph(checkpointer)
            return cls(graph)

    async def start(self, engagement_id: str, initial_state: dict) -> None:
        """
        Start engagement baru.
        Thread ID = engagement_id untuk checkpoint persistence.
        """
        config = {"configurable": {"thread_id": engagement_id}}
        await self.graph.ainvoke(initial_state, config=config)

    async def resume(self, engagement_id: str, user_decision: str) -> None:
        """
        Resume setelah HITL interrupt.
        user_decision: "approve" | "skip" | "modify"
        """
        config = {"configurable": {"thread_id": engagement_id}}

        await self.graph.aupdate_state(
            config=config,
            values={
                "user_decision": user_decision,
                "awaiting_approval": False,
            },
        )
        await self.graph.ainvoke(None, config=config)

    async def stream_events(
        self, engagement_id: str
    ) -> AsyncIterator[dict]:
        """
        Stream LangGraph events untuk dikirim ke WebSocket.
        Dipanggil dari Redis pub/sub bridge, bukan langsung dari HTTP.
        """
        config = {"configurable": {"thread_id": engagement_id}}

        async for event in self.graph.astream_events(
            None, config=config, version="v2"
        ):
            ws_event = _langgraph_to_ws_event(event)
            if ws_event:
                yield ws_event

    def get_current_state(self, engagement_id: str) -> dict:
        """Ambil current state dari checkpoint (sync)."""
        config = {"configurable": {"thread_id": engagement_id}}
        snapshot = self.graph.get_state(config)
        return snapshot.values if snapshot else {}


def _langgraph_to_ws_event(lg_event: dict) -> dict | None:
    """
    Convert LangGraph event ke WebSocket event format.
    Format yang dikirim ke frontend via WebSocket.
    """
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    event_type = lg_event.get("event", "")
    name = lg_event.get("name", "")

    TRACKED_NODES = {
        "plan", "hitl_plan", "recon",
        "hitl_recon", "vuln_hunt", "hitl_exploit", "report"
    }

    if event_type == "on_chain_start" and name in TRACKED_NODES:
        return {
            "type": "NODE_START",
            "node": name,
            "timestamp": now,
        }

    if event_type == "on_chain_end" and name in TRACKED_NODES:
        output = lg_event.get("data", {}).get("output", {})
        interrupts = lg_event.get("data", {}).get("__interrupt__", [])

        if interrupts:
            interrupt_value = interrupts[0].value if interrupts else {}
            return {
                "type": "AWAITING_APPROVAL",
                "node": name,
                "timestamp": now,
                "data": interrupt_value,
            }

        # Cek findings baru di output
        new_findings = output.get("findings", [])
        if new_findings:
            return {
                "type": "FINDINGS_UPDATED",
                "node": name,
                "timestamp": now,
                "data": {
                    "count": len(new_findings),
                    "preview": [
                        {
                            "title": f.get("title", "Finding"),
                            "severity": f.get("severity", "unknown"),
                        }
                        for f in new_findings[:3]
                    ],
                },
            }

        return {
            "type": "NODE_COMPLETE",
            "node": name,
            "timestamp": now,
            "data": {
                "subdomains": len(output.get("subdomains", [])),
                "findings": len(output.get("findings", [])),
            },
        }

    if event_type == "on_chat_model_stream":
        chunk = lg_event.get("data", {}).get("chunk")
        if chunk and hasattr(chunk, "content") and chunk.content:
            return {
                "type": "LLM_STREAM",
                "content": chunk.content,
                "timestamp": now,
            }

    return None
```

**Update `apps/worker/app/tasks/agent.py`:**

```python
# apps/worker/app/tasks/agent.py

import asyncio
import json
import os
from celery import shared_task
import redis


@shared_task(
    bind=True,
    name="tasks.agent.run_engagement",
    max_retries=0,          # Jangan retry — engagement adalah stateful
    acks_late=True,         # Ack setelah selesai, bukan sebelum
)
def run_engagement(self, engagement_id: str):
    """
    Celery task: jalankan agent untuk engagement baru.
    Berjalan di background worker.
    """
    asyncio.run(_run_async(engagement_id))


@shared_task(
    bind=True,
    name="tasks.agent.resume_engagement",
    max_retries=0,
    acks_late=True,
)
def resume_engagement(self, engagement_id: str, user_decision: str):
    """
    Celery task: resume agent setelah HITL approval.
    user_decision: "approve" | "skip" | "modify"
    """
    asyncio.run(_resume_async(engagement_id, user_decision))


async def _run_async(engagement_id: str):
    from apps.api.app.db.session import async_session_factory
    from apps.api.app.db.models import EngagementORM
    from sqlalchemy import select
    from pentra_agent.service import AgentService

    # Fetch engagement dari DB
    async with async_session_factory() as db:
        result = await db.execute(
            select(EngagementORM).where(EngagementORM.id == engagement_id)
        )
        engagement = result.scalar_one_or_none()
        if not engagement:
            return

        # Update status ke active
        engagement.status = "active"
        await db.commit()

    # Build initial state
    initial_state = _build_initial_state(engagement)

    # Broadcast event: engagement started
    _publish_event(engagement_id, {
        "type": "ENGAGEMENT_STARTED",
        "engagement_id": engagement_id,
        "timestamp": _now(),
    })

    try:
        db_url = os.getenv("DATABASE_URL", "").replace(
            "postgresql+asyncpg://", "postgresql://"
        )
        service = await AgentService.create(db_url)

        # Stream events ke Redis pub/sub saat graph berjalan
        async for event in service.stream_events_during_start(
            engagement_id, initial_state
        ):
            _publish_event(engagement_id, event)

    except Exception as e:
        _publish_event(engagement_id, {
            "type": "AGENT_ERROR",
            "engagement_id": engagement_id,
            "error": str(e),
            "timestamp": _now(),
        })
        # Update status ke failed
        async with async_session_factory() as db:
            result = await db.execute(
                select(EngagementORM).where(EngagementORM.id == engagement_id)
            )
            eng = result.scalar_one_or_none()
            if eng:
                eng.status = "failed"
                await db.commit()


async def _resume_async(engagement_id: str, user_decision: str):
    from pentra_agent.service import AgentService

    db_url = os.getenv("DATABASE_URL", "").replace(
        "postgresql+asyncpg://", "postgresql://"
    )
    service = await AgentService.create(db_url)

    _publish_event(engagement_id, {
        "type": "AGENT_RESUMED",
        "decision": user_decision,
        "timestamp": _now(),
    })

    await service.resume(engagement_id, user_decision)


def _build_initial_state(engagement) -> dict:
    """Build PentraState dict dari EngagementORM."""
    return {
        "engagement_id": str(engagement.id),
        "target": {
            "domain": engagement.target_domain or _extract_domain(engagement.in_scope),
            "ip_ranges": [s for s in engagement.in_scope if "/" in s and not s.startswith("http")],
            "base_urls": [],
        },
        "scope": {
            "in_scope": engagement.in_scope or [],
            "out_of_scope": engagement.out_of_scope or [],
        },
        "mode": engagement.mode,
        "llm_model": engagement.llm_model,
        "opsec_mode": engagement.opsec_mode,
        "request_jitter_ms": engagement.request_jitter_ms,
        "current_phase": "planning",
        "phase_history": [],
        "subdomains": [],
        "open_ports": [],
        "tech_stack": [],
        "endpoints": [],
        "findings": [],
        "messages": [],
        "tool_outputs": [],
        "errors": [],
        "awaiting_approval": False,
        "pending_action": None,
        "user_decision": None,
        "pentest_plan": "",
        "current_hypothesis": "",
        "knowledge_context": [],
    }


def _extract_domain(in_scope: list[str]) -> str:
    """Extract domain pertama dari scope list."""
    for s in in_scope:
        s = s.lstrip("*.")
        if "." in s and "/" not in s:
            return s
    return ""


def _publish_event(engagement_id: str, event: dict):
    """Publish event ke Redis pub/sub channel."""
    r = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))
    r.publish(
        f"engagement:{engagement_id}:events",
        json.dumps(event)
    )
    r.close()


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
```

**Update `AgentService.stream_events_during_start()`:**

```python
# Tambahkan method ini ke AgentService di service.py:

async def stream_events_during_start(
    self,
    engagement_id: str,
    initial_state: dict,
) -> AsyncIterator[dict]:
    """
    Start engagement DAN stream events secara bersamaan.
    Yield events ke caller (Celery task) untuk di-publish ke Redis.
    """
    config = {"configurable": {"thread_id": engagement_id}}

    async for event in self.graph.astream_events(
        initial_state, config=config, version="v2"
    ):
        ws_event = _langgraph_to_ws_event(event)
        if ws_event:
            yield ws_event
```

---

### Task 11.2 — OPSEC Jitter Terintegrasi ke Agent Execution

**Konteks:**  
`opsec_mode` dan `request_jitter_ms` sudah ada di `PentraState` dan `EngagementORM`, tapi belum dipakai di dalam agent nodes. `_maybe_jitter()` sudah ada di `AsyncToolWrapper.base` — perlu dipanggil dengan nilai dari state.

**Update `recon_node.py` — inject opsec config ke wrappers:**

```python
# packages/pentra-agent/pentra_agent/nodes/recon_node.py

# Buat helper untuk create scope-enforced wrapper dengan OPSEC config
def _make_scope(state: PentraState) -> ScopeEnforcer:
    return ScopeEnforcer(
        in_scope=state["scope"]["in_scope"],
        out_of_scope=state["scope"]["out_of_scope"],
    )


def _opsec_kwargs(state: PentraState) -> dict:
    """
    Return kwargs untuk inject ke setiap tool wrapper.
    Wrapper akan panggil _maybe_jitter() sebelum exec jika opsec_mode=True.
    """
    return {
        "opsec_mode": state.get("opsec_mode", False),
        "request_jitter_ms": state.get("request_jitter_ms", 0),
    }


async def recon_node(state: PentraState) -> dict:
    scope = _make_scope(state)
    opsec = _opsec_kwargs(state)

    # Pass opsec config ke setiap wrapper
    subfinder = SubfinderWrapper(scope_enforcer=scope, **opsec)
    httpx_wrapper = HttpxWrapper(scope_enforcer=scope, **opsec)
    nmap = NmapWrapper(scope_enforcer=scope, **opsec)
    # ... dst
```

**Pastikan `AsyncToolWrapper.__init__` menerima opsec params:**

```python
# packages/pentra-tools/pentra_tools/base.py

class AsyncToolWrapper:
    def __init__(
        self,
        scope_enforcer: ScopeEnforcer,
        opsec_mode: bool = False,
        request_jitter_ms: int = 0,
    ):
        self.scope = scope_enforcer
        self.opsec_mode = opsec_mode
        self.request_jitter_ms = request_jitter_ms

    async def _maybe_jitter(self):
        """Sleep random delay sebelum exec jika OPSEC mode aktif."""
        if self.opsec_mode and self.request_jitter_ms > 0:
            import asyncio
            import random
            delay = random.uniform(0, self.request_jitter_ms / 1000)
            await asyncio.sleep(delay)

    async def _exec_stream(self, cmd: list[str], **kwargs):
        await self._maybe_jitter()  # OPSEC jitter sebelum setiap exec
        # ... existing exec logic
```

---

### Task 11.3 — Internal API Endpoint untuk Agent

**Konteks:**  
`report_node.py` memanggil `POST /api/v1/internal/engagements/{id}/findings/bulk` tapi endpoint ini belum ada. Agent tidak boleh akses DB langsung.

**Buat `apps/api/app/api/internal_router.py`:**

```python
# apps/api/app/api/internal_router.py

"""
Internal endpoints — hanya untuk komunikasi agent worker → API.
Tidak bisa diakses dari luar Docker network.
Verifikasi via X-Internal-Token header.
"""

import os
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.db.session import get_db
from app.db.models import FindingORM, EngagementORM

router = APIRouter(prefix="/api/v1/internal", tags=["Internal"])


def verify_internal_token(x_internal_token: str = Header(...)):
    expected = os.getenv("INTERNAL_API_TOKEN", "")
    if not expected:
        raise HTTPException(500, "INTERNAL_API_TOKEN not configured")
    if x_internal_token != expected:
        raise HTTPException(403, "Invalid internal token")


class BulkFindingItem(BaseModel):
    title: str
    severity: str = "medium"
    vuln_class: str = "UNKNOWN"
    vuln_subclass: str = ""
    target_url: str = ""
    http_method: str = "GET"
    description: str = ""
    request_raw: str = ""
    response_raw: str = ""
    source: str = "agent"
    reproduction_steps: list[str] = []
    cve_ids: list[str] = []


class BulkFindingsCreate(BaseModel):
    findings: list[BulkFindingItem]


class EngagementStatusUpdate(BaseModel):
    status: str   # "active" | "completed" | "failed" | "paused"


@router.post(
    "/engagements/{engagement_id}/findings/bulk",
    dependencies=[Depends(verify_internal_token)],
    status_code=201,
)
async def bulk_create_findings(
    engagement_id: UUID,
    payload: BulkFindingsCreate,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Bulk create findings dari agent.
    Dipanggil oleh report_node via httpx.
    """
    from sqlalchemy import select
    from uuid import uuid4
    from datetime import datetime, timezone

    # Verify engagement exists
    result = await db.execute(
        select(EngagementORM).where(EngagementORM.id == engagement_id)
    )
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise HTTPException(404, "Engagement not found")

    created = []
    for item in payload.findings:
        finding = FindingORM(
            id=uuid4(),
            engagement_id=engagement_id,
            title=item.title,
            severity=item.severity,
            vuln_class=item.vuln_class,
            vuln_subclass=item.vuln_subclass,
            target_url=item.target_url,
            http_method=item.http_method,
            description=item.description,
            request_raw=item.request_raw,
            response_raw=item.response_raw,
            source=item.source,
            reproduction_steps=item.reproduction_steps,
            cve_ids=item.cve_ids,
            status="new",
            discovered_at=datetime.now(timezone.utc),
        )
        db.add(finding)
        created.append(finding)

    await db.commit()
    return {"created": len(created), "engagement_id": str(engagement_id)}


@router.patch(
    "/engagements/{engagement_id}/status",
    dependencies=[Depends(verify_internal_token)],
)
async def update_engagement_status(
    engagement_id: UUID,
    payload: EngagementStatusUpdate,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Update engagement status dari agent."""
    from sqlalchemy import select

    result = await db.execute(
        select(EngagementORM).where(EngagementORM.id == engagement_id)
    )
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise HTTPException(404, "Engagement not found")

    engagement.status = payload.status
    if payload.status == "completed":
        from datetime import datetime, timezone
        engagement.completed_at = datetime.now(timezone.utc)

    await db.commit()
    return {"updated": True, "status": payload.status}
```

**Daftarkan router di `apps/api/app/main.py`:**

```python
# apps/api/app/main.py — tambahkan:
from app.api.internal_router import router as internal_router
app.include_router(internal_router)
```

**Tambahkan `INTERNAL_API_TOKEN` ke `.env.example`:**

```bash
# .env.example
# Token untuk komunikasi internal agent worker → API
# Generate: python -c "import secrets; print(secrets.token_hex(32))"
INTERNAL_API_TOKEN=change-this-to-a-random-32-char-token
```

---

### Task 11.4 — Tests Sprint 11

```python
# packages/pentra-agent/tests/test_service.py

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.mark.asyncio
async def test_agent_service_resume_updates_state_and_continues():
    """resume() harus update state dengan user_decision lalu invoke graph."""
    mock_graph = MagicMock()
    mock_graph.aupdate_state = AsyncMock()
    mock_graph.ainvoke = AsyncMock()

    from pentra_agent.service import AgentService
    service = AgentService(mock_graph)

    await service.resume("eng-123", "approve")

    mock_graph.aupdate_state.assert_called_once()
    call_kwargs = mock_graph.aupdate_state.call_args
    assert call_kwargs[1]["values"]["user_decision"] == "approve"
    assert call_kwargs[1]["values"]["awaiting_approval"] is False

    mock_graph.ainvoke.assert_called_once_with(
        None,
        config={"configurable": {"thread_id": "eng-123"}}
    )


def test_langgraph_to_ws_event_converts_node_start():
    from pentra_agent.service import _langgraph_to_ws_event
    event = {"event": "on_chain_start", "name": "recon", "data": {}}
    result = _langgraph_to_ws_event(event)
    assert result is not None
    assert result["type"] == "NODE_START"
    assert result["node"] == "recon"
    assert "timestamp" in result


def test_langgraph_to_ws_event_returns_none_for_unknown_nodes():
    from pentra_agent.service import _langgraph_to_ws_event
    event = {"event": "on_chain_start", "name": "some_internal_node", "data": {}}
    result = _langgraph_to_ws_event(event)
    assert result is None


def test_langgraph_to_ws_event_detects_interrupt():
    from pentra_agent.service import _langgraph_to_ws_event

    class MockInterrupt:
        value = {"type": "AWAITING_APPROVAL", "phase": "planning"}

    event = {
        "event": "on_chain_end",
        "name": "hitl_plan",
        "data": {"__interrupt__": [MockInterrupt()]},
    }
    result = _langgraph_to_ws_event(event)
    assert result is not None
    assert result["type"] == "AWAITING_APPROVAL"


def test_build_initial_state_extracts_domain_from_scope():
    from apps.worker.app.tasks.agent import _build_initial_state, _extract_domain

    assert _extract_domain(["*.shopify.com", "shopify.com"]) == "shopify.com"
    assert _extract_domain(["10.0.0.0/24"]) == ""
    assert _extract_domain([]) == ""


# apps/api/tests/test_internal_api.py

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


def test_bulk_findings_requires_internal_token():
    """Endpoint harus return 422/403 tanpa token."""
    # Mock FastAPI TestClient call tanpa header
    # Verifikasi dependency verify_internal_token di-call
    pass  # Implementasi dengan FastAPI TestClient


@pytest.mark.asyncio
async def test_verify_internal_token_raises_on_wrong_token():
    import os
    os.environ["INTERNAL_API_TOKEN"] = "correct-token"

    from fastapi import HTTPException
    from apps.api.app.api.internal_router import verify_internal_token

    with pytest.raises(HTTPException) as exc:
        await verify_internal_token(x_internal_token="wrong-token")
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_verify_internal_token_passes_with_correct_token():
    import os
    os.environ["INTERNAL_API_TOKEN"] = "correct-token"

    from apps.api.app.api.internal_router import verify_internal_token
    # Tidak raise = success
    result = await verify_internal_token(x_internal_token="correct-token")
    assert result is None
```

---

## Sprint 12 — HITL Frontend Real-Time

> **Tujuan:** WebSocket live feed + HITL approval dialog + live engagement dashboard  
> **Estimasi:** 3–4 hari  
> **Mulai Sprint 12 hanya setelah Sprint 11 selesai dan tests pass**

---

### Task 12.1 — WebSocket Manager + Redis Bridge

**Buat `apps/api/app/core/ws_manager.py`:**

```python
# apps/api/app/core/ws_manager.py

import asyncio
import json
from collections import defaultdict
from fastapi import WebSocket


class WebSocketManager:
    """
    Manage WebSocket connections per engagement.
    Thread-safe via asyncio — single event loop.
    """

    def __init__(self):
        self._connections: dict[str, list[WebSocket]] = defaultdict(list)

    async def connect(self, websocket: WebSocket, engagement_id: str):
        await websocket.accept()
        self._connections[engagement_id].append(websocket)

    def disconnect(self, websocket: WebSocket, engagement_id: str):
        conns = self._connections.get(engagement_id, [])
        if websocket in conns:
            conns.remove(websocket)

    async def broadcast(self, engagement_id: str, event: dict):
        """Kirim event ke semua client yang terhubung ke engagement ini."""
        conns = list(self._connections.get(engagement_id, []))
        dead = []
        for ws in conns:
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws, engagement_id)

    def connection_count(self, engagement_id: str) -> int:
        return len(self._connections.get(engagement_id, []))


# Singleton — satu instance untuk seluruh API process
ws_manager = WebSocketManager()
```

**Buat `apps/api/app/core/redis_bridge.py`:**

```python
# apps/api/app/core/redis_bridge.py

"""
Redis pub/sub → WebSocket bridge.
Celery worker publish events ke Redis.
API process subscribe dan forward ke WebSocket clients.
Jalankan sebagai background asyncio task saat startup.
"""

import asyncio
import json
import os
import redis.asyncio as aioredis

from app.core.ws_manager import ws_manager


async def start_redis_bridge():
    """
    Subscribe ke pattern 'engagement:*:events'.
    Forward setiap message ke WebSocket clients yang sesuai.
    Loop terus — restart otomatis jika koneksi putus.
    """
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")

    while True:
        try:
            r = aioredis.from_url(redis_url)
            pubsub = r.pubsub()
            await pubsub.psubscribe("engagement:*:events")

            async for message in pubsub.listen():
                if message["type"] != "pmessage":
                    continue

                channel = message["channel"]
                if isinstance(channel, bytes):
                    channel = channel.decode()

                # Extract engagement_id: "engagement:{id}:events"
                parts = channel.split(":")
                if len(parts) < 3:
                    continue
                engagement_id = parts[1]

                try:
                    data = message["data"]
                    if isinstance(data, bytes):
                        data = data.decode()
                    event = json.loads(data)
                    await ws_manager.broadcast(engagement_id, event)
                except Exception:
                    pass

        except Exception:
            # Reconnect setelah 3 detik jika Redis terputus
            await asyncio.sleep(3)
        finally:
            try:
                await r.aclose()
            except Exception:
                pass
```

**Daftarkan di `apps/api/app/main.py`:**

```python
# apps/api/app/main.py

from contextlib import asynccontextmanager
import asyncio
from app.core.redis_bridge import start_redis_bridge

@asynccontextmanager
async def lifespan(app):
    # Startup
    await startup_validator.validate_all()

    # Start Redis bridge sebagai background task
    bridge_task = asyncio.create_task(start_redis_bridge())

    yield

    # Shutdown
    bridge_task.cancel()
    try:
        await bridge_task
    except asyncio.CancelledError:
        pass

app = FastAPI(lifespan=lifespan, ...)
```

---

### Task 12.2 — WebSocket Endpoint

**Buat `apps/api/app/api/ws_router.py`:**

```python
# apps/api/app/api/ws_router.py

import asyncio
from uuid import UUID
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.ws_manager import ws_manager
from app.core.auth import decode_ws_token
from app.db.session import get_db

router = APIRouter(tags=["WebSocket"])


@router.websocket("/ws/engagements/{engagement_id}/feed")
async def engagement_live_feed(
    websocket: WebSocket,
    engagement_id: str,
    token: str = Query(...),
):
    """
    WebSocket endpoint untuk live feed per engagement.
    
    Events yang dikirim ke client:
    - NODE_START: agent mulai eksekusi sebuah node
    - NODE_COMPLETE: node selesai
    - LLM_STREAM: streaming token dari LLM
    - AWAITING_APPROVAL: HITL interrupt — butuh user decision
    - FINDINGS_UPDATED: ada finding baru
    - ENGAGEMENT_STARTED: agent mulai
    - ENGAGEMENT_COMPLETED: engagement selesai
    - AGENT_ERROR: error terjadi
    - ping: keepalive
    
    Client mengirim: hanya keepalive, approval dilakukan via REST API
    """
    # Validasi token
    try:
        user = await decode_ws_token(token)
    except Exception:
        await websocket.close(code=4001, reason="Invalid token")
        return

    await ws_manager.connect(websocket, engagement_id)

    # Kirim event connected
    await websocket.send_json({
        "type": "CONNECTED",
        "engagement_id": engagement_id,
        "user": user.username,
    })

    try:
        while True:
            # Keepalive ping setiap 25 detik
            await asyncio.sleep(25)
            await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, engagement_id)
```

**Daftarkan di `apps/api/app/main.py`:**

```python
from app.api.ws_router import router as ws_router
app.include_router(ws_router)
```

---

### Task 12.3 — API Endpoints untuk Engagement Lifecycle

**Update `apps/api/app/api/router.py` — tambahkan endpoints:**

```python
# apps/api/app/api/router.py

from celery import Celery

celery_app = Celery(broker=os.getenv("REDIS_URL"))


@router.post("/engagements/{engagement_id}/start", status_code=202)
async def start_engagement(
    engagement_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """
    Start agent untuk engagement.
    Agent berjalan di Celery worker — endpoint ini langsung return.
    Monitor progress via WebSocket /ws/engagements/{id}/feed.
    """
    from sqlalchemy import select
    from app.db.models import EngagementORM

    result = await db.execute(
        select(EngagementORM).where(
            EngagementORM.id == engagement_id,
        )
    )
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise HTTPException(404, "Engagement not found")

    # Verifikasi ownership atau admin
    if not current_user.is_admin and engagement.owner_id != current_user.id:
        raise HTTPException(403, "Not authorized")

    if engagement.status == "active":
        raise HTTPException(409, "Engagement already running")

    # Send ke Celery
    celery_app.send_task(
        "tasks.agent.run_engagement",
        args=[str(engagement_id)],
        task_id=f"engagement-{engagement_id}",
    )

    return {
        "status": "started",
        "engagement_id": str(engagement_id),
        "message": "Agent started. Connect to WebSocket for live updates.",
        "ws_url": f"/ws/engagements/{engagement_id}/feed",
    }


@router.post("/engagements/{engagement_id}/approve", status_code=200)
async def approve_hitl(
    engagement_id: UUID,
    decision: HitlDecision,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """
    Approve atau skip HITL interrupt.
    Resume agent execution di Celery worker.
    """
    from sqlalchemy import select
    from app.db.models import EngagementORM

    result = await db.execute(
        select(EngagementORM).where(EngagementORM.id == engagement_id)
    )
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise HTTPException(404, "Engagement not found")

    if not current_user.is_admin and engagement.owner_id != current_user.id:
        raise HTTPException(403, "Not authorized")

    # Send resume task ke Celery
    celery_app.send_task(
        "tasks.agent.resume_engagement",
        args=[str(engagement_id), decision.action],
    )

    return {
        "status": "resumed",
        "decision": decision.action,
        "engagement_id": str(engagement_id),
    }


class HitlDecision(BaseModel):
    action: str  # "approve" | "skip"

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        if v not in ("approve", "skip"):
            raise ValueError("action must be 'approve' or 'skip'")
        return v
```

---

### Task 12.4 — Frontend: useEngagementFeed Hook

**Buat `apps/web/src/hooks/useEngagementFeed.ts`:**

```typescript
// apps/web/src/hooks/useEngagementFeed.ts

import { useState, useEffect, useCallback, useRef } from "react";
import { useAuthStore } from "@/stores/auth";

export type FeedEventType =
  | "NODE_START"
  | "NODE_COMPLETE"
  | "LLM_STREAM"
  | "AWAITING_APPROVAL"
  | "FINDINGS_UPDATED"
  | "ENGAGEMENT_STARTED"
  | "ENGAGEMENT_COMPLETED"
  | "AGENT_ERROR"
  | "CONNECTED"
  | "ping";

export interface FeedEvent {
  type: FeedEventType;
  node?: string;
  content?: string;
  timestamp?: string;
  data?: Record<string, unknown>;
  error?: string;
}

export interface HitlRequest {
  node: string;
  timestamp: string;
  data: {
    type: string;
    phase: string;
    message: string;
    data: Record<string, unknown>;
  };
}

const WS_URL = import.meta.env.VITE_WS_URL ?? "ws://localhost:8000";
const MAX_EVENTS = 500;
const RECONNECT_DELAY_MS = 3000;

export function useEngagementFeed(engagementId: string | undefined) {
  const [events, setEvents] = useState<FeedEvent[]>([]);
  const [hitlRequest, setHitlRequest] = useState<HitlRequest | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [currentNode, setCurrentNode] = useState<string | null>(null);
  const [agentStatus, setAgentStatus] = useState<
    "idle" | "running" | "waiting" | "completed" | "error"
  >("idle");

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const { accessToken } = useAuthStore();

  const connect = useCallback(() => {
    if (!engagementId || !accessToken) return;

    const url = `${WS_URL}/ws/engagements/${engagementId}/feed?token=${accessToken}`;
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setIsConnected(true);
      if (reconnectRef.current) {
        clearTimeout(reconnectRef.current);
        reconnectRef.current = null;
      }
    };

    ws.onclose = () => {
      setIsConnected(false);
      // Auto-reconnect
      reconnectRef.current = setTimeout(connect, RECONNECT_DELAY_MS);
    };

    ws.onerror = () => {
      ws.close();
    };

    ws.onmessage = (e: MessageEvent) => {
      const event: FeedEvent = JSON.parse(e.data);

      if (event.type === "ping") return;

      // Update status berdasarkan event
      if (event.type === "ENGAGEMENT_STARTED") setAgentStatus("running");
      if (event.type === "ENGAGEMENT_COMPLETED") setAgentStatus("completed");
      if (event.type === "AGENT_ERROR") setAgentStatus("error");
      if (event.type === "AWAITING_APPROVAL") setAgentStatus("waiting");
      if (event.type === "NODE_START") setAgentStatus("running");

      // Track current node
      if (event.type === "NODE_START") setCurrentNode(event.node ?? null);
      if (event.type === "NODE_COMPLETE") setCurrentNode(null);

      // Set HITL request
      if (event.type === "AWAITING_APPROVAL") {
        setHitlRequest({
          node: event.node ?? "",
          timestamp: event.timestamp ?? new Date().toISOString(),
          data: event.data as HitlRequest["data"],
        });
      }

      // Accumulate events (newest first, capped)
      setEvents((prev) =>
        [event, ...prev].slice(0, MAX_EVENTS)
      );
    };
  }, [engagementId, accessToken]);

  useEffect(() => {
    connect();
    return () => {
      wsRef.current?.close();
      if (reconnectRef.current) clearTimeout(reconnectRef.current);
    };
  }, [connect]);

  const clearHitlRequest = useCallback(() => {
    setHitlRequest(null);
    setAgentStatus("running");
  }, []);

  const clearEvents = useCallback(() => setEvents([]), []);

  return {
    events,
    hitlRequest,
    isConnected,
    currentNode,
    agentStatus,
    clearHitlRequest,
    clearEvents,
  };
}
```

---

### Task 12.5 — Frontend: LiveFeed + HitlApprovalDialog

**Buat `apps/web/src/components/engagement/LiveFeed.tsx`:**

```typescript
// apps/web/src/components/engagement/LiveFeed.tsx

import { useRef, useEffect, useState } from "react";
import { FeedEvent } from "@/hooks/useEngagementFeed";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ChevronDown } from "lucide-react";

const NODE_LABELS: Record<string, string> = {
  plan: "📋 Planning",
  hitl_plan: "⏸ Awaiting Plan Approval",
  recon: "🔍 Reconnaissance",
  hitl_recon: "⏸ Awaiting Recon Review",
  vuln_hunt: "🎯 Vulnerability Hunt",
  hitl_exploit: "⚠️ Awaiting Exploit Approval",
  report: "📄 Report Generation",
};

const EVENT_STYLES: Record<string, string> = {
  NODE_START:           "text-blue-400",
  NODE_COMPLETE:        "text-green-400",
  AWAITING_APPROVAL:    "text-yellow-400 font-semibold",
  LLM_STREAM:           "text-slate-300",
  FINDINGS_UPDATED:     "text-orange-400 font-semibold",
  ENGAGEMENT_STARTED:   "text-cyan-400",
  ENGAGEMENT_COMPLETED: "text-green-300 font-semibold",
  AGENT_ERROR:          "text-red-400 font-semibold",
};

function formatEventMessage(event: FeedEvent): string {
  switch (event.type) {
    case "NODE_START":
      return `▶ ${NODE_LABELS[event.node ?? ""] ?? event.node} started`;
    case "NODE_COMPLETE":
      return `✓ ${NODE_LABELS[event.node ?? ""] ?? event.node} complete`;
    case "AWAITING_APPROVAL":
      return `⏸ Approval required — ${(event.data as any)?.phase ?? event.node}`;
    case "LLM_STREAM":
      return event.content ?? "";
    case "FINDINGS_UPDATED": {
      const d = event.data as any;
      return `🔴 ${d?.count ?? 0} new finding(s) — ${d?.preview?.[0]?.title ?? ""}`;
    }
    case "ENGAGEMENT_STARTED":
      return "🚀 Agent started";
    case "ENGAGEMENT_COMPLETED":
      return "✅ Engagement complete";
    case "AGENT_ERROR":
      return `❌ Error: ${event.error ?? "Unknown error"}`;
    default:
      return event.type;
  }
}

interface LiveFeedProps {
  events: FeedEvent[];
  isConnected: boolean;
  currentNode: string | null;
  agentStatus: string;
}

export function LiveFeed({
  events,
  isConnected,
  currentNode,
  agentStatus,
}: LiveFeedProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  // Auto-scroll ke bawah saat event baru
  useEffect(() => {
    if (autoScroll) {
      bottomRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [events.length, autoScroll]);

  const handleScroll = () => {
    if (!containerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
    const isNearBottom = scrollHeight - scrollTop - clientHeight < 100;
    setAutoScroll(isNearBottom);
  };

  return (
    <div className="flex flex-col h-full bg-slate-950 rounded-lg border border-slate-800 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-slate-800 shrink-0">
        <div className="flex items-center gap-3">
          <div className={cn(
            "w-2 h-2 rounded-full transition-colors",
            isConnected ? "bg-green-500 animate-pulse" : "bg-slate-600"
          )} />
          <span className="text-xs font-mono text-slate-400">
            {isConnected ? "LIVE" : "DISCONNECTED"}
          </span>
          {currentNode && (
            <Badge variant="outline" className="text-xs text-blue-400 border-blue-800">
              {NODE_LABELS[currentNode] ?? currentNode}
            </Badge>
          )}
        </div>
        <Badge
          variant="outline"
          className={cn("text-xs", {
            "text-cyan-400 border-cyan-800": agentStatus === "running",
            "text-yellow-400 border-yellow-800": agentStatus === "waiting",
            "text-green-400 border-green-800": agentStatus === "completed",
            "text-red-400 border-red-800": agentStatus === "error",
            "text-slate-400 border-slate-700": agentStatus === "idle",
          })}
        >
          {agentStatus.toUpperCase()}
        </Badge>
      </div>

      {/* Events */}
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto p-3 space-y-0.5 font-mono text-xs"
      >
        {events.length === 0 && (
          <p className="text-slate-600 text-center mt-12 text-sm">
            Start the agent to see live events...
          </p>
        )}

        {/* Events newest at bottom */}
        {[...events].reverse().map((event, i) => (
          <div
            key={i}
            className={cn(
              "flex gap-2 py-0.5 leading-relaxed",
              EVENT_STYLES[event.type] ?? "text-slate-400"
            )}
          >
            <span className="text-slate-600 shrink-0 w-20 text-right">
              {event.timestamp
                ? new Date(event.timestamp).toLocaleTimeString([], {
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit",
                  })
                : ""}
            </span>
            <span className="break-all">{formatEventMessage(event)}</span>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      {/* Scroll to bottom button */}
      {!autoScroll && (
        <div className="absolute bottom-16 right-4">
          <Button
            size="sm"
            variant="secondary"
            onClick={() => {
              setAutoScroll(true);
              bottomRef.current?.scrollIntoView({ behavior: "smooth" });
            }}
          >
            <ChevronDown size={14} className="mr-1" />
            Latest
          </Button>
        </div>
      )}
    </div>
  );
}
```

**Buat `apps/web/src/components/engagement/HitlApprovalDialog.tsx`:**

```typescript
// apps/web/src/components/engagement/HitlApprovalDialog.tsx

import {
  Dialog, DialogContent, DialogHeader,
  DialogTitle, DialogFooter, DialogDescription,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, CheckCircle, XCircle, Loader2 } from "lucide-react";
import { HitlRequest } from "@/hooks/useEngagementFeed";
import { useMutation } from "@tanstack/react-query";
import { apiClient } from "@/lib/api";

interface HitlApprovalDialogProps {
  engagementId: string;
  request: HitlRequest | null;
  onClose: () => void;
}

export function HitlApprovalDialog({
  engagementId,
  request,
  onClose,
}: HitlApprovalDialogProps) {
  const isDestructive = request?.data?.phase === "exploit_validation";

  const approveMutation = useMutation({
    mutationFn: (action: "approve" | "skip") =>
      apiClient.post(`/api/v1/engagements/${engagementId}/approve`, { action }),
    onSuccess: () => onClose(),
  });

  if (!request) return null;

  return (
    <Dialog open={true} onOpenChange={() => !approveMutation.isPending && onClose()}>
      <DialogContent
        className="bg-slate-900 border-slate-700 max-w-lg"
        onPointerDownOutside={(e) => e.preventDefault()} // Prevent accidental close
      >
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-base">
            {isDestructive ? (
              <AlertTriangle className="text-red-400 shrink-0" size={18} />
            ) : (
              <CheckCircle className="text-yellow-400 shrink-0" size={18} />
            )}
            {isDestructive
              ? "⚠️ Destructive Action — Approval Required"
              : "Agent Approval Required"}
          </DialogTitle>
          <DialogDescription className="text-slate-400 text-sm">
            {request.data.message}
          </DialogDescription>
        </DialogHeader>

        {/* Phase badge */}
        <div className="flex items-center gap-2 mt-1">
          <Badge
            variant="outline"
            className={
              isDestructive
                ? "border-red-800 text-red-400"
                : "border-yellow-800 text-yellow-400"
            }
          >
            Phase: {request.data.phase}
          </Badge>
          <span className="text-xs text-slate-500 font-mono">
            Node: {request.node}
          </span>
        </div>

        {/* Data preview */}
        {request.data.data &&
          Object.keys(request.data.data).length > 0 && (
            <div className="bg-slate-950 rounded border border-slate-800 p-3 max-h-52 overflow-y-auto">
              <pre className="text-xs text-slate-400 whitespace-pre-wrap">
                {JSON.stringify(request.data.data, null, 2)}
              </pre>
            </div>
          )}

        {isDestructive && (
          <p className="text-red-400 text-xs bg-red-950/30 border border-red-900/50 rounded p-2">
            ⚠️ This action will send active payloads to the target.
            Ensure it is within scope and you have authorization.
          </p>
        )}

        <DialogFooter className="gap-2 mt-2">
          <Button
            variant="outline"
            className="border-slate-600 text-slate-300"
            onClick={() => approveMutation.mutate("skip")}
            disabled={approveMutation.isPending}
          >
            <XCircle size={15} className="mr-1" />
            Skip
          </Button>
          <Button
            onClick={() => approveMutation.mutate("approve")}
            disabled={approveMutation.isPending}
            className={
              isDestructive
                ? "bg-red-700 hover:bg-red-600"
                : "bg-green-700 hover:bg-green-600"
            }
          >
            {approveMutation.isPending ? (
              <Loader2 size={15} className="mr-1 animate-spin" />
            ) : (
              <CheckCircle size={15} className="mr-1" />
            )}
            {isDestructive ? "Approve (Destructive)" : "Approve & Continue"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
```

---

### Task 12.6 — Live Engagement Dashboard Page

**Update `apps/web/src/pages/EngagementDetailPage.tsx`:**

```typescript
// apps/web/src/pages/EngagementDetailPage.tsx

import { useState } from "react";
import { useParams } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Play, Pause, Download } from "lucide-react";
import { useEngagementFeed } from "@/hooks/useEngagementFeed";
import { LiveFeed } from "@/components/engagement/LiveFeed";
import { HitlApprovalDialog } from "@/components/engagement/HitlApprovalDialog";
import { FindingsTable } from "@/components/findings/FindingsTable";
import { apiClient } from "@/lib/api";
import { cn } from "@/lib/utils";

export function EngagementDetailPage() {
  const { engagementId } = useParams<{ engagementId: string }>();
  const [activeTab, setActiveTab] = useState("live");

  // Fetch engagement data
  const { data: engagement } = useQuery({
    queryKey: ["engagement", engagementId],
    queryFn: () => apiClient.get(`/api/v1/engagements/${engagementId}`),
    refetchInterval: 5000, // Refresh status setiap 5 detik
  });

  // WebSocket live feed
  const {
    events,
    hitlRequest,
    isConnected,
    currentNode,
    agentStatus,
    clearHitlRequest,
  } = useEngagementFeed(engagementId);

  // Start engagement mutation
  const startMutation = useMutation({
    mutationFn: () =>
      apiClient.post(`/api/v1/engagements/${engagementId}/start`),
  });

  // Switch ke live tab saat HITL request muncul
  if (hitlRequest && activeTab !== "live") {
    setActiveTab("live");
  }

  return (
    <div className="flex flex-col h-full gap-4 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">
            {engagement?.name ?? "Loading..."}
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">
            {engagement?.target_domain ?? ""} ·{" "}
            <span className="capitalize">{engagement?.mode}</span> mode
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* Start / Running indicator */}
          {agentStatus === "idle" || agentStatus === "error" ? (
            <Button
              onClick={() => startMutation.mutate()}
              disabled={startMutation.isPending}
              className="bg-green-700 hover:bg-green-600"
            >
              <Play size={15} className="mr-1" />
              Start Agent
            </Button>
          ) : (
            <div className={cn(
              "flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium border",
              {
                "bg-blue-950/50 text-blue-400 border-blue-800 animate-pulse":
                  agentStatus === "running",
                "bg-yellow-950/50 text-yellow-400 border-yellow-800":
                  agentStatus === "waiting",
                "bg-green-950/50 text-green-400 border-green-800":
                  agentStatus === "completed",
              }
            )}>
              {agentStatus === "running" && (
                <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse" />
              )}
              {agentStatus === "waiting" && <Pause size={14} />}
              {agentStatus.charAt(0).toUpperCase() + agentStatus.slice(1)}
            </div>
          )}

          {/* Export report */}
          <Button variant="outline" size="sm" className="border-slate-700" asChild>
            <a
              href={`/api/v1/engagements/${engagementId}/report?format=pdf`}
              target="_blank"
              rel="noopener noreferrer"
            >
              <Download size={14} className="mr-1" />
              Report
            </a>
          </Button>
        </div>
      </div>

      {/* HITL Dialog — rendered di luar tabs agar visible di semua tab */}
      <HitlApprovalDialog
        engagementId={engagementId ?? ""}
        request={hitlRequest}
        onClose={clearHitlRequest}
      />

      {/* Tabs */}
      <Tabs
        value={activeTab}
        onValueChange={setActiveTab}
        className="flex-1 flex flex-col min-h-0"
      >
        <TabsList className="bg-slate-900 border border-slate-800 w-fit">
          <TabsTrigger value="live" className="relative">
            Live Feed
            {hitlRequest && (
              <span className="absolute -top-1 -right-1 w-2 h-2 bg-yellow-400 rounded-full" />
            )}
          </TabsTrigger>
          <TabsTrigger value="findings">
            Findings
            {(engagement?.findings_count ?? 0) > 0 && (
              <span className="ml-1.5 bg-red-900 text-red-300 text-xs px-1.5 rounded-full">
                {engagement?.findings_count}
              </span>
            )}
          </TabsTrigger>
          <TabsTrigger value="monitoring">Monitoring</TabsTrigger>
          <TabsTrigger value="report">Report</TabsTrigger>
        </TabsList>

        <TabsContent value="live" className="flex-1 min-h-0 mt-3">
          <LiveFeed
            events={events}
            isConnected={isConnected}
            currentNode={currentNode}
            agentStatus={agentStatus}
          />
        </TabsContent>

        <TabsContent value="findings" className="flex-1 min-h-0 mt-3">
          <FindingsTable engagementId={engagementId ?? ""} />
        </TabsContent>

        <TabsContent value="monitoring" className="mt-3">
          {/* MonitoringDashboard dari Sprint 4 */}
          <p className="text-slate-400">Monitoring alerts akan muncul di sini.</p>
        </TabsContent>

        <TabsContent value="report" className="mt-3">
          <div className="flex gap-3">
            {["markdown", "html", "pdf", "h1"].map((format) => (
              <Button key={format} variant="outline" size="sm" asChild>
                <a
                  href={`/api/v1/engagements/${engagementId}/report?format=${format}`}
                  target="_blank"
                >
                  Download {format.toUpperCase()}
                </a>
              </Button>
            ))}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
```

---

### Task 12.7 — Tests Sprint 12

```python
# apps/api/tests/test_ws_manager.py

import pytest
from unittest.mock import AsyncMock, MagicMock


@pytest.mark.asyncio
async def test_ws_manager_broadcast_sends_to_all_connected():
    from app.core.ws_manager import WebSocketManager

    manager = WebSocketManager()

    ws1 = AsyncMock()
    ws2 = AsyncMock()

    await manager.connect(ws1, "eng-1")
    await manager.connect(ws2, "eng-1")

    await manager.broadcast("eng-1", {"type": "test"})

    ws1.send_json.assert_called_once_with({"type": "test"})
    ws2.send_json.assert_called_once_with({"type": "test"})


@pytest.mark.asyncio
async def test_ws_manager_broadcast_removes_dead_connections():
    from app.core.ws_manager import WebSocketManager

    manager = WebSocketManager()

    ws_dead = AsyncMock()
    ws_dead.send_json.side_effect = Exception("Connection closed")
    ws_alive = AsyncMock()

    await manager.connect(ws_dead, "eng-1")
    await manager.connect(ws_alive, "eng-1")

    await manager.broadcast("eng-1", {"type": "test"})

    # Dead connection harus dihapus
    assert manager.connection_count("eng-1") == 1
    ws_alive.send_json.assert_called_once()


@pytest.mark.asyncio
async def test_ws_manager_disconnect_removes_specific_ws():
    from app.core.ws_manager import WebSocketManager

    manager = WebSocketManager()

    ws1 = AsyncMock()
    ws2 = AsyncMock()

    await manager.connect(ws1, "eng-1")
    await manager.connect(ws2, "eng-1")
    manager.disconnect(ws1, "eng-1")

    assert manager.connection_count("eng-1") == 1


def test_ws_manager_connection_count_returns_zero_for_unknown():
    from app.core.ws_manager import WebSocketManager

    manager = WebSocketManager()
    assert manager.connection_count("unknown-eng") == 0
```

---

## Checklist Akhir Phase 6

```
Sprint 11 — Tool Integration
[ ] AgentService.create() berhasil setup AsyncPostgresSaver
[ ] AgentService.resume() update state dan invoke graph
[ ] AgentService.stream_events_during_start() yield events
[ ] run_engagement Celery task bisa dijalankan tanpa error
[ ] resume_engagement Celery task berhasil resume graph
[ ] _build_initial_state() mengisi semua PentraState fields
[ ] OPSEC jitter dipanggil sebelum setiap tool exec jika opsec_mode=True
[ ] POST /api/v1/internal/engagements/{id}/findings/bulk return 201
[ ] POST /api/v1/internal/engagements/{id}/status return 200
[ ] verify_internal_token return 403 untuk token salah
[ ] test_service.py: 4+ tests pass
[ ] test_internal_api.py: 3+ tests pass

Sprint 12 — HITL Frontend Real-Time
[ ] WebSocketManager.broadcast() mengirim ke semua connected clients
[ ] Dead connections otomatis dihapus saat broadcast
[ ] Redis bridge subscribe "engagement:*:events" dan forward ke WS
[ ] Redis bridge restart otomatis jika Redis terputus
[ ] /ws/engagements/{id}/feed accept connection dengan valid token
[ ] /ws/engagements/{id}/feed reject dengan 4001 untuk invalid token
[ ] POST /api/v1/engagements/{id}/start send Celery task dan return 202
[ ] POST /api/v1/engagements/{id}/approve send resume task dan return 200
[ ] useEngagementFeed hook: events terakumulasi saat WS message masuk
[ ] useEngagementFeed hook: hitlRequest diset saat AWAITING_APPROVAL event
[ ] useEngagementFeed hook: auto-reconnect setelah 3 detik
[ ] LiveFeed: events ditampilkan dengan color coding yang benar
[ ] LiveFeed: auto-scroll ke bawah saat event baru
[ ] LiveFeed: "Latest" button muncul saat user scroll up
[ ] HitlApprovalDialog: muncul saat hitlRequest tidak null
[ ] HitlApprovalDialog: Approve → POST /approve dengan action=approve
[ ] HitlApprovalDialog: Skip → POST /approve dengan action=skip
[ ] HitlApprovalDialog: disabled saat mutation pending
[ ] EngagementDetailPage: Start Agent button trigger POST /start
[ ] EngagementDetailPage: status badge update realtime dari agentStatus
[ ] EngagementDetailPage: tab Live Feed highlight saat HITL request masuk
[ ] test_ws_manager.py: 4 tests pass

Security Compliance (final check)
[ ] WebSocket hanya menerima koneksi dengan valid JWT token
[ ] Internal API hanya menerima request dengan INTERNAL_API_TOKEN
[ ] hitl_exploit_review SELALU interrupt — tidak ada bypass
[ ] OPSEC jitter aktif saat opsec_mode=True di semua tool wrappers
[ ] Semua agent actions tercatat di audit_logs

Total tests setelah Phase 6: 82 existing + 10+ baru = 92+ passing
```

---

## Cara Memulai Phase 6

Gunakan prompt ini di Copilot Chat:

```
Baca CLAUDE.md, docs/PRD.md, PROGRESS.md, dan PHASE-6-EXECUTION.md secara lengkap.

Kita mulai Sprint 11, Task 11.1 — AgentService dan Celery task end-to-end.

1. Update packages/pentra-agent/pentra_agent/service.py dengan
   AgentService.create(), resume(), dan stream_events_during_start()
   sesuai Task 11.1

2. Update apps/worker/app/tasks/agent.py dengan
   run_engagement dan resume_engagement Celery tasks

3. Buat packages/pentra-agent/tests/test_service.py dengan 4 tests

4. Jalankan tests dan pastikan pass

Ikuti semua konvensi di CLAUDE.md, terutama Section 7 (LangGraph patterns).
```

---

*Phase 6 Execution Plan — Pentra AI*  
*Dibuat berdasarkan gap analysis dari PROGRESS.md (Sprint 1–10, 82 tests) vs arsitektur target*  
*Setelah Phase 6 selesai: Pentra AI berjalan end-to-end — agent → live feed → HITL → findings → report*
