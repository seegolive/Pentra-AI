# SPRINT-12-SMOKETEST.md — Pentra AI
> **Untuk:** GitHub Copilot dengan Claude Sonnet 4.6  
> **Baca terlebih dahulu:** `CLAUDE.md` → `PROGRESS.md` → file ini  
> **Status:** Sprint 1–11.1 selesai, 143 tests passing  
> **Tujuan:** Tutup loop — agent berjalan dari browser sampai findings muncul

---

## Filosofi Dokumen Ini

Kamu sudah membangun mesin yang lengkap tapi belum pernah dihidupkan secara nyata.  
143 tests pass, tapi belum ada yang duduk di browser, klik Start, dan lihat agent bekerja.

**Dokumen ini melakukan satu hal: menutup loop.**

```
Sebelum Sprint 12:
  Browser ──► API ──► Celery ──► Agent ──► Redis ──► ???
                                                      ↑
                                              tidak sampai ke browser

Setelah Sprint 12:
  Browser ──► API ──► Celery ──► Agent ──► Redis ──► WebSocket ──► Browser
     ↑                                                                  │
     └──────────────── HITL Approval ◄───────────────────────────────┘
```

---

## Bagian 1 — Sprint 12: Closing the Loop

> **Estimasi:** 3–4 hari  
> **Urutan wajib diikuti — setiap task bergantung pada task sebelumnya**

---

### Task 12.1 — WebSocket Manager + Redis Bridge

**File yang perlu dibuat:**

**`apps/api/app/core/ws_manager.py`**

```python
# apps/api/app/core/ws_manager.py

import asyncio
import json
from collections import defaultdict
from fastapi import WebSocket


class WebSocketManager:
    """
    Manage WebSocket connections per engagement.
    Satu instance (singleton) untuk seluruh API process.
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
        """
        Kirim event ke semua client yang terhubung ke engagement ini.
        Hapus otomatis koneksi yang sudah mati.
        """
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


# Singleton — import ini dari modul lain
ws_manager = WebSocketManager()
```

**`apps/api/app/core/redis_bridge.py`**

```python
# apps/api/app/core/redis_bridge.py

"""
Redis pub/sub → WebSocket bridge.

Celery worker publish events ke Redis channel:
  "engagement:{engagement_id}:events"

API process subscribe dan forward ke WebSocket clients.
Berjalan sebagai background asyncio task — restart otomatis jika Redis putus.
"""

import asyncio
import json
import os

import redis.asyncio as aioredis

from app.core.ws_manager import ws_manager


async def start_redis_bridge() -> None:
    """
    Entry point — dipanggil sekali saat API startup via asyncio.create_task().
    Loop tak terbatas dengan auto-reconnect.
    """
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")

    while True:
        r = None
        try:
            r = aioredis.from_url(redis_url, decode_responses=True)
            pubsub = r.pubsub()
            await pubsub.psubscribe("engagement:*:events")

            async for message in pubsub.listen():
                if message["type"] != "pmessage":
                    continue

                channel: str = message["channel"]
                # channel format: "engagement:{id}:events"
                parts = channel.split(":")
                if len(parts) < 3:
                    continue
                engagement_id = parts[1]

                try:
                    event = json.loads(message["data"])
                    await ws_manager.broadcast(engagement_id, event)
                except (json.JSONDecodeError, Exception):
                    pass

        except asyncio.CancelledError:
            break
        except Exception:
            # Redis terputus — tunggu 3 detik lalu reconnect
            await asyncio.sleep(3)
        finally:
            if r:
                try:
                    await r.aclose()
                except Exception:
                    pass
```

**Update `apps/api/app/main.py` — daftarkan bridge di lifespan:**

```python
# apps/api/app/main.py

from contextlib import asynccontextmanager
import asyncio
from app.core.redis_bridge import start_redis_bridge
from app.core.startup import StartupValidator

@asynccontextmanager
async def lifespan(app):
    # 1. Validasi semua dependencies
    validator = StartupValidator()
    await validator.validate_all()

    # 2. Start Redis → WebSocket bridge sebagai background task
    bridge_task = asyncio.create_task(start_redis_bridge())

    yield

    # 3. Cleanup saat shutdown
    bridge_task.cancel()
    try:
        await bridge_task
    except asyncio.CancelledError:
        pass


app = FastAPI(lifespan=lifespan, ...)
```

---

### Task 12.2 — WebSocket Endpoint + Auth Helper

**`apps/api/app/api/ws_router.py`**

```python
# apps/api/app/api/ws_router.py

import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from app.core.ws_manager import ws_manager
from app.core.auth import decode_token   # fungsi yang sudah ada

router = APIRouter(tags=["WebSocket"])


@router.websocket("/ws/engagements/{engagement_id}/feed")
async def engagement_live_feed(
    websocket: WebSocket,
    engagement_id: str,
    token: str = Query(...),
):
    """
    WebSocket live feed per engagement.

    Event types yang dikirim ke client:
      NODE_START          → agent mulai eksekusi node
      NODE_COMPLETE       → node selesai
      LLM_STREAM          → streaming token dari LLM
      AWAITING_APPROVAL   → HITL interrupt — butuh decision
      FINDINGS_UPDATED    → finding baru ditemukan
      ENGAGEMENT_STARTED  → agent mulai
      ENGAGEMENT_COMPLETED → engagement selesai
      AGENT_ERROR         → error terjadi
      ping                → keepalive 25 detik

    Client hanya mengirim keepalive.
    Approval dilakukan via POST /api/v1/engagements/{id}/approve.
    """
    # Validasi JWT token
    try:
        _user = await decode_token(token)
    except Exception:
        await websocket.close(code=4001, reason="Invalid or expired token")
        return

    await ws_manager.connect(websocket, engagement_id)

    # Kirim konfirmasi koneksi berhasil
    await websocket.send_json({
        "type": "CONNECTED",
        "engagement_id": engagement_id,
    })

    try:
        while True:
            # Keepalive ping setiap 25 detik
            # Browser WebSocket timeout biasanya 30–60 detik
            await asyncio.sleep(25)
            await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, engagement_id)
    except Exception:
        ws_manager.disconnect(websocket, engagement_id)
```

**Daftarkan di `apps/api/app/main.py`:**

```python
from app.api.ws_router import router as ws_router
app.include_router(ws_router)
```

---

### Task 12.3 — REST Endpoints: Start + Approve + Internal

**Tambahkan ke `apps/api/app/api/router.py`:**

```python
# apps/api/app/api/router.py — tambahkan 3 endpoints ini

import os
from celery import Celery
from pydantic import BaseModel, field_validator

celery_app = Celery(broker=os.getenv("REDIS_URL", "redis://localhost:6379"))


class HitlDecision(BaseModel):
    action: str

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        if v not in ("approve", "skip"):
            raise ValueError("action must be 'approve' or 'skip'")
        return v


@router.post(
    "/engagements/{engagement_id}/start",
    status_code=202,
    summary="Start agent untuk engagement",
    description=(
        "Trigger Celery task untuk menjalankan agent. "
        "Langsung return 202 — monitor progress via WebSocket /ws/engagements/{id}/feed."
    ),
)
async def start_engagement(
    engagement_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    from sqlalchemy import select
    from app.db.models import EngagementORM

    result = await db.execute(
        select(EngagementORM).where(EngagementORM.id == engagement_id)
    )
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise HTTPException(404, "Engagement not found")

    if not current_user.is_admin and str(engagement.owner_id) != str(current_user.id):
        raise HTTPException(403, "Not authorized")

    if engagement.status == "active":
        raise HTTPException(409, "Engagement is already running")

    # Send task ke Celery worker
    celery_app.send_task(
        "tasks.agent.run_engagement",
        args=[str(engagement_id)],
        task_id=f"engagement-{engagement_id}",
    )

    return {
        "status": "started",
        "engagement_id": str(engagement_id),
        "ws_url": f"/ws/engagements/{engagement_id}/feed",
        "message": "Agent started. Connect to WebSocket for live updates.",
    }


@router.post(
    "/engagements/{engagement_id}/approve",
    summary="Resume agent setelah HITL interrupt",
    description="Approve atau skip HITL decision. Agent akan dilanjutkan di Celery worker.",
)
async def approve_hitl(
    engagement_id: UUID,
    decision: HitlDecision,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    from sqlalchemy import select
    from app.db.models import EngagementORM

    result = await db.execute(
        select(EngagementORM).where(EngagementORM.id == engagement_id)
    )
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise HTTPException(404, "Engagement not found")

    if not current_user.is_admin and str(engagement.owner_id) != str(current_user.id):
        raise HTTPException(403, "Not authorized")

    celery_app.send_task(
        "tasks.agent.resume_engagement",
        args=[str(engagement_id), decision.action],
    )

    return {
        "status": "resumed",
        "decision": decision.action,
        "engagement_id": str(engagement_id),
    }
```

**Buat `apps/api/app/api/internal_router.py`:**

```python
# apps/api/app/api/internal_router.py

"""
Internal endpoints — agent worker → API.
Verifikasi via X-Internal-Token header.
Tidak accessible dari luar Docker network.
"""

import os
from uuid import UUID, uuid4
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel

from app.db.session import get_db
from app.db.models import FindingORM, EngagementORM

router = APIRouter(prefix="/api/v1/internal", tags=["Internal"])


async def verify_internal_token(x_internal_token: str = Header(...)):
    expected = os.getenv("INTERNAL_API_TOKEN", "")
    if not expected:
        raise HTTPException(500, "INTERNAL_API_TOKEN not configured on server")
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
    status: str  # "active" | "completed" | "failed" | "paused"


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
    """Bulk create findings dari agent. Internal only."""
    result = await db.execute(
        select(EngagementORM).where(EngagementORM.id == engagement_id)
    )
    if not result.scalar_one_or_none():
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
    return {"created": len(created)}


@router.patch(
    "/engagements/{engagement_id}/status",
    dependencies=[Depends(verify_internal_token)],
)
async def update_engagement_status(
    engagement_id: UUID,
    payload: EngagementStatusUpdate,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Update engagement status dari agent. Internal only."""
    result = await db.execute(
        select(EngagementORM).where(EngagementORM.id == engagement_id)
    )
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise HTTPException(404, "Engagement not found")

    engagement.status = payload.status
    if payload.status == "completed":
        engagement.completed_at = datetime.now(timezone.utc)

    await db.commit()
    return {"updated": True, "status": payload.status}
```

**Daftarkan di `apps/api/app/main.py`:**

```python
from app.api.internal_router import router as internal_router
from app.api.ws_router import router as ws_router
app.include_router(internal_router)
app.include_router(ws_router)
```

---

### Task 12.4 — Frontend: useEngagementFeed Hook

**Buat `apps/web/src/hooks/useEngagementFeed.ts`:**

```typescript
// apps/web/src/hooks/useEngagementFeed.ts

import { useState, useEffect, useCallback, useRef } from "react";
import { useAuthStore } from "@/stores/auth";

export type FeedEventType =
  | "NODE_START" | "NODE_COMPLETE" | "LLM_STREAM"
  | "AWAITING_APPROVAL" | "FINDINGS_UPDATED"
  | "ENGAGEMENT_STARTED" | "ENGAGEMENT_COMPLETED"
  | "AGENT_ERROR" | "CONNECTED" | "ping";

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

export type AgentStatus =
  | "idle" | "running" | "waiting" | "completed" | "error";

const WS_BASE = import.meta.env.VITE_WS_URL ?? "ws://localhost:8000";
const MAX_EVENTS = 500;
const RECONNECT_MS = 3000;

export function useEngagementFeed(engagementId: string | undefined) {
  const [events, setEvents] = useState<FeedEvent[]>([]);
  const [hitlRequest, setHitlRequest] = useState<HitlRequest | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [currentNode, setCurrentNode] = useState<string | null>(null);
  const [agentStatus, setAgentStatus] = useState<AgentStatus>("idle");

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const { accessToken } = useAuthStore();

  const connect = useCallback(() => {
    if (!engagementId || !accessToken) return;

    const url = `${WS_BASE}/ws/engagements/${engagementId}/feed?token=${accessToken}`;
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
      reconnectRef.current = setTimeout(connect, RECONNECT_MS);
    };

    ws.onerror = () => ws.close();

    ws.onmessage = (e: MessageEvent) => {
      const event: FeedEvent = JSON.parse(e.data);
      if (event.type === "ping" || event.type === "CONNECTED") return;

      // Update agent status
      const statusMap: Partial<Record<FeedEventType, AgentStatus>> = {
        ENGAGEMENT_STARTED: "running",
        ENGAGEMENT_COMPLETED: "completed",
        AGENT_ERROR: "error",
        AWAITING_APPROVAL: "waiting",
        NODE_START: "running",
      };
      if (statusMap[event.type]) setAgentStatus(statusMap[event.type]!);

      // Track active node
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

      setEvents((prev) => [event, ...prev].slice(0, MAX_EVENTS));
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

  return {
    events,
    hitlRequest,
    isConnected,
    currentNode,
    agentStatus,
    clearHitlRequest,
  };
}
```

---

### Task 12.5 — Frontend: LiveFeed Component

**Buat `apps/web/src/components/engagement/LiveFeed.tsx`:**

```typescript
// apps/web/src/components/engagement/LiveFeed.tsx

import { useRef, useEffect, useState } from "react";
import { FeedEvent, AgentStatus } from "@/hooks/useEngagementFeed";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ChevronDown } from "lucide-react";
import { cn } from "@/lib/utils";

const NODE_LABELS: Record<string, string> = {
  plan:          "📋 Planning",
  hitl_plan:     "⏸ Awaiting Plan Approval",
  recon:         "🔍 Reconnaissance",
  hitl_recon:    "⏸ Awaiting Recon Review",
  vuln_hunt:     "🎯 Vulnerability Hunt",
  hitl_exploit:  "⚠️ Awaiting Exploit Approval",
  report:        "📄 Report Generation",
};

const EVENT_COLORS: Record<string, string> = {
  NODE_START:           "text-blue-400",
  NODE_COMPLETE:        "text-green-400",
  AWAITING_APPROVAL:    "text-yellow-300 font-semibold",
  LLM_STREAM:           "text-slate-300",
  FINDINGS_UPDATED:     "text-orange-400 font-semibold",
  ENGAGEMENT_STARTED:   "text-cyan-400",
  ENGAGEMENT_COMPLETED: "text-green-300 font-semibold",
  AGENT_ERROR:          "text-red-400 font-semibold",
};

const STATUS_STYLES: Record<AgentStatus, string> = {
  idle:      "text-slate-400 border-slate-700",
  running:   "text-blue-400 border-blue-800",
  waiting:   "text-yellow-400 border-yellow-800",
  completed: "text-green-400 border-green-800",
  error:     "text-red-400 border-red-800",
};

function formatEvent(event: FeedEvent): string {
  const d = event.data as Record<string, unknown> | undefined;
  switch (event.type) {
    case "NODE_START":
      return `▶ ${NODE_LABELS[event.node ?? ""] ?? event.node}`;
    case "NODE_COMPLETE":
      return `✓ ${NODE_LABELS[event.node ?? ""] ?? event.node} complete`;
    case "AWAITING_APPROVAL":
      return `⏸ Approval needed — ${d?.phase ?? event.node}`;
    case "LLM_STREAM":
      return event.content ?? "";
    case "FINDINGS_UPDATED":
      return `🔴 ${d?.count ?? 0} finding(s) — ${(d?.preview as any)?.[0]?.title ?? ""}`;
    case "ENGAGEMENT_STARTED":
      return "🚀 Agent started";
    case "ENGAGEMENT_COMPLETED":
      return "✅ Engagement complete";
    case "AGENT_ERROR":
      return `❌ ${event.error ?? "Agent error"}`;
    default:
      return event.type;
  }
}

export function LiveFeed({
  events,
  isConnected,
  currentNode,
  agentStatus,
}: {
  events: FeedEvent[];
  isConnected: boolean;
  currentNode: string | null;
  agentStatus: AgentStatus;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  useEffect(() => {
    if (autoScroll) bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [events.length, autoScroll]);

  return (
    <div className="relative flex flex-col h-full bg-slate-950 rounded-lg border border-slate-800 overflow-hidden">
      {/* Header bar */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-slate-800 shrink-0">
        <div className="flex items-center gap-3">
          <div className={cn(
            "w-2 h-2 rounded-full",
            isConnected ? "bg-green-500 animate-pulse" : "bg-slate-600"
          )} />
          <span className="text-xs font-mono text-slate-500">
            {isConnected ? "LIVE" : "RECONNECTING..."}
          </span>
          {currentNode && (
            <Badge variant="outline" className="text-xs text-blue-400 border-blue-900">
              {NODE_LABELS[currentNode] ?? currentNode}
            </Badge>
          )}
        </div>
        <Badge
          variant="outline"
          className={cn("text-xs", STATUS_STYLES[agentStatus])}
        >
          {agentStatus.toUpperCase()}
        </Badge>
      </div>

      {/* Event stream */}
      <div
        ref={containerRef}
        onScroll={() => {
          if (!containerRef.current) return;
          const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
          setAutoScroll(scrollHeight - scrollTop - clientHeight < 80);
        }}
        className="flex-1 overflow-y-auto p-3 space-y-0.5 font-mono text-xs"
      >
        {events.length === 0 && (
          <p className="text-slate-600 text-center mt-16 text-sm">
            Start the agent to see live events...
          </p>
        )}

        {[...events].reverse().map((ev, i) => (
          <div
            key={i}
            className={cn(
              "flex gap-2 py-0.5 leading-relaxed",
              EVENT_COLORS[ev.type] ?? "text-slate-400"
            )}
          >
            <span className="text-slate-600 shrink-0 tabular-nums">
              {ev.timestamp
                ? new Date(ev.timestamp).toLocaleTimeString([], {
                    hour: "2-digit", minute: "2-digit", second: "2-digit",
                  })
                : ""}
            </span>
            <span className="break-all">{formatEvent(ev)}</span>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      {/* Scroll to latest button */}
      {!autoScroll && (
        <div className="absolute bottom-4 right-4">
          <Button
            size="sm"
            variant="secondary"
            className="shadow-lg"
            onClick={() => {
              setAutoScroll(true);
              bottomRef.current?.scrollIntoView({ behavior: "smooth" });
            }}
          >
            <ChevronDown size={14} className="mr-1" /> Latest
          </Button>
        </div>
      )}
    </div>
  );
}
```

---

### Task 12.6 — Frontend: HitlApprovalDialog

**Buat `apps/web/src/components/engagement/HitlApprovalDialog.tsx`:**

```typescript
// apps/web/src/components/engagement/HitlApprovalDialog.tsx

import {
  Dialog, DialogContent, DialogHeader,
  DialogTitle, DialogDescription, DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, CheckCircle, XCircle, Loader2 } from "lucide-react";
import { useMutation } from "@tanstack/react-query";
import { HitlRequest } from "@/hooks/useEngagementFeed";
import { apiClient } from "@/lib/api";

interface Props {
  engagementId: string;
  request: HitlRequest | null;
  onClose: () => void;
}

export function HitlApprovalDialog({ engagementId, request, onClose }: Props) {
  const isDestructive = request?.data?.phase === "exploit_validation";

  const mutation = useMutation({
    mutationFn: (action: "approve" | "skip") =>
      apiClient.post(`/api/v1/engagements/${engagementId}/approve`, { action }),
    onSuccess: onClose,
  });

  if (!request) return null;

  return (
    <Dialog
      open
      onOpenChange={() => !mutation.isPending && onClose()}
    >
      <DialogContent
        className="bg-slate-900 border-slate-700 max-w-lg"
        onPointerDownOutside={(e) => e.preventDefault()}
      >
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-sm font-semibold">
            {isDestructive
              ? <AlertTriangle className="text-red-400 shrink-0" size={16} />
              : <CheckCircle className="text-yellow-400 shrink-0" size={16} />
            }
            {isDestructive
              ? "⚠️ Destructive Action — Approval Required"
              : "Agent Approval Required"}
          </DialogTitle>
          <DialogDescription className="text-slate-400 text-xs mt-1">
            {request.data.message}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3 mt-1">
          <div className="flex gap-2">
            <Badge
              variant="outline"
              className={isDestructive
                ? "border-red-900 text-red-400 text-xs"
                : "border-yellow-900 text-yellow-400 text-xs"}
            >
              Phase: {request.data.phase}
            </Badge>
            <Badge variant="outline" className="border-slate-700 text-slate-400 text-xs">
              Node: {request.node}
            </Badge>
          </div>

          {/* Context data */}
          {request.data.data && Object.keys(request.data.data).length > 0 && (
            <div className="bg-slate-950 border border-slate-800 rounded p-3 max-h-48 overflow-y-auto">
              <pre className="text-xs text-slate-400 whitespace-pre-wrap">
                {JSON.stringify(request.data.data, null, 2)}
              </pre>
            </div>
          )}

          {/* Destructive warning */}
          {isDestructive && (
            <p className="text-xs text-red-400 bg-red-950/30 border border-red-900/40 rounded p-2">
              ⚠️ Active payloads will be sent to the target.
              Ensure this is within scope and you have authorization.
            </p>
          )}
        </div>

        <DialogFooter className="gap-2 mt-3">
          <Button
            variant="outline"
            size="sm"
            className="border-slate-600"
            onClick={() => mutation.mutate("skip")}
            disabled={mutation.isPending}
          >
            <XCircle size={14} className="mr-1" />
            Skip
          </Button>
          <Button
            size="sm"
            onClick={() => mutation.mutate("approve")}
            disabled={mutation.isPending}
            className={isDestructive
              ? "bg-red-700 hover:bg-red-600"
              : "bg-green-700 hover:bg-green-600"}
          >
            {mutation.isPending
              ? <Loader2 size={14} className="mr-1 animate-spin" />
              : <CheckCircle size={14} className="mr-1" />
            }
            {isDestructive ? "Approve (Destructive)" : "Approve & Continue"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
```

---

### Task 12.7 — Frontend: EngagementDetailPage Update

**Update `apps/web/src/pages/EngagementDetailPage.tsx`:**

```typescript
// apps/web/src/pages/EngagementDetailPage.tsx

import { useState } from "react";
import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Play, Download, RefreshCw } from "lucide-react";
import { useEngagementFeed } from "@/hooks/useEngagementFeed";
import { LiveFeed } from "@/components/engagement/LiveFeed";
import { HitlApprovalDialog } from "@/components/engagement/HitlApprovalDialog";
import { apiClient } from "@/lib/api";
import { cn } from "@/lib/utils";

export function EngagementDetailPage() {
  const { engagementId } = useParams<{ engagementId: string }>();
  const [activeTab, setActiveTab] = useState("live");
  const queryClient = useQueryClient();

  // Fetch engagement metadata
  const { data: engagement, isLoading } = useQuery({
    queryKey: ["engagement", engagementId],
    queryFn: () => apiClient.get(`/api/v1/engagements/${engagementId}`),
    refetchInterval: 5_000,
    enabled: !!engagementId,
  });

  // Live feed
  const {
    events, hitlRequest, isConnected,
    currentNode, agentStatus, clearHitlRequest,
  } = useEngagementFeed(engagementId);

  // Start agent
  const startMutation = useMutation({
    mutationFn: () =>
      apiClient.post(`/api/v1/engagements/${engagementId}/start`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["engagement", engagementId] });
    },
  });

  // Auto-switch ke live tab saat HITL muncul
  if (hitlRequest && activeTab !== "live") setActiveTab("live");

  if (isLoading) return <div className="p-6 text-slate-400">Loading...</div>;
  if (!engagement) return <div className="p-6 text-slate-400">Engagement not found.</div>;

  const canStart = ["idle", "failed"].includes(agentStatus) &&
    !["active"].includes(engagement.status);

  return (
    <div className="flex flex-col h-full p-6 gap-4">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">
            {engagement.name}
          </h1>
          <p className="text-sm text-slate-500 mt-0.5">
            {engagement.target_domain} · {" "}
            <span className="capitalize">{engagement.mode}</span> mode
            {engagement.opsec_mode && (
              <span className="ml-2 text-xs text-purple-400">[OPSEC]</span>
            )}
          </p>
        </div>

        <div className="flex items-center gap-2">
          {canStart ? (
            <Button
              size="sm"
              onClick={() => startMutation.mutate()}
              disabled={startMutation.isPending}
              className="bg-green-700 hover:bg-green-600"
            >
              {startMutation.isPending
                ? <RefreshCw size={14} className="mr-1 animate-spin" />
                : <Play size={14} className="mr-1" />
              }
              Start Agent
            </Button>
          ) : (
            <div className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium border",
              {
                "bg-blue-950/40 text-blue-400 border-blue-900": agentStatus === "running",
                "bg-yellow-950/40 text-yellow-400 border-yellow-900": agentStatus === "waiting",
                "bg-green-950/40 text-green-400 border-green-900": agentStatus === "completed",
                "bg-red-950/40 text-red-400 border-red-900": agentStatus === "error",
              }
            )}>
              {agentStatus === "running" && (
                <div className="w-1.5 h-1.5 bg-blue-400 rounded-full animate-pulse" />
              )}
              {agentStatus.charAt(0).toUpperCase() + agentStatus.slice(1)}
            </div>
          )}

          <Button variant="outline" size="sm" className="border-slate-700" asChild>
            <a
              href={`/api/v1/engagements/${engagementId}/report?format=pdf`}
              target="_blank" rel="noopener noreferrer"
            >
              <Download size={14} className="mr-1" />
              PDF
            </a>
          </Button>
        </div>
      </div>

      {/* HITL Dialog — rendered di luar tabs agar visible kapanpun */}
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
          <TabsTrigger value="live" className="relative text-xs">
            Live Feed
            {hitlRequest && (
              <span className="absolute -top-1 -right-1 w-2 h-2 bg-yellow-400 rounded-full animate-pulse" />
            )}
            {!isConnected && (
              <span className="absolute -top-1 -right-1 w-2 h-2 bg-slate-600 rounded-full" />
            )}
          </TabsTrigger>
          <TabsTrigger value="findings" className="text-xs">
            Findings
            {(engagement.findings_count ?? 0) > 0 && (
              <span className="ml-1 bg-red-900/60 text-red-300 text-xs px-1 rounded">
                {engagement.findings_count}
              </span>
            )}
          </TabsTrigger>
          <TabsTrigger value="report" className="text-xs">Report</TabsTrigger>
        </TabsList>

        <TabsContent value="live" className="flex-1 min-h-0 mt-3">
          <LiveFeed
            events={events}
            isConnected={isConnected}
            currentNode={currentNode}
            agentStatus={agentStatus}
          />
        </TabsContent>

        <TabsContent value="findings" className="mt-3 overflow-auto">
          {/* FindingsTable sudah ada dari sprint sebelumnya */}
          <p className="text-slate-400 text-sm">
            {engagement.findings_count
              ? `${engagement.findings_count} findings`
              : "No findings yet. Start the agent to begin."}
          </p>
        </TabsContent>

        <TabsContent value="report" className="mt-3">
          <div className="flex flex-wrap gap-2">
            {["markdown", "html", "pdf", "h1"].map((fmt) => (
              <Button key={fmt} variant="outline" size="sm" asChild>
                <a
                  href={`/api/v1/engagements/${engagementId}/report?format=${fmt}`}
                  target="_blank"
                >
                  Download {fmt.toUpperCase()}
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

### Task 12.8 — Tests Sprint 12

```python
# apps/api/tests/test_ws_manager.py

import pytest
from unittest.mock import AsyncMock


@pytest.mark.asyncio
async def test_broadcast_sends_to_all_connected():
    from app.core.ws_manager import WebSocketManager
    m = WebSocketManager()
    ws1, ws2 = AsyncMock(), AsyncMock()
    await m.connect(ws1, "eng-1")
    await m.connect(ws2, "eng-1")
    await m.broadcast("eng-1", {"type": "test"})
    ws1.send_json.assert_called_once_with({"type": "test"})
    ws2.send_json.assert_called_once_with({"type": "test"})


@pytest.mark.asyncio
async def test_broadcast_removes_dead_connections():
    from app.core.ws_manager import WebSocketManager
    m = WebSocketManager()
    ws_dead = AsyncMock()
    ws_dead.send_json.side_effect = Exception("closed")
    ws_alive = AsyncMock()
    await m.connect(ws_dead, "eng-1")
    await m.connect(ws_alive, "eng-1")
    await m.broadcast("eng-1", {"type": "test"})
    assert m.connection_count("eng-1") == 1
    ws_alive.send_json.assert_called_once()


def test_disconnect_removes_specific_ws():
    from app.core.ws_manager import WebSocketManager
    import asyncio
    m = WebSocketManager()
    ws1, ws2 = AsyncMock(), AsyncMock()
    asyncio.run(m.connect(ws1, "eng-1"))
    asyncio.run(m.connect(ws2, "eng-1"))
    m.disconnect(ws1, "eng-1")
    assert m.connection_count("eng-1") == 1


def test_connection_count_zero_for_unknown():
    from app.core.ws_manager import WebSocketManager
    m = WebSocketManager()
    assert m.connection_count("unknown") == 0


@pytest.mark.asyncio
async def test_verify_internal_token_rejects_wrong_token(monkeypatch):
    monkeypatch.setenv("INTERNAL_API_TOKEN", "correct")
    from fastapi import HTTPException
    from app.api.internal_router import verify_internal_token
    with pytest.raises(HTTPException) as exc:
        await verify_internal_token(x_internal_token="wrong")
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_verify_internal_token_passes_correct(monkeypatch):
    monkeypatch.setenv("INTERNAL_API_TOKEN", "correct")
    from app.api.internal_router import verify_internal_token
    result = await verify_internal_token(x_internal_token="correct")
    assert result is None
```

---

## Bagian 2 — Smoke Test End-to-End

> **Lakukan setelah Sprint 12 selesai**  
> **Target:** testphp.vulnweb.com (deliberately vulnerable, legal untuk testing)  
> **Estimasi:** 2–4 jam (termasuk waktu agent berjalan)

---

### Persiapan Smoke Test

```bash
# 1. Pastikan semua service running
docker compose -f infra/docker-compose.yml up -d
docker compose ps   # semua harus "healthy"

# 2. Pastikan Ollama punya model yang dibutuhkan
ollama list
# Harus ada: bge-m3, qwen2.5-coder:7b (minimum)
# Kalau belum: ollama pull bge-m3 && ollama pull qwen2.5-coder:7b

# 3. Pastikan Burp Pro aktif dengan MCP enabled (optional tapi recommended)
curl http://127.0.0.1:9876   # harus response, bukan connection refused

# 4. Apply migrations
cd apps/api
uv run alembic upgrade head
uv run alembic current   # harus: 5270364c5870 (head)

# 5. Start API dan frontend
uv run fastapi dev app/main.py --port 8000 &
cd apps/web && pnpm dev &

# 6. Run tests dulu — pastikan 143+ tests pass sebelum smoke test
uv run pytest tests/ -q
```

---

### Smoke Test Script — Jalankan Urut

#### ST-01: Setup Admin (jika fresh install)

```bash
# Cek apakah sudah ada admin
curl http://localhost:8000/api/v1/setup/status | jq .

# Jika requires_setup=true:
curl -X POST http://localhost:8000/api/v1/setup/initialize \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin@localhost","password":"Pentra@2026!"}'

# Simpan token
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Pentra@2026!"}' | jq -r .access_token)

echo "TOKEN: $TOKEN"
```

#### ST-02: Buat Workspace dan Engagement

```bash
# Buat workspace
WS_ID=$(curl -s -X POST http://localhost:8000/api/v1/workspaces \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Smoke Test Workspace"}' | jq -r .id)

echo "Workspace ID: $WS_ID"

# Buat engagement
ENG_ID=$(curl -s -X POST http://localhost:8000/api/v1/engagements \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"Smoke Test — testphp.vulnweb.com\",
    \"workspace_id\": \"$WS_ID\",
    \"mode\": \"semi_auto\",
    \"in_scope\": [\"testphp.vulnweb.com\"],
    \"out_of_scope\": [],
    \"llm_model\": \"qwen2.5-coder:7b\"
  }" | jq -r .id)

echo "Engagement ID: $ENG_ID"
```

#### ST-03: Verifikasi WebSocket Koneksi

```bash
# Install wscat jika belum ada
npm install -g wscat

# Koneksi ke live feed (biarkan berjalan di terminal terpisah)
wscat -c "ws://localhost:8000/ws/engagements/$ENG_ID/feed?token=$TOKEN"

# Expected output:
# Connected (press CTRL+C to quit)
# < {"type":"CONNECTED","engagement_id":"..."}
# < {"type":"ping"}   (setiap 25 detik)
```

#### ST-04: Start Agent

```bash
# Di terminal baru
curl -s -X POST http://localhost:8000/api/v1/engagements/$ENG_ID/start \
  -H "Authorization: Bearer $TOKEN" | jq .

# Expected:
# {"status":"started","engagement_id":"...","ws_url":"..."}

# Observe wscat terminal — harus muncul events:
# {"type":"ENGAGEMENT_STARTED",...}
# {"type":"NODE_START","node":"plan",...}
# {"type":"LLM_STREAM","content":"...",...}
# {"type":"NODE_COMPLETE","node":"plan",...}
# {"type":"AWAITING_APPROVAL","node":"hitl_plan",...}
```

#### ST-05: HITL Approval — Plan Review

```bash
# Saat AWAITING_APPROVAL muncul di wscat:
curl -s -X POST http://localhost:8000/api/v1/engagements/$ENG_ID/approve \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"approve"}' | jq .

# Expected: {"status":"resumed","decision":"approve",...}
# wscat terminal: agent lanjut ke recon phase
```

#### ST-06: Tunggu Recon Selesai

```bash
# Observe wscat:
# NODE_START recon
# LLM_STREAM (subfinder output analysis)
# NODE_COMPLETE recon
# AWAITING_APPROVAL hitl_recon — tampilkan subdomain yang ditemukan

# Approve recon:
curl -s -X POST http://localhost:8000/api/v1/engagements/$ENG_ID/approve \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"approve"}' | jq .
```

#### ST-07: Tunggu Vuln Hunt dan Report

```bash
# Observe wscat:
# NODE_START vuln_hunt
# FINDINGS_UPDATED (jika nuclei/tools menemukan sesuatu)
# NODE_COMPLETE vuln_hunt
# AWAITING_APPROVAL hitl_exploit (jika ada high/critical finding)
#   → approve atau skip
# NODE_START report
# NODE_COMPLETE report
# ENGAGEMENT_COMPLETED

# Cek findings
curl -s http://localhost:8000/api/v1/engagements/$ENG_ID/findings \
  -H "Authorization: Bearer $TOKEN" | jq '.[] | {title, severity, url: .target_url}'

# Download report
curl -s http://localhost:8000/api/v1/engagements/$ENG_ID/report?format=pdf \
  -H "Authorization: Bearer $TOKEN" \
  --output /tmp/pentra-smoke-test-report.pdf

ls -lh /tmp/pentra-smoke-test-report.pdf
```

#### ST-08: Verifikasi via Browser UI

```
1. Buka http://localhost:5173
2. Login dengan admin credentials
3. Navigasi ke Workspaces → Smoke Test Workspace → engagement
4. Klik tab "Live Feed" — harus tampilkan semua events dari ST-04 s/d ST-07
5. Klik tab "Findings" — harus tampilkan findings yang ditemukan
6. Klik "Download PDF" — harus download report
7. Buat engagement kedua → klik "Start Agent" dari UI → observe Live Feed real-time
```

---

### Checklist Smoke Test

```
Setup
[ ] docker compose ps — semua 7 services "healthy"
[ ] ollama list — ada bge-m3 dan minimal qwen2.5-coder:7b
[ ] uv run alembic current — menunjukkan head migration
[ ] 143+ unit tests pass sebelum mulai

Sprint 12 Components
[ ] ws_manager.py dibuat dan daftarkan di main.py
[ ] redis_bridge.py dibuat dan dijalankan di lifespan startup
[ ] /ws/engagements/{id}/feed accept connection dengan valid JWT
[ ] /ws/engagements/{id}/feed reject dengan 4001 untuk invalid token
[ ] POST /api/v1/engagements/{id}/start return 202
[ ] POST /api/v1/engagements/{id}/approve return 200
[ ] POST /api/v1/internal/engagements/{id}/findings/bulk return 201
[ ] useEngagementFeed hook connect dan accumulate events
[ ] LiveFeed component render events dengan color coding
[ ] HitlApprovalDialog muncul saat hitlRequest tidak null
[ ] EngagementDetailPage ada tombol "Start Agent"
[ ] 6+ unit tests di test_ws_manager.py pass

Smoke Test — Backend
[ ] ST-01: Admin dibuat, token berhasil didapat
[ ] ST-02: Workspace dan engagement dibuat dengan scope testphp.vulnweb.com
[ ] ST-03: wscat terhubung, menerima CONNECTED event
[ ] ST-04: POST /start return 202, wscat menerima NODE_START plan
[ ] ST-05: AWAITING_APPROVAL hitl_plan muncul, POST /approve berhasil resume
[ ] ST-06: Recon berjalan (subfinder, httpx, nmap output di wscat)
[ ] ST-06: AWAITING_APPROVAL hitl_recon muncul dengan subdomain list
[ ] ST-07: Vuln hunt berjalan (nuclei output di wscat)
[ ] ST-07: ENGAGEMENT_COMPLETED event diterima
[ ] ST-07: GET /findings return minimal 1 finding
[ ] ST-07: GET /report?format=pdf return file PDF yang valid

Smoke Test — Browser UI
[ ] Login berhasil di http://localhost:5173
[ ] Engagement detail page tampilkan tombol "Start Agent"
[ ] Live Feed tab menampilkan events real-time saat agent berjalan
[ ] HitlApprovalDialog muncul di browser saat AWAITING_APPROVAL
[ ] Klik Approve di browser → agent lanjut (wscat confirm)
[ ] Findings tab menampilkan findings setelah engagement selesai
[ ] Download PDF dari UI berhasil
```

---

### Masalah yang Mungkin Ditemukan

**Kemungkinan 1: Agent berjalan tapi tidak ada events di wscat**
```
Cek:
- Apakah Redis bridge berjalan? (log startup API)
- Apakah Celery worker berjalan?
  docker compose logs worker | grep "run_engagement"
- Apakah Redis menerima publish?
  redis-cli PSUBSCRIBE "engagement:*:events"
  (jalankan ini lalu trigger agent, harus muncul messages)
```

**Kemungkinan 2: AWAITING_APPROVAL tidak muncul (semi_auto mode)**
```
Cek:
- Apakah hitl_nodes.py memanggil interrupt() dengan benar?
- Apakah mode di engagement adalah "semi_auto" (bukan "agentic")?
- Cek LangGraph checkpoint di PostgreSQL:
  SELECT * FROM checkpoints WHERE thread_id = '{engagement_id}';
```

**Kemungkinan 3: Findings tidak tersimpan**
```
Cek:
- Apakah INTERNAL_API_TOKEN di-set di .env?
- Apakah internal_router di-include di main.py?
- Cek log report_node.py — apakah persist_findings() berhasil?
- Cek: SELECT * FROM findings WHERE engagement_id = '{id}';
```

**Kemungkinan 4: Tools tidak berjalan (subfinder not found)**
```
Cek apakah tools terinstall di worker container:
  docker compose exec worker which subfinder
  docker compose exec worker which nmap
  docker compose exec worker nuclei --version

Jika tidak ada:
  Update infra/docker/Dockerfile.worker untuk install tools
  docker compose build worker && docker compose up -d worker
```

**Kemungkinan 5: LLM timeout atau error**
```
Cek:
- Apakah Ollama berjalan? curl http://localhost:11434/api/tags
- Apakah model tersedia? ollama list
- Cek log worker: docker compose logs -f worker | grep ERROR
- Coba model yang lebih kecil: ganti llm_model ke "qwen2.5-coder:7b"
```

---

### Setelah Smoke Test: Apa yang Diperbaiki

Smoke test akan mengungkap beberapa hal yang tidak terdeteksi unit test.  
Catat semua masalah, lalu prioritaskan berdasarkan:

```
P1 — Blocking (agent tidak bisa selesai):
  - Tools not found di container
  - LLM timeout/error
  - Internal API tidak bisa persist findings
  - WebSocket tidak terhubung

P2 — Degraded (agent selesai tapi kurang optimal):
  - LLM plan terlalu generic
  - RAG tidak return relevant results
  - Findings kurang, false positive banyak
  - Report kurang detail

P3 — Polish (berjalan tapi UI kurang nyaman):
  - Live Feed formatting
  - Error messages tidak jelas
  - Loading states tidak ada
  - Edge cases di HITL dialog
```

---

## Prompt untuk Copilot

Gunakan prompt ini untuk mulai Sprint 12:

```
Baca CLAUDE.md, PROGRESS.md, dan SPRINT-12-SMOKETEST.md secara lengkap.

Kita akan menyelesaikan Sprint 12 — menutup loop agent ke browser.

Mulai dari Task 12.1:
1. Buat apps/api/app/core/ws_manager.py dengan class WebSocketManager
2. Buat apps/api/app/core/redis_bridge.py dengan start_redis_bridge()
3. Update apps/api/app/main.py untuk jalankan bridge di lifespan startup
4. Buat apps/api/tests/test_ws_manager.py dengan 4 tests
5. Jalankan tests dan pastikan pass

Ikuti konvensi di CLAUDE.md. Jangan mulai Task 12.2 sebelum Task 12.1 selesai.
```

Setelah Sprint 12 selesai, lanjut dengan smoke test:

```
Sprint 12 semua tasks selesai dan tests pass.
Sekarang bantu saya menjalankan smoke test dari SPRINT-12-SMOKETEST.md Bagian 2.
Mulai dari ST-01 — setup admin dan dapatkan token.
Target: testphp.vulnweb.com
```

---

*SPRINT-12-SMOKETEST.md — Pentra AI*  
*Dokumen eksekusi terakhir: menutup loop browser → agent → findings → browser*  
*Setelah ini selesai: Pentra AI siap digunakan untuk real bug bounty engagement*
