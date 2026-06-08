import { useEffect, useRef, useState } from "react";
import type { FeedEvent, ApprovalRequest } from "../lib/types";
import { useAuthStore } from "../lib/authStore";

const _apiUrl = import.meta.env.VITE_API_URL ?? "http://localhost:8001";
const WS_URL = import.meta.env.VITE_WS_URL ?? _apiUrl.replace(/^http/, "ws");
const MAX_EVENTS = 500;

function processEvent(
  event: FeedEvent,
  setEvents: React.Dispatch<React.SetStateAction<FeedEvent[]>>,
  setPendingApproval: React.Dispatch<React.SetStateAction<ApprovalRequest | null>>,
) {
  if (event.type === "AWAITING_APPROVAL" && event.data) {
    setPendingApproval(event.data as unknown as ApprovalRequest);
  }
  if (event.type !== "ping") {
    setEvents((prev) => [event, ...prev].slice(0, MAX_EVENTS));
  }
}

export function useEngagementFeed(engagementId: string | undefined) {
  const [events, setEvents] = useState<FeedEvent[]>([]);
  const [pendingApproval, setPendingApproval] = useState<ApprovalRequest | null>(null);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  // Track which engagement's history we've already loaded to avoid duplicate fetch
  const loadedRef = useRef<string | null>(null);
  const accessToken = useAuthStore((s) => s.accessToken);

  useEffect(() => {
    if (!engagementId) return;

    // Reset state when engagement changes
    setEvents([]);
    setPendingApproval(null);
    setConnected(false);
    loadedRef.current = null;

    // Fetch buffered history from REST endpoint (survives WS reconnects).
    // The WS will also replay the buffer on connect, but REST is faster on
    // initial load and avoids a flash of "Waiting for agent events...".
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (accessToken) headers["Authorization"] = `Bearer ${accessToken}`;

    fetch(`${_apiUrl}/api/v1/engagements/${engagementId}/events`, { headers })
      .then((r) => r.ok ? r.json() : [])
      .then((history: FeedEvent[]) => {
        if (!Array.isArray(history) || history.length === 0) return;
        // History arrives oldest-first; display newest-first
        const sorted = [...history].reverse().slice(0, MAX_EVENTS);
        setEvents(sorted);
        // Restore last pending approval if any
        const last = sorted.find((e) => e.type === "AWAITING_APPROVAL" && e.data);
        if (last) setPendingApproval(last.data as unknown as ApprovalRequest);
        loadedRef.current = engagementId;
      })
      .catch(() => { /* non-fatal */ });

    const ws = new WebSocket(`${WS_URL}/api/v1/ws/engagements/${engagementId}/feed`);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);

    ws.onmessage = (e) => {
      try {
        const event: FeedEvent = JSON.parse(e.data);
        // Skip replayed events that are already loaded via REST to avoid duplicates
        if (loadedRef.current === engagementId) {
          processEvent(event, setEvents, setPendingApproval);
        } else {
          // REST hasn't returned yet — accept WS events (incl. replay) as-is
          processEvent(event, setEvents, setPendingApproval);
        }
      } catch {
        // ignore malformed frames
      }
    };

    ws.onclose = () => setConnected(false);
    ws.onerror = () => setConnected(false);

    return () => {
      ws.close();
      wsRef.current = null;
    };
  }, [engagementId, accessToken]);

  const clearApproval = () => setPendingApproval(null);

  return { events, pendingApproval, connected, clearApproval };
}
