import { useEffect, useRef, useState } from "react";
import type { FeedEvent, ApprovalRequest } from "../lib/types";
import { useAuthStore } from "../lib/authStore";
import { addNotification } from "./useNotifications";

const _apiUrl = import.meta.env.VITE_API_URL ?? "http://localhost:8001";
const WS_URL = import.meta.env.VITE_WS_URL ?? _apiUrl.replace(/^http/, "ws");
const MAX_EVENTS = 500;

function processEvent(
  event: FeedEvent,
  setEvents: React.Dispatch<React.SetStateAction<FeedEvent[]>>,
  setPendingApproval: React.Dispatch<React.SetStateAction<ApprovalRequest | null>>,
  engagementId?: string,
) {
  if (event.type === "AWAITING_APPROVAL" && event.data) {
    setPendingApproval(event.data as unknown as ApprovalRequest);
    const phase = (event.data as Record<string, unknown>)["phase"] as string | undefined;
    addNotification({
      type: "AWAITING_APPROVAL",
      title: "Approval Required",
      description: phase,
      engagementId,
    });
  }
  if (event.type === "FINDINGS_UPDATED") {
    const count = event.count ?? 0;
    addNotification({
      type: "FINDING_CONFIRMED",
      title: "New Findings",
      description: `${count} finding(s) discovered`,
      engagementId,
    });
  }
  if (event.type === "ENGAGEMENT_COMPLETED") {
    addNotification({
      type: "ENGAGEMENT_COMPLETED",
      title: "Engagement Complete",
      engagementId,
    });
  }
  if (event.type === "error") {
    addNotification({
      type: "AGENT_ERROR",
      title: "Agent Error",
      description: event.message,
      engagementId,
    });
  }
  if (event.type === "subscan_started") {
    const target = (event.data as Record<string, unknown>)?.["target"] as string | undefined;
    addNotification({
      type: "FINDING_CONFIRMED",
      title: "Subscan Started",
      description: target ? `Scanning ${target}` : "Subscan running…",
      engagementId,
    });
  }
  if (event.type === "subscan_complete") {
    const found = (event.data as Record<string, unknown>)?.["findings_count"] as number | undefined;
    addNotification({
      type: "ENGAGEMENT_COMPLETED",
      title: "Subscan Complete",
      description: found !== undefined ? `${found} finding(s) found` : "Subscan finished",
      engagementId,
    });
  }
  if (event.type === "subscan_error") {
    addNotification({
      type: "AGENT_ERROR",
      title: "Subscan Failed",
      description: event.message ?? "Subscan encountered an error",
      engagementId,
    });
  }
  if (event.type !== "ping") {
    setEvents((prev) => [event, ...prev].slice(0, MAX_EVENTS));
  }
}

export function useEngagementFeed(engagementId: string | undefined) {
  const [events, setEvents] = useState<FeedEvent[]>([]);
  const [pendingApproval, setPendingApproval] = useState<ApprovalRequest | null>(null);
  const [connected, setConnected] = useState(false);
  // Task 19.4: agent status restored from history on mount
  const [agentStatus, setAgentStatus] = useState<"idle" | "running" | "waiting" | "completed">("idle");
  const wsRef = useRef<WebSocket | null>(null);
  // Track which engagement's history we've already loaded to avoid duplicate fetch
  const loadedRef = useRef<string | null>(null);
  const accessToken = useAuthStore((s) => s.accessToken);

  useEffect(() => {
    if (!engagementId) return;
    if (!accessToken) return;

    // Reset state when engagement changes
    // eslint-disable-next-line react-hooks/set-state-in-effect
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
        // Task 19.4: restore agent status from last event
        const lastEvent = history[history.length - 1];
        if (lastEvent) {
          if (lastEvent.type === "ENGAGEMENT_COMPLETED") setAgentStatus("completed");
          else if (lastEvent.type === "AWAITING_APPROVAL") setAgentStatus("waiting");
          else if (lastEvent.type === "NODE_START" || lastEvent.type === "NODE_COMPLETE") setAgentStatus("running");
        }
        loadedRef.current = engagementId;
      })
      .catch(() => { /* non-fatal */ });

    const wsTokenParam = accessToken ? `?token=${encodeURIComponent(accessToken)}` : "";
    const ws = new WebSocket(`${WS_URL}/api/v1/ws/engagements/${engagementId}/feed${wsTokenParam}`);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);

    ws.onmessage = (e) => {
      try {
        const event: FeedEvent = JSON.parse(e.data);
        // Skip replayed events that are already loaded via REST to avoid duplicates
        if (loadedRef.current === engagementId) {
          processEvent(event, setEvents, setPendingApproval, engagementId);
        } else {
          // REST hasn't returned yet — accept WS events (incl. replay) as-is
          processEvent(event, setEvents, setPendingApproval, engagementId);
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

  return { events, pendingApproval, connected, agentStatus, clearApproval };
}
