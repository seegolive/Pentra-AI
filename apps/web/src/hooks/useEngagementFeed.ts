import { useEffect, useRef, useState } from "react";
import type { FeedEvent, ApprovalRequest } from "../lib/types";

const WS_URL = import.meta.env.VITE_WS_URL ?? "ws://localhost:8000";
const MAX_EVENTS = 500;

export function useEngagementFeed(engagementId: string | undefined) {
  const [events, setEvents] = useState<FeedEvent[]>([]);
  const [pendingApproval, setPendingApproval] = useState<ApprovalRequest | null>(null);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!engagementId) return;

    const ws = new WebSocket(`${WS_URL}/ws/engagements/${engagementId}/feed?token=dev`);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);

    ws.onmessage = (e) => {
      try {
        const event: FeedEvent = JSON.parse(e.data);
        if (event.type === "AWAITING_APPROVAL" && event.data) {
          setPendingApproval(event.data as unknown as ApprovalRequest);
        }
        if (event.type !== "ping") {
          setEvents((prev) => [event, ...prev].slice(0, MAX_EVENTS));
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
  }, [engagementId]);

  const clearApproval = () => setPendingApproval(null);

  return { events, pendingApproval, connected, clearApproval };
}
