---
applyTo: "apps/web/**"
---

# Frontend — Copilot Instructions

You are working inside `apps/web/` — React 18 + Vite 5 + Tailwind + Shadcn/ui.

## Component Rules

- All components: TypeScript strict, explicit `interface` for props
- File naming: `PascalCase.tsx` for components, `camelCase.ts` for utilities
- Export: named exports (not default) unless it's a page component
- State: local `useState` for UI state, Zustand for global app state
- No prop drilling beyond 2 levels — use Zustand store or context

## WebSocket Hook Pattern

```typescript
// hooks/useEngagementFeed.ts
export function useEngagementFeed(engagementId: string) {
  const [events, setEvents] = useState<FeedEvent[]>([]);
  const [pendingApproval, setPendingApproval] = useState<ApprovalRequest | null>(null);

  useEffect(() => {
    const ws = new WebSocket(
      `${import.meta.env.VITE_WS_URL}/ws/engagements/${engagementId}/feed?token=${getToken()}`
    );

    ws.onmessage = (e) => {
      const event: FeedEvent = JSON.parse(e.data);
      if (event.type === "AWAITING_APPROVAL") {
        setPendingApproval(event.data);
      }
      setEvents(prev => [event, ...prev].slice(0, 500)); // keep last 500
    };

    return () => ws.close();
  }, [engagementId]);

  return { events, pendingApproval };
}
```

## API Client Pattern

```typescript
// lib/api.ts — use TanStack Query for all REST calls
export const useFindings = (engagementId: string) =>
  useQuery({
    queryKey: ["findings", engagementId],
    queryFn: () => apiClient.get<Finding[]>(`/engagements/${engagementId}/findings`),
  });

export const useApproveAction = (engagementId: string) =>
  useMutation({
    mutationFn: (decision: "approve" | "skip" | "modify") =>
      apiClient.post(`/engagements/${engagementId}/approve`, { action: decision }),
  });
```

## Severity Color Convention

```typescript
const SEVERITY_COLORS = {
  critical: "text-red-500 bg-red-500/10 border-red-500/20",
  high:     "text-orange-500 bg-orange-500/10 border-orange-500/20",
  medium:   "text-yellow-500 bg-yellow-500/10 border-yellow-500/20",
  low:      "text-blue-500 bg-blue-500/10 border-blue-500/20",
  info:     "text-slate-400 bg-slate-400/10 border-slate-400/20",
} as const;
```

## Dark Mode

All components must work in dark mode. Use `dark:` prefix for dark variants.
Default: `className="bg-background text-foreground"` (Shadcn CSS variables).
Never hardcode `bg-white` or `text-black`.

## Live Feed Component

The Live Feed is the most critical UI component.
It displays streaming agent logs with HITL approval prompts.
Must handle: rapid event streaming (50+ events/minute), approval UI overlay,
pause/resume controls, and scroll-to-bottom with manual scroll override.
