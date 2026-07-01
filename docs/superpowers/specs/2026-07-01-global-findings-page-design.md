# Global Findings Page — Design Spec
**Date:** 2026-07-01
**Status:** Approved

---

## 1. Problem

Clicking "Total Findings" on the Dashboard navigates to `/engagements` — a list of engagements, not findings. There is no dedicated view for browsing, filtering, and triaging findings across all engagements. Users must click into each engagement separately to see its findings.

---

## 2. Goal

A top-level `/findings` page that shows every finding across all engagements, filterable by severity, status, vuln class, engagement, and date range, with column sorting and pagination. Follows the pattern of Cobalt.io, Tenable.io, and HackerOne.

---

## 3. Architecture Overview

```
Dashboard
  └─ "Total Findings" StatCard  →  navigate("/findings")
  └─ FindingRow click            →  navigate("/findings?engagement_id={id}")

AppShell sidebar
  Dashboard → Engagements → [Findings ← NEW] → Knowledge Base → ...

Routes (App.tsx)
  /findings   →   FindingsPage.tsx   [NEW]

Backend (router.py)
  GET /findings   [NEW — filters + pagination]
  GET /findings/recent   [KEEP — dashboard summary only]
```

---

## 4. Backend Changes

### 4.1 New Schema: `FindingWithEngagementResponse`

File: `apps/api/app/api/schemas.py`

```python
class FindingWithEngagementResponse(FindingResponse):
    engagement_name: str
```

Extends the existing `FindingResponse` (19 fields) by adding `engagement_name` from a JOIN — no N+1 queries.

### 4.2 New Schema: `PaginatedFindingsResponse`

```python
class PaginatedFindingsResponse(BaseModel):
    results: list[FindingWithEngagementResponse]
    total: int
    page: int
    page_size: int
```

### 4.3 New Endpoint: `GET /findings`

File: `apps/api/app/api/router.py`

```python
@router.get("/findings", response_model=PaginatedFindingsResponse)
async def list_all_findings(
    severity: list[str] | None = Query(default=None),
    status: list[str] | None = Query(default=None),
    vuln_class: list[str] | None = Query(default=None),
    engagement_id: UUID | None = Query(default=None),
    discovered_after: datetime | None = Query(default=None),
    discovered_before: datetime | None = Query(default=None),
    sort_by: str = Query(default="discovered_at", pattern="^(discovered_at|severity|cvss_score|title)$"),
    sort_dir: str = Query(default="desc", pattern="^(asc|desc)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> PaginatedFindingsResponse
```

**Query logic:**
1. JOIN `findings → engagements → workspaces`
2. Non-admin users: `WHERE workspaces.owner_id = current_user.id`
3. Apply all filters with `AND` semantics
4. `severity` sort uses a CASE expression: critical=0, high=1, medium=2, low=3, info=4
5. COUNT(*) with same WHERE clause for `total` (single extra query)
6. OFFSET/LIMIT for pagination: `offset = (page - 1) * page_size`

**Important:** This endpoint is placed **before** the existing `GET /findings/recent` in the router file to avoid the `/findings/{finding_id}` catch-all route matching "recent".

---

## 5. Frontend Changes

### 5.1 Sidebar Nav (`apps/web/src/components/AppShell.tsx`)

Add to `NAV_ITEMS` between Engagements and Knowledge Base:

```typescript
{ to: "/findings", label: "Findings", icon: <Bug className="h-4 w-4" /> },
```

Import `Bug` from `lucide-react`.

### 5.2 Route (`apps/web/src/App.tsx`)

```tsx
<Route path="/findings" element={<FindingsPage />} />
```

Place alongside the `/engagements` routes inside the `ProtectedRoute`/`AppShell` wrapper.

### 5.3 Dashboard navigation (`apps/web/src/pages/DashboardPage.tsx`)

Change the `StatCard` onClick:
```tsx
// Before:
onClick={() => navigate("/engagements")}
// After:
onClick={() => navigate("/findings")}
```

Dashboard `FindingRow` clicks: change to navigate to `/findings?engagement_id={finding.engagement_id}` so the findings page opens pre-filtered to that engagement.

### 5.4 New API types (`apps/web/src/lib/types.ts`)

```typescript
export interface FindingWithEngagement extends Finding {
  engagement_name: string;
}

export interface PaginatedFindings {
  results: FindingWithEngagement[];
  total: number;
  page: number;
  page_size: number;
}

export interface FindingFilters {
  severity: Severity[];
  status: FindingStatus[];
  vuln_class: string[];
  engagement_id: string | null;
  discovered_after: string | null;   // ISO date string YYYY-MM-DD
  discovered_before: string | null;
}
```

### 5.5 New API hook (`apps/web/src/lib/api.ts`)

```typescript
export function useAllFindings(
  filters: FindingFilters,
  sortBy: string,
  sortDir: "asc" | "desc",
  page: number,
  pageSize = 25,
) {
  return useQuery<PaginatedFindings>({
    queryKey: ["findings", "all", filters, sortBy, sortDir, page],
    queryFn: () => fetchAllFindings(filters, sortBy, sortDir, page, pageSize),
    staleTime: 15_000,
    placeholderData: keepPreviousData,  // no flicker on page/filter changes
  });
}
```

`fetchAllFindings` builds URLSearchParams and calls `GET /findings`.

### 5.6 FindingsTable adaptation (`apps/web/src/components/findings/FindingsTable.tsx`)

Two changes only:

1. Make `engagementId` optional:
   ```typescript
   interface FindingsTableProps {
     engagementId?: string;           // optional — omit for global view
     findings: Finding[] | FindingWithEngagement[];
     showEngagementColumn?: boolean;  // default false
   }
   ```

2. When `showEngagementColumn` is true, add an **Engagement** column after the Status column — displays `finding.engagement_name` as a link to `/engagements/{finding.engagement_id}`.

3. Status patch and KB submit actions derive `engagementId` from `prop.engagementId ?? finding.engagement_id`.

### 5.7 New Page: `apps/web/src/pages/FindingsPage.tsx`

**Three-zone layout** (matches existing KnowledgeBrowser pattern for consistency):

```
┌─ header (fixed, border-b) ──────────────────────────────────┐
│ [Bug] All Findings   87 total  ●12 crit  ●8 high  ●5 med   │
├─ sidebar (240px, overflow-y-auto) ─┬─ main (flex-1) ────────┤
│ SEVERITY                           │ [table + pagination]    │
│  ● Critical (12)                   │                         │
│  ● High (8)                        │                         │
│  ● Medium (5)  ← toggle chips      │                         │
│  ● Low (2)                         │                         │
│  ● Info (0)                        │                         │
│                                    │                         │
│ STATUS                             │                         │
│  open  confirmed  false_positive   │                         │
│                                    │                         │
│ VULN CLASS                         │                         │
│  [select ▾ searchable]             │                         │
│                                    │                         │
│ ENGAGEMENT                         │                         │
│  [select ▾]                        │                         │
│                                    │                         │
│ DATE RANGE                         │                         │
│  From [date input]                 │                         │
│  To   [date input]                 │                         │
│                                    │                         │
│ [Clear all filters]                │                         │
└────────────────────────────────────┴─────────────────────────┘
```

**Header bar:** Title, total count badge, colored severity chips (Critical N · High N · Medium N · Low N) — clicking a chip toggles that severity filter.

**Filter sidebar:** Uses the same pentra design tokens as FilterPanel in KnowledgeBrowser. All filter changes are reflected in URL query params so the view is linkable/bookmarkable.

**URL sync:** Filters and page are kept in sync with `URLSearchParams` via `useSearchParams()`. Loading the URL `/findings?severity=critical&severity=high&page=2` restores the filter state instantly.

**Main content:**
- `FindingsTable` with `showEngagementColumn={true}`, no `engagementId` prop
- Column headers are clickable for sort (severity, title, cvss_score, discovered_at)
- Footer: "Showing 26–50 of 87 findings" + Prev / Next buttons

**Loading state:** `placeholderData: keepPreviousData` in TanStack Query means the old results stay visible while the new page/filter loads — no flicker.

**Empty state:** If no findings match filters, show a centered "No findings match your filters" message with a "Clear filters" button.

**Error state:** Inline error message with retry button (same pattern as KnowledgeBrowser).

---

## 6. Severity Sort Order

For the `sort_by=severity` case, the backend uses a SQL CASE expression so "critical" sorts first in desc order:

```sql
CASE severity
  WHEN 'critical' THEN 0
  WHEN 'high'     THEN 1
  WHEN 'medium'   THEN 2
  WHEN 'low'      THEN 3
  WHEN 'info'     THEN 4
  ELSE 5
END ASC  -- (reversed when sort_dir=desc)
```

---

## 7. File Change Summary

| File | Change |
|------|--------|
| `apps/api/app/api/schemas.py` | Add `FindingWithEngagementResponse`, `PaginatedFindingsResponse` |
| `apps/api/app/api/router.py` | Add `GET /findings` endpoint (before `/findings/recent`) |
| `apps/web/src/lib/types.ts` | Add `FindingWithEngagement`, `PaginatedFindings`, `FindingFilters` |
| `apps/web/src/lib/api.ts` | Add `fetchAllFindings()`, `useAllFindings()` |
| `apps/web/src/components/AppShell.tsx` | Add "Findings" nav item, import Bug icon |
| `apps/web/src/App.tsx` | Add `/findings` route |
| `apps/web/src/pages/DashboardPage.tsx` | Change StatCard onClick + FindingRow navigation |
| `apps/web/src/pages/FindingsPage.tsx` | NEW — full page implementation |
| `apps/web/src/components/findings/FindingsTable.tsx` | Make `engagementId` optional, add engagement column |

---

## 8. Out of Scope

- Export to CSV/PDF (future sprint)
- Bulk status update (future sprint)
- Saved filter presets (future sprint)
- Push notifications for new findings (already handled by existing WebSocket feed)
