# Global Findings Page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `/findings` top-level page that shows every finding across all engagements, filterable by severity, status, vuln class, engagement, and date range, with column sorting and pagination.

**Architecture:** Backend adds `GET /api/v1/findings` with a JOIN-based query (findings → engagements → workspaces) plus filter/sort/pagination; frontend wires a new `FindingsPage` using an adapted `FindingsTable` (optional engagementId + engagement column), a three-zone layout (header summary chips + filter sidebar + paginated table), and URL-synced filter state via `useSearchParams`.

**Tech Stack:** FastAPI + SQLAlchemy 2 async, React 18 + TanStack Query v5, `useSearchParams`, lucide-react, Tailwind CSS, Shadcn/ui patterns

## Global Constraints

- Every SQLAlchemy call uses `await` — no sync DB calls
- No raw SQL: SQLAlchemy ORM/Core expressions only
- New `GET /findings` route MUST be placed BEFORE `GET /findings/recent` in `router.py` (line 652) to avoid catch-all matching
- `FindingsTable.tsx` changes must not break existing usage in `EngagementDetailPage` (currently passes `engagementId: string`)
- TypeScript strict mode — no implicit `any`
- Tailwind utility classes only — no new CSS files
- `FindingWithEngagementResponse` adds one field to `FindingResponse`; no DB migrations needed (comes from JOIN)

---

### Task 1: Backend schemas

**Files:**
- Modify: `apps/api/app/api/schemas.py` (after line 147, after `FindingResponse`)

**Interfaces:**
- Consumes: existing `FindingResponse` (lines 123–146 of schemas.py)
- Produces: `FindingWithEngagementResponse`, `PaginatedFindingsResponse` (used in Task 2)

- [ ] **Step 1: Add the two new schemas after `FindingResponse`**

Open `apps/api/app/api/schemas.py`. After the closing of `FindingResponse` (after line 146, before `FindingExport`), insert:

```python
class FindingWithEngagementResponse(FindingResponse):
    engagement_name: str


class PaginatedFindingsResponse(BaseModel):
    results: list[FindingWithEngagementResponse]
    total: int
    page: int
    page_size: int
```

- [ ] **Step 2: Verify the file parses**

```bash
cd apps/api
uv run python -c "from app.api.schemas import FindingWithEngagementResponse, PaginatedFindingsResponse; print('OK')"
```

Expected output: `OK`

- [ ] **Step 3: Commit**

```bash
git add apps/api/app/api/schemas.py
git commit -m "feat(api): add FindingWithEngagementResponse and PaginatedFindingsResponse schemas"
```

---

### Task 2: Backend endpoint `GET /findings`

**Files:**
- Modify: `apps/api/app/api/router.py` (add imports + new endpoint before line 652)

**Interfaces:**
- Consumes: `FindingWithEngagementResponse`, `PaginatedFindingsResponse` from Task 1
- Consumes: `FindingORM`, `EngagementORM`, `WorkspaceORM` (already imported in router.py)
- Produces: `GET /api/v1/findings` with query params: `severity[]`, `status[]`, `vuln_class[]`, `engagement_id`, `discovered_after`, `discovered_before`, `sort_by`, `sort_dir`, `page`, `page_size`

- [ ] **Step 1: Write a failing test**

Create `apps/api/tests/test_findings_global.py`:

```python
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_list_all_findings_requires_auth(client: AsyncClient):
    resp = await client.get("/api/v1/findings")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_list_all_findings_returns_paginated(auth_client: AsyncClient, sample_finding):
    resp = await auth_client.get("/api/v1/findings?page=1&page_size=10")
    assert resp.status_code == 200
    data = resp.json()
    assert "results" in data
    assert "total" in data
    assert "page" in data
    assert "page_size" in data
    assert isinstance(data["results"], list)


@pytest.mark.asyncio
async def test_list_all_findings_filter_severity(auth_client: AsyncClient, sample_finding):
    resp = await auth_client.get("/api/v1/findings?severity=critical")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_list_all_findings_invalid_sort_by(auth_client: AsyncClient):
    resp = await auth_client.get("/api/v1/findings?sort_by=invalid_field")
    assert resp.status_code == 422
```

- [ ] **Step 2: Run to confirm failure**

```bash
cd apps/api
uv run pytest tests/test_findings_global.py -v 2>&1 | head -30
```

Expected: FAILED (endpoint does not exist yet → 404 or import error)

- [ ] **Step 3: Add imports to router.py**

At line 29 in `apps/api/app/api/router.py`, extend the sqlalchemy import:

```python
from sqlalchemy import and_, case, func, select
```

(replace the existing `from sqlalchemy import select` line)

In the schemas import block (lines 32–55), add `FindingWithEngagementResponse` and `PaginatedFindingsResponse`:

```python
from app.api.schemas import (
    EngagementCreate,
    EngagementExportBundle,
    EngagementImportRequest,
    EngagementResponse,
    FindingExport,
    FindingPatch,
    FindingResponse,
    FindingWithEngagementResponse,   # NEW
    HitlDecision,
    KBManualInjectRequest,
    KBUrlInjectRequest,
    KnowledgeInjectRequest,
    KnowledgeInjectResponse,
    PaginatedFindingsResponse,        # NEW
    PayloadGenerateAPIRequest,
    PayloadGenerateAPIResponse,
    PayloadItem,
    ReconStateResponse,
    SubdomainInfo,
    PortInfo,
    EndpointInfo,
    SubscanRequest,
    WorkspaceCreate,
    WorkspaceResponse,
)
```

- [ ] **Step 4: Add the endpoint**

In `router.py`, immediately before the line `@router.get("/findings/recent", ...)` (currently at line 652), insert the following block:

```python
# ── Global findings list (ALL engagements) ─────────────────────────────────────

@router.get(
    "/findings",
    response_model=PaginatedFindingsResponse,
    summary="List all findings (global)",
    description="Return paginated findings across all engagements the user can access.",
)
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
) -> PaginatedFindingsResponse:
    severity_case = case(
        (FindingORM.severity == "critical", 0),
        (FindingORM.severity == "high", 1),
        (FindingORM.severity == "medium", 2),
        (FindingORM.severity == "low", 3),
        (FindingORM.severity == "info", 4),
        else_=5,
    )

    base = (
        select(FindingORM, EngagementORM.name.label("engagement_name"))
        .join(EngagementORM, FindingORM.engagement_id == EngagementORM.id)
        .join(WorkspaceORM, EngagementORM.workspace_id == WorkspaceORM.id)
        .where(WorkspaceORM.owner_id == current_user.id)
    )

    if severity:
        base = base.where(FindingORM.severity.in_(severity))
    if status:
        base = base.where(FindingORM.status.in_(status))
    if vuln_class:
        base = base.where(FindingORM.vuln_class.in_(vuln_class))
    if engagement_id:
        base = base.where(FindingORM.engagement_id == engagement_id)
    if discovered_after:
        base = base.where(FindingORM.discovered_at >= discovered_after)
    if discovered_before:
        base = base.where(FindingORM.discovered_at <= discovered_before)

    count_result = await db.execute(select(func.count()).select_from(base.subquery()))
    total = count_result.scalar_one()

    if sort_by == "severity":
        order_col = severity_case if sort_dir == "desc" else severity_case.desc()
    elif sort_by == "cvss_score":
        col = FindingORM.cvss_score
        order_col = col.asc() if sort_dir == "asc" else col.desc()
    elif sort_by == "title":
        col = FindingORM.title
        order_col = col.asc() if sort_dir == "asc" else col.desc()
    else:
        col = FindingORM.discovered_at
        order_col = col.asc() if sort_dir == "asc" else col.desc()

    rows_result = await db.execute(
        base.order_by(order_col).offset((page - 1) * page_size).limit(page_size)
    )

    results = []
    for row in rows_result:
        finding_orm, eng_name = row[0], row[1]
        data = FindingResponse.model_validate(finding_orm).model_dump()
        data["engagement_name"] = eng_name
        results.append(FindingWithEngagementResponse(**data))

    return PaginatedFindingsResponse(
        results=results,
        total=total,
        page=page,
        page_size=page_size,
    )

```

- [ ] **Step 5: Run tests to confirm they pass**

```bash
cd apps/api
uv run pytest tests/test_findings_global.py -v
```

Expected: `test_list_all_findings_requires_auth` PASS, `test_list_all_findings_invalid_sort_by` PASS. The other two need fixture setup — they may skip/fail if fixtures are missing; confirm the endpoint returns 200 by testing manually:

```bash
# In another terminal, with the API running:
curl -s "http://localhost:8002/api/v1/findings?page=1&page_size=5" \
  -H "Authorization: Bearer <token>" | python3 -m json.tool | head -30
```

Expected: JSON with `results`, `total`, `page`, `page_size`.

- [ ] **Step 6: Commit**

```bash
git add apps/api/app/api/router.py apps/api/tests/test_findings_global.py
git commit -m "feat(api): add GET /findings endpoint with filter/sort/pagination"
```

---

### Task 3: Frontend types + API hook

**Files:**
- Modify: `apps/web/src/lib/types.ts` (add after Finding interface, ~line 210)
- Modify: `apps/web/src/lib/api.ts` (add after `usePatchFinding`, ~line 337)

**Interfaces:**
- Consumes: `Finding`, `Severity`, `FindingStatus` from `types.ts`
- Produces: `FindingWithEngagement`, `PaginatedFindings`, `FindingFilters` (used in Tasks 4 & 6), `useAllFindings` hook (used in Task 6)

- [ ] **Step 1: Add types to types.ts**

Open `apps/web/src/lib/types.ts`. After the `Finding` interface (find the closing `}` of the `Finding` interface, after the `chains` field), add:

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
  discovered_after: string | null;
  discovered_before: string | null;
}
```

- [ ] **Step 2: Add fetch function and hook to api.ts**

Open `apps/web/src/lib/api.ts`. At the top of the file, verify `keepPreviousData` is imported from `@tanstack/react-query`. If not, add it to the existing import:

```typescript
import {
  useQuery,
  useMutation,
  useQueryClient,
  keepPreviousData,
} from "@tanstack/react-query";
```

After the `usePatchFinding` export (around line 337), add:

```typescript
// ── Global findings (all engagements) ────────────────────────────────────────

async function fetchAllFindings(
  filters: FindingFilters,
  sortBy: string,
  sortDir: "asc" | "desc",
  page: number,
  pageSize: number,
): Promise<PaginatedFindings> {
  const qp = new URLSearchParams();
  filters.severity.forEach((s) => qp.append("severity", s));
  filters.status.forEach((s) => qp.append("status", s));
  filters.vuln_class.forEach((v) => qp.append("vuln_class", v));
  if (filters.engagement_id) qp.set("engagement_id", filters.engagement_id);
  if (filters.discovered_after) qp.set("discovered_after", filters.discovered_after);
  if (filters.discovered_before) qp.set("discovered_before", filters.discovered_before);
  qp.set("sort_by", sortBy);
  qp.set("sort_dir", sortDir);
  qp.set("page", String(page));
  qp.set("page_size", String(pageSize));
  const res = await apiClient.get<PaginatedFindings>(`/api/v1/findings?${qp.toString()}`);
  return res.data;
}

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
    placeholderData: keepPreviousData,
  });
}
```

Also add the type imports at the top of the api.ts imports block (find the `import type { ... } from "./types"` line and add the new types):

```typescript
import type {
  Finding,
  FindingFilters,
  FindingStatus,
  FindingWithEngagement,
  PaginatedFindings,
  // ... existing imports
} from "./types";
```

- [ ] **Step 3: Type-check**

```bash
cd apps/web
pnpm type-check 2>&1 | head -40
```

Expected: no errors related to the new types. Fix any import errors before proceeding.

- [ ] **Step 4: Commit**

```bash
git add apps/web/src/lib/types.ts apps/web/src/lib/api.ts
git commit -m "feat(web): add FindingWithEngagement types and useAllFindings hook"
```

---

### Task 4: Adapt FindingsTable for global view

**Files:**
- Modify: `apps/web/src/components/findings/FindingsTable.tsx`

**Interfaces:**
- Consumes: `FindingWithEngagement` from `types.ts` (Task 3)
- Produces: updated `FindingsTable` component with `engagementId?: string` and `showEngagementColumn?: boolean` (used in Task 6)

- [ ] **Step 1: Update the props interface (line 34–37)**

Replace:
```typescript
interface FindingsTableProps {
  engagementId: string;
  findings: Finding[];
}
```

With:
```typescript
interface FindingsTableProps {
  engagementId?: string;
  findings: Finding[] | FindingWithEngagement[];
  showEngagementColumn?: boolean;
}
```

Also update the import to include `FindingWithEngagement`:
```typescript
import type {
  Finding,
  FindingWithEngagement,
  FindingStatus,
  Severity,
} from "../../lib/types";
```

- [ ] **Step 2: Thread engagementId through StatusSelect**

The `StatusSelect` sub-component currently receives `engagementId: string`. Make it accept `string` (not optional) — but compute the value at call site from the resolved prop.

In `FindingsTable` main component (line 518), update the signature and compute effective engagement ID per finding:

Change the function signature:
```typescript
export function FindingsTable({
  engagementId,
  findings,
  showEngagementColumn = false,
}: FindingsTableProps) {
```

Then in the render loop where `StatusSelect` is called (around line 694), pass the resolved ID:

```tsx
<StatusSelect
  finding={finding}
  engagementId={engagementId ?? (finding as FindingWithEngagement).engagement_id ?? ""}
/>
```

- [ ] **Step 3: Add Engagement column to table header**

In the `<thead>` section (around line 613), after the existing `<Th field="status" ...>Status</Th>`, add:

```tsx
{showEngagementColumn && (
  <th className="px-3 py-2 text-left text-[11px] font-medium text-muted-foreground whitespace-nowrap w-40">
    Engagement
  </th>
)}
```

Also add `Link` import from `react-router-dom` at the top of the file:
```typescript
import { Link } from "react-router-dom";
```

- [ ] **Step 4: Add Engagement column to table body**

In the `<tbody>` row section, after the `<td>` containing `<StatusSelect>` (around line 693–699), add:

```tsx
{showEngagementColumn && (
  <td
    className="px-3 py-2"
    onClick={(e) => e.stopPropagation()}
  >
    <Link
      to={`/engagements/${(finding as FindingWithEngagement).engagement_id}`}
      className="text-xs text-primary hover:underline truncate max-w-[140px] block"
    >
      {(finding as FindingWithEngagement).engagement_name ?? "—"}
    </Link>
  </td>
)}
```

Also update the `colSpan` on expanded detail rows from `6` to `{showEngagementColumn ? 7 : 6}` (there are three such rows: detail, KB, payload panels).

- [ ] **Step 5: Type-check and verify existing usage still works**

```bash
cd apps/web
pnpm type-check 2>&1 | grep -i findingstable
```

Expected: no errors. The existing `EngagementDetailPage` calls `<FindingsTable engagementId={id} findings={data} />` — this still works because `engagementId` is now optional (string | undefined), and `showEngagementColumn` defaults to false.

- [ ] **Step 6: Commit**

```bash
git add apps/web/src/components/findings/FindingsTable.tsx
git commit -m "feat(web): make FindingsTable engagementId optional, add showEngagementColumn"
```

---

### Task 5: Wire routing, nav, and dashboard navigation

**Files:**
- Modify: `apps/web/src/components/AppShell.tsx`
- Modify: `apps/web/src/App.tsx`
- Modify: `apps/web/src/pages/DashboardPage.tsx`

**Interfaces:**
- Consumes: `FindingsPage` component (created in Task 6 — but import can be added now as it'll exist by the time the app boots)
- Produces: `/findings` route, sidebar nav item, corrected dashboard navigation

- [ ] **Step 1: Add Bug import and Findings nav item to AppShell.tsx**

Open `apps/web/src/components/AppShell.tsx`. Add `Bug` to the lucide-react import (line 3):

```typescript
import {
  BookOpen,
  Bug,          // ADD THIS
  Target,
  ShieldCheck,
  ChevronRight,
  LogOut,
  Settings,
  Users,
  Activity,
  LayoutDashboard,
  Map,
  BarChart2,
  OctagonX,
} from "lucide-react";
```

In the `NAV_ITEMS` array (lines 33–40), insert between Engagements and Knowledge Base:

```typescript
const NAV_ITEMS: NavItem[] = [
  { to: "/dashboard", label: "Dashboard", icon: <LayoutDashboard className="h-4 w-4" /> },
  { to: "/engagements", label: "Engagements", icon: <Target className="h-4 w-4" /> },
  { to: "/findings", label: "Findings", icon: <Bug className="h-4 w-4" /> },
  { to: "/knowledge", label: "Knowledge Base", icon: <BookOpen className="h-4 w-4" /> },
  { to: "/attack-surface", label: "Attack Surface", icon: <Map className="h-4 w-4" /> },
  { to: "/trends", label: "Trends", icon: <BarChart2 className="h-4 w-4" /> },
  { to: "/settings", label: "Settings", icon: <Settings className="h-4 w-4" /> },
];
```

- [ ] **Step 2: Add route to App.tsx**

Open `apps/web/src/App.tsx`. Add the import at the top (with the other page imports):

```typescript
import FindingsPage from "./pages/FindingsPage";
```

Inside the protected `<Route element={<AppShell />}>` block, after the engagements routes (line 41), add:

```tsx
<Route path="/findings" element={<FindingsPage />} />
```

- [ ] **Step 3: Fix DashboardPage navigation**

Open `apps/web/src/pages/DashboardPage.tsx`.

Find the "Total Findings" `StatCard` (around line 574–580). Change its `onClick`:
```tsx
// Before:
onClick={() => navigate("/engagements")}
// After (on the Total Findings card only):
onClick={() => navigate("/findings")}
```

Find the `FindingRow` onClick (around line 669–671). Change:
```tsx
// Before:
onClick={() => navigate(`/engagements/${f.engagement_id}?tab=findings`)}
// After:
onClick={() => navigate(`/findings?engagement_id=${f.engagement_id}`)}
```

Find the "All findings →" button (around line 651–655). Change its onClick:
```tsx
// Before:
onClick={() => navigate("/engagements")}
// After (the "All findings →" button, not "All engagements →"):
onClick={() => navigate("/findings")}
```

- [ ] **Step 4: Type-check**

```bash
cd apps/web
pnpm type-check 2>&1 | head -20
```

Expected: errors about `FindingsPage` not found (Task 6 not done yet) — this is acceptable. All other type errors should be 0.

- [ ] **Step 5: Commit**

```bash
git add apps/web/src/components/AppShell.tsx apps/web/src/App.tsx apps/web/src/pages/DashboardPage.tsx
git commit -m "feat(web): add Findings nav item, /findings route, fix dashboard navigation"
```

---

### Task 6: FindingsPage — new page

**Files:**
- Create: `apps/web/src/pages/FindingsPage.tsx`

**Interfaces:**
- Consumes: `useAllFindings(filters, sortBy, sortDir, page)` from `api.ts` (Task 3)
- Consumes: `FindingsTable` with `showEngagementColumn={true}` (Task 4)
- Consumes: `useEngagements()` from `api.ts` (already exists)
- Consumes: `FindingFilters`, `Severity`, `FindingStatus` from `types.ts` (Task 3)
- Produces: `FindingsPage` default export mounted at `/findings`

- [ ] **Step 1: Create the file**

Create `apps/web/src/pages/FindingsPage.tsx` with the full implementation:

```tsx
import { useSearchParams } from "react-router-dom";
import { Bug, AlertTriangle } from "lucide-react";
import { useAllFindings } from "../lib/api";
import { useEngagements } from "../lib/api";
import { FindingsTable } from "../components/findings/FindingsTable";
import type { FindingFilters, Severity, FindingStatus } from "../lib/types";
import { cn } from "../lib/utils";

const SEVERITY_OPTIONS: Severity[] = ["critical", "high", "medium", "low", "info"];
const STATUS_OPTIONS: FindingStatus[] = ["open", "confirmed", "false_positive", "wont_fix", "resolved"];

const SEVERITY_CHIP_STYLES: Record<Severity, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/30",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  low: "text-blue-400 bg-blue-400/10 border-blue-400/30",
  info: "text-slate-400 bg-slate-500/10 border-slate-500/30",
};

const VULN_CLASS_OPTIONS = [
  "idor", "bola", "bfla", "privilege_escalation",
  "sqli", "xss_stored", "xss_reflected", "xss_dom",
  "xxe", "ssti", "cmdi",
  "auth_bypass", "session", "oauth_misconfig", "jwt_issues",
  "ssrf", "path_traversal", "rce", "deserialization",
  "race_condition", "mass_assignment", "workflow_bypass",
  "api_key_leak", "pii_exposure", "cors", "cloud_misconfig",
  "dos", "open_redirect", "other",
] as const;

function useFiltersFromUrl(): [FindingFilters & { page: number; sortBy: string; sortDir: "asc" | "desc" }, (patch: Partial<FindingFilters & { page: number; sortBy: string; sortDir: "asc" | "desc" }>) => void] {
  const [sp, setSp] = useSearchParams();

  const filters: FindingFilters & { page: number; sortBy: string; sortDir: "asc" | "desc" } = {
    severity: sp.getAll("severity") as Severity[],
    status: sp.getAll("status") as FindingStatus[],
    vuln_class: sp.getAll("vuln_class"),
    engagement_id: sp.get("engagement_id"),
    discovered_after: sp.get("discovered_after"),
    discovered_before: sp.get("discovered_before"),
    page: Number(sp.get("page") ?? "1"),
    sortBy: sp.get("sort_by") ?? "discovered_at",
    sortDir: (sp.get("sort_dir") ?? "desc") as "asc" | "desc",
  };

  const setFilters = (patch: Partial<typeof filters>) => {
    setSp((prev) => {
      const next = new URLSearchParams(prev);
      // When any filter changes, reset to page 1
      if (!("page" in patch)) next.set("page", "1");

      (Object.keys(patch) as Array<keyof typeof patch>).forEach((k) => {
        const v = patch[k];
        if (k === "severity" || k === "status" || k === "vuln_class") {
          next.delete(k);
          (v as string[]).forEach((s) => next.append(k, s));
        } else if (v === null || v === "" || v === undefined) {
          next.delete(k === "sortBy" ? "sort_by" : k === "sortDir" ? "sort_dir" : k);
        } else {
          next.set(k === "sortBy" ? "sort_by" : k === "sortDir" ? "sort_dir" : k, String(v));
        }
      });
      return next;
    });
  };

  return [filters, setFilters];
}

export default function FindingsPage() {
  const [filters, setFilters] = useFiltersFromUrl();
  const { data, isLoading, isError, refetch } = useAllFindings(
    {
      severity: filters.severity,
      status: filters.status,
      vuln_class: filters.vuln_class,
      engagement_id: filters.engagement_id,
      discovered_after: filters.discovered_after,
      discovered_before: filters.discovered_before,
    },
    filters.sortBy,
    filters.sortDir,
    filters.page,
    25,
  );
  const { data: engagements } = useEngagements();

  const total = data?.total ?? 0;
  const results = data?.results ?? [];
  const totalPages = Math.max(1, Math.ceil(total / 25));

  // Severity summary from current page (or from total — use total when available)
  const severityCounts = results.reduce<Partial<Record<Severity, number>>>((acc, f) => {
    acc[f.severity as Severity] = (acc[f.severity as Severity] ?? 0) + 1;
    return acc;
  }, {});

  const clearFilters = () => {
    setFilters({
      severity: [],
      status: [],
      vuln_class: [],
      engagement_id: null,
      discovered_after: null,
      discovered_before: null,
      page: 1,
    });
  };

  const hasFilters =
    filters.severity.length > 0 ||
    filters.status.length > 0 ||
    filters.vuln_class.length > 0 ||
    filters.engagement_id !== null ||
    filters.discovered_after !== null ||
    filters.discovered_before !== null;

  const toggleSeverity = (sev: Severity) => {
    const next = filters.severity.includes(sev)
      ? filters.severity.filter((s) => s !== sev)
      : [...filters.severity, sev];
    setFilters({ severity: next });
  };

  const toggleStatus = (st: FindingStatus) => {
    const next = filters.status.includes(st)
      ? filters.status.filter((s) => s !== st)
      : [...filters.status, st];
    setFilters({ status: next });
  };

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* ── Header ── */}
      <div className="flex items-center gap-3 px-6 py-3 border-b border-border bg-background/80 backdrop-blur-sm shrink-0">
        <Bug className="h-4 w-4 text-primary" />
        <h1 className="text-sm font-semibold text-foreground">All Findings</h1>
        <span className="text-xs text-muted-foreground border border-border rounded px-1.5 py-0.5 font-mono">
          {total}
        </span>
        <div className="flex items-center gap-1.5 ml-2">
          {(["critical", "high", "medium", "low"] as const).map((sev) => {
            const count = severityCounts[sev];
            if (!count) return null;
            return (
              <button
                key={sev}
                onClick={() => toggleSeverity(sev)}
                className={cn(
                  "text-[10px] font-medium px-1.5 py-0.5 rounded border transition-colors",
                  SEVERITY_CHIP_STYLES[sev],
                  filters.severity.includes(sev) && "ring-1 ring-current",
                )}
              >
                {sev.charAt(0).toUpperCase() + sev.slice(1)} {count}
              </button>
            );
          })}
        </div>
      </div>

      {/* ── Body ── */}
      <div className="flex flex-1 overflow-hidden">
        {/* ── Filter sidebar ── */}
        <aside className="w-56 shrink-0 border-r border-border overflow-y-auto p-4 space-y-5 bg-background/50">
          {/* Severity */}
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-2">Severity</p>
            <div className="flex flex-col gap-1">
              {SEVERITY_OPTIONS.map((sev) => (
                <button
                  key={sev}
                  onClick={() => toggleSeverity(sev)}
                  className={cn(
                    "text-xs text-left px-2 py-1 rounded border transition-colors w-full",
                    SEVERITY_CHIP_STYLES[sev],
                    filters.severity.includes(sev) ? "ring-1 ring-current font-semibold" : "opacity-60 hover:opacity-100",
                  )}
                >
                  {sev.charAt(0).toUpperCase() + sev.slice(1)}
                </button>
              ))}
            </div>
          </div>

          {/* Status */}
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-2">Status</p>
            <div className="flex flex-col gap-1">
              {STATUS_OPTIONS.map((st) => (
                <button
                  key={st}
                  onClick={() => toggleStatus(st)}
                  className={cn(
                    "text-xs text-left px-2 py-1 rounded border border-border transition-colors w-full",
                    filters.status.includes(st)
                      ? "bg-primary/10 border-primary/30 text-primary font-medium"
                      : "text-muted-foreground hover:text-foreground hover:bg-muted/30",
                  )}
                >
                  {st.replace(/_/g, " ")}
                </button>
              ))}
            </div>
          </div>

          {/* Vuln Class */}
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-2">Vuln Class</p>
            <select
              value={filters.vuln_class[0] ?? ""}
              onChange={(e) => setFilters({ vuln_class: e.target.value ? [e.target.value] : [] })}
              className="w-full text-xs bg-background border border-border rounded px-2 py-1.5 text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            >
              <option value="">All classes</option>
              {VULN_CLASS_OPTIONS.map((vc) => (
                <option key={vc} value={vc}>{vc.replace(/_/g, " ")}</option>
              ))}
            </select>
          </div>

          {/* Engagement */}
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-2">Engagement</p>
            <select
              value={filters.engagement_id ?? ""}
              onChange={(e) => setFilters({ engagement_id: e.target.value || null })}
              className="w-full text-xs bg-background border border-border rounded px-2 py-1.5 text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            >
              <option value="">All engagements</option>
              {(engagements ?? []).map((eng) => (
                <option key={eng.id} value={eng.id}>{eng.name}</option>
              ))}
            </select>
          </div>

          {/* Date Range */}
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-2">Date Range</p>
            <div className="space-y-1.5">
              <div>
                <label className="text-[10px] text-muted-foreground">From</label>
                <input
                  type="date"
                  value={filters.discovered_after ?? ""}
                  onChange={(e) => setFilters({ discovered_after: e.target.value || null })}
                  className="w-full text-xs bg-background border border-border rounded px-2 py-1 text-foreground focus:outline-none focus:ring-1 focus:ring-primary mt-0.5"
                />
              </div>
              <div>
                <label className="text-[10px] text-muted-foreground">To</label>
                <input
                  type="date"
                  value={filters.discovered_before ?? ""}
                  onChange={(e) => setFilters({ discovered_before: e.target.value || null })}
                  className="w-full text-xs bg-background border border-border rounded px-2 py-1 text-foreground focus:outline-none focus:ring-1 focus:ring-primary mt-0.5"
                />
              </div>
            </div>
          </div>

          {/* Clear */}
          {hasFilters && (
            <button
              onClick={clearFilters}
              className="w-full text-xs text-muted-foreground hover:text-foreground border border-border rounded px-2 py-1.5 transition-colors"
            >
              Clear all filters
            </button>
          )}
        </aside>

        {/* ── Main content ── */}
        <main className="flex-1 overflow-auto p-4 flex flex-col gap-3">
          {isError ? (
            <div className="flex flex-col items-center justify-center flex-1 gap-3 text-muted-foreground">
              <AlertTriangle className="h-8 w-8 text-red-400 opacity-70" />
              <p className="text-sm">Failed to load findings</p>
              <button
                onClick={() => void refetch()}
                className="text-xs px-3 py-1.5 rounded border border-border hover:bg-muted/30 transition-colors"
              >
                Retry
              </button>
            </div>
          ) : !isLoading && results.length === 0 ? (
            <div className="flex flex-col items-center justify-center flex-1 gap-3 text-muted-foreground">
              <Bug className="h-8 w-8 opacity-30" />
              <p className="text-sm">
                {hasFilters ? "No findings match your filters" : "No findings yet"}
              </p>
              {hasFilters && (
                <button
                  onClick={clearFilters}
                  className="text-xs px-3 py-1.5 rounded border border-border hover:bg-muted/30 transition-colors"
                >
                  Clear filters
                </button>
              )}
            </div>
          ) : (
            <>
              <FindingsTable
                findings={results}
                showEngagementColumn={true}
              />

              {/* Pagination footer */}
              <div className="flex items-center justify-between text-xs text-muted-foreground pt-1 shrink-0">
                <span>
                  Showing {results.length === 0 ? 0 : (filters.page - 1) * 25 + 1}–
                  {Math.min(filters.page * 25, total)} of {total} findings
                </span>
                <div className="flex items-center gap-2">
                  <button
                    disabled={filters.page <= 1}
                    onClick={() => setFilters({ page: filters.page - 1 })}
                    className="px-2.5 py-1 rounded border border-border disabled:opacity-40 hover:bg-muted/30 transition-colors disabled:cursor-not-allowed"
                  >
                    Prev
                  </button>
                  <span className="font-mono">
                    {filters.page} / {totalPages}
                  </span>
                  <button
                    disabled={filters.page >= totalPages}
                    onClick={() => setFilters({ page: filters.page + 1 })}
                    className="px-2.5 py-1 rounded border border-border disabled:opacity-40 hover:bg-muted/30 transition-colors disabled:cursor-not-allowed"
                  >
                    Next
                  </button>
                </div>
              </div>
            </>
          )}
        </main>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Check that `useEngagements` is exported**

In `apps/web/src/lib/api.ts`, verify `useEngagements` is exported (it's used in AppShell already — just confirm the export name):

```bash
grep "export function useEngagements" apps/web/src/lib/api.ts
```

Expected: one match. If the function name differs, update the import in `FindingsPage.tsx`.

- [ ] **Step 3: Type-check**

```bash
cd apps/web
pnpm type-check 2>&1 | head -30
```

Expected: 0 errors. Fix any type errors before proceeding.

- [ ] **Step 4: Manual smoke test**

Start the dev server if not running:
```bash
cd apps/web
pnpm dev
```

Navigate to `http://localhost:5173/findings`.

Verify:
- [ ] Page renders without console errors
- [ ] Sidebar shows Severity, Status, Vuln Class, Engagement, Date Range sections
- [ ] Clicking a severity chip toggles it and URL updates (`?severity=critical`)
- [ ] Table shows findings with Engagement column
- [ ] Pagination Prev/Next buttons work
- [ ] Navigating to `/findings?engagement_id=<uuid>` pre-selects the engagement filter
- [ ] "Clear all filters" removes all filter params from URL
- [ ] Dashboard "Total Findings" stat card navigates to `/findings`
- [ ] Dashboard finding rows navigate to `/findings?engagement_id=<id>`
- [ ] Sidebar nav shows "Findings" between Engagements and Knowledge Base

- [ ] **Step 5: Commit**

```bash
git add apps/web/src/pages/FindingsPage.tsx
git commit -m "feat(web): add FindingsPage with three-zone layout, filters, and pagination"
```

---

## Self-Review

### Spec coverage check

| Spec requirement | Task covering it |
|---|---|
| `GET /findings` backend endpoint | Task 2 |
| `FindingWithEngagementResponse` schema | Task 1 |
| `PaginatedFindingsResponse` schema | Task 1 |
| Dashboard StatCard → `/findings` | Task 5 |
| Dashboard FindingRow → `/findings?engagement_id=` | Task 5 |
| AppShell Findings nav item | Task 5 |
| `/findings` route in App.tsx | Task 5 |
| `FindingWithEngagement` / `PaginatedFindings` / `FindingFilters` types | Task 3 |
| `useAllFindings` hook | Task 3 |
| `FindingsTable` engagementId optional | Task 4 |
| `FindingsTable` showEngagementColumn + Engagement column | Task 4 |
| Three-zone FindingsPage layout | Task 6 |
| URL-synced filter state | Task 6 |
| Severity filter chips (header + sidebar) | Task 6 |
| Status filter | Task 6 |
| Vuln class filter | Task 6 |
| Engagement filter | Task 6 |
| Date range filter | Task 6 |
| Pagination Prev/Next | Task 6 |
| Empty/error states | Task 6 |
| `placeholderData: keepPreviousData` (no flicker) | Task 3 |
| Severity CASE sort on backend | Task 2 |
| `GET /findings` placed before `/findings/recent` | Task 2 (note in step 4) |

All 9 files from the spec are covered. No gaps found.

### Type consistency check

- `FindingWithEngagementResponse` in Python extends `FindingResponse` (same fields + `engagement_name: str`) ✓
- `FindingWithEngagement` in TypeScript extends `Finding` (same fields + `engagement_name: string`) ✓
- `fetchAllFindings` returns `Promise<PaginatedFindings>` matching `useAllFindings` type param ✓
- `FindingsTable` `findings` prop accepts `Finding[] | FindingWithEngagement[]` — cast in render is safe since `FindingWithEngagement` extends `Finding` ✓
- `useEngagements` returns `Engagement[]` — accessed via `eng.id` and `eng.name` which both exist on `Engagement` interface ✓
