# Pentra AI — Handoff Report untuk Sprint 43+
> Dibuat: 2026-06-23 | Untuk: Codex / Claude sesi berikutnya

---

## Ringkasan Eksekutif

Pentra AI adalah self-hosted AI Security Research Platform (FastAPI + LangGraph + Ollama + React).
Sprint 33–42 fokus pada **test coverage** — dari ~496 tests menjadi **873 tests passing (0 failed)**.

---

## Status Saat Ini

| Metrik | Nilai |
|--------|-------|
| Total tests | **873 passing, 0 failed** |
| Python tests | 736 (pytest) |
| TypeScript tests | 137 (Vitest) |
| E2E Playwright | 90 tests |
| Frontend test files | 12 (`src/**/*.test.{ts,tsx}`) |
| Branch | `main` |
| Last commit | `a1b5bd2` |

---

## Apa yang Sudah Dikerjakan (Sprint 33–42)

### Sprint 37 — pentra-scope + pentra-report (56 tests)
- `packages/pentra-scope/tests/test_scope_enforcer.py` — 32 tests
  - ScopeEnforcer: exact domain, wildcard `*.domain`, CIDR, IP, URL stripping, exclusion, case-insensitive, port-qualified
- `packages/pentra-report/tests/test_report_generator.py` — 24 tests
  - ReportGenerator: Markdown/HTML/H1 output, PDF via weasyprint mock, FindingReport properties

### Sprint 38 — pentra-payload + worker helpers (56 tests)
- `packages/pentra-payload/tests/test_payload_generator.py` — 24 tests
  - `_format_knowledge`, `_parse_response` (pure), `generate()` dengan mocked httpx
- `apps/worker/tests/test_agent_tasks.py` — 19 tests
  - `_extract_domain`, `_build_initial_state`, `_publish_event` (mocked redis)
- `apps/worker/tests/test_monitoring_tasks.py` — 13 tests
  - `_detect_delta`: subdomain/port/endpoint changes

### Sprint 39 — worker notifications/rss/payloads + bugfix (68 tests)
- **BUGFIX**: `payloads_all_things.py` — `VulnClass.XSS` → `VulnClass.XSS_STORED`, `VulnClass.CSRF` → `VulnClass.AUTH_BYPASS` (module-level AttributeError)
- `apps/worker/tests/test_notifications_tasks.py` — 12 tests
- `apps/worker/tests/test_rss_ingestion_tasks.py` — 24 tests
- `apps/worker/tests/test_payloads_all_things.py` — 32 tests

### Sprint 40 — Vitest setup + frontend dasar (47 tests)
- Setup: `vite.config.ts` (test env jsdom), `package.json` (scripts), `tsconfig.app.json` (types)
- `src/lib/utils.test.ts` — 25 tests: `cn()`, `formatBounty()`, SEVERITY_COLORS/DOT, VULN_CLASS_LABELS
- `src/components/EmptyState.test.tsx` — 9 tests
- `src/components/LoadingSpinner.test.tsx` — 8 tests
- `src/components/ErrorBoundary.test.tsx` — 5 tests

### Sprint 41 — Zustand + KnowledgeCard + ProtectedRoute + NotificationBell (42 tests)
- `src/hooks/useNotifications.test.ts` — 16 tests (Zustand store: add, mark read, clear)
- `src/components/KnowledgeCard.test.tsx` — 17 tests
- `src/components/ProtectedRoute.test.tsx` — 5 tests (dengan MemoryRouter)
- `src/components/NotificationBell.test.tsx` — 8 tests (vi.mock NotificationPanel)

### Sprint 42 — toast + FilterPanel + KBInjectDialog + EngagementOverviewCard (48 tests)
- `src/lib/toast.test.ts` — 12 tests (Zustand toast store)
- `src/components/FilterPanel.test.tsx` — 13 tests
- `src/components/KBInjectDialog.test.tsx` — 13 tests (vi.mock useKBManualInject)
- `src/components/EngagementOverviewCard.test.tsx` — 14 tests (vi.mock useApproveAction/useStopEngagement)

---

## Yang BELUM Dikerjakan (Backlog Sprint 43+)

### PRIORITAS TINGGI

#### 1. Frontend: LoginPage
**File**: `apps/web/src/pages/LoginPage.tsx`
**Tests to write**: `src/pages/LoginPage.test.tsx`

```
Tests yang diperlukan:
- renders username + password fields
- renders "Sign in" heading
- submit calls login.mutateAsync with {username, password}
- error message shown when login fails
- already-authenticated user redirected to /workspaces
- form fields are required (HTML5 validation)
```

**Mocks yang perlu dibuat**:
```typescript
vi.mock('../lib/api', () => ({
  useLogin: () => ({ mutateAsync: mockLogin, isPending: false }),
  getMeApi: vi.fn(),
}))
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom')
  return { ...actual, useNavigate: () => mockNavigate }
})
vi.mock('axios')  // untuk setup check
```

---

#### 2. Frontend: useEngagementFeed hook
**File**: `apps/web/src/hooks/useEngagementFeed.ts`
**Tests to write**: `src/hooks/useEngagementFeed.test.ts`

```
Tests yang diperlukan:
- connects to WebSocket on mount
- disconnects on unmount
- parses incoming JSON events
- updates messages state on each event
- handles ping events (no state change)
- handles AGENT_ERROR event
- handles AWAITING_APPROVAL event (sets awaitingApproval=true)
```

**Cara mock WebSocket di Vitest/jsdom**:
```typescript
class MockWebSocket {
  static instances: MockWebSocket[] = []
  onmessage: ((e: MessageEvent) => void) | null = null
  onopen: (() => void) | null = null
  onclose: (() => void) | null = null
  close = vi.fn()
  send = vi.fn()
  constructor(url: string) { MockWebSocket.instances.push(this) }
  // Helper to trigger message from test:
  emit(data: object) { this.onmessage?.({ data: JSON.stringify(data) } as MessageEvent) }
}
vi.stubGlobal('WebSocket', MockWebSocket)
```

---

#### 3. Frontend: DashboardPage / WorkspacesPage
**Files**: `apps/web/src/pages/DashboardPage.tsx`, `apps/web/src/pages/WorkspacesPage.tsx`

```
Tests yang diperlukan (masing-masing):
- renders page heading
- shows loading state
- shows empty state when no workspaces/engagements
- renders workspace/engagement cards
- create button navigates correctly
```

**Mocks**: `vi.mock('../lib/api', ...)` untuk `useWorkspaces`, `useEngagements`

---

#### 4. Python: Worker task integration tests (lebih dalam)
**Files yang belum punya tests mendalam**:
- `apps/worker/app/tasks/knowledge_update.py` — `_extract_knowledge_batch()` helper
- `apps/worker/app/tasks/bugcrowd_scraper.py` — sudah ada tests di `test_bugcrowd_scraper.py`, tapi bisa ditambah

---

#### 5. Python: Endpoint tests yang masih kurang
**File**: `apps/api/tests/` — cek coverage dengan:
```bash
cd apps/api && uv run pytest --co -q 2>&1 | grep "test session"
```

Router yang belum ada tests:
- `apps/api/app/api/workspace_router.py`
- `apps/api/app/api/findings_router.py`
- `apps/api/app/api/engagement_router.py`

---

### PRIORITAS RENDAH (nice to have)

#### 6. Frontend: StopAllModal
**File**: `apps/web/src/components/StopAllModal.tsx`
```
Tests: dialog visibility, confirm stops all engagements, cancel closes
```

#### 7. pentra-agent: Node tests yang lebih dalam
**File**: `packages/pentra-agent/` — sudah ada tests, tapi node individu bisa ditambah

#### 8. E2E live run manual (Sprint 17.2)
**Tidak bisa diotomasi** — harus manual dengan target real

---

## Cara Menjalankan Tests

```bash
# Python — semua packages + apps
cd /home/mdilab/projects/Pentra-AI

# pentra-scope
cd packages/pentra-scope && uv run pytest tests/ -q

# pentra-report
cd packages/pentra-report && uv run pytest tests/ -q

# pentra-payload
cd packages/pentra-payload && uv run pytest tests/ -q --extra dev

# apps/api
cd apps/api && uv run pytest tests/ -q

# apps/worker
cd apps/worker && uv run pytest tests/ -q

# Frontend (Vitest)
cd apps/web && pnpm test

# E2E Playwright (perlu server running)
cd apps/web && pnpm e2e
```

---

## Instruksi untuk Codex

1. **Baca file ini dulu** sebelum mulai coding
2. **Baca CLAUDE.md** di root project untuk coding standards
3. **Mulai dari LoginPage** (PRIORITAS TINGGI #1) — paling straightforward
4. **Setelah setiap batch tests**, jalankan full test suite untuk verifikasi tidak ada regresi
5. **Pattern mock** yang sudah terbukti kerja:
   - Local imports dalam function body → patch di source module, bukan caller
   - SVG className di jsdom → `getAttribute('class')` bukan `.className`
   - Zustand store → `useStore.setState({})` di `beforeEach` untuk reset
   - Multiple matching elements → `getAllByRole` bukan `getByRole`
6. **Commit format**: `feat(sprintN): description` dengan `Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>`
7. **Push ke git** setelah setiap sprint selesai

---

## File Struktur Tests (yang sudah ada)

```
packages/
  pentra-scope/tests/test_scope_enforcer.py        ✅ 32 tests
  pentra-report/tests/test_report_generator.py     ✅ 24 tests
  pentra-payload/tests/test_payload_generator.py   ✅ 24 tests
  pentra-agent/tests/                              ✅ 156 tests (existing)
  pentra-tools/tests/                              ✅ 225 tests (existing)
  pentra-knowledge/tests/                          ✅ 25 tests (existing)

apps/
  api/tests/
    test_auth_router.py        ✅ 12 tests
    test_h1_router.py          ✅ 6 tests
    test_internal_router.py    ✅ 10 tests
    test_monitoring_router.py  ✅ 16 tests
    test_report_router.py      ✅ 9 tests
    test_setup_router.py       ✅ 7 tests
    (+ existing tests ~63)

  worker/tests/
    test_agent_tasks.py          ✅ 19 tests
    test_bugcrowd_scraper.py     ✅ existing
    test_knowledge_update.py     ✅ existing
    test_maintenance.py          ✅ existing
    test_monitoring_tasks.py     ✅ 13 tests
    test_notifications_tasks.py  ✅ 12 tests
    test_payloads_all_things.py  ✅ 32 tests
    test_rss_ingestion_tasks.py  ✅ 24 tests

web/src/
  lib/
    utils.test.ts              ✅ 25 tests
    toast.test.ts              ✅ 12 tests
  hooks/
    useNotifications.test.ts   ✅ 16 tests
  components/
    EmptyState.test.tsx              ✅ 9 tests
    LoadingSpinner.test.tsx          ✅ 8 tests
    ErrorBoundary.test.tsx           ✅ 5 tests
    KnowledgeCard.test.tsx           ✅ 17 tests
    NotificationBell.test.tsx        ✅ 8 tests
    ProtectedRoute.test.tsx          ✅ 5 tests
    FilterPanel.test.tsx             ✅ 13 tests
    KBInjectDialog.test.tsx          ✅ 13 tests
    EngagementOverviewCard.test.tsx  ✅ 14 tests

  pages/
    LoginPage.test.tsx         ❌ BELUM
    DashboardPage.test.tsx     ❌ BELUM
    WorkspacesPage.test.tsx    ❌ BELUM
  hooks/
    useEngagementFeed.test.ts  ❌ BELUM
```

---

*Total: 873 tests passing | Target Sprint 43+: 950+ tests*
