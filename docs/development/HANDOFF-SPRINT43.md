# Pentra AI — Handoff Report untuk Sprint 43+
> Dibuat: 2026-06-23 | Untuk: Codex / Claude sesi berikutnya

---

## Ringkasan Eksekutif

Pentra AI adalah self-hosted AI Security Research Platform (FastAPI + LangGraph + Ollama + React).
Sprint 33–44 fokus pada **test coverage** — dari ~496 tests menjadi **972 tests passing (0 failed)**.

---

## Status Saat Ini

| Metrik | Nilai |
|--------|-------|
| Total tests | **972 passing, 0 failed** |
| Python tests | 761 (pytest) |
| TypeScript tests | 211 (Vitest, 20 files) |
| E2E Playwright | 90 tests |
| Frontend test files | 20 (`src/**/*.test.{ts,tsx}`) |
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

### Sprint 43 — frontend pages + API router coverage (77 tests)
- `apps/web/src/pages/LoginPage.test.tsx` — 7 tests
  - render heading/fields, required fields, login submit, API error, authenticated redirect, setup redirect
- `apps/web/src/hooks/useEngagementFeed.test.ts` — 9 tests
  - WebSocket connect/disconnect, JSON event parsing, ping ignore, error notifications, approval state, REST history restore
- `apps/web/src/pages/DashboardPage.test.tsx` — 7 tests
  - heading, empty state, engagement cards, findings, navigation, quick actions
- `apps/web/src/pages/WorkspacesPage.test.tsx` — 7 tests
  - heading, loading, empty state, cards, create form, create submit, card navigation
- `apps/web/src/components/StopAllModal.test.tsx` — 8 tests
  - visibility, empty/running state, cancel, row stop, stop all success, partial failure, disabled state
- `apps/web/src/pages/EngagementsPage.test.tsx` — 14 tests
  - heading/breadcrumb, hook params, loading/empty/list states, navigation, create form, agentic warning, H1 scope import, JSON import
- `apps/api/tests/test_workspace_router.py` — 6 tests
  - create/list/get workspace, 404, non-owner 403, admin access
- `apps/api/tests/test_engagement_router.py` — 11 tests
  - create/list/get/start/stop/subscan/mode validation
- `apps/api/tests/test_findings_router.py` — 8 tests
  - list/recent findings, patch 404/success, submit-to-knowledge 404/existing/create

### Sprint 44 — frontend Settings + KnowledgeBrowser coverage (22 tests)
- `apps/web/src/pages/SettingsPage.test.tsx` — 11 tests
  - sections, profile roles/placeholders, version info, password required fields, local validation, mutation success, API error, pending state
- `apps/web/src/pages/KnowledgeBrowser.test.tsx` — 11 tests
  - initial state, search enable/submit/click/Enter, loading/error/zero-results/results, drawer open/close, inject navigation, filter propagation

**Verifikasi terbaru:**
- `cd apps/web && pnpm test` → 211 passed, 0 failed
- `cd apps/web && pnpm type-check` → pass
- `cd apps/api && uv run pytest tests/ -q` → 148 passed, 0 failed

---

## Yang BELUM Dikerjakan (Backlog Sprint 45+)

### PRIORITAS TINGGI

#### 1. Python: Worker task integration tests (lebih dalam)
**Files yang belum punya tests mendalam**:
- `apps/worker/app/tasks/knowledge_update.py` — `_extract_knowledge_batch()` helper
- `apps/worker/app/tasks/bugcrowd_scraper.py` — sudah ada tests di `test_bugcrowd_scraper.py`, tapi bisa ditambah

---

#### 2. Frontend pages/components berikutnya
- `apps/web/src/pages/WorkerHealthPage.tsx`
- `apps/web/src/pages/AdminPage.tsx`
- `apps/web/src/pages/AdminUsersPage.tsx`
- `apps/web/src/pages/AttackSurfacePage.tsx`
- `apps/web/src/pages/ApiVaultPage.tsx`
- `apps/web/src/pages/GFPatternsPage.tsx`
- `apps/web/src/pages/TrendsPage.tsx`

Mulai dari halaman yang paling sedikit dependency eksternal: `ApiVaultPage`, `GFPatternsPage`, lalu `WorkerHealthPage`.

---

### PRIORITAS RENDAH (nice to have)

#### 3. pentra-agent: Node tests yang lebih dalam
**File**: `packages/pentra-agent/` — sudah ada tests, tapi node individu bisa ditambah

#### 4. E2E live run manual (Sprint 17.2)
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
3. **Mulai dari Worker task deeper tests atau frontend pages ringan** (`ApiVaultPage`, `GFPatternsPage`, `WorkerHealthPage`)
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
    test_engagement_router.py  ✅ 11 tests
    test_findings_router.py    ✅ 8 tests
    test_h1_router.py          ✅ 6 tests
    test_internal_router.py    ✅ 10 tests
    test_monitoring_router.py  ✅ 16 tests
    test_report_router.py      ✅ 9 tests
    test_setup_router.py       ✅ 7 tests
    test_workspace_router.py   ✅ 6 tests
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
    useEngagementFeed.test.ts  ✅ 9 tests
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
    StopAllModal.test.tsx            ✅ 8 tests

  pages/
    DashboardPage.test.tsx           ✅ 7 tests
    EngagementsPage.test.tsx         ✅ 14 tests
    KnowledgeBrowser.test.tsx        ✅ 11 tests
    LoginPage.test.tsx               ✅ 7 tests
    SettingsPage.test.tsx            ✅ 11 tests
    WorkspacesPage.test.tsx          ✅ 7 tests
```

---

*Total: 972 tests passing | Target Sprint 43+: achieved; Sprint 45 target: 1000+ tests*
