# PHASE-3-EXECUTION.md — Pentra AI
> **Untuk:** GitHub Copilot dengan Claude Sonnet 4.6  
> **Baca terlebih dahulu:** `CLAUDE.md` → `docs/PRD.md` → `PROGRESS.md` → file ini  
> **Status saat ini:** MVP + Sprint 1–3 Post-MVP selesai, 84 tests pass  
> **Tujuan dokumen ini:** Membawa Pentra AI dari "production-ready backend" ke "platform yang benar-benar siap digunakan di lapangan"

---

## Konteks: Apa yang Sudah Ada

```
✅ Knowledge Engine         — 1.500 records Qdrant, BGE-M3, hybrid search
✅ LangGraph Agent          — 7 nodes, HITL + agentic mode, AsyncPostgresSaver
✅ Tool Wrappers            — subfinder, nmap, nuclei, httpx, Burp MCP, amass,
                              katana, ffuf, dalfox, sqlmap (scope-gated, rate-limited)
✅ Report Generator         — MD, HTML, PDF, H1 format
✅ Auth System              — JWT HS256, bcrypt, admin + user roles
✅ Docker Compose           — 7 services, healthcheck, nginx
✅ Rate Limiting            — Redis sliding window middleware
✅ Payload Generator        — pentra-payload, context-aware via LLM
✅ Continuous Monitoring    — delta detection, Celery daily task
✅ Notifications            — Slack webhook + Telegram Bot
✅ KB Self-Learning         — finding → knowledge pipeline
✅ KB Manual Inject         — URL, file upload, raw text (UI + API)
✅ Workspace Isolation      — row-level, owner_id FK
✅ Screenshot Capture       — Playwright + MinIO
✅ Tests                    — 84 tests, 0 failed
```

## Apa yang Masih Kurang (Gap dari PRD + Roadmap)

```
❌ E2E tests (Playwright)                — UI flow belum teruji otomatis
❌ Burp Pro real integration test        — kode ada, belum divalidasi dengan Burp Pro aktif
❌ Monitoring dashboard UI               — backend siap, UI belum ada
❌ Celery worker health UI               — tidak ada visibility ke worker status
❌ Knowledge base volume                 — 1.500 records, target 50.000+
❌ Nuclei template auto-update           — template tidak pernah di-refresh
❌ API documentation (Swagger/OpenAPI)   — belum dikurasi untuk external use
❌ Setup wizard (first-run experience)   — admin harus setup manual via CLI
❌ OPSEC mode                            — tidak ada traffic blending / rate delay
❌ Multi-user invite flow                — admin belum bisa invite user via UI
❌ Engagement export/import             — belum ada
❌ CVE correlation pada findings        — findings tidak terlink ke NVD/CVE
❌ HackerOne program sync               — scope tidak bisa diimport dari H1 program
❌ GraphQL attack surface analysis      — katana crawl tidak analisis GraphQL schema
❌ Bugcrowd / Intigriti integration     — hanya H1 yang tercover
```

---

## Sprint 4 — Production Quality

> **Prioritas:** Hal-hal yang langsung berdampak pada penggunaan real di lapangan  
> **Estimasi:** 1–2 minggu  
> **Fokus:** Testing otomatis, UI yang missing, knowledge base volume

---

### Task 4.1 — E2E Tests dengan Playwright

**Konteks:**  
84 unit tests sudah pass. Tapi tidak ada test yang memvalidasi user journey secara end-to-end di browser — login, buat engagement, lihat live feed, approve HITL, download report.

**Setup Playwright:**

```bash
# Install di apps/web
cd apps/web
pnpm add -D @playwright/test
pnpm playwright install chromium
```

**Buat file konfigurasi:**

```typescript
// apps/web/playwright.config.ts
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,          // Sequential — ada shared state (DB)
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  timeout: 60_000,               // 60s per test — agent bisa lambat
  use: {
    baseURL: process.env.E2E_BASE_URL || "http://localhost:5174",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
  ],
  // Jalankan dev server sebelum test
  webServer: {
    command: "pnpm dev",
    port: 5174,
    reuseExistingServer: !process.env.CI,
  },
});
```

**Buat test file — auth flow:**

```typescript
// apps/web/e2e/auth.spec.ts
import { test, expect } from "@playwright/test";

test.describe("Authentication Flow", () => {
  test("login dengan credentials valid berhasil", async ({ page }) => {
    await page.goto("/login");
    
    await page.getByLabel("Username").fill("admin");
    await page.getByLabel("Password").fill("pentra123");
    await page.getByRole("button", { name: "Sign In" }).click();
    
    // Harus redirect ke dashboard
    await expect(page).toHaveURL("/");
    await expect(page.getByText("Dashboard")).toBeVisible();
  });

  test("login dengan credentials salah tampilkan error", async ({ page }) => {
    await page.goto("/login");
    
    await page.getByLabel("Username").fill("admin");
    await page.getByLabel("Password").fill("wrong-password");
    await page.getByRole("button", { name: "Sign In" }).click();
    
    await expect(page.getByText(/invalid credentials/i)).toBeVisible();
  });

  test("halaman protected redirect ke login jika belum auth", async ({ page }) => {
    await page.goto("/workspaces");
    await expect(page).toHaveURL("/login");
  });

  test("sign out berhasil", async ({ page }) => {
    // Login dulu
    await page.goto("/login");
    await page.getByLabel("Username").fill("admin");
    await page.getByLabel("Password").fill("pentra123");
    await page.getByRole("button", { name: "Sign In" }).click();
    await page.waitForURL("/");
    
    // Sign out
    await page.getByRole("button", { name: /sign out/i }).click();
    await expect(page).toHaveURL("/login");
  });
});
```

**Buat test file — workspace dan engagement flow:**

```typescript
// apps/web/e2e/engagement.spec.ts
import { test, expect, Page } from "@playwright/test";

// Helper: login sebelum setiap test
async function login(page: Page) {
  await page.goto("/login");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill("pentra123");
  await page.getByRole("button", { name: "Sign In" }).click();
  await page.waitForURL("/");
}

test.describe("Workspace & Engagement Flow", () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test("buat workspace baru dan muncul di list", async ({ page }) => {
    await page.goto("/workspaces");
    await page.getByRole("button", { name: /new workspace/i }).click();
    
    await page.getByLabel("Name").fill("E2E Test Workspace");
    await page.getByRole("button", { name: /create/i }).click();
    
    await expect(page.getByText("E2E Test Workspace")).toBeVisible();
  });

  test("buat engagement dengan scope dan muncul di list", async ({ page }) => {
    await page.goto("/workspaces");
    await page.getByText("E2E Test Workspace").click();
    await page.getByRole("button", { name: /new engagement/i }).click();
    
    await page.getByLabel("Name").fill("Test Engagement");
    await page.getByLabel("In Scope").fill("testphp.vulnweb.com");
    await page.getByRole("button", { name: /create/i }).click();
    
    await expect(page.getByText("Test Engagement")).toBeVisible();
  });

  test("KB Browser dapat search dan tampilkan hasil", async ({ page }) => {
    await page.goto("/knowledge");
    
    await page.getByPlaceholder(/search/i).fill("IDOR");
    await page.getByRole("button", { name: /search/i }).click();
    
    // Harus ada hasil (minimal 1 dari seed data)
    await expect(page.locator("[data-testid='knowledge-result']").first()).toBeVisible({
      timeout: 10_000,
    });
  });
});
```

**Buat test file — HITL approval flow:**

```typescript
// apps/web/e2e/hitl.spec.ts
import { test, expect, Page } from "@playwright/test";

test.describe("HITL Approval Flow", () => {
  // NOTE: Test ini membutuhkan mock agent yang inject event AWAITING_APPROVAL
  // ke WebSocket. Gunakan MSW (Mock Service Worker) untuk mock WS events.
  
  test("approval dialog muncul saat agent kirim AWAITING_APPROVAL", async ({ page }) => {
    // Setup MSW untuk intercept WebSocket
    // ... (implementasi dengan playwright-msw atau custom WS mock)
    
    await page.goto("/engagements/test-id/live");
    
    // Tunggu approval dialog muncul
    await expect(page.getByRole("dialog", { name: /approval required/i })).toBeVisible({
      timeout: 15_000,
    });
    
    // Click Approve
    await page.getByRole("button", { name: /approve/i }).click();
    
    // Dialog hilang setelah approve
    await expect(page.getByRole("dialog")).not.toBeVisible();
  });
});
```

**Tambahkan script ke `package.json`:**

```json
// apps/web/package.json
{
  "scripts": {
    "e2e": "playwright test",
    "e2e:ui": "playwright test --ui",
    "e2e:headed": "playwright test --headed"
  }
}
```

**Tambahkan ke Turborepo pipeline:**

```json
// turbo.json
{
  "pipeline": {
    "e2e": {
      "dependsOn": ["build"],
      "cache": false
    }
  }
}
```

---

### Task 4.2 — Monitoring Dashboard UI

**Konteks:**  
Backend sudah siap: `ReconSnapshotORM`, `MonitoringAlertORM`, delta detection Celery task. Tapi tidak ada UI untuk lihat alertnya.

**Buat halaman baru: `/engagements/:id/monitoring`**

**Tambah tab baru di Engagement Detail:**

```typescript
// apps/web/src/pages/EngagementDetail.tsx
// Tambah tab ke: Live Feed | Findings | Monitoring | Reports
```

**Komponen utama yang perlu dibuat:**

```typescript
// apps/web/src/components/monitoring/

MonitoringDashboard.tsx        // Container utama
├── AlertTimeline.tsx          // Timeline vertikal semua alerts
├── AlertCard.tsx              // Card per alert (new_subdomain, new_port, dll)
├── SnapshotDiff.tsx           // Sebelum vs sesudah snapshot (diff view)
└── MonitoringSchedule.tsx     // Toggle aktif/nonaktif + interval setting
```

**`AlertTimeline.tsx` — design:**

```typescript
// Timeline vertikal dengan alert cards
// Setiap card menampilkan:
// - Icon berdasarkan alert_type (🌐 subdomain, 🔌 port, 📄 endpoint)
// - Timestamp relative ("2 jam yang lalu")
// - Detail: "New subdomain found: api-v2.target.com"
// - Badge: [NEW] [READ]
// - Tombol: [View Diff] [Start Scan] [Dismiss]
//
// Filter di atas: All | Subdomain | Port | Endpoint | Unread only
```

**`SnapshotDiff.tsx` — design:**

```typescript
// Diff view dua snapshot (sebelum vs sesudah)
// Layout split: kiri = snapshot lama, kanan = snapshot baru
// Highlight:
// - Hijau: item baru yang muncul di snapshot baru
// - Merah: item yang hilang dari snapshot lama
// - Abu-abu: item yang sama (tidak berubah)
//
// Tabs: Subdomains | Ports | Tech Stack
```

**API endpoints yang dibutuhkan (tambahkan jika belum ada):**

```python
# apps/api/app/api/v1/monitoring.py

@router.get("/engagements/{engagement_id}/monitoring/alerts")
async def list_monitoring_alerts(
    engagement_id: UUID,
    is_read: bool | None = None,
    alert_type: str | None = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[MonitoringAlertResponse]:
    """List semua monitoring alerts untuk engagement."""
    ...

@router.patch("/engagements/{engagement_id}/monitoring/alerts/{alert_id}/read")
async def mark_alert_read(
    engagement_id: UUID,
    alert_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MonitoringAlertResponse:
    """Mark alert sebagai sudah dibaca."""
    ...

@router.get("/engagements/{engagement_id}/monitoring/snapshots")
async def list_snapshots(
    engagement_id: UUID,
    limit: int = 10,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ReconSnapshotResponse]:
    """List recon snapshots untuk engagement (untuk diff view)."""
    ...

@router.get("/engagements/{engagement_id}/monitoring/snapshots/diff")
async def get_snapshot_diff(
    engagement_id: UUID,
    snapshot_a: UUID,  # query param
    snapshot_b: UUID,  # query param
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SnapshotDiff:
    """Hitung diff antara dua snapshot."""
    ...

@router.post("/engagements/{engagement_id}/monitoring/schedule")
async def set_monitoring_schedule(
    engagement_id: UUID,
    schedule: MonitoringSchedule,  # {"enabled": true, "interval_hours": 24}
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Set jadwal monitoring untuk engagement."""
    ...
```

**Tambahkan unread alert badge di sidebar:**

```typescript
// apps/web/src/components/AppShell.tsx
// Di sidebar item "Monitoring", tampilkan badge merah dengan jumlah unread alerts
// Fetch dari GET /api/v1/engagements/{id}/monitoring/alerts?is_read=false
// Update setiap 60 detik via polling (bukan WebSocket)
```

---

### Task 4.3 — Knowledge Base Volume Expansion

**Konteks:**  
Saat ini 1.500 records. Target PRD: 50.000+. Scraper sudah ada tapi belum pernah dijalankan secara agresif.

**Step 1 — Jalankan H1 scraper secara manual untuk bulk import:**

```bash
# Jalankan dari CLI dulu untuk monitor progress
cd apps/worker
uv run celery -A app.worker call tasks.knowledge_update \
  --args='[{"source": "h1_graphql", "max_pages": 500}]' \
  --countdown=0

# Monitor progress
uv run celery -A app.worker inspect active
uv run celery -A app.worker inspect stats
```

**Step 2 — Buat admin endpoint untuk trigger bulk import dari UI:**

```python
# apps/api/app/api/v1/admin.py — tambahkan endpoint (admin only):

@router.post("/admin/knowledge/bulk-import")
async def trigger_bulk_import(
    config: BulkImportConfig,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_admin),
) -> BulkImportJob:
    """
    Trigger bulk import ke knowledge base.
    Hanya admin yang bisa akses endpoint ini.
    """
    ...

class BulkImportConfig(BaseModel):
    source: Literal["h1_graphql", "payloads_all_things", "rss_feeds"]
    max_records: int = 1000
    overwrite_existing: bool = False
```

**Step 3 — Buat halaman Admin di UI:**

```typescript
// apps/web/src/pages/Admin.tsx (route: /admin — admin only)
// Section: Knowledge Base Management
// - Card: Total records di Qdrant (live counter)
// - Card: Records per source (H1, Bugcrowd, writeup, pentra_finding)
// - Card: Records per VulnClass (bar chart)
// - Button: [Trigger H1 Import] [Trigger RSS Import] [Trigger PAT Import]
// - Table: Recent import jobs dengan status dan progress
```

**Step 4 — Tambah Bugcrowd public disclosures scraper:**

```python
# apps/worker/tasks/bugcrowd_scraper.py

"""
Scrape public disclosures dari Bugcrowd.
URL: https://bugcrowd.com/disclosures
Format: HTML scraping (tidak ada API publik)
"""

import httpx
from bs4 import BeautifulSoup
from pentra_knowledge.ingestion.processor import KnowledgeProcessor

BUGCROWD_DISCLOSURES_URL = "https://bugcrowd.com/disclosures"

async def scrape_bugcrowd_disclosures(max_pages: int = 50):
    """
    Scrape Bugcrowd public disclosures.
    Parse: title, severity, researcher, program, date, description.
    Convert → KnowledgeRecord → embed → index.
    Respect robots.txt, rate limit 2 req/sec.
    """
    async with httpx.AsyncClient(
        headers={"User-Agent": "Mozilla/5.0 (security research)"},
        follow_redirects=True,
    ) as client:
        for page in range(1, max_pages + 1):
            response = await client.get(
                BUGCROWD_DISCLOSURES_URL,
                params={"page": page}
            )
            if response.status_code != 200:
                break
            
            soup = BeautifulSoup(response.text, "html.parser")
            disclosures = soup.find_all("div", class_="disclosure-card")
            
            if not disclosures:
                break
            
            for disclosure in disclosures:
                # Parse dan process setiap disclosure
                ...
            
            await asyncio.sleep(0.5)  # rate limit
```

---

### Task 4.4 — Setup Wizard (First-Run Experience)

**Konteks:**  
Saat ini admin baru harus setup segalanya manual via CLI. Perlu wizard di UI untuk first-run setup yang guided.

**Trigger:** Jika belum ada user admin di DB, redirect ke `/setup` (bukan `/login`).

**Buat halaman: `/setup`**

```typescript
// apps/web/src/pages/Setup.tsx
// Multi-step wizard — 4 langkah:

// Step 1: Create Admin Account
// - Username, Email, Password, Confirm Password
// - Validasi: password min 12 karakter, username unik

// Step 2: Configure Ollama
// - Ollama URL (default: http://host.docker.internal:11434)
// - [Test Connection] → tampilkan model yang tersedia
// - Pilih Default LLM Model (dropdown dari model yang available di Ollama)
// - Pilih Embedding Model (harus bge-m3, warn jika tidak ada)

// Step 3: Configure Burp Suite (optional)
// - Burp MCP URL (default: http://host.docker.internal:9876)
// - [Test Connection] → tampilkan status
// - Skip jika tidak punya Burp Pro

// Step 4: Seed Knowledge Base
// - Tampilkan: "Knowledge base kosong. Import data awal?"
// - [Import HackerOne Dataset] → trigger background task
// - [Skip — I'll do this later]
// - Progress bar jika import dimulai

// Setelah step 4: redirect ke dashboard
```

**Backend — setup status endpoint:**

```python
# apps/api/app/api/v1/setup.py

@router.get("/setup/status")
async def get_setup_status(db: AsyncSession = Depends(get_db)) -> SetupStatus:
    """
    Cek apakah platform sudah di-setup.
    Dipanggil saat pertama kali buka aplikasi.
    Jika belum ada admin → redirect ke /setup.
    """
    admin_exists = await user_service.admin_exists(db)
    ollama_connected = await ollama_service.health_check()
    kb_record_count = await knowledge_service.count_records()
    
    return SetupStatus(
        is_configured=admin_exists,
        ollama_connected=ollama_connected,
        kb_record_count=kb_record_count,
        requires_setup=not admin_exists,
    )

@router.post("/setup/initialize")
async def initialize_platform(
    config: SetupConfig,
    db: AsyncSession = Depends(get_db),
) -> SetupResult:
    """
    First-run setup: buat admin, simpan config, trigger seed jika diminta.
    Endpoint ini hanya bisa diakses SEKALI — setelah admin ada, return 403.
    """
    # Guard: jika sudah ada admin, tolak
    if await user_service.admin_exists(db):
        raise HTTPException(403, "Platform already configured")
    
    # Buat admin user
    admin = await user_service.create_admin(db, config.admin)
    
    # Simpan Ollama + Burp config ke DB/env
    await config_service.save(config.ollama_url, config.burp_mcp_url)
    
    # Trigger seed jika diminta
    if config.seed_knowledge:
        celery.send_task("tasks.knowledge_update", 
                         args=[{"source": "h1_graphql", "max_pages": 100}])
    
    return SetupResult(success=True, admin_username=admin.username)
```

**Update `main.tsx` — cek setup status:**

```typescript
// apps/web/src/main.tsx atau apps/web/src/App.tsx
// Tambahkan logic:
// 1. Fetch GET /api/v1/setup/status
// 2. Jika requires_setup === true → redirect ke /setup
// 3. Jika false → lanjut ke normal routing (ProtectedRoute)
```

---

### Task 4.5 — User Management UI (Admin Invite Flow)

**Konteks:**  
Auth sudah ada (JWT, roles), tapi tidak ada UI untuk admin menambah user baru. Saat ini harus via `POST /register` langsung.

**Buat halaman: `/admin/users`**

```typescript
// apps/web/src/pages/AdminUsers.tsx
// Hanya visible untuk user dengan is_admin === true

// Layout:
// ┌─────────────────────────────────────────────────┐
// │  USER MANAGEMENT                 [+ Invite User] │
// ├─────────────────────────────────────────────────┤
// │  admin@pentra.local    admin     active  [Edit]  │
// │  alice@pentra.local    operator  active  [Edit]  │
// │  bob@pentra.local      viewer    inactive [Edit] │
// └─────────────────────────────────────────────────┘

// Tombol [+ Invite User] → modal dengan form:
// - Username
// - Email
// - Password (generated otomatis atau manual)
// - Role: operator / viewer (admin tidak bisa di-assign via UI)
// - [Create User]

// Tombol [Edit] → modal dengan:
// - Toggle active/inactive
// - Change role
// - Reset password
// - [Delete User] (dengan konfirmasi)
```

**Backend endpoints (cek apakah sudah ada, tambahkan jika belum):**

```python
# apps/api/app/api/v1/admin.py

@router.get("/admin/users")
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
) -> list[UserResponse]:
    """List semua users. Admin only."""
    ...

@router.post("/admin/users")
async def create_user(
    data: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
) -> UserResponse:
    """Admin buat user baru. Admin only."""
    ...

@router.patch("/admin/users/{user_id}")
async def update_user(
    user_id: UUID,
    data: UserUpdate,  # role, is_active
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
) -> UserResponse:
    """Update user role atau status. Admin only."""
    ...

@router.delete("/admin/users/{user_id}")
async def delete_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
) -> dict:
    """Hapus user. Tidak bisa hapus diri sendiri. Admin only."""
    ...

@router.post("/admin/users/{user_id}/reset-password")
async def reset_user_password(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
) -> dict:
    """Reset password user, return temporary password. Admin only."""
    ...
```

---

## Sprint 5 — Intelligence Upgrade

> **Prioritas:** Tingkatkan kualitas intelligence dan coverage teknik  
> **Estimasi:** 1–2 minggu  
> **Mulai Sprint 5 hanya setelah Sprint 4 semua task selesai**

---

### Task 5.1 — Nuclei Template Auto-Update

**Konteks:**  
`NucleiWrapper` menggunakan template yang sudah terinstall di Docker image. Template tidak pernah di-refresh → scanner tidak dapat template baru.

```python
# apps/worker/tasks/nuclei_update.py

async def update_nuclei_templates():
    """
    Jalankan `nuclei -update-templates` di dalam worker container.
    Schedule: setiap Minggu pagi.
    Log jumlah template baru yang di-download.
    """
    import asyncio
    
    process = await asyncio.create_subprocess_exec(
        "nuclei", "-update-templates", "-silent",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    
    # Parse output untuk count template baru
    # Log ke audit_logs atau dedicated table
    ...
```

**Tambahkan ke Celery Beat schedule:**

```python
# apps/worker/app/celeryconfig.py
beat_schedule = {
    # ... existing schedules ...
    "nuclei-template-update-weekly": {
        "task": "tasks.nuclei_update",
        "schedule": crontab(day_of_week=0, hour=5, minute=0),  # Minggu 05:00
    },
}
```

---

### Task 5.2 — CVE Correlation pada Findings

**Konteks:**  
Findings yang ditemukan (terutama dari Nuclei) sering berkorelasi dengan CVE tertentu. Perlu auto-link ke NVD/CVE database untuk enrichment.

**Buat service baru:**

```python
# packages/pentra-knowledge/services/cve_enrichment.py

import httpx

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

class CVEEnrichmentService:
    """
    Enrich findings dengan data CVE dari NVD (National Vulnerability Database).
    Dipanggil setelah finding dibuat — background task.
    """
    
    async def enrich_finding(self, finding: Finding) -> CVEEnrichment | None:
        """
        Cari CVE yang relevan untuk finding.
        Strategy:
        1. Jika finding dari Nuclei → extract CVE ID dari template metadata
        2. Jika tidak ada CVE ID → search NVD berdasarkan:
           - software name dari tech_stack
           - vuln_class → CPE keyword mapping
        """
        ...
    
    async def search_nvd(
        self,
        keyword: str,
        cvss_severity: str | None = None,
    ) -> list[CVEData]:
        """
        Search NVD API v2.0.
        Rate limit: 5 req/30 detik tanpa API key, 50 req/30 detik dengan API key.
        """
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 5,
        }
        if cvss_severity:
            params["cvssV3Severity"] = cvss_severity.upper()
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                NVD_API_BASE,
                params=params,
                headers={"apiKey": settings.NVD_API_KEY} if settings.NVD_API_KEY else {},
            )
        ...
    
    async def get_cve_detail(self, cve_id: str) -> CVEData:
        """Fetch detail satu CVE by ID (e.g., CVE-2024-1234)."""
        ...

class CVEData(BaseModel):
    cve_id: str
    description: str
    cvss_score: float | None
    cvss_vector: str | None
    severity: str
    published: datetime
    references: list[str]
    cpe: list[str]              # Affected software
```

**Tambahkan CVE info ke Finding model dan UI:**

```python
# apps/api/app/models/finding.py — tambahkan field:
cve_ids: Mapped[list] = mapped_column(JSONB, default=list)
cve_data: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
```

```typescript
// apps/web/src/components/findings/FindingDetail.tsx
// Tambahkan section "CVE Correlation":
// Jika cve_ids tidak kosong:
// - Tampilkan badge per CVE ID (clickable → link ke NVD)
// - CVSS score dan severity
// - Brief description
// Jika kosong:
// - Tampilkan "No CVE correlation found"
```

---

### Task 5.3 — GraphQL Attack Surface Analysis

**Konteks:**  
`KatanaWrapper` sudah bisa crawl web, tapi tidak secara khusus analisis endpoint GraphQL. GraphQL memiliki attack surface unik (introspection, batching, depth bypass) yang perlu coverage tersendiri.

**Buat wrapper baru:**

```python
# packages/pentra-tools/vuln/graphql_analyzer.py

class GraphQLAnalyzer(AsyncToolWrapper):
    """
    Analisis attack surface endpoint GraphQL.
    Deteksi: introspection enabled, query depth, batching, field suggestion.
    """
    name = "graphql_analyzer"
    IS_DESTRUCTIVE = False

    async def run(
        self,
        endpoint_url: str,
        headers: dict | None = None,
    ) -> ToolResult:
        self.scope.validate_or_raise(endpoint_url)
        
        results = []
        
        # Test 1: Introspection enabled?
        introspection_result = await self._test_introspection(endpoint_url, headers)
        results.append(introspection_result)
        
        # Test 2: Query depth bypass
        depth_result = await self._test_query_depth(endpoint_url, headers)
        results.append(depth_result)
        
        # Test 3: Batching abuse
        batch_result = await self._test_batching(endpoint_url, headers)
        results.append(batch_result)
        
        # Test 4: Field suggestion (information disclosure)
        suggestion_result = await self._test_field_suggestion(endpoint_url, headers)
        results.append(suggestion_result)
        
        findings = [r for r in results if r.is_vulnerable]
        
        return ToolResult(
            tool=self.name,
            success=True,
            data={"findings": findings, "total": len(findings)},
            raw=str(results),
        )
    
    async def _test_introspection(self, url: str, headers: dict | None) -> GraphQLTestResult:
        """
        Kirim introspection query.
        Jika response mengandung __schema → VULNERABLE.
        """
        introspection_query = {"query": "{ __schema { types { name } } }"}
        async with httpx.AsyncClient() as client:
            response = await client.post(url, json=introspection_query, headers=headers or {})
        
        is_vulnerable = (
            response.status_code == 200 
            and "__schema" in response.text
        )
        
        return GraphQLTestResult(
            test_name="introspection_enabled",
            is_vulnerable=is_vulnerable,
            severity="medium" if is_vulnerable else "info",
            detail="GraphQL introspection is enabled — schema exposed",
            request=str(introspection_query),
            response=response.text[:500],
        )
```

**Integrasi ke `vuln_hunt_node`:**

```python
# packages/pentra-agent/nodes/vuln_hunt.py
# Setelah httpx detect endpoint GraphQL:
# → Otomatis jalankan GraphQLAnalyzer pada endpoint tersebut
# → Hasil masuk ke findings
```

---

### Task 5.4 — HackerOne Program Sync (Scope Import)

**Konteks:**  
Bug bounty hunter sering kerja pada program H1 tertentu. Saat ini scope harus diisi manual. Perlu fitur import scope langsung dari H1 program.

**Buat service:**

```python
# packages/pentra-knowledge/services/h1_program_sync.py

H1_GRAPHQL_URL = "https://hackerone.com/graphql"

PROGRAM_SCOPE_QUERY = """
query ProgramScope($handle: String!) {
  team(handle: $handle) {
    name
    url
    structured_scope_versions {
      max_provided_severity
      in_scope {
        asset_identifier
        asset_type
        eligible_for_bounty
        instruction
      }
      out_of_scope {
        asset_identifier
        asset_type
      }
    }
  }
}
"""

class H1ProgramSync:
    async def fetch_program_scope(
        self, 
        program_handle: str
    ) -> H1ProgramScope:
        """
        Fetch scope dari H1 program publik.
        Return in_scope dan out_of_scope lists.
        Tidak butuh auth — hanya program publik.
        """
        ...
    
    async def convert_to_engagement_scope(
        self,
        h1_scope: H1ProgramScope
    ) -> EngagementScope:
        """
        Convert H1 scope format ke Pentra AI engagement scope format.
        H1 asset_type: URL, DOMAIN, WILDCARD, IP_ADDRESS, CIDR, etc.
        """
        in_scope = []
        out_of_scope = []
        
        for item in h1_scope.in_scope:
            if item.asset_type in ["URL", "DOMAIN", "WILDCARD"]:
                in_scope.append(item.asset_identifier)
            elif item.asset_type in ["IP_ADDRESS", "CIDR"]:
                in_scope.append(item.asset_identifier)
        
        for item in h1_scope.out_of_scope:
            out_of_scope.append(item.asset_identifier)
        
        return EngagementScope(
            in_scope=in_scope,
            out_of_scope=out_of_scope
        )
```

**UI — Import dari H1 di Engagement Create:**

```typescript
// apps/web/src/components/engagements/EngagementForm.tsx
// Tambahkan section "Import Scope from HackerOne":
// - Input: Program Handle (e.g., "shopify", "hackerone")
// - Button: [Import Scope]
// → Fetch GET /api/v1/h1/programs/{handle}/scope
// → Auto-fill in_scope dan out_of_scope fields
// → User masih bisa edit sebelum submit
```

**Backend endpoint:**

```python
# apps/api/app/api/v1/h1.py

@router.get("/h1/programs/{handle}/scope")
async def get_h1_program_scope(
    handle: str,
    current_user: User = Depends(get_current_user),
) -> H1ProgramScopeResponse:
    """
    Fetch dan convert scope dari H1 program publik.
    Cache hasil selama 24 jam di Redis.
    """
    cache_key = f"h1_scope:{handle}"
    cached = await redis.get(cache_key)
    if cached:
        return H1ProgramScopeResponse.model_validate_json(cached)
    
    scope = await h1_program_sync.fetch_program_scope(handle)
    converted = await h1_program_sync.convert_to_engagement_scope(scope)
    
    await redis.setex(cache_key, 86400, converted.model_dump_json())
    return converted
```

---

## Checklist Akhir Phase 3

```
Sprint 4 — Production Quality
[ ] Playwright terinstall di apps/web
[ ] test_auth.spec.ts — 4 tests pass (login, wrong creds, protected, logout)
[ ] test_engagement.spec.ts — 3 tests pass (workspace, engagement, KB search)
[ ] Monitoring Dashboard UI — AlertTimeline dan SnapshotDiff berjalan
[ ] GET /monitoring/alerts endpoint tersedia
[ ] PATCH /monitoring/alerts/{id}/read endpoint tersedia
[ ] GET /monitoring/snapshots/diff endpoint tersedia
[ ] Qdrant record count > 10.000 setelah bulk import
[ ] Admin endpoint POST /admin/knowledge/bulk-import tersedia
[ ] Halaman /admin dengan KB stats dan import trigger
[ ] Bugcrowd scraper berjalan tanpa error
[ ] Halaman /setup muncul saat DB kosong (tidak ada admin)
[ ] Setup wizard 4 langkah berjalan end-to-end
[ ] GET /setup/status endpoint tersedia
[ ] POST /setup/initialize hanya bisa diakses sekali
[ ] Halaman /admin/users menampilkan semua users
[ ] Admin bisa create user baru via UI
[ ] Admin bisa toggle active/inactive via UI
[ ] Admin bisa change role via UI

Sprint 5 — Intelligence Upgrade
[ ] Celery Beat task nuclei-template-update-weekly terdaftar
[ ] nuclei -update-templates berjalan tanpa error di worker container
[ ] CVEEnrichmentService.search_nvd() return CVEData list
[ ] Finding model punya field cve_ids dan cve_data
[ ] FindingDetail UI tampilkan CVE section
[ ] GraphQLAnalyzer._test_introspection() return is_vulnerable=True untuk endpoint yang vulnerable
[ ] GraphQLAnalyzer._test_batching() berjalan tanpa error
[ ] vuln_hunt_node memanggil GraphQLAnalyzer jika GraphQL endpoint terdeteksi
[ ] H1ProgramSync.fetch_program_scope() return scope untuk program publik
[ ] GET /h1/programs/{handle}/scope return converted scope
[ ] EngagementForm punya tombol "Import from HackerOne"
[ ] Import scope dari H1 mengisi in_scope field dengan benar

Total tests setelah Phase 3: minimal 120 tests, semua pass
```

---

## Gap yang Sengaja Tidak Dicover di Phase 3

Item berikut ada di PRD tapi ditunda ke v2.0 — jangan diimplementasikan dulu:

```
⏸ OPSEC Mode (rate delay, traffic blending)    — kompleks, beda threat model
⏸ Engagement export/import                     — kebutuhan private saat ini
⏸ Bugcrowd / Intigriti full integration        — H1 dulu
⏸ CI/CD gate (GitHub Actions)                  — belum ada customer yang butuh
⏸ Mobile app testing                           — beda scope
⏸ Multi-GPU / high-end LLM routing             — hardware dependent
```

---

## Cara Memulai Phase 3

Taruh file ini di root repo, lalu gunakan prompt berikut di Copilot Chat:

```
Baca CLAUDE.md, docs/PRD.md, PROGRESS.md, dan PHASE-3-EXECUTION.md secara lengkap.

Kita akan mulai Sprint 4, Task 4.1 — E2E Tests dengan Playwright.

1. Install Playwright di apps/web
2. Buat playwright.config.ts
3. Buat e2e/auth.spec.ts dengan 4 test cases yang dijelaskan di Task 4.1
4. Jalankan tests dan pastikan pass

Ikuti semua konvensi yang ada di CLAUDE.md.
```

---

*Phase 3 Execution Plan — Pentra AI*  
*Dibuat berdasarkan gap analysis dari PROGRESS.md (MVP + Sprint 1–3 complete) vs PRD v0.2*  
*Target setelah Phase 3: platform production-ready yang siap digunakan di lapangan*
