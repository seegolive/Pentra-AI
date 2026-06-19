# SPRINT-17.md — Pentra AI
> **Untuk:** GitHub Copilot dengan Claude Sonnet 4.6  
> **Baca terlebih dahulu:** `CLAUDE.md` → `PROGRESS.md` → file ini  
> **Status:** Sprint 1–16.x, 170 tests, 30/35 smoke  
> **Tujuan:** Selesaikan Sprint 16, validasi E2E, scale KB, tutup gap kualitas

---

## Filosofi Sprint 17

Sprint 1–16 telah membangun platform yang sangat lengkap secara arsitektur.
Sprint 17 bukan tentang fitur baru — ini tentang **membuktikan bahwa semua yang sudah dibangun benar-benar bekerja**.

```
Urutan prioritas:
  1. Selesaikan 16.2 (DO NOT STOP) — 2 jam
  2. E2E-v16 live run — validasi semua Sprint 14-16
  3. Frontend BLOK 6 smoke test manual — tutup 30/35 → 35/35
  4. KB scale-up — import BugHunter patterns + H1 bulk
  5. E2E Playwright untuk BLOK 6 (otomatis)
```

---

## Task 17.1 — Selesaikan DO NOT STOP Routing (dari 16.2)

> **Estimasi:** 2–3 jam  
> **Dependency:** Triage Gate (16.1) sudah ada ✅

### Tambahkan `hunt_rounds` ke PentraState

```python
# packages/pentra-agent/pentra_agent/graph/state.py
# Tambahkan di PentraState TypedDict:

hunt_rounds: int   # Counter untuk prevent infinite loop di DO NOT STOP
```

### Buat conditional routing setelah triage

```python
# packages/pentra-agent/pentra_agent/graph/builder.py

from langchain_core.messages import AIMessage

def route_after_triage(state: PentraState) -> str:
    """
    DO NOT STOP directive dari Claude-BugHunter:
    - Jika triage menemukan CHAIN_REQUIRED findings → balik ke vuln_hunt
    - Max 3 rounds untuk prevent infinite loop
    - Setelah itu → normal flow ke hitl_exploit atau report
    """
    findings = state.get("triaged_findings", state.get("findings", []))
    hunt_rounds = state.get("hunt_rounds", 0)
    MAX_ROUNDS = 3

    if hunt_rounds >= MAX_ROUNDS:
        logger.info(
            "[router] DO NOT STOP: max %d rounds reached — forcing to report", MAX_ROUNDS
        )
        high_value = [f for f in findings if f.get("severity") in ("critical", "high")]
        return "hitl_exploit" if high_value else "report"

    # Cek apakah ada finding yang butuh chain
    chain_required = [
        f for f in findings
        if f.get("triage_verdict") == "CHAIN_REQUIRED"
    ]

    if chain_required:
        logger.info(
            "[router] DO NOT STOP: %d findings need chaining (round %d/%d) — re-entering vuln_hunt",
            len(chain_required), hunt_rounds + 1, MAX_ROUNDS
        )
        return "vuln_hunt"  # Loop kembali

    # Normal flow
    high_value = [f for f in findings if f.get("severity") in ("critical", "high")]
    return "hitl_exploit" if high_value else "report"


# Update graph edges di build_pentra_graph():
# Ganti: graph.add_edge("triage", "hitl_exploit")
# Dengan:
graph.add_conditional_edges(
    "triage",
    route_after_triage,
    {
        "vuln_hunt": "vuln_hunt",      # DO NOT STOP — loop
        "hitl_exploit": "hitl_exploit",
        "report": "report",
    }
)
```

### Update vuln_hunt_node untuk increment hunt_rounds

```python
# packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py
# Di awal fungsi vuln_hunt_node(), tambahkan:

async def vuln_hunt_node(state: PentraState) -> dict:
    current_round = state.get("hunt_rounds", 0)
    logger.info("[vuln_hunt] Starting hunt round %d", current_round + 1)

    # Jika ini chain round, focus pada chain suggestions dari triage
    chain_context = []
    if current_round > 0:
        chain_required = [
            f for f in state.get("triaged_findings", [])
            if f.get("triage_verdict") == "CHAIN_REQUIRED"
        ]
        if chain_required:
            chain_context = [
                f.get("chain_suggestion", "")
                for f in chain_required
                if f.get("chain_suggestion")
            ]
            logger.info(
                "[vuln_hunt] Chain round — focusing on: %s",
                chain_context[:3]
            )

    # ... rest of existing vuln_hunt logic ...

    return {
        # ... existing fields ...
        "hunt_rounds": current_round + 1,  # Increment counter
    }
```

### Tests Task 17.1

```python
# packages/pentra-agent/tests/test_do_not_stop.py

def test_route_after_triage_chain_required_loops_back():
    """CHAIN_REQUIRED finding harus loop kembali ke vuln_hunt."""
    from pentra_agent.graph.builder import route_after_triage
    state = {
        "hunt_rounds": 0,
        "triaged_findings": [
            {"title": "IDOR", "severity": "medium", "triage_verdict": "CHAIN_REQUIRED",
             "chain_suggestion": "Chain with XSS for account takeover"}
        ],
    }
    result = route_after_triage(state)
    assert result == "vuln_hunt"


def test_route_after_triage_max_rounds_stops():
    """Setelah max rounds, tidak boleh loop lagi."""
    from pentra_agent.graph.builder import route_after_triage
    state = {
        "hunt_rounds": 3,  # MAX_ROUNDS
        "triaged_findings": [
            {"title": "IDOR", "severity": "medium", "triage_verdict": "CHAIN_REQUIRED"}
        ],
    }
    result = route_after_triage(state)
    assert result in ("hitl_exploit", "report")  # Tidak loop


def test_route_after_triage_no_chain_goes_to_report():
    """Tanpa chain required dan tanpa high findings → langsung report."""
    from pentra_agent.graph.builder import route_after_triage
    state = {
        "hunt_rounds": 0,
        "triaged_findings": [
            {"title": "Info leak", "severity": "low", "triage_verdict": "PASS"}
        ],
    }
    result = route_after_triage(state)
    assert result == "report"


def test_route_after_triage_high_finding_goes_to_hitl():
    """High finding yang PASS → ke hitl_exploit."""
    from pentra_agent.graph.builder import route_after_triage
    state = {
        "hunt_rounds": 0,
        "triaged_findings": [
            {"title": "SQLi", "severity": "high", "triage_verdict": "PASS"}
        ],
    }
    result = route_after_triage(state)
    assert result == "hitl_exploit"
```

---

## Task 17.2 — E2E-v16 Live Run

> **Manual execution — bukan Copilot**  
> **Target:** testaspnet.vulnweb.com  
> **Tujuan:** Validasi semua fitur Sprint 14–16 bekerja bersama

### Persiapan

```bash
# Pastikan semua berjalan
cd apps/api && uv run alembic upgrade head
nohup uv run uvicorn app.main:app --host 0.0.0.0 --port 8001 &>/tmp/api.log &

# Pastikan Burp Pro aktif
curl -s http://localhost:9877 | head -1

# Token
TOKEN=$(curl -sX POST http://localhost:8001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Pentra@2026!"}' | jq -r .access_token)
```

### Buat Workspace + Engagement v16

```bash
WS_ID=$(curl -sX POST http://localhost:8001/api/v1/workspaces \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"E2E-v16 Validation"}' | jq -r .id)

ENG_ID=$(curl -sX POST http://localhost:8001/api/v1/engagements \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"E2E-v16-FullStack\",
    \"workspace_id\": \"$WS_ID\",
    \"mode\": \"semi_auto\",
    \"in_scope\": [\"testaspnet.vulnweb.com\"],
    \"out_of_scope\": [],
    \"llm_model\": \"qwen2.5:32b\"
  }" | jq -r .id)

echo "ENG_ID=$ENG_ID"
```

### Monitor dengan grep yang spesifik

```bash
# Terminal 1 — API log dengan filter Sprint 14-16 features
tail -f /tmp/api.log | grep -E \
  "osint_node|crt\.sh|h1_program|\
triage|KILL|DOWNGRADE|CHAIN_REQUIRED|\
ANOMALY|ERROR_DISCLOSURE|REFLECTION|SIZE_ANOMALY|\
playbook|sqli_error|xss_reflected|\
react_thought|test_injection|skip_candidate|\
learning|engagement_learning|\
chains|correlate_findings|\
rate_limit_detector|safe_rps|\
summarizer|Compressing messages"
```

### Start dan approve HITL steps

```bash
# Start agent
curl -sX POST http://localhost:8001/api/v1/engagements/$ENG_ID/start \
  -H "Authorization: Bearer $TOKEN" | jq .

# WebSocket monitor di terminal lain
wscat -c "ws://localhost:8001/ws/engagements/$ENG_ID/feed?token=$TOKEN"

# Approve HITL steps saat AWAITING_APPROVAL muncul:
curl -sX POST http://localhost:8001/api/v1/engagements/$ENG_ID/approve \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"approve"}'
```

### Validasi Checklist E2E-v16

```
OSINT Phase
[ ] Log: [osint_node] Starting passive OSINT for testaspnet.vulnweb.com
[ ] Log: crt.sh — N subdomains via certificate transparency
[ ] Log: H1 program found (atau: H1 lookup failed gracefully)
[ ] PentraState.osint_results terisi

Recon Phase  
[ ] Log: [rate_limit_detector] → safe_rps=20 (no rate limiting)
[ ] Log: [recon_node] subfinder: N subdomains
[ ] Log: [recon_node] Rate limit probe: safe_rps=20

Vuln Hunt + Triage
[ ] Log: [vuln_hunt] Running playbook 'SQL Injection — Error Based' for cat param
[ ] Log: ANOMALY SIGNALS: (minimal 1 anomaly terdeteksi)
[ ] Log: [react_thought] action=test_injection / skip_candidate
[ ] Log: [triage] KILL/DOWNGRADE (minimal 1 informational finding di-kill)
[ ] Log: [triage] Triage complete: N passed, M killed, K downgraded

Correlation + CVSS
[ ] Findings di DB punya cvss_vector (bukan null)
[ ] Findings di DB punya chains field (bisa null jika tidak ada chain)
[ ] Log: [report_node] CVSS enrichment: N findings

EngagementLearning
[ ] Log: [report_node] learning saved — tech_stack, effective_tools
[ ] DB: SELECT * FROM engagement_learnings ORDER BY created_at DESC LIMIT 1
```

### Validasi via API setelah selesai

```bash
# Jumlah findings
curl -s http://localhost:8001/api/v1/engagements/$ENG_ID/findings \
  -H "Authorization: Bearer $TOKEN" | jq 'length'
# Expected: lebih sedikit dari E2E-v11 (18) karena triage KILL informational

# Semua findings punya CVSS vector
curl -s http://localhost:8001/api/v1/engagements/$ENG_ID/findings \
  -H "Authorization: Bearer $TOKEN" | \
  jq '[.[] | select(.cvss_vector != null)] | length'
# Expected: sama dengan total findings

# Cek chains
curl -s http://localhost:8001/api/v1/engagements/$ENG_ID/findings \
  -H "Authorization: Bearer $TOKEN" | \
  jq '[.[] | select(.chains != null and (.chains | length) > 0)] | length'
# Expected: >=0 (mungkin 0 jika tidak ada chain pattern)

# Download PDF
curl -s "http://localhost:8001/api/v1/reports/engagements/$ENG_ID?format=pdf" \
  -H "Authorization: Bearer $TOKEN" --output /tmp/e2e-v16-report.pdf
file /tmp/e2e-v16-report.pdf
# Expected: "PDF document"
```

---

## Task 17.3 — Frontend BLOK 6 Smoke Test (Manual)

> **Manual di browser — bukan Copilot**  
> **Prerequisite:** `cd apps/web && pnpm dev`  
> **Tujuan:** Tutup 30/35 → 35/35

```bash
cd apps/web && pnpm dev
# Browser: http://localhost:5173
```

### ST-6.1 Login Flow

```
[ ] Buka /login → form tampil dalam dark mode
[ ] Input admin / Pentra@2026! → klik Sign In
[ ] Redirect ke / (dashboard) dengan workspace list
[ ] Sign out dari navbar → kembali ke /login
[ ] Akses /workspaces langsung (tanpa login) → redirect /login
```

### ST-6.2 Engagement + Live Feed

```
[ ] Buat workspace baru dari UI
[ ] Buat engagement: target testaspnet.vulnweb.com, Semi-Auto mode
[ ] Tombol "Start Agent" ada dan bisa diklik
[ ] Live Feed tab: events muncul real-time (NODE_START berwarna biru)
[ ] HITL dialog muncul saat AWAITING_APPROVAL event
[ ] Dialog tampilkan: phase, message, data context
[ ] Tombol "Approve" berfungsi → dialog hilang → agent lanjut
[ ] Status badge berubah: Idle → Running → Waiting → Running
[ ] WebSocket auto-reconnect setelah tab di-refresh
```

### ST-6.3 FindingsTable

```
[ ] Tab Findings tampilkan findings dari engagement E2E-v16
[ ] Severity pills (critical/high/medium/low) tampil dengan count
[ ] Klik severity pill → filter aktif
[ ] Search box filter by title

[ ] Expand row → detail tampil:
    [ ] CVSS Vector (format CVSS:3.1/...) dalam monospace
    [ ] CVE badges dengan link ke NVD (jika ada)
    [ ] Reproduction steps
    [ ] Request/response (truncated)
    [ ] Attack Chains section (jika chains ada) dengan badge merah

[ ] Tombol "Confirm" → status berubah ke "confirmed" (badge hijau)
[ ] Tombol "False Positive" → status berubah
[ ] Tombol "Add to KB" → tidak error (success toast)
[ ] Auto-refresh setiap 15 detik (check count berubah saat agent masih running)
```

### ST-6.4 ReportViewer

```
[ ] Tab Report → ReportViewer tampil (bukan hanya list button)
[ ] Markdown tab default → text report tampil dalam pre block
[ ] Switch ke HTML tab → render di iframe (tidak blank)
[ ] Download MD → file ter-download
[ ] Download PDF → file ter-download, bisa dibuka
[ ] Refresh button → report di-regenerate
```

### ST-6.5 KB Browser

```
[ ] Navigasi ke /knowledge
[ ] Search "SQL injection" → hasil muncul dalam 5 detik
[ ] Filter severity "high" → hanya high records
[ ] Klik result → detail panel dengan key_insight, quality_score badge
[ ] "Add Knowledge" → form tampil (URL/file/text)
[ ] Submit URL "https://portswigger.net/web-security/sql-injection" → job created
```

---

## Task 17.4 — KB Scale-Up

> **Estimasi:** Background process — bisa berjalan sambil task lain  
> **Tujuan:** 1.500 → 10.000+ records

### Step 1 — Trigger H1 Bulk Import

```bash
# Via Admin UI:
# Buka http://localhost:5173/admin
# Section "Knowledge Base Management"
# Klik [Trigger H1 Import] → max_records: 5000
# Monitor progress di Worker Health UI (/admin/workers)

# Atau via CLI:
curl -sX POST http://localhost:8001/api/v1/admin/knowledge/bulk-import \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"source": "h1_graphql", "max_records": 5000}'

# Monitor Celery
cd apps/worker
uv run celery -A app.worker inspect active
```

### Step 2 — Import BugHunter Patterns

```python
# scripts/import_bughunter_patterns.py
# Fetch 20 hunt-* skills dari GitHub dan inject ke KB

import asyncio
import httpx

SKILL_URLS = {
    "hunt-sqli": "SQL_INJECTION",
    "hunt-xss": "XSS",
    "hunt-ssrf": "SSRF",
    "hunt-idor": "IDOR",
    "hunt-xxe": "XXE",
    "hunt-jwt": "JWT_VULNERABILITY",
    "hunt-oauth": "OAUTH_MISCONFIGURATION",
    "hunt-graphql": "GRAPHQL",
    "hunt-ssti": "SSTI",
    "hunt-rce": "RCE",
    "hunt-file-upload": "PATH_TRAVERSAL",
    "hunt-business-logic": "BUSINESS_LOGIC",
    "hunt-race-conditions": "RACE_CONDITION",
    "hunt-api-misconfig": "MISCONFIGURATION",
    "hunt-auth-bypass": "BROKEN_AUTH",
    "hunt-cache-poison": "CACHE_POISONING",
    "hunt-http-smuggling": "HTTP_SMUGGLING",
    "hunt-ato": "ACCOUNT_TAKEOVER",
    "hunt-mfa-bypass": "AUTH_BYPASS",
    "hunt-pii-leak": "INFORMATION_DISCLOSURE",
}

BASE_URL = "https://raw.githubusercontent.com/elementalsouls/Claude-BugHunter/main/skills"

async def fetch_and_inject(skill_name: str, vuln_class: str, api_token: str):
    """Fetch skill content dan inject ke Pentra AI KB."""
    skill_url = f"{BASE_URL}/{skill_name}.md"

    async with httpx.AsyncClient(timeout=30) as client:
        # Fetch skill content
        try:
            resp = await client.get(skill_url)
            if resp.status_code != 200:
                print(f"❌ {skill_name}: HTTP {resp.status_code}")
                return
            content = resp.text
        except Exception as e:
            print(f"❌ {skill_name}: {e}")
            return

        # Inject ke Pentra AI KB via manual inject endpoint
        inject_resp = await client.post(
            "http://localhost:8001/api/v1/knowledge/inject/raw",
            headers={"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"},
            json={
                "title": f"BugHunter Pattern: {skill_name}",
                "content": content[:5000],  # Max 5000 chars
                "source": "bughunter",
                "vuln_class": vuln_class,
                "quality_score": 0.9,  # High quality — manually curated
                "tags": ["bughunter", "curated", "detection-pattern"],
            }
        )

        if inject_resp.status_code in (200, 201):
            print(f"✅ {skill_name} ({vuln_class}) → imported")
        else:
            print(f"⚠️  {skill_name}: inject failed {inject_resp.status_code}")

async def main():
    token = input("Enter API token: ")
    tasks = [
        fetch_and_inject(skill, vuln, token)
        for skill, vuln in SKILL_URLS.items()
    ]
    await asyncio.gather(*tasks)
    print(f"\nImported {len(SKILL_URLS)} BugHunter patterns")

asyncio.run(main())
```

```bash
# Jalankan
cd pentra-ai
uv run python scripts/import_bughunter_patterns.py
# Input token saat diminta
```

---

## Task 17.5 — E2E Playwright Tests BLOK 6

> **Estimasi:** 2 jam  
> **Tujuan:** Otomatis-kan 5 manual tests yang selalu tertunda

```typescript
// apps/web/e2e/frontend-smoke.spec.ts

import { test, expect, Page } from "@playwright/test";

const BASE_URL = process.env.PLAYWRIGHT_BASE_URL ?? "http://localhost:5173";
const API_URL = process.env.PLAYWRIGHT_API_URL ?? "http://localhost:8001";
const TEST_ENG_ID = process.env.TEST_ENG_ID ?? "";

// Helper: login
async function login(page: Page) {
  await page.goto(`${BASE_URL}/login`);
  await page.getByLabel(/username/i).fill("admin");
  await page.getByLabel(/password/i).fill("Pentra@2026!");
  await page.getByRole("button", { name: /sign in/i }).click();
  await page.waitForURL(`${BASE_URL}/`);
}

// ── ST-6.1 Login Flow ─────────────────────────────────────────────────────

test.describe("ST-6.1 — Login Flow", () => {
  test("login valid → redirect ke dashboard", async ({ page }) => {
    await login(page);
    await expect(page).toHaveURL(`${BASE_URL}/`);
    // Dashboard harus ada setidaknya 1 elemen
    await expect(page.getByRole("heading").first()).toBeVisible();
  });

  test("login invalid → tampilkan error", async ({ page }) => {
    await page.goto(`${BASE_URL}/login`);
    await page.getByLabel(/username/i).fill("admin");
    await page.getByLabel(/password/i).fill("wrong-password");
    await page.getByRole("button", { name: /sign in/i }).click();
    // Error message harus muncul
    await expect(page.getByText(/invalid|incorrect|error/i)).toBeVisible({
      timeout: 5_000,
    });
  });

  test("halaman protected redirect ke login", async ({ page }) => {
    await page.goto(`${BASE_URL}/workspaces`);
    await expect(page).toHaveURL(/\/login/);
  });
});

// ── ST-6.3 FindingsTable ──────────────────────────────────────────────────

test.describe("ST-6.3 — FindingsTable", () => {
  test.skip(!TEST_ENG_ID, "TEST_ENG_ID env var required");

  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test("findings table tampil dengan data", async ({ page }) => {
    await page.goto(`${BASE_URL}/engagements/${TEST_ENG_ID}`);
    await page.getByRole("tab", { name: /findings/i }).click();

    // Tunggu findings load
    await expect(page.locator("table, [role='table']")).toBeVisible({
      timeout: 10_000,
    });
  });

  test("expand row tampilkan detail", async ({ page }) => {
    await page.goto(`${BASE_URL}/engagements/${TEST_ENG_ID}`);
    await page.getByRole("tab", { name: /findings/i }).click();
    await page.waitForTimeout(2000);

    // Klik row pertama untuk expand
    await page.locator("tbody tr").first().click();

    // Detail harus muncul
    await expect(
      page.getByText(/cvss|description|reproduction|request/i).first()
    ).toBeVisible({ timeout: 5_000 });
  });
});

// ── ST-6.5 KB Browser ─────────────────────────────────────────────────────

test.describe("ST-6.5 — KB Browser", () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test("KB search returns results", async ({ page }) => {
    await page.goto(`${BASE_URL}/knowledge`);

    // Cari SQL injection
    const searchInput = page.getByPlaceholder(/search/i).first();
    await searchInput.fill("SQL injection");
    await searchInput.press("Enter");

    // Hasil harus muncul
    await expect(
      page.locator("[data-testid='knowledge-result'], .knowledge-result, tbody tr").first()
    ).toBeVisible({ timeout: 10_000 });
  });
});
```

**Setup playwright.config.ts:**

```typescript
// apps/web/playwright.config.ts — pastikan sudah ada dari Sprint 4
// Jika belum:
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  use: {
    baseURL: process.env.PLAYWRIGHT_BASE_URL ?? "http://localhost:5173",
    screenshot: "only-on-failure",
  },
  webServer: {
    command: "pnpm dev",
    port: 5173,
    reuseExistingServer: !process.env.CI,
  },
});
```

**Jalankan:**

```bash
cd apps/web
TEST_ENG_ID="<paste ENG_ID dari E2E-v16>" \
pnpm playwright test e2e/frontend-smoke.spec.ts --headed
# Expected: 5+ tests pass
```

---

## Checklist Sprint 17

```
Task 17.1 — DO NOT STOP Routing
[ ] hunt_rounds field ditambah ke PentraState
[ ] route_after_triage() dengan DO NOT STOP logic
[ ] vuln_hunt_node increment hunt_rounds di return dict
[ ] builder.py: conditional_edges dari triage
[ ] 4 tests pass: chain loops, max rounds, no chain, high finding

Task 17.2 — E2E-v16 Validation Run
[ ] Engagement berjalan end-to-end tanpa error
[ ] Log: [osint_node] muncul sebelum plan_node
[ ] Log: [rate_limit_detector] safe_rps = 20
[ ] Log: [vuln_hunt] playbook steps muncul per parameter
[ ] Log: ANOMALY SIGNALS muncul minimal 1x
[ ] Log: [triage] KILL/DOWNGRADE minimal 1 finding
[ ] Log: [triage] Triage complete: X passed, Y killed, Z downgraded
[ ] Log: [react_thought] muncul per candidate
[ ] Findings di DB punya cvss_vector (100%)
[ ] PDF report ter-download dan valid
[ ] engagement_learnings record tersimpan

Task 17.3 — Frontend BLOK 6 Manual
[ ] ST-6.1 Login: 4/4 checks ✅
[ ] ST-6.2 Live Feed: 10/10 checks ✅
[ ] ST-6.3 FindingsTable: 10/10 checks ✅
[ ] ST-6.4 ReportViewer: 7/7 checks ✅
[ ] ST-6.5 KB Browser: 7/7 checks ✅
[ ] Smoke test update: 30/35 → 35/35

Task 17.4 — KB Scale-Up
[ ] H1 bulk import triggered dengan max_records: 5000
[ ] Celery worker berjalan untuk import
[ ] Qdrant record count > 5.000 setelah import
[ ] scripts/import_bughunter_patterns.py dibuat
[ ] 20 BugHunter skill patterns imported ke KB
[ ] KB search "SQL injection" return results dari BugHunter source

Task 17.5 — E2E Playwright BLOK 6
[ ] apps/web/e2e/frontend-smoke.spec.ts dibuat
[ ] 3+ tests pass: login valid, login invalid, KB search
[ ] Smoke test BLOK 6 sekarang otomatis

Final Metrics Target
[ ] 170 → 174+ tests passing
[ ] Smoke test: 35/35
[ ] KB records: > 5.000
[ ] E2E-v16: engagement selesai dengan findings yang di-triage
```

---

## Apa yang TIDAK Perlu Dilakukan di Sprint 17

Setelah analisis mendalam, beberapa item dari backlog **bisa ditunda ke v2.0** karena diminishing returns:

```
⏸ Enterprise Attack Matrix (M365/Okta/VPN)
  Alasan: Beda scope dari web bug bounty — perlu research tersendiri
  Impact Pentra AI: Marginal untuk use case utama

⏸ Bugcrowd/Intigriti integration
  Alasan: H1 sudah cukup untuk bug bounty workflow
  Impact: Kecil — user bisa copy-paste ke Bugcrowd

⏸ Mobile app testing
  Alasan: Platform berbeda, perlu tooling khusus

⏸ CI/CD gate integration
  Alasan: Beda target user (DevSecOps vs security researcher)
```

---

## Prompt untuk Copilot

**Task 17.1 — DO NOT STOP:**
```
Baca CLAUDE.md, PROGRESS.md, dan SPRINT-17.md.

Kita mulai Task 17.1 — DO NOT STOP Routing.

1. Tambahkan field `hunt_rounds: int` ke PentraState di state.py
2. Buat fungsi route_after_triage() di builder.py sesuai Task 17.1 SPRINT-17.md
3. Update vuln_hunt_node.py untuk increment hunt_rounds di return dict
4. Update build_pentra_graph() — conditional_edges dari triage node
5. Buat packages/pentra-agent/tests/test_do_not_stop.py dengan 4 tests
6. Jalankan: uv run pytest packages/pentra-agent/tests/ -q

Ikuti konvensi CLAUDE.md.
```

**Task 17.4 — KB Scale-Up:**
```
Task 17.1 selesai. Sekarang Task 17.4 — KB Scale-Up.

1. Buat scripts/import_bughunter_patterns.py sesuai Task 17.4 SPRINT-17.md
2. Test script dengan 3 skill pertama (sqli, xss, ssrf)
3. Trigger H1 bulk import via admin API:
   POST /api/v1/admin/knowledge/bulk-import dengan max_records: 5000
4. Verifikasi Qdrant record count bertambah
```

**Task 17.5 — Playwright:**
```
Buat apps/web/e2e/frontend-smoke.spec.ts sesuai Task 17.5 SPRINT-17.md.
3 test cases: login valid, login invalid, KB search.
Jalankan: pnpm playwright test e2e/frontend-smoke.spec.ts
```

---

*SPRINT-17.md — Pentra AI*  
*Validasi, kelengkapan, dan quality — sebelum v1.0 release*  
*Target: 174+ tests, 35/35 smoke, 5000+ KB records, E2E-v16 validated*
