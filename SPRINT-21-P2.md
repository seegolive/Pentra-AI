# SPRINT-21-P2.md — Pentra AI
> **Untuk:** GitHub Copilot  
> **Baca:** `CLAUDE.md` → `PROGRESS.md` → file ini  
> **Status:** Sprint 21 validation partial — 3/8 tasks done  
> **Tujuan:** Fix critical bug + complete remaining validations

---

## Status Sprint 21

```
✅ 21.3 GraphQL E2E    — introspection confirmed (trevorblades)
✅ 21.4 Race Condition  — TOCTOU confirmed 20/20 (Flask mock)
✅ 21.5 JWT E2E         — alg:none confirmed (Flask mock)

❌ BUG DITEMUKAN       — httpx 'proxies' → harus fix SEKARANG
⏳ 21.2 DVWA Auth Scan — "mock" dilaporkan, perlu real DVWA
⏳ 21.6 Playwright      — belum dikerjakan
⏳ 21.7 Takeover mock  — belum dikerjakan
⏳ 21.8 EngagementLearning — belum dikerjakan
⏳ 21.1 PROGRESS.md    — belum di-update
```

---

## URGENT — Fix httpx proxies Bug

> **Estimasi:** 30 menit  
> **Blocking:** Authenticated scan crash setiap kali dijalankan

### Diagnosa

```bash
# Konfirmasi bug
grep -rn "proxies=" packages/pentra-tools/pentra_tools/auth/session_manager.py
grep -rn "proxies=" packages/pentra-agent/ packages/pentra-tools/ apps/ --include="*.py" | \
  grep -v ".pyc\|#\|test_" | head -20
```

### Fix

```python
# packages/pentra-tools/pentra_tools/auth/session_manager.py
# Cari semua instance httpx.AsyncClient(proxies=...) dan ganti:

# SEBELUM (httpx ≤0.19 — broken di versi terinstall):
async with httpx.AsyncClient(proxies={"http://": proxy}) as client:
async with httpx.AsyncClient(proxies={"https://": proxy}) as client:
async with httpx.AsyncClient(proxies={"all://": proxy}) as client:

# SESUDAH (httpx ≥0.20):
async with httpx.AsyncClient(proxy=proxy) as client:
# Jika butuh dict format:
async with httpx.AsyncClient(mounts={"http://": httpx.HTTPTransport(proxy=proxy)}) as client:
```

```bash
# Setelah fix, jalankan tests
uv run pytest packages/pentra-tools/tests/test_session_manager.py -v
# Expected: semua pass

# Verify fix
python3 -c "
import httpx
# Test bahwa proxy= (bukan proxies=) berfungsi
print('httpx version:', httpx.__version__)
# Jika tidak error = fix berhasil
c = httpx.AsyncClient()
print('AsyncClient OK')
"
```

---

## Task 21.2 — DVWA Real (Bukan Mock)

> **Estimasi:** 1-2 jam  
> **Prerequisite:** httpx bug sudah difix

### Setup DVWA

```bash
# Pull dan jalankan DVWA
docker pull vulnerables/web-dvwa
docker run -d --name dvwa_test -p 8080:80 vulnerables/web-dvwa
sleep 5

# Verifikasi DVWA up
curl -s http://localhost:8080/login.php | grep -i "dvwa\|login" | head -3
# Expected: ada form login DVWA

# Setup database DVWA (required sebelum bisa login)
curl -s -c /tmp/dvwa_cookie.txt \
  http://localhost:8080/setup.php \
  -d "create_db=Create+%2F+Reset+Database" | grep -i "success\|created"

# Test login manual
curl -s -c /tmp/dvwa_session.txt \
  -X POST http://localhost:8080/login.php \
  -d "username=admin&password=password&Login=Login" \
  -L | grep -i "dashboard\|logout\|welcome" | head -3
# Expected: ada kata dashboard atau logout
```

### Run Authenticated Scan

```bash
# Jalankan dengan auto-login
uv run python scripts/live_scan.py \
  --domain localhost:8080 \
  --preset authenticated \
  --auth-login-url "http://localhost:8080/login.php" \
  --auth-user "admin" \
  --auth-pass "password" \
  2>&1 | tee /tmp/dvwa-scan.log

# Monitor log
tail -f /tmp/pentra.log | grep -E \
  "auth.*session|cookie.*inject|auto.*login|\
  sqli.*confirmed|xss.*confirmed|lfi.*confirmed|\
  idor.*confirmed|gf.*pattern|playbook"
```

### Expected Findings di DVWA

DVWA adalah deliberately vulnerable — expected findings dengan `--security=low` (DVWA default):

```
/vulnerabilities/sqli/?id=1           → SQLi (id param, integer)
/vulnerabilities/sqli_blind/?id=1     → Blind SQLi
/vulnerabilities/xss_r/?name=test     → Reflected XSS
/vulnerabilities/xss_s/               → Stored XSS (POST)
/vulnerabilities/fi/?page=include.php → LFI / File Inclusion
/vulnerabilities/idor/                → IDOR (user lookup)
/vulnerabilities/csrf/                → CSRF (POST request)
/vulnerabilities/exec/                → Command Injection
```

### Checklist DVWA E2E

```
[ ] auto-login berhasil (session cookie ter-inject ke requests)
[ ] Recon menemukan /vulnerabilities/* endpoints
[ ] GF patterns match: ?id=1, ?page=, ?name= (semua punya GF pattern)
[ ] SQLi ditemukan di /vulnerabilities/sqli/?id=
[ ] XSS ditemukan di /vulnerabilities/xss_r/?name=
[ ] LFI ditemukan di /vulnerabilities/fi/?page=
[ ] Findings >= 3 confirmed
[ ] Auth headers di-inject ke semua tool calls (verify di log)
[ ] Report PDF berhasil generate
```

- [ ] PASS / [ ] FAIL

---

## Task 21.6 — Playwright Frontend Tests

> **Estimasi:** 1 jam

### Setup

```bash
cd apps/web
pnpm add -D @playwright/test
npx playwright install chromium --with-deps
```

### Test File

```typescript
// apps/web/e2e/smoke.spec.ts

import { test, expect } from '@playwright/test';

const BASE = process.env.BASE_URL ?? 'http://localhost:5173';

// Helper: login
async function login(page: any) {
  await page.goto(`${BASE}/login`);
  await page.getByLabel(/username/i).fill('admin');
  await page.getByLabel(/password/i).fill('Pentra@2026!');
  await page.getByRole('button', { name: /sign in/i }).click();
  await page.waitForURL(`${BASE}/`);
}

test('ST-6.1 login valid', async ({ page }) => {
  await login(page);
  await expect(page).toHaveURL(`${BASE}/`);
});

test('ST-6.2 login invalid shows error', async ({ page }) => {
  await page.goto(`${BASE}/login`);
  await page.getByLabel(/username/i).fill('admin');
  await page.getByLabel(/password/i).fill('wrongpassword');
  await page.getByRole('button', { name: /sign in/i }).click();
  await expect(page.getByText(/invalid|incorrect|error/i)).toBeVisible({ timeout: 5000 });
});

test('ST-6.3 protected route redirects to login', async ({ page }) => {
  await page.goto(`${BASE}/workspaces`);
  await expect(page).toHaveURL(/login/);
});

test('ST-6.4 dashboard has content', async ({ page }) => {
  await login(page);
  // Dashboard harus tampilkan sesuatu — workspace, stats, atau empty state
  await expect(page.locator('h1, h2, [data-testid="dashboard"]').first())
    .toBeVisible({ timeout: 5000 });
});

test('ST-6.5 KB browser search', async ({ page }) => {
  await login(page);
  await page.goto(`${BASE}/knowledge`);
  // Cari search input
  const searchInput = page.getByPlaceholder(/search/i).first();
  await searchInput.fill('SQL injection');
  await searchInput.press('Enter');
  // Tunggu hasil
  await expect(
    page.locator('table tbody tr, [data-testid="kb-result"], .result-item').first()
  ).toBeVisible({ timeout: 10000 });
});
```

```typescript
// apps/web/playwright.config.ts

import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  timeout: 30000,
  use: {
    baseURL: process.env.BASE_URL ?? 'http://localhost:5173',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  webServer: {
    command: 'pnpm dev',
    port: 5173,
    reuseExistingServer: true,
    timeout: 30000,
  },
});
```

### Run

```bash
cd apps/web
npx playwright test e2e/smoke.spec.ts --headed 2>&1 | tail -20
# Expected: 5 passed
```

- [ ] 5/5 PASS / [ ] FAIL

---

## Task 21.7 — Subdomain Takeover Validation

> **Estimasi:** 15 menit

```bash
python3 << 'EOF'
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

async def test_takeover():
    """
    Simulate subdomain takeover detection.
    Testing yang diperlukan cukup dengan mock karena:
    - DNS query real akan lambat dan tidak deterministik
    - Logic yang penting adalah fingerprint matching
    """
    from pentra_tools.recon.takeover_detector import (
        check_takeover_fingerprint,
        TAKEOVER_FINGERPRINTS,
    )
    
    print(f"Fingerprints loaded: {len(TAKEOVER_FINGERPRINTS)}")
    
    tests = [
        ("old-blog.target.com", "target-org.github.io",
         "There isn't a GitHub Pages site here", "GitHub Pages"),
        ("app.target.com", "target.herokuapp.com",
         "No such app", "Heroku"),
        ("media.target.com", "target.s3.amazonaws.com",
         "NoSuchBucket", "AWS S3"),
    ]
    
    passed = 0
    for subdomain, cname, fingerprint_body, expected_service in tests:
        mock_resp = MagicMock()
        mock_resp.text = f"<html><p>{fingerprint_body}</p></html>"
        mock_resp.status_code = 404
        
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        
        result = await check_takeover_fingerprint(subdomain, cname, mock_client)
        
        if result and result.service == expected_service:
            print(f"  ✅ {expected_service}: {subdomain} → {result.confidence}")
            passed += 1
        else:
            print(f"  ❌ {expected_service}: expected finding, got {result}")
    
    print(f"\nTakeover tests: {passed}/{len(tests)}")

asyncio.run(test_takeover())
EOF
```

- [ ] 3/3 PASS / [ ] FAIL

---

## Task 21.8 — EngagementLearning in plan_node

> **Estimasi:** 2 jam

### Buat `packages/pentra-agent/pentra_agent/utils/learning_query.py`

```python
# packages/pentra-agent/pentra_agent/utils/learning_query.py

"""
Query EngagementLearning records untuk konteks plan_node.
Terinspirasi dari PentAGI Graphiti-style knowledge reuse.
"""

import logging
import os
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)


async def query_similar_learnings(
    tech_stack: list[str],
    db_url: str | None = None,
    limit: int = 3,
) -> list:
    """
    Query engagement learnings yang relevan berdasarkan tech stack overlap.
    
    Returns:
        List of EngagementLearningORM objects, sorted by high_critical_count desc.
        Empty list jika db_url None atau DB tidak tersedia.
    """
    if not db_url:
        return []

    try:
        from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
        from sqlalchemy import select
        from apps.api.app.db.models import EngagementLearningORM

        engine = create_async_engine(db_url, echo=False)
        async with AsyncSession(engine) as session:
            result = await session.execute(
                select(EngagementLearningORM)
                .where(EngagementLearningORM.findings_count > 0)
                .order_by(EngagementLearningORM.high_critical_count.desc())
                .limit(limit * 3)
            )
            all_learnings = result.scalars().all()

        # Score by tech stack overlap
        scored = []
        for l in all_learnings:
            l_tech = [t.lower() for t in (l.tech_stack or [])]
            score = sum(
                2 for t in tech_stack
                if t.lower() in l_tech
            )
            if score > 0:
                scored.append((score, l))

        scored.sort(key=lambda x: -x[0])
        top = [l for _, l in scored[:limit]]

        if top:
            logger.info(
                "[learning_query] %d relevant past engagements found "
                "(tech overlap: %s)",
                len(top),
                [l.tech_stack for l in top[:2]],
            )

        return top

    except Exception as e:
        logger.debug("[learning_query] Query failed (non-critical): %s", e)
        return []


def format_learning_context(learnings: list) -> str:
    """
    Format learnings sebagai context string untuk LLM prompt.
    """
    if not learnings:
        return ""

    lines = ["Past similar engagements:"]
    for l in learnings:
        ep_patterns = [
            ep.get("pattern", "")
            for ep in (l.high_value_endpoints or [])[:3]
            if ep.get("pattern")
        ]
        lines.append(
            f"- {l.tech_stack} target: {l.findings_count} findings "
            f"({l.high_critical_count} high/critical). "
            f"Effective tools: {l.effective_tools}. "
            + (f"High-value endpoints: {ep_patterns}." if ep_patterns else "")
        )

    return "\n".join(lines)
```

### Update `plan_node.py`

```python
# packages/pentra-agent/pentra_agent/nodes/plan_node.py
# Tambahkan setelah knowledge query, sebelum llm.plan_engagement():

from pentra_agent.utils.learning_query import (
    query_similar_learnings,
    format_learning_context,
)

# Query past learnings
past_learnings = await query_similar_learnings(
    tech_stack=state.get("tech_stack", []),
    db_url=os.getenv("DATABASE_URL"),
)
learning_context = format_learning_context(past_learnings)

if learning_context:
    logger.info("[plan_node] Injecting %d past learnings into plan", len(past_learnings))

# Update plan generation call
plan = await llm.plan_engagement(
    target=state["target"],
    scope=state["scope"],
    knowledge_hints=[k.model_dump() for k in knowledge],
    learning_context=learning_context,  # NEW
)
```

### Update `LLMClient.plan_engagement()`

```python
# packages/pentra-agent/pentra_agent/llm/client.py
# Tambahkan learning_context parameter:

async def plan_engagement(
    self,
    target: dict,
    scope: dict,
    knowledge_hints: list[dict],
    learning_context: str = "",   # NEW
) -> str:
    user = f"""Target: {json.dumps(target, indent=2)}
Scope: {json.dumps(scope, indent=2)}
Similar findings from knowledge base:
{json.dumps(knowledge_hints[:5], indent=2)}
"""
    if learning_context:
        user += f"\n{learning_context}\n"
    user += "\nCreate a prioritized pentest plan."
    return await self.complete(system, user)
```

### Tests

```python
# packages/pentra-agent/tests/test_learning_query.py

import pytest


def test_query_similar_learnings_no_db():
    """Tanpa DB URL harus return empty list."""
    import asyncio
    from pentra_agent.utils.learning_query import query_similar_learnings
    result = asyncio.run(query_similar_learnings(tech_stack=["ASP.NET"], db_url=None))
    assert result == []


def test_format_learning_context_empty():
    """Empty learnings → empty string."""
    from pentra_agent.utils.learning_query import format_learning_context
    assert format_learning_context([]) == ""


def test_format_learning_context_with_data():
    """Learning context harus include tech_stack dan findings_count."""
    from pentra_agent.utils.learning_query import format_learning_context
    from unittest.mock import MagicMock

    mock_learning = MagicMock()
    mock_learning.tech_stack = ["ASP.NET", "IIS"]
    mock_learning.findings_count = 8
    mock_learning.high_critical_count = 3
    mock_learning.effective_tools = ["nuclei", "burp"]
    mock_learning.high_value_endpoints = [{"pattern": "/products?id="}]

    result = format_learning_context([mock_learning])
    assert "ASP.NET" in result
    assert "8 findings" in result
    assert "nuclei" in result
```

---

## Task 21.1 — Update PROGRESS.md

```bash
# Setelah semua task selesai, update PROGRESS.md:
# 1. Test count: 268 → 302+
# 2. bge-m3: 2,757/2,758 → 8,309/8,309  
# 3. Smoke test: 43/45 → 45/45
# 4. Add Sprint 21 completion entry
```

---

## Checklist Sprint 21 P2

```
BUG FIX (URGENT)
[ ] httpx proxies= → proxy= fix di session_manager.py
[ ] uv run pytest tests/ -q → tidak ada regression
[ ] Authenticated scan tidak crash lagi

Task 21.2 — DVWA Real
[ ] docker run vulnerables/web-dvwa berhasil
[ ] DVWA accessible di localhost:8080
[ ] auto-login berhasil (session cookie diperoleh)
[ ] Scan menemukan SQLi/XSS di /vulnerabilities/*
[ ] >= 3 confirmed findings
[ ] Auth headers ter-inject (verify dari log)

Task 21.6 — Playwright
[ ] playwright.config.ts dibuat
[ ] smoke.spec.ts dengan 5 tests
[ ] npx playwright test → 5/5 passed

Task 21.7 — Takeover Mock
[ ] 3/3 fingerprint tests passed

Task 21.8 — EngagementLearning
[ ] learning_query.py dibuat
[ ] plan_node inject learning context
[ ] LLMClient.plan_engagement() punya param learning_context
[ ] 3 unit tests pass
[ ] Log: "[plan_node] Injecting N past learnings" saat ada history

Task 21.1 — PROGRESS.md Updated
[ ] Test count benar
[ ] bge-m3 count benar
[ ] Smoke test result benar
[ ] Sprint 21 entry lengkap

Final
[ ] uv run pytest packages/ -q → 305+ tests, 0 failed
```

---

## Prompt untuk Copilot

**Mulai bug fix dulu (urgent):**

```
Baca CLAUDE.md, PROGRESS.md, dan SPRINT-21-P2.md.

Ada critical bug ditemukan dari Sprint 21 validation:
session_manager.py menggunakan httpx API lama: 'proxies='
httpx versi terinstall menggunakan 'proxy=' (singular)

Task pertama:
1. grep -rn "proxies=" packages/pentra-tools/pentra_tools/auth/session_manager.py
2. Fix semua instance: proxies={...} → proxy=url_string
3. Jalankan: uv run pytest packages/pentra-tools/tests/ -q
4. Verifikasi tidak ada regression

Setelah bug difix, lanjut Task 21.2 (DVWA setup + authenticated scan).
```

**Setelah bug fix + DVWA, lanjut task ringan:**

```
Bug fix selesai, DVWA E2E selesai.
Kerjakan berurutan:
- Task 21.7: takeover mock test (15 menit)
- Task 21.8: learning_query.py + update plan_node (2 jam)  
- Task 21.6: Playwright tests (1 jam)
- Task 21.1: update PROGRESS.md
```

---

*SPRINT-21-P2.md — Pentra AI*
*Fix httpx bug + DVWA real E2E + complete remaining validations*
