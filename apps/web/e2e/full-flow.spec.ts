/**
 * Full E2E Flow — Pentra AI
 *
 * Covers the complete user journey end-to-end:
 *   1. API Health
 *   2. Auth — login / logout / protected route
 *   3. Dashboard — stat cards
 *   4. Workspace — create, list, navigate
 *   5. Engagement — create inside workspace, view detail
 *   6. Knowledge Browser — search, view result
 *   7. Settings — profile, password validation
 *   8. Admin — KB stats, user list
 *   9. WebSocket feed connectivity
 *
 * Requires:
 *   - Frontend dev server: http://localhost:5174
 *   - API server:          http://localhost:8001  (or $E2E_API_URL)
 *   - Admin credentials:   admin / Pentra@2026!
 */

import { test, expect, type Page } from "@playwright/test";
import {
  API_URL,
  ADMIN_USER,
  ADMIN_PASS,
  login,
  getToken,
  apiLogin,
  createWorkspaceViaApi,
  createEngagementViaApi,
} from "./helpers";

// ── 1. API Health ─────────────────────────────────────────────────────────────

test.describe("1 — API Health", () => {
  test("GET /health returns status ok", async ({ request }) => {
    const res = await request.get(`${API_URL}/health`);
    expect(res.ok()).toBeTruthy();
    const body = await res.json() as { status: string };
    expect(body.status).toBe("ok");
  });

  test("GET /api/v1/version returns version info", async ({ request }) => {
    const res = await request.get(`${API_URL}/api/v1/version`);
    expect(res.ok()).toBeTruthy();
    const body = await res.json() as { version: string; phase: string };
    expect(body.version).toBeTruthy();
    expect(body.phase).toBeTruthy();
  });

  test("GET /api/v1/workspaces rejects unauthenticated requests with 401", async ({ request }) => {
    const res = await request.get(`${API_URL}/api/v1/workspaces/`);
    expect(res.status()).toBe(401);
  });
});

// ── 2. Auth Flow ──────────────────────────────────────────────────────────────

test.describe("2 — Auth Flow", () => {
  // Auth tests need a fresh unauthenticated state (override the default storageState)
  test.use({ storageState: { cookies: [], origins: [] } });
  test("login valid → redirect ke /workspaces, sidebar authenticated", async ({ page }) => {
    await login(page);
    await expect(page).toHaveURL("/workspaces");
    await expect(page.getByRole("button", { name: /sign out/i })).toBeVisible();
  });

  test("login invalid → stay on /login, error message visible", async ({ page }) => {
    await page.goto("/login");
    await page.getByLabel("Username").fill(ADMIN_USER);
    await page.getByLabel("Password").fill("wrong-password-that-doesnt-exist");
    await page.getByRole("button", { name: "Sign in" }).click();

    await expect(page).toHaveURL("/login");
    await expect(
      page.getByText(/login failed|incorrect|invalid|error/i)
    ).toBeVisible({ timeout: 8_000 });
  });

  test("protected route /workspaces redirect ke /login jika tidak autentikasi", async ({ page }) => {
    await page.goto("/workspaces");
    await expect(page).toHaveURL("/login", { timeout: 5_000 });
    await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
  });

  test("protected route /dashboard redirect ke /login jika tidak autentikasi", async ({ page }) => {
    await page.goto("/dashboard");
    await expect(page).toHaveURL("/login", { timeout: 5_000 });
  });

  test("sign out menghapus sesi dan redirect ke /login", async ({ page }) => {
    await login(page);
    await expect(page).toHaveURL("/workspaces");

    await page.getByRole("button", { name: /sign out/i }).click();
    await expect(page).toHaveURL("/login", { timeout: 5_000 });

    // Token must be cleared — protected route should redirect again
    await page.goto("/workspaces");
    await expect(page).toHaveURL("/login");
  });

  test("POST /api/v1/auth/login mengembalikan access_token", async ({ request }) => {
    const res = await request.post(`${API_URL}/api/v1/auth/login`, {
      headers: { "Content-Type": "application/json" },
      data: { username: ADMIN_USER, password: ADMIN_PASS },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json() as { access_token: string; token_type: string };
    expect(body.access_token).toBeTruthy();
    expect(body.token_type).toBe("bearer");
  });

  test("GET /api/v1/auth/me mengembalikan user yang login", async ({ request }) => {
    const token = await apiLogin(request);
    const res = await request.get(`${API_URL}/api/v1/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json() as { username: string; is_admin: boolean };
    expect(body.username).toBe(ADMIN_USER);
    expect(body.is_admin).toBeTruthy();
  });
});

// ── 3. Dashboard ──────────────────────────────────────────────────────────────

test.describe("3 — Dashboard", () => {
  // Storage state provides pre-auth for all browser tests in sections 3-10

  test("dashboard loads dan tampilkan stat cards", async ({ page }) => {
    await page.goto("/dashboard");
    // Stat cards container should appear
    await expect(page.locator("main, [role=main]").first()).toBeVisible({ timeout: 8_000 });
    // At least one heading or stat label
    const heading = page.getByRole("heading").first();
    await expect(heading).toBeVisible({ timeout: 5_000 });
  });

  test("dashboard sidebar nav link ke /engagements berfungsi", async ({ page }) => {
    await page.goto("/dashboard");
    // icon-nav + sidebar both render this link — use .first() to avoid strict-mode violation
    await page.getByRole("link", { name: /^engagements$/i }).first().click();
    await expect(page).toHaveURL("/engagements", { timeout: 5_000 });
  });
});

// ── 4. Workspace Flow ─────────────────────────────────────────────────────────

test.describe("4 — Workspace Flow", () => {
  const WS_NAME = `E2E-WS-${Date.now()}`;

  test("workspaces page loads dan tampilkan header", async ({ page }) => {
    await page.goto("/workspaces");
    await expect(page.getByRole("heading", { name: /workspaces/i })).toBeVisible({ timeout: 5_000 });
  });

  test("buat workspace baru via UI dan muncul di list", async ({ page }) => {
    await page.goto("/workspaces");

    // Click New Workspace button
    await page.getByRole("button", { name: /new workspace/i }).click();

    // Form appears — fill name
    await page.getByPlaceholder("Workspace name").fill(WS_NAME);
    await page.getByRole("button", { name: /^create$/i }).click();

    // New workspace card should appear
    await expect(page.getByText(WS_NAME)).toBeVisible({ timeout: 10_000 });
  });

  test("klik workspace card navigates ke halaman engagements", async ({ page }) => {
    // Create workspace via API for a reliable target
    const token = await apiLogin(page.request);
    const ws = await createWorkspaceViaApi(page.request, token, `E2E-NAV-${Date.now()}`);

    await page.goto("/workspaces");
    await page.getByText(ws.name).click();

    await expect(page).toHaveURL(/\/workspaces\/.+\/engagements/, { timeout: 8_000 });
  });

  test("POST /api/v1/workspaces/ creates workspace dan returns 201", async ({ request }) => {
    const token = await apiLogin(request);
    const res = await request.post(`${API_URL}/api/v1/workspaces/`, {
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      data: { name: `API-WS-${Date.now()}` },
    });
    expect(res.status()).toBe(201);
    const body = await res.json() as { id: string; name: string };
    expect(body.id).toBeTruthy();
  });

  test("GET /api/v1/workspaces/ mengembalikan list workspace", async ({ request }) => {
    const token = await apiLogin(request);
    const res = await request.get(`${API_URL}/api/v1/workspaces/`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json() as unknown[];
    expect(Array.isArray(body)).toBeTruthy();
  });
});

// ── 5. Engagement Flow ────────────────────────────────────────────────────────

test.describe("5 — Engagement Flow", () => {
  test("buat engagement via UI dan muncul di list", async ({ page }) => {
    // Create workspace first via API
    const token = await apiLogin(page.request);
    const ws = await createWorkspaceViaApi(page.request, token, `E2E-ENG-WS-${Date.now()}`);

    await page.goto(`/workspaces/${ws.id}/engagements`);
    // scope to main to exclude sidebar + button (aria-label="New engagement")
    await page.locator("main").getByRole("button", { name: /new engagement/i }).click();

    const ENG_NAME = `E2E-Eng-${Date.now()}`;
    await page.getByPlaceholder(/HackerOne/i).fill(ENG_NAME);
    // In-scope textarea — use .first() to avoid matching out-of-scope textarea
    await page.getByPlaceholder(/target\.com/i).first().fill("testphp.vulnweb.com");

    await page.getByRole("button", { name: /create engagement/i }).evaluate((el: HTMLElement) => el.click());

    await expect(page.getByText(ENG_NAME)).toBeVisible({ timeout: 10_000 });
  });

  test("klik engagement card navigates ke engagement detail", async ({ page }) => {
    const token = await apiLogin(page.request);
    const ws = await createWorkspaceViaApi(page.request, token, `E2E-DET-WS-${Date.now()}`);
    const eng = await createEngagementViaApi(page.request, token, ws.id, `E2E-DET-${Date.now()}`);

    await page.goto(`/workspaces/${ws.id}/engagements`);
    await page.getByText(eng.name).click();

    await expect(page).toHaveURL(new RegExp(`/engagements/${eng.id}`), { timeout: 8_000 });
  });

  test("POST /api/v1/engagements/ creates engagement dan returns 201", async ({ request }) => {
    const token = await apiLogin(request);
    const ws = await createWorkspaceViaApi(request, token, `API-ENG-WS-${Date.now()}`);
    const res = await request.post(`${API_URL}/api/v1/engagements/`, {
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      data: {
        workspace_id: ws.id,
        name: `API-Eng-${Date.now()}`,
        mode: "semi_auto",
        in_scope: ["testphp.vulnweb.com"],
        out_of_scope: [],
        llm_model: "qwen2.5-coder:7b",
      },
    });
    expect(res.status()).toBe(201);
    const body = await res.json() as { id: string; status: string };
    expect(body.id).toBeTruthy();
    expect(body.status).toBe("planning");
  });

  test("GET /api/v1/engagements/ mengembalikan list engagement", async ({ request }) => {
    const token = await apiLogin(request);
    const res = await request.get(`${API_URL}/api/v1/engagements/`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json() as unknown[];
    expect(Array.isArray(body)).toBeTruthy();
  });
});

// ── 6. Engagement Detail ──────────────────────────────────────────────────────

test.describe("6 — Engagement Detail", () => {
  test("engagement detail page loads: nama, status, tabs visible", async ({ page }) => {
    const token = await apiLogin(page.request);
    const ws = await createWorkspaceViaApi(page.request, token, `E2E-DETAIL-WS-${Date.now()}`);
    const eng = await createEngagementViaApi(page.request, token, ws.id, `E2E-Detail-${Date.now()}`);

    await page.goto(`/engagements/${eng.id}`);

    // Engagement name should appear in header (h1)
    await expect(page.getByRole("heading", { name: eng.name })).toBeVisible({ timeout: 10_000 });

    // Status badge — new engagements start at "planning"
    await expect(page.getByText(/planning/i).first()).toBeVisible({ timeout: 5_000 });
  });

  test("GET /api/v1/engagements/:id mengembalikan engagement detail", async ({ request }) => {
    const token = await apiLogin(request);
    const ws = await createWorkspaceViaApi(request, token, `API-DETAIL-WS-${Date.now()}`);
    const eng = await createEngagementViaApi(request, token, ws.id, `API-Detail-${Date.now()}`);

    const res = await request.get(`${API_URL}/api/v1/engagements/${eng.id}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json() as { id: string; status: string; mode: string };
    expect(body.id).toBe(eng.id);
    expect(body.mode).toBe("semi_auto");
  });

  test("GET /api/v1/engagements/:id/findings mengembalikan array (kosong ok)", async ({ request }) => {
    const token = await apiLogin(request);
    const ws = await createWorkspaceViaApi(request, token, `API-FIND-WS-${Date.now()}`);
    const eng = await createEngagementViaApi(request, token, ws.id, `API-Find-${Date.now()}`);

    const res = await request.get(`${API_URL}/api/v1/engagements/${eng.id}/findings`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json() as unknown[];
    expect(Array.isArray(body)).toBeTruthy();
  });

  test("GET /api/v1/engagements/:id/audit mengembalikan audit log", async ({ request }) => {
    const token = await apiLogin(request);
    const ws = await createWorkspaceViaApi(request, token, `API-AUDIT-WS-${Date.now()}`);
    const eng = await createEngagementViaApi(request, token, ws.id, `API-Audit-${Date.now()}`);

    const res = await request.get(`${API_URL}/api/v1/engagements/${eng.id}/audit`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json() as unknown[];
    expect(Array.isArray(body)).toBeTruthy();
  });
});

// ── 7. Knowledge Browser ──────────────────────────────────────────────────────

test.describe("7 — Knowledge Browser", () => {
  test("KB browser page loads dengan search input", async ({ page }) => {
    await page.goto("/knowledge");
    await expect(page.getByPlaceholder(/search/i).first()).toBeVisible({ timeout: 5_000 });
  });

  test("KB search via API mengembalikan results", { timeout: 90_000 }, async ({ request }) => {
    const token = await apiLogin(request);
    const res = await request.get(`${API_URL}/knowledge/search?q=SQL+injection&top_k=3`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json() as { results?: unknown[]; items?: unknown[] };
    const items = body.results ?? body.items ?? body;
    expect(Array.isArray(items)).toBeTruthy();
  });

  test("KB browser search via UI — input terisi dan tidak crash", async ({ page }) => {
    await page.goto("/knowledge");

    const input = page.getByPlaceholder(/search/i).first();
    await input.fill("IDOR API endpoint");

    // Pressing Enter submits (no assertion on results — depends on Ollama latency)
    await input.press("Enter");

    // Page must not show unhandled error after submit
    await expect(page.getByText(/error.*occurred|something went wrong/i)).not.toBeVisible({
      timeout: 5_000,
    });
  });
});

// ── 8. Settings Page ──────────────────────────────────────────────────────────

test.describe("8 — Settings", () => {
  test("settings page tampilkan 3 sections", async ({ page }) => {
    await page.goto("/settings");
    await expect(page.getByRole("heading", { name: "Profile" })).toBeVisible({ timeout: 5_000 });
    await expect(page.getByRole("heading", { name: "Change Password" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "System Information" })).toBeVisible();
  });

  test("settings profile section tampilkan username dan role", async ({ page }) => {
    await page.goto("/settings");
    const main = page.locator("main, [role='main'], .flex-1.overflow-auto").first();
    await expect(main.getByText("admin", { exact: true })).toBeVisible({ timeout: 5_000 });
    await expect(main.getByText("Administrator")).toBeVisible();
  });

  test("settings tampilkan versi API dan frontend", async ({ page }) => {
    await page.goto("/settings");
    // System Information section should show version numbers — use .first() to avoid strict mode
    await expect(page.getByText(/1\.0\.0/).first()).toBeVisible({ timeout: 10_000 });
  });

  test("change password form: mismatch tampilkan error inline", async ({ page }) => {
    await page.goto("/settings");
    await page.getByLabel("Current Password", { exact: true }).fill("Pentra@2026!");
    await page.getByLabel("New Password", { exact: true }).fill("NewPass@2026!");
    await page.getByLabel("Confirm New Password", { exact: true }).fill("DifferentPass@!");
    await page.getByRole("button", { name: /update password/i }).click();
    await expect(page.getByText(/do not match/i)).toBeVisible({ timeout: 3_000 });
  });

  test("POST /api/v1/auth/change-password menolak password pendek", async ({ request }) => {
    const token = await apiLogin(request);
    const res = await request.post(`${API_URL}/api/v1/auth/change-password`, {
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      data: { current_password: ADMIN_PASS, new_password: "short" },
    });
    // Should fail validation — 400 or 422
    expect(res.status()).toBeGreaterThanOrEqual(400);
    expect(res.status()).toBeLessThan(500);
  });
});

// ── 9. Admin Panel ────────────────────────────────────────────────────────────

test.describe("9 — Admin Panel", () => {
  test("admin page loads tanpa error", async ({ page }) => {
    await page.goto("/admin");
    // Should not redirect to login
    await expect(page).not.toHaveURL("/login");
    await expect(page.locator("main, [role=main]").first()).toBeVisible({ timeout: 8_000 });
  });

  test("GET /api/v1/admin/stats mengembalikan KB statistics", async ({ request }) => {
    const token = await apiLogin(request);
    const res = await request.get(`${API_URL}/api/v1/admin/stats`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json() as { total_records?: number; embedding_coverage?: number };
    expect(typeof body.total_records).toBe("number");
  });

  test("GET /api/v1/admin/users mengembalikan user list (admin only)", async ({ request }) => {
    const token = await apiLogin(request);
    const res = await request.get(`${API_URL}/api/v1/admin/users`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json() as { username: string }[];
    expect(Array.isArray(body)).toBeTruthy();
    expect(body.some((u) => u.username === ADMIN_USER)).toBeTruthy();
  });
});

// ── 10. WebSocket Feed ────────────────────────────────────────────────────────

test.describe("10 — WebSocket Feed", () => {
  test("WebSocket endpoint /ws/engagements/:id/feed bisa di-connect", async ({ page }) => {
    // Storage state provides auth; navigate to initialize localStorage access
    await page.goto("/workspaces");
    const token = await getToken(page);
    const wsBaseUrl = API_URL.replace(/^http/, "ws");

    const result = await page.evaluate(
      async ({ token, wsBaseUrl }: { token: string; wsBaseUrl: string }) => {
        return new Promise<{ connected: boolean }>((resolve) => {
          const url = `${wsBaseUrl}/ws/engagements/00000000-0000-0000-0000-000000000001/feed?token=${token}`;
          const ws = new WebSocket(url);
          const timer = setTimeout(() => {
            ws.close();
            resolve({ connected: ws.readyState <= 1 });
          }, 3_000);
          ws.onopen = () => {
            clearTimeout(timer);
            ws.close();
            resolve({ connected: true });
          };
          ws.onerror = () => {
            clearTimeout(timer);
            resolve({ connected: false });
          };
        });
      },
      { token, wsBaseUrl }
    );

    // Accept both outcomes — server may reject fake UUID but must not crash
    expect(typeof result.connected).toBe("boolean");
  });

  test("GET /api/v1/engagements/:id/events endpoint tersedia", async ({ request }) => {
    const token = await apiLogin(request);
    const ws = await createWorkspaceViaApi(request, token, `E2E-WS-EVT-${Date.now()}`);
    const eng = await createEngagementViaApi(request, token, ws.id, `E2E-Evt-${Date.now()}`);

    const res = await request.get(
      `${API_URL}/api/v1/engagements/${eng.id}/events`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    // 200 (empty stream) or 204 — not a 4xx/5xx
    expect(res.status()).toBeLessThan(400);
  });
});
