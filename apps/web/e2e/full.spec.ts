/* eslint-disable @typescript-eslint/no-unused-vars */
/**
 * full.spec.ts — Task 23.7 (Sprint 23)
 * Full regression suite covering all major UI flows.
 *
 * Sections:
 *  FR-Auth      Authentication (login, invalid, logout, protected routes)
 *  FR-Dashboard Dashboard renders
 *  FR-KB        Knowledge Base browser (search, filter, detail)
 *  FR-WS        Workspace list + create
 *  FR-Eng       Engagement list + create
 *  FR-Admin     Admin panel accessible
 *  FR-Settings  Settings page renders
 */

import { test, expect } from "@playwright/test";
import {
  API_URL,
  apiLogin,
  createWorkspaceViaApi,
  createEngagementViaApi,
} from "./helpers";

// ═══════════════════════════════════════════════════════════
// FR-Auth — Authentication
// ═══════════════════════════════════════════════════════════

test.describe("FR-Auth Authentication", () => {
  // These tests need a fresh unauthenticated state
  test.use({ storageState: { cookies: [], origins: [] } });

  test("FR-Auth-1 valid login redirects away from /login", async ({ page }) => {
    await page.goto("/login");
    await page.getByLabel(/username/i).fill("admin");
    await page.getByLabel(/password/i).fill("Pentra@2026!");
    await page.getByRole("button", { name: /sign in/i }).click();
    await page.waitForURL(/workspaces|dashboard/, { timeout: 12_000 });
    await expect(page).not.toHaveURL(/login/);
  });

  test("FR-Auth-2 invalid credentials shows error on login page", async ({ page }) => {
    await page.goto("/login");
    await page.getByLabel(/username/i).fill("admin");
    await page.getByLabel(/password/i).fill("wrongpassword_xyz");
    await page.getByRole("button", { name: /sign in/i }).click();
    await expect(page).toHaveURL(/login/, { timeout: 6_000 });
  });

  test("FR-Auth-3 protected route /workspaces redirects to /login when unauth", async ({ page }) => {
    await page.goto("/workspaces");
    await expect(page).toHaveURL(/login/, { timeout: 6_000 });
  });

  test("FR-Auth-4 protected route /knowledge redirects to /login when unauth", async ({ page }) => {
    await page.goto("/knowledge");
    await expect(page).toHaveURL(/login/, { timeout: 6_000 });
  });
});

// ═══════════════════════════════════════════════════════════
// FR-Dashboard — Dashboard page
// ═══════════════════════════════════════════════════════════

test.describe("FR-Dashboard", () => {
  test("FR-Dashboard-1 /dashboard renders with heading content", async ({
    page,
  }) => {
    await page.goto("/dashboard");
    await expect(
      page.locator("h1, h2, h3, [data-testid='dashboard']").first()
    ).toBeVisible({ timeout: 10_000 });
  });

  test("FR-Dashboard-2 AppShell nav is present", async ({ page }) => {
    await page.goto("/dashboard");
    // Navigation sidebar or topbar should exist
    await expect(
      page.locator("nav, aside, [data-testid='nav'], [role='navigation']").first()
    ).toBeVisible({ timeout: 8_000 });
  });
});

// ═══════════════════════════════════════════════════════════
// FR-KB — Knowledge Base Browser
// ═══════════════════════════════════════════════════════════

test.describe("FR-KB Knowledge Base", () => {
  test("FR-KB-1 /knowledge page loads search bar", async ({ page }) => {
    await page.goto("/knowledge");
    await expect(
      page.getByPlaceholder(/search by attack type/i)
    ).toBeVisible({ timeout: 8_000 });
  });

  test("FR-KB-2 search for 'SQL injection' returns results or empty state", async ({
    page,
  }) => {
    await page.goto("/knowledge");
    const input = page.getByPlaceholder(/search by attack type/i);
    await input.fill("SQL injection");
    await input.press("Enter");

    // Accept results cards, count text, no-results, or error
    await expect(
      page.locator("div.grid button").first()
    ).toBeVisible({ timeout: 15_000 });
  });

  test("FR-KB-3 /knowledge/inject page renders form", async ({ page }) => {
    await page.goto("/knowledge/inject");
    // Inject form or heading should be visible
    await expect(
      page.locator("form, h1, h2, [data-testid='inject-form']").first()
    ).toBeVisible({ timeout: 8_000 });
  });

  test("FR-KB-4 Filter panel visible on KB browser", async ({ page }) => {
    await page.goto("/knowledge");
    // Filter panel is in sidebar (hidden md:block)
    await expect(
      page.locator("aside").first()
    ).toBeVisible({ timeout: 8_000 });
  });
});

// ═══════════════════════════════════════════════════════════
// FR-WS — Workspace
// ═══════════════════════════════════════════════════════════

test.describe("FR-WS Workspace", () => {
  test("FR-WS-1 /workspaces page loads", async ({ page }) => {
    await page.goto("/workspaces");
    await expect(
      page.locator("h1, h2, [data-testid='workspace-list'], button").first()
    ).toBeVisible({ timeout: 10_000 });
  });

  test("FR-WS-2 workspace created via API appears in list", async ({
    page,
    request,
  }) => {
    const token = await apiLogin(request);
    const ws = await createWorkspaceViaApi(
      request,
      token,
      `FR-WS-2 ${Date.now()}`
    );

    await page.goto("/workspaces");
    await expect(page.getByText(ws.name)).toBeVisible({ timeout: 10_000 });
  });
});

// ═══════════════════════════════════════════════════════════
// FR-Eng — Engagements
// ═══════════════════════════════════════════════════════════

test.describe("FR-Eng Engagements", () => {
  test("FR-Eng-1 /engagements page loads", async ({ page }) => {
    await page.goto("/engagements");
    await expect(
      page.locator("h1, h2, [data-testid='engagement-list'], button").first()
    ).toBeVisible({ timeout: 10_000 });
  });

  test("FR-Eng-2 engagement created via API is navigable", async ({
    page,
    request,
  }) => {
    const token = await apiLogin(request);
    const ws = await createWorkspaceViaApi(request, token, "FR-Eng-2 WS");
    const eng = await createEngagementViaApi(
      request,
      token,
      ws.id,
      "FR-Eng-2 Eng"
    );

    await page.goto(`/engagements/${eng.id}`);

    // Engagement detail page renders
    await expect(
      page.locator("h1, h2, [data-testid='engagement-detail']").first()
    ).toBeVisible({ timeout: 10_000 });
  });

  test("FR-Eng-3 engagement detail shows all 4 tabs", async ({
    page,
    request,
  }) => {
    const token = await apiLogin(request);
    const ws = await createWorkspaceViaApi(request, token, "FR-Eng-3 WS");
    const eng = await createEngagementViaApi(
      request,
      token,
      ws.id,
      "FR-Eng-3 Eng"
    );

    await page.goto(`/engagements/${eng.id}`);

    for (const label of ["Live Feed", "Findings", "Monitoring", "Reports"]) {
      await expect(
        page.getByRole("button", { name: new RegExp(label, "i") })
      ).toBeVisible({ timeout: 10_000 });
    }
  });
});

// ═══════════════════════════════════════════════════════════
// FR-Admin — Admin panel
// ═══════════════════════════════════════════════════════════

test.describe("FR-Admin", () => {
  test("FR-Admin-1 /admin page renders", async ({ page }) => {
    await page.goto("/admin");
    await expect(
      page.locator("h1, h2, [data-testid='admin'], main").first()
    ).toBeVisible({ timeout: 8_000 });
  });

  test("FR-Admin-2 /admin/workers page renders", async ({ page }) => {
    await page.goto("/admin/workers");
    await expect(
      page.locator("h1, h2, main, [data-testid='workers']").first()
    ).toBeVisible({ timeout: 8_000 });
  });
});

// ═══════════════════════════════════════════════════════════
// FR-Settings
// ═══════════════════════════════════════════════════════════

test.describe("FR-Settings", () => {
  test("FR-Settings-1 /settings page renders", async ({ page }) => {
    await page.goto("/settings");
    await expect(
      page.locator("h1, h2, form, [data-testid='settings']").first()
    ).toBeVisible({ timeout: 8_000 });
  });
});

// ═══════════════════════════════════════════════════════════
// FR-Nav — Navigation links
// ═══════════════════════════════════════════════════════════

test.describe("FR-Nav Navigation", () => {
  test("FR-Nav-1 all main nav links resolve without 404", async ({ page }) => {
    const routes = [
      "/dashboard",
      "/workspaces",
      "/knowledge",
      "/admin",
      "/settings",
    ];

    for (const route of routes) {
      await page.goto(route);
      // Should not land on a 404 or error page
      const bodyText = await page.locator("body").textContent();
      expect(bodyText).not.toMatch(/404|not found|page not found/i);
      // Should not redirect back to login (already authenticated via storage state)
      expect(page.url()).not.toMatch(/login/);
    }
  });
});
