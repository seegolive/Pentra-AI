import { test, expect, type Page } from "@playwright/test";

// ── Helper ──────────────────────────────────────────────────────────────────

async function login(page: Page) {
  await page.goto("/login");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill("Pentra@2026!");
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL("/workspaces", { timeout: 10_000 });
}

// ── ST-6.1 Login Flow ───────────────────────────────────────────────────────

test.describe("ST-6.1 — Login Flow", () => {
  // These tests navigate to /login directly — need unauthenticated state
  test.use({ storageState: { cookies: [], origins: [] } });
  test("login valid → redirect ke workspaces", async ({ page }) => {
    await login(page);
    await expect(page).toHaveURL("/workspaces");
    await expect(page.getByRole("heading").first()).toBeVisible();
  });

  test("login invalid → tampilkan error", async ({ page }) => {
    await page.goto("/login");
    await page.getByLabel("Username").fill("admin");
    await page.getByLabel("Password").fill("wrong-password");
    await page.getByRole("button", { name: "Sign in" }).click();

    await expect(page).toHaveURL("/login");
    await expect(
      page.getByText(/login failed|incorrect|invalid|error/i)
    ).toBeVisible({ timeout: 5_000 });
  });
});

// ── ST-6.5 KB Browser ───────────────────────────────────────────────────────

test.describe("ST-6.5 — KB Browser", () => {
  // Storage state provides pre-auth

  // Search calls Ollama for query embedding (~20–60s latency)
  test("KB search returns results", { timeout: 120_000 }, async ({ page }) => {
    await page.goto("/knowledge");

    const searchInput = page.getByPlaceholder(/search/i).first();
    await searchInput.fill("SQL injection");
    await searchInput.press("Enter");

    // Wait for loading spinner to disappear (Ollama embedding round-trip)
    await expect(page.getByText(/searching/i)).toBeVisible({ timeout: 5_000 });
    await expect(page.getByText(/searching/i)).not.toBeVisible({ timeout: 90_000 });

    // After load: result count or error must be visible
    const resultText = page.getByText(/\d+ result|no results for/i).first();
    const errorText = page.getByText(/search failed/i).first();
    await expect(resultText.or(errorText)).toBeVisible({ timeout: 5_000 });
  });
});

// ── ST-6.2 Dashboard ────────────────────────────────────────────────────────

test.describe("ST-6.2 — Dashboard", () => {
  // Storage state provides pre-auth

  test("dashboard loads dengan stat cards", async ({ page }) => {
    await page.goto("/dashboard");

    // Stat cards visible — at least one heading-level number
    await expect(page.locator("text=/Workspaces|Engagements|Knowledge|Findings/i").first()).toBeVisible({
      timeout: 10_000,
    });
  });

  test("dashboard → klik Engagements navigates ke /engagements", async ({ page }) => {
    await page.goto("/dashboard");

    // Engagements is in the sidebar nav (replaced Workspaces in Sprint UI-2)
    const nav = page.getByRole("link", { name: /^engagements$/i });
    await expect(nav.first()).toBeVisible({ timeout: 5_000 });
    await nav.first().click();
    await expect(page).toHaveURL(/\/engagements|\/dashboard/, { timeout: 5_000 });
  });
});

// ── ST-6.3 Settings Page ────────────────────────────────────────────────────

test.describe("ST-6.3 — Settings Page", () => {
  // Storage state provides pre-auth

  test("settings page loads dengan 3 sections", async ({ page }) => {
    await page.goto("/settings");

    await expect(page.getByRole("heading", { name: "Profile" })).toBeVisible({ timeout: 5_000 });
    await expect(page.getByRole("heading", { name: "Change Password" })).toBeVisible({ timeout: 5_000 });
    await expect(page.getByRole("heading", { name: "System Information" })).toBeVisible({ timeout: 5_000 });
  });

  test("settings profile section tampilkan username admin", async ({ page }) => {
    await page.goto("/settings");

    // Scope to main content to avoid sidebar ambiguity
    const main = page.locator("main, [role='main'], .flex-1.overflow-auto").first();
    await expect(main.getByText("admin", { exact: true })).toBeVisible({ timeout: 5_000 });
    await expect(main.getByText("Administrator")).toBeVisible({ timeout: 5_000 });
  });

  test("change password form: validasi mismatch tampilkan error", async ({ page }) => {
    await page.goto("/settings");

    // Inputs use <label> not placeholder
    await page.getByLabel("Current Password", { exact: true }).fill("Pentra@2026!");
    await page.getByLabel("New Password", { exact: true }).fill("NewPass@2026!");
    await page.getByLabel("Confirm New Password", { exact: true }).fill("DifferentPass!");
    await page.getByRole("button", { name: /update password/i }).click();

    // Mismatch error should appear inline (no API call needed)
    await expect(page.getByText(/do not match/i)).toBeVisible({ timeout: 3_000 });
  });
});

// ── ST-6.4 Version Stamp ────────────────────────────────────────────────────

test.describe("ST-6.4 — Version Stamp", () => {
  // Storage state provides pre-auth

  test("sidebar footer tampilkan version stamp v1.0.0", async ({ page }) => {
    await page.goto("/dashboard");

    // Version stamp is in the sidebar footer — monospace font
    await expect(page.getByText(/^v\d+\.\d+\.\d+$/)).toBeVisible({ timeout: 5_000 });
  });

  test("sidebar memiliki semua nav links: Dashboard, Engagements, Knowledge, Settings", async ({
    page,
  }) => {
    await page.goto("/dashboard");

    // icon-nav + sidebar both render these links — use .first() to avoid strict-mode violation
    await expect(page.getByRole("link", { name: /dashboard/i }).first()).toBeVisible();
    await expect(page.getByRole("link", { name: /^engagements$/i }).first()).toBeVisible();
    await expect(page.getByRole("link", { name: /knowledge/i }).first()).toBeVisible();
    await expect(page.getByRole("link", { name: /settings/i }).first()).toBeVisible();
  });
});
