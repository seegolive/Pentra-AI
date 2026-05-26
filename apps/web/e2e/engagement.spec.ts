import { test, expect, type Page } from "@playwright/test";

/**
 * Workspace & Engagement E2E tests — Task 4.1
 *
 * Requires:
 *  - Frontend running on http://localhost:5174
 *  - Backend API running on http://localhost:8000
 *  - Default admin account: username=admin, password=admin123
 */

// ── Helpers ────────────────────────────────────────────────────────────────────

async function login(page: Page) {
  await page.goto("/login");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill("admin123");
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL("/workspaces", { timeout: 10_000 });
}

// ── Tests ──────────────────────────────────────────────────────────────────────

test.describe("Workspace & Engagement Flow", () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test("buat workspace baru dan muncul di list", async ({ page }) => {
    await page.goto("/workspaces");

    // Open create form
    await page.getByRole("button", { name: /new workspace/i }).click();

    // Fill workspace name
    await page.getByPlaceholder("Workspace name").fill("E2E Test Workspace");

    // Submit
    await page.getByRole("button", { name: /^create$/i }).click();

    // New workspace card should appear in the list
    await expect(page.getByText("E2E Test Workspace")).toBeVisible({
      timeout: 10_000,
    });
  });

  test("buat engagement dengan scope dan muncul di list", async ({ page }) => {
    await page.goto("/workspaces");

    // Click the test workspace created above (or any workspace)
    const workspaceCard = page.getByText("E2E Test Workspace");
    await workspaceCard.click();

    // Should navigate to engagements page for that workspace
    await expect(page).toHaveURL(/\/workspaces\/.+\/engagements/, {
      timeout: 5_000,
    });

    // Open new engagement form
    await page.getByRole("button", { name: /new engagement/i }).click();

    // Fill engagement name
    await page.getByPlaceholder("e.g. HackerOne – Acme Corp Q2").fill("E2E Test Engagement");

    // Fill in-scope targets
    await page.getByPlaceholder(/target\.com/).fill("testphp.vulnweb.com");

    // Submit
    await page.getByRole("button", { name: /^create$/i }).click();

    // Engagement card should appear
    await expect(page.getByText("E2E Test Engagement")).toBeVisible({
      timeout: 10_000,
    });
  });

  test("KB Browser dapat search dan tampilkan hasil", async ({ page }) => {
    await page.goto("/knowledge");

    // Type in search box
    await page.getByPlaceholder("Search by attack type, tech, CVE…").fill("IDOR");

    // Click search button
    await page.getByRole("button", { name: "Search" }).click();

    // Should show at least one result (seed data must have IDOR records)
    // Wait for loading to finish and results to appear
    await expect(page.locator(".grid > div").first()).toBeVisible({
      timeout: 15_000,
    });

    // The results header should say N result(s)
    await expect(
      page.getByText(/result(s)? for "IDOR"/i)
    ).toBeVisible({ timeout: 10_000 });
  });
});
