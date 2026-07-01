/* eslint-disable @typescript-eslint/no-unused-vars */
import { test, expect, type Page } from "@playwright/test";

/**
 * Workspace & Engagement E2E tests — Task 4.1
 *
 * Requires:
 *  - Frontend running on http://localhost:5174
 *  - Backend API running on http://localhost:8001
 *  - Default admin account: username=admin, password=Pentra@2026!
 */

// ── Helpers ────────────────────────────────────────────────────────────────────

const RUN_ID = Date.now();
const WORKSPACE_NAME = `E2E Test Workspace ${RUN_ID}`;
const ENGAGEMENT_NAME = `E2E Test Engagement ${RUN_ID}`;

async function login(page: Page) {
  await page.goto("/login");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill("Pentra@2026!");
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL("/workspaces", { timeout: 10_000 });
}

// ── Tests ──────────────────────────────────────────────────────────────────────

test.describe("Workspace & Engagement Flow", () => {
  // Storage state provides pre-auth; no beforeEach login needed

  test("buat workspace baru dan muncul di list", async ({ page }) => {
    await page.goto("/workspaces");

    // Open create form
    await page.getByRole("button", { name: /new workspace/i }).click();

    // Fill workspace name
    await page.getByPlaceholder("Workspace name").fill(WORKSPACE_NAME);

    // Submit
    await page.getByRole("button", { name: /^create$/i }).click();

    // New workspace card should appear in the list
    await expect(page.getByRole("button", { name: new RegExp(WORKSPACE_NAME) })).toBeVisible({
      timeout: 10_000,
    });
  });

  test("buat engagement dengan scope dan muncul di list", async ({ page }) => {
    await page.goto("/workspaces");

    // Click the test workspace created above (or any workspace)
    const workspaceCard = page
      .getByRole("button", { name: new RegExp(WORKSPACE_NAME) })
      .first();
    await workspaceCard.click();

    // Should navigate to engagements page for that workspace
    await expect(page).toHaveURL(/\/workspaces\/.+\/engagements/, {
      timeout: 5_000,
    });

    // Open new engagement form — scope to main to exclude sidebar + button
    await page.locator("main").getByRole("button", { name: /new engagement/i }).click();

    // Fill engagement name
    await page.getByPlaceholder("e.g. HackerOne – Acme Corp Q2").fill(ENGAGEMENT_NAME);

    // Fill in-scope targets
    await page
      .getByPlaceholder("target.com\n*.api.target.com\n192.168.1.0/24")
      .fill("testphp.vulnweb.com");

    // Submit
    await page.getByRole("button", { name: /^create engagement$/i }).click();

    // Engagement card should appear
    await expect(page.getByText(ENGAGEMENT_NAME)).toBeVisible({
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
    await expect(
      page.getByText(/result(s)? for "IDOR"/i)
    ).toBeVisible({ timeout: 15_000 });

    await expect(
      page.locator("main button").filter({ hasText: /IDOR/i }).first()
    ).toBeVisible({ timeout: 10_000 });
  });
});
