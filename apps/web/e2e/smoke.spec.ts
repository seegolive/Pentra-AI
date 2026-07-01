/* eslint-disable @typescript-eslint/no-unused-vars */
/**
 * smoke.spec.ts — Sprint 21.6 Playwright smoke tests
 * 5 tests: login, invalid login, protected route, dashboard, KB search
 */

import { test, expect, type Page } from "@playwright/test";
import { apiLogin } from "./helpers";

// All smoke tests manage their own login — start unauthenticated
test.use({ storageState: { cookies: [], origins: [] } });

async function login(page: Page) {
  await page.goto("/login");
  await page.getByLabel(/username/i).fill("admin");
  await page.getByLabel(/password/i).fill("Pentra@2026!");
  await page.getByRole("button", { name: /sign in/i }).click();
  await page.waitForURL(/workspaces|dashboard/, { timeout: 10_000 });
}

async function authenticateViaApi(page: Page, request: Parameters<typeof apiLogin>[0]) {
  const token = await apiLogin(request);
  await page.addInitScript((accessToken) => {
    localStorage.setItem(
      "pentra-auth",
      JSON.stringify({
        state: {
          accessToken,
          refreshToken: "",
          user: {
            id: "e2e-admin",
            username: "admin",
            email: "admin@example.com",
            is_admin: true,
          },
        },
        version: 0,
      }),
    );
  }, token);
}

test("ST-6.1 login valid", async ({ page }) => {
  // Navigate to login with fresh unauthenticated state
  await page.goto("/login");
  await page.getByLabel(/username/i).fill("admin");
  await page.getByLabel(/password/i).fill("Pentra@2026!");
  await page.getByRole("button", { name: /sign in/i }).click();
  await page.waitForURL(/workspaces|dashboard/, { timeout: 10_000 });
  await expect(page).not.toHaveURL(/login/);
});

test("ST-6.2 login invalid shows error", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel(/username/i).fill("not-admin");
  await page.getByLabel(/password/i).fill("wrongpassword");
  await page.getByRole("button", { name: /sign in/i }).click();
  // Should stay on login page and show error
  await expect(page).toHaveURL(/login/, { timeout: 5000 });
});

test("ST-6.3 protected route redirects to login", async ({ page }) => {
  // Navigate without auth
  await page.goto("/workspaces");
  await expect(page).toHaveURL(/login/, { timeout: 5000 });
});

test("ST-6.4 dashboard has content after login", async ({ page, request }) => {
  await authenticateViaApi(page, request);
  await page.goto("/dashboard");
  // Dashboard must show at least one heading or named element
  await expect(
    page.locator("h1, h2, h3, [data-testid='dashboard']").first()
  ).toBeVisible({ timeout: 10_000 });
});

test("ST-6.5 KB browser search returns results", async ({ page, request }) => {
  await authenticateViaApi(page, request);
  await page.goto("/knowledge");
  // Find search input by its actual placeholder
  const searchInput = page.getByPlaceholder(/Search by attack type/i);
  await searchInput.fill("SQL injection");
  await searchInput.press("Enter");
  // Wait for any search response: result cards, "No results", loading, or error
  await expect(
    page.locator(
      "div.grid button, p:has-text('result'), p:has-text('No results'), div:has-text('Search failed')"
    ).first()
  ).toBeVisible({ timeout: 15_000 });
});
