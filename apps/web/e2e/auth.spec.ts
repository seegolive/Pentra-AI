import { test, expect } from "@playwright/test";

/**
 * Authentication E2E tests — Task 4.1
 *
 * Requires:
 *  - Frontend running on http://localhost:5174
 *  - Backend API running on http://localhost:8001
 *  - Default admin account: username=admin, password=Pentra@2026!
 */

// ── Helpers ────────────────────────────────────────────────────────────────────

/** Fill and submit the login form. */
async function fillLoginForm(
  page: import("@playwright/test").Page,
  username: string,
  password: string
) {
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
}

// ── Tests ──────────────────────────────────────────────────────────────────────

test.describe("Authentication Flow", () => {
  // These tests navigate to /login directly — need unauthenticated state
  test.use({ storageState: { cookies: [], origins: [] } });
  test("login dengan credentials valid berhasil redirect ke workspaces", async ({
    page,
  }) => {
    await page.goto("/login");

    await fillLoginForm(page, "admin", "Pentra@2026!");

    // Should redirect away from /login to /workspaces
    await expect(page).toHaveURL("/workspaces", { timeout: 10_000 });

    // Sidebar sign-out button confirms we are authenticated
    await expect(
      page.getByRole("button", { name: /sign out/i })
    ).toBeVisible();
  });

  test("login dengan credentials salah menampilkan pesan error", async ({
    page,
  }) => {
    await page.goto("/login");

    await fillLoginForm(page, "admin", "wrong-password");

    // Error message should be visible — stays on /login
    await expect(page).toHaveURL("/login");
    await expect(
      page.getByText(/incorrect username or password|login failed/i)
    ).toBeVisible({ timeout: 10_000 });
  });

  test("halaman protected redirect ke /login jika belum autentikasi", async ({
    page,
  }) => {
    // Navigate directly to a protected route without any stored token
    await page.goto("/workspaces");

    // ProtectedRoute should push to /login
    await expect(page).toHaveURL("/login", { timeout: 5_000 });

    // Login form should be visible
    await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
  });

  test("sign out berhasil menghapus sesi dan redirect ke /login", async ({
    page,
  }) => {
    // First log in
    await page.goto("/login");
    await fillLoginForm(page, "admin", "Pentra@2026!");
    await expect(page).toHaveURL("/workspaces", { timeout: 10_000 });

    // Click sign out
    await page.getByRole("button", { name: /sign out/i }).click();

    // Should be back on /login
    await expect(page).toHaveURL("/login", { timeout: 5_000 });

    // Navigating to a protected route must redirect again (token cleared)
    await page.goto("/workspaces");
    await expect(page).toHaveURL("/login");
  });
});
