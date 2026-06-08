/**
 * Playwright auth setup — runs ONCE before the test suite.
 * Logs in as admin, saves the browser storage state (localStorage) to a file.
 * All subsequent test files load this state so every test starts authenticated.
 *
 * Tests that need a FRESH unauthenticated state should add:
 *   test.use({ storageState: { cookies: [], origins: [] } });
 */
import { test as setup } from "@playwright/test";
import { ADMIN_USER, ADMIN_PASS } from "./helpers";
import { fileURLToPath } from "url";
import * as path from "path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const AUTH_STATE_FILE = path.join(__dirname, ".auth-state.json");

setup("authenticate admin user", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Username").fill(ADMIN_USER);
  await page.getByLabel("Password").fill(ADMIN_PASS);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL("/workspaces", { timeout: 15_000 });
  await page.context().storageState({ path: AUTH_STATE_FILE });
});
