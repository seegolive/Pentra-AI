/**
 * Shared E2E helpers — credentials, API URL, login utilities.
 * Import from every spec file to keep consistency.
 */

import type { Page, APIRequestContext } from "@playwright/test";
import { existsSync, readFileSync } from "fs";
import { fileURLToPath } from "url";
import * as path from "path";

// ── Constants ──────────────────────────────────────────────────────────────

export const API_URL = process.env.E2E_API_URL ?? "http://localhost:8001";
export const ADMIN_USER = "admin";
export const ADMIN_PASS = "Pentra@2026!";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const AUTH_STATE_FILE = path.join(__dirname, ".auth-state.json");

// ── Auth helpers ───────────────────────────────────────────────────────────

/** Navigate to /login, fill credentials, wait for redirect to /workspaces. */
export async function login(page: Page): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Username").fill(ADMIN_USER);
  await page.getByLabel("Password").fill(ADMIN_PASS);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL("/workspaces", { timeout: 12_000 });
}

/** Extract the JWT access token from browser localStorage. */
export async function getToken(page: Page): Promise<string> {
  return page.evaluate(() => {
    const raw = localStorage.getItem("pentra-auth");
    if (!raw) return "";
    return (JSON.parse(raw) as { state?: { accessToken?: string } })?.state?.accessToken ?? "";
  });
}

/** Return Authorization + Content-Type headers for `request` fixture calls. */
export async function authHeaders(
  page: Page
): Promise<Record<string, string>> {
  const token = await getToken(page);
  return {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };
}

/** Obtain a JWT via the API without a browser page (for pure API tests).
 *  Token is cached for the duration of the test process to avoid rate-limiting. */
let _cachedToken: string | null = null;
let _cachedTokenExpiry = 0;

export async function apiLogin(request: APIRequestContext): Promise<string> {
  if (_cachedToken && Date.now() < _cachedTokenExpiry) {
    return _cachedToken;
  }

  const storedToken = readTokenFromStorageState();
  if (storedToken) {
    _cachedToken = storedToken;
    _cachedTokenExpiry = Date.now() + 50 * 60 * 1000;
    return storedToken;
  }

  const res = await request.post(`${API_URL}/api/v1/auth/login`, {
    headers: { "Content-Type": "application/json" },
    data: { username: ADMIN_USER, password: ADMIN_PASS },
  });
  if (!res.ok()) throw new Error(`apiLogin failed: ${res.status()}`);
  const body = await res.json() as { access_token: string };
  _cachedToken = body.access_token;
  _cachedTokenExpiry = Date.now() + 50 * 60 * 1000; // cache for 50 minutes
  return _cachedToken;
}

function readTokenFromStorageState(): string | null {
  if (!existsSync(AUTH_STATE_FILE)) return null;
  try {
    const raw = readFileSync(AUTH_STATE_FILE, "utf-8");
    const parsed = JSON.parse(raw) as {
      origins?: Array<{
        origin?: string;
        localStorage?: Array<{ name: string; value: string }>;
      }>;
    };
    const authEntry = parsed.origins
      ?.flatMap((origin) => origin.localStorage ?? [])
      .find((entry) => entry.name === "pentra-auth");
    if (!authEntry?.value) return null;
    const auth = JSON.parse(authEntry.value) as { state?: { accessToken?: string } };
    return auth.state?.accessToken ?? null;
  } catch {
    return null;
  }
}

/** Create a workspace via the API and return its id + name. */
export async function createWorkspaceViaApi(
  request: APIRequestContext,
  token: string,
  name: string
): Promise<{ id: string; name: string }> {
  const res = await request.post(`${API_URL}/api/v1/workspaces/`, {
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    data: { name },
  });
  if (!res.ok()) throw new Error(`createWorkspace failed: ${res.status()}`);
  return res.json();
}

/** Create an engagement via the API and return its id. */
export async function createEngagementViaApi(
  request: APIRequestContext,
  token: string,
  workspaceId: string,
  name: string
): Promise<{ id: string; name: string }> {
  const res = await request.post(`${API_URL}/api/v1/engagements/`, {
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    data: {
      workspace_id: workspaceId,
      name,
      mode: "semi_auto",
      in_scope: ["testphp.vulnweb.com"],
      out_of_scope: [],
      llm_model: "qwen2.5-coder:7b",
    },
  });
  if (!res.ok()) throw new Error(`createEngagement failed: ${res.status()}`);
  return res.json();
}
