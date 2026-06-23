# Sprint 32 Progress Report

Date: 2026-06-23

## Summary

Sprint 32 reNgine-adoption work is implemented for historical URL mining, OSINT dorking, email OSINT, and extra vulnerability scanners. The changes are integrated into the agent recon, OSINT, and vuln-hunt nodes with graceful fallbacks when optional external tools or API keys are unavailable.

## Implemented

- 32.1 Wayback URL mining
  - Added `WaybackCrawler` with Wayback CDX support, Common Crawl fallback, URL filtering, dedupe, and query parameter extraction.
  - Integrated historical URLs into recon endpoint discovery.

- 32.3 Dorking
  - Added `DorkScanner` with security-focused query categories and URL classification.
  - Integrated dorking results into OSINT summaries without polluting state when no results are found.

- 32.4 CRLFuzz and Dalfox
  - Added `CRLFuzzScanner` and `DalfoxScanner` wrappers with availability checks, timeout handling, parsing, and batch scanning.
  - Integrated both scanners into vuln-hunt findings.

- 32.5 Email OSINT and breach checks
  - Added `EmailOSINT` with theHarvester support, optional Hunter API support, optional HIBP breach checks, pattern generation, and text email extraction.
  - Integrated email OSINT into OSINT node with env-driven API keys.

## Validation

- `cd packages/pentra-tools && uv run pytest tests -q`
  - Result: 268 passed, 3 skipped, 1 warning

- `cd packages/pentra-agent && uv run pytest tests -q`
  - Result: 156 passed, 4 skipped, 1 warning

- `cd apps/web && pnpm exec playwright test --config=e2e.runtime.config.ts`
  - Result: 90 passed
  - Note: Playwright needed to run outside the sandbox because Chromium failed to launch in sandbox with `sandbox_host_linux.cc: Operation not permitted`.
  - Note: the standard `pnpm e2e` bootstrap hit a local port issue on 5174, so the runtime config used the already healthy Vite server on 5173 and API on 8001.

## Current Notes

- Screenshot gathering was not duplicated because the repository already contains a screenshot package under `packages/pentra-tools/pentra_tools/screenshot/`; adding the prompt's parallel path would create overlapping implementation.
- External scanners remain optional at runtime. Missing `crlfuzz`, `dalfox`, `theHarvester`, Hunter API key, or HIBP API key results in empty/graceful output, not hard failures.
- `uv run` may rewrite lockfile metadata locally during tests; these mechanical lockfile changes were removed after validation.

## Remaining Follow-Up

- Decide whether to wire the existing screenshot package into the current agent flow or leave it as-is.
- If desired, normalize the Playwright dev-server port issue so `pnpm e2e` can run without the temporary runtime config workaround.
