import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import type { Severity, VulnClass } from "./types";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "text-red-500 bg-red-500/10 border-red-500/20",
  high:     "text-orange-500 bg-orange-500/10 border-orange-500/20",
  medium:   "text-yellow-500 bg-yellow-500/10 border-yellow-500/20",
  low:      "text-blue-500 bg-blue-500/10 border-blue-500/20",
  info:     "text-slate-400 bg-slate-400/10 border-slate-400/20",
};

export const SEVERITY_DOT: Record<Severity, string> = {
  critical: "bg-red-500",
  high:     "bg-orange-500",
  medium:   "bg-yellow-500",
  low:      "bg-blue-500",
  info:     "bg-slate-400",
};

export const VULN_CLASS_LABELS: Record<VulnClass, string> = {
  sqli:                 "SQLi",
  xss:                  "XSS",
  ssrf:                 "SSRF",
  idor:                 "IDOR",
  rce:                  "RCE",
  lfi:                  "LFI",
  xxe:                  "XXE",
  auth_bypass:          "Auth Bypass",
  privilege_escalation: "Priv Esc",
  info_disclosure:      "Info Disclosure",
  csrf:                 "CSRF",
  open_redirect:        "Open Redirect",
  ssti:                 "SSTI",
  path_traversal:       "Path Traversal",
  race_condition:       "Race Condition",
  business_logic:       "Business Logic",
  misconfig:            "Misconfig",
  dos:                  "DoS",
  other:                "Other",
};

export function formatBounty(usd: number | null): string {
  if (usd == null) return "—";
  if (usd >= 1000) return `$${(usd / 1000).toFixed(1)}k`;
  return `$${usd}`;
}
