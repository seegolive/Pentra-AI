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
  // Access control
  idor:                 "IDOR",
  bola:                 "BOLA",
  bfla:                 "BFLA",
  privilege_escalation: "Priv Esc",
  // Injection
  sqli:                 "SQLi",
  xss_stored:           "XSS (Stored)",
  xss_reflected:        "XSS (Reflected)",
  xss_dom:              "XSS (DOM)",
  mxss:                 "mXSS",
  xxe:                  "XXE",
  ssti:                 "SSTI",
  cmdi:                 "Cmd Injection",
  // Auth
  auth_bypass:          "Auth Bypass",
  session:              "Session",
  oauth_misconfig:      "OAuth Misconfig",
  jwt_issues:           "JWT Issues",
  // Server-side
  ssrf:                 "SSRF",
  path_traversal:       "Path Traversal",
  rce:                  "RCE",
  deserialization:      "Deserialization",
  // Logic / API
  race_condition:       "Race Condition",
  mass_assignment:      "Mass Assignment",
  param_pollution:      "Param Pollution",
  workflow_bypass:      "Workflow Bypass",
  // Info disclosure
  api_key_leak:         "API Key Leak",
  pii_exposure:         "PII Exposure",
  debug_info:           "Debug Info",
  source_code:          "Source Code",
  // Infrastructure
  subdomain_takeover:   "Subdomain Takeover",
  cache_poisoning:      "Cache Poisoning",
  cloud_misconfig:      "Cloud Misconfig",
  cors:                 "CORS",
  // GraphQL
  introspection:        "GraphQL Introspection",
  query_depth:          "Query Depth",
  batch_abuse:          "Batch Abuse",
  field_suggestion:     "Field Suggestion",
  // Other
  dos:                  "DoS",
  open_redirect:        "Open Redirect",
  // Memory corruption
  buffer_overflow:      "Buffer Overflow",
  use_after_free:       "Use-After-Free",
  integer_overflow:     "Int Overflow",
  // Crypto
  weak_algo:            "Weak Algo",
  padding_oracle:       "Padding Oracle",
  timing_attack:        "Timing Attack",
  other:                "Other",
};

export function formatBounty(usd: number | null): string {
  if (usd == null) return "—";
  if (usd >= 1000) return `$${(usd / 1000).toFixed(1)}k`;
  return `$${usd}`;
}
