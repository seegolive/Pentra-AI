import { X } from "lucide-react";
import { cn, SEVERITY_COLORS, VULN_CLASS_LABELS } from "../lib/utils";
import type { Severity, VulnClass, SearchFilters } from "../lib/types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

const VULN_CLASSES: VulnClass[] = [
  "idor", "bola", "privilege_escalation",
  "sqli", "xss_stored", "xss_reflected", "xss_dom",
  "xxe", "ssti", "cmdi",
  "auth_bypass", "jwt_issues", "oauth_misconfig",
  "ssrf", "path_traversal", "rce", "deserialization",
  "race_condition", "mass_assignment",
  "pii_exposure", "api_key_leak",
  "subdomain_takeover", "cloud_misconfig", "cors",
  "dos", "open_redirect", "other",
];

interface FilterPanelProps {
  filters: SearchFilters;
  onChange: (filters: SearchFilters) => void;
}

function toggle<T>(arr: T[], item: T): T[] {
  return arr.includes(item) ? arr.filter((x) => x !== item) : [...arr, item];
}

export function FilterPanel({ filters, onChange }: FilterPanelProps) {
  const activeCount =
    filters.severity.length + filters.vuln_class.length + filters.tech_stack.length;

  function clearAll() {
    onChange({ severity: [], vuln_class: [], tech_stack: [] });
  }

  return (
    <aside className="w-52 shrink-0 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Filters
        </span>
        {activeCount > 0 && (
          <button
            type="button"
            onClick={clearAll}
            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
          >
            <X className="h-3 w-3" /> Clear {activeCount}
          </button>
        )}
      </div>

      {/* Severity */}
      <div className="space-y-1.5">
        <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Severity</p>
        {SEVERITIES.map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => onChange({ ...filters, severity: toggle(filters.severity, s) })}
            className={cn(
              "w-full flex items-center gap-2 rounded px-2 py-1 text-xs transition-colors",
              filters.severity.includes(s)
                ? cn(SEVERITY_COLORS[s], "border")
                : "text-muted-foreground hover:text-foreground hover:bg-accent/50",
            )}
          >
            <span className={cn("h-2 w-2 rounded-full shrink-0", {
              "bg-red-500":    s === "critical",
              "bg-orange-500": s === "high",
              "bg-yellow-500": s === "medium",
              "bg-blue-500":   s === "low",
              "bg-slate-400":  s === "info",
            })} />
            <span className="capitalize">{s}</span>
          </button>
        ))}
      </div>

      {/* Vuln class */}
      <div className="space-y-1.5">
        <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Vuln Class</p>
        <div className="flex flex-wrap gap-1">
          {VULN_CLASSES.map((vc) => (
            <button
              key={vc}
              type="button"
              onClick={() => onChange({ ...filters, vuln_class: toggle(filters.vuln_class, vc) })}
              className={cn(
                "text-[10px] px-1.5 py-0.5 rounded border transition-colors",
                filters.vuln_class.includes(vc)
                  ? "border-primary bg-primary/10 text-primary"
                  : "border-border text-muted-foreground hover:border-primary/40 hover:text-foreground",
              )}
            >
              {VULN_CLASS_LABELS[vc] ?? vc}
            </button>
          ))}
        </div>
      </div>
    </aside>
  );
}
