import { useSearchParams } from "react-router-dom";
import { Bug, AlertTriangle, RefreshCw } from "lucide-react";
import { useAllFindings, useEngagements } from "../lib/api";
import { FindingsTable } from "../components/findings/FindingsTable";
import type { FindingFilters, Severity, FindingStatus } from "../lib/types";
import { cn } from "../lib/utils";

const SEVERITY_OPTIONS: Severity[] = ["critical", "high", "medium", "low", "info"];
const STATUS_OPTIONS: FindingStatus[] = ["open", "confirmed", "false_positive", "wont_fix", "resolved"];

const SEVERITY_CHIP_STYLES: Record<Severity, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/30",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  low: "text-blue-400 bg-blue-400/10 border-blue-400/30",
  info: "text-slate-400 bg-slate-500/10 border-slate-500/30",
};

const VULN_CLASS_OPTIONS = [
  "idor", "bola", "bfla", "privilege_escalation",
  "sqli", "xss_stored", "xss_reflected", "xss_dom",
  "xxe", "ssti", "cmdi",
  "auth_bypass", "session", "oauth_misconfig", "jwt_issues",
  "ssrf", "path_traversal", "rce", "deserialization",
  "race_condition", "mass_assignment", "workflow_bypass",
  "api_key_leak", "pii_exposure", "cors", "cloud_misconfig",
  "dos", "open_redirect", "other",
] as const;

function useFiltersFromUrl(): [FindingFilters & { page: number; sortBy: string; sortDir: "asc" | "desc" }, (patch: Partial<FindingFilters & { page: number; sortBy: string; sortDir: "asc" | "desc" }>) => void] {
  const [sp, setSp] = useSearchParams();

  const filters: FindingFilters & { page: number; sortBy: string; sortDir: "asc" | "desc" } = {
    severity: sp.getAll("severity") as Severity[],
    status: sp.getAll("status") as FindingStatus[],
    vuln_class: sp.get("vuln_class") ? [sp.get("vuln_class")!] : [],
    engagement_id: sp.get("engagement_id"),
    discovered_after: sp.get("discovered_after"),
    discovered_before: sp.get("discovered_before"),
    page: Number(sp.get("page") ?? "1"),
    sortBy: sp.get("sort_by") ?? "discovered_at",
    sortDir: (sp.get("sort_dir") ?? "desc") as "asc" | "desc",
  };

  const setFilters = (patch: Partial<typeof filters>) => {
    setSp((prev) => {
      const next = new URLSearchParams(prev);
      // When any filter changes, reset to page 1
      if (!("page" in patch)) next.set("page", "1");

      (Object.keys(patch) as Array<keyof typeof patch>).forEach((k) => {
        const v = patch[k];
        if (k === "severity" || k === "status" || k === "vuln_class") {
          next.delete(k);
          (v as string[]).forEach((s) => next.append(k, s));
        } else if (v === null || v === "" || v === undefined) {
          next.delete(k === "sortBy" ? "sort_by" : k === "sortDir" ? "sort_dir" : k);
        } else {
          next.set(k === "sortBy" ? "sort_by" : k === "sortDir" ? "sort_dir" : k, String(v));
        }
      });
      return next;
    });
  };

  return [filters, setFilters];
}

export default function FindingsPage() {
  const [filters, setFilters] = useFiltersFromUrl();
  const { data, isLoading, isError, refetch } = useAllFindings(
    {
      severity: filters.severity,
      status: filters.status,
      vuln_class: filters.vuln_class,
      engagement_id: filters.engagement_id,
      discovered_after: filters.discovered_after,
      discovered_before: filters.discovered_before,
    },
    filters.sortBy,
    filters.sortDir,
    filters.page,
    25,
  );
  const { data: engagements } = useEngagements();

  const total = data?.total ?? 0;
  const results = data?.results ?? [];
  const totalPages = Math.max(1, Math.ceil(total / (data?.page_size ?? 25)));

  const clearFilters = () => {
    setFilters({
      severity: [],
      status: [],
      vuln_class: [],
      engagement_id: null,
      discovered_after: null,
      discovered_before: null,
      page: 1,
      sortBy: "discovered_at",
      sortDir: "desc",
    });
  };

  const hasFilters =
    filters.severity.length > 0 ||
    filters.status.length > 0 ||
    filters.vuln_class.length > 0 ||
    filters.engagement_id !== null ||
    filters.discovered_after !== null ||
    filters.discovered_before !== null;

  const toggleSeverity = (sev: Severity) => {
    const next = filters.severity.includes(sev)
      ? filters.severity.filter((s) => s !== sev)
      : [...filters.severity, sev];
    setFilters({ severity: next });
  };

  const toggleStatus = (st: FindingStatus) => {
    const next = filters.status.includes(st)
      ? filters.status.filter((s) => s !== st)
      : [...filters.status, st];
    setFilters({ status: next });
  };

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* ── Header ── */}
      <div className="flex items-center gap-3 px-6 py-3 border-b border-border bg-background/80 backdrop-blur-sm shrink-0">
        <Bug className="h-4 w-4 text-primary" />
        <h1 className="text-sm font-semibold text-foreground">All Findings</h1>
        <span className="text-xs text-muted-foreground border border-border rounded px-1.5 py-0.5 font-mono">
          {total}
        </span>
        <div className="flex items-center gap-1.5 ml-2">
          {(["critical", "high", "medium", "low"] as const).map((sev) => (
            <button
              key={sev}
              onClick={() => toggleSeverity(sev)}
              className={cn(
                "text-[10px] font-medium px-1.5 py-0.5 rounded border transition-colors",
                SEVERITY_CHIP_STYLES[sev],
                filters.severity.includes(sev) ? "ring-1 ring-current" : "opacity-50",
              )}
            >
              {sev.charAt(0).toUpperCase() + sev.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* ── Body ── */}
      <div className="flex flex-1 overflow-hidden">
        {/* ── Filter sidebar ── */}
        <aside className="w-56 shrink-0 border-r border-border overflow-y-auto p-4 space-y-5 bg-background/50">
          {/* Severity */}
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-2">Severity</p>
            <div className="flex flex-col gap-1">
              {SEVERITY_OPTIONS.map((sev) => (
                <button
                  key={sev}
                  onClick={() => toggleSeverity(sev)}
                  className={cn(
                    "text-xs text-left px-2 py-1 rounded border transition-colors w-full",
                    SEVERITY_CHIP_STYLES[sev],
                    filters.severity.includes(sev) ? "ring-1 ring-current font-semibold" : "opacity-60 hover:opacity-100",
                  )}
                >
                  {sev.charAt(0).toUpperCase() + sev.slice(1)}
                </button>
              ))}
            </div>
          </div>

          {/* Status */}
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-2">Status</p>
            <div className="flex flex-col gap-1">
              {STATUS_OPTIONS.map((st) => (
                <button
                  key={st}
                  onClick={() => toggleStatus(st)}
                  className={cn(
                    "text-xs text-left px-2 py-1 rounded border border-border transition-colors w-full",
                    filters.status.includes(st)
                      ? "bg-primary/10 border-primary/30 text-primary font-medium"
                      : "text-muted-foreground hover:text-foreground hover:bg-muted/30",
                  )}
                >
                  {st.replace(/_/g, " ")}
                </button>
              ))}
            </div>
          </div>

          {/* Vuln Class */}
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-2">Vuln Class</p>
            <select
              value={filters.vuln_class[0] ?? ""}
              onChange={(e) => setFilters({ vuln_class: e.target.value ? [e.target.value] : [] })}
              className="w-full text-xs bg-background border border-border rounded px-2 py-1.5 text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            >
              <option value="">All classes</option>
              {VULN_CLASS_OPTIONS.map((vc) => (
                <option key={vc} value={vc}>{vc.replace(/_/g, " ")}</option>
              ))}
            </select>
          </div>

          {/* Engagement */}
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-2">Engagement</p>
            <select
              value={filters.engagement_id ?? ""}
              onChange={(e) => setFilters({ engagement_id: e.target.value || null })}
              className="w-full text-xs bg-background border border-border rounded px-2 py-1.5 text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            >
              <option value="">All engagements</option>
              {(engagements ?? []).map((eng) => (
                <option key={eng.id} value={eng.id}>{eng.name}</option>
              ))}
            </select>
          </div>

          {/* Date Range */}
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-2">Date Range</p>
            <div className="space-y-1.5">
              <div>
                <label className="text-[10px] text-muted-foreground">From</label>
                <input
                  type="date"
                  value={filters.discovered_after ?? ""}
                  onChange={(e) => setFilters({ discovered_after: e.target.value || null })}
                  className="w-full text-xs bg-background border border-border rounded px-2 py-1 text-foreground focus:outline-none focus:ring-1 focus:ring-primary mt-0.5"
                />
              </div>
              <div>
                <label className="text-[10px] text-muted-foreground">To</label>
                <input
                  type="date"
                  value={filters.discovered_before ?? ""}
                  onChange={(e) => setFilters({ discovered_before: e.target.value || null })}
                  className="w-full text-xs bg-background border border-border rounded px-2 py-1 text-foreground focus:outline-none focus:ring-1 focus:ring-primary mt-0.5"
                />
              </div>
            </div>
          </div>

          {/* Clear */}
          {hasFilters && (
            <button
              onClick={clearFilters}
              className="w-full text-xs text-muted-foreground hover:text-foreground border border-border rounded px-2 py-1.5 transition-colors"
            >
              Clear all filters
            </button>
          )}
        </aside>

        {/* ── Main content ── */}
        <main className="flex-1 overflow-auto p-4 flex flex-col gap-3">
          {isError ? (
            <div className="flex flex-col items-center justify-center flex-1 gap-3 text-muted-foreground">
              <AlertTriangle className="h-8 w-8 text-red-400 opacity-70" />
              <p className="text-sm">Failed to load findings</p>
              <button
                onClick={() => void refetch()}
                className="text-xs px-3 py-1.5 rounded border border-border hover:bg-muted/30 transition-colors"
              >
                Retry
              </button>
            </div>
          ) : !isLoading && results.length === 0 ? (
            <div className="flex flex-col items-center justify-center flex-1 gap-3 text-muted-foreground">
              <Bug className="h-8 w-8 opacity-30" />
              <p className="text-sm">
                {hasFilters ? "No findings match your filters" : "No findings yet"}
              </p>
              {hasFilters && (
                <button
                  onClick={clearFilters}
                  className="text-xs px-3 py-1.5 rounded border border-border hover:bg-muted/30 transition-colors"
                >
                  Clear filters
                </button>
              )}
            </div>
          ) : isLoading ? (
            <div className="flex-1 flex items-center justify-center gap-2 text-muted-foreground text-xs">
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              Loading findings…
            </div>
          ) : (
            <>
              <FindingsTable
                findings={results}
                showEngagementColumn={true}
              />

              {/* Pagination footer */}
              <div className="flex items-center justify-between text-xs text-muted-foreground pt-1 shrink-0">
                <span>
                  Showing {results.length === 0 ? 0 : (filters.page - 1) * 25 + 1}–
                  {Math.min(filters.page * 25, total)} of {total} findings
                </span>
                <div className="flex items-center gap-2">
                  <button
                    disabled={filters.page <= 1}
                    onClick={() => setFilters({ page: filters.page - 1 })}
                    className="px-2.5 py-1 rounded border border-border disabled:opacity-40 hover:bg-muted/30 transition-colors disabled:cursor-not-allowed"
                  >
                    Prev
                  </button>
                  <span className="font-mono">
                    {filters.page} / {totalPages}
                  </span>
                  <button
                    disabled={filters.page >= totalPages}
                    onClick={() => setFilters({ page: filters.page + 1 })}
                    className="px-2.5 py-1 rounded border border-border disabled:opacity-40 hover:bg-muted/30 transition-colors disabled:cursor-not-allowed"
                  >
                    Next
                  </button>
                </div>
              </div>
            </>
          )}
        </main>
      </div>
    </div>
  );
}
