import { useState } from "react";
import {
  Bug,
  BookMarked,
  Wand2,
  ChevronDown,
  ChevronUp,
  ChevronsUpDown,
  ExternalLink,
  X,
  CheckCircle2,
  Loader2,
  Copy,
  Check,
} from "lucide-react";
import { useSubmitFindingToKB, useGeneratePayloads } from "../../lib/api";
import type { GeneratedPayload } from "../../lib/api";
import type { Finding, FindingStatus, Severity } from "../../lib/types";
import { cn } from "../../lib/utils";

// ── Types ─────────────────────────────────────────────────────────────────────

type SortField = "severity" | "title" | "vuln_class" | "status" | "cvss_score";
type SortDir = "asc" | "desc";

interface FindingsTableProps {
  engagementId: string;
  findings: Finding[];
}

// ── Constants ─────────────────────────────────────────────────────────────────

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`severity-badge ${severity}`}>
      {severity.toUpperCase()}
    </span>
  );
}

function FilterChip({
  label,
  severity,
  count,
  active,
  onClick,
}: {
  label: string;
  severity: string;
  count: number;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        `severity-badge ${severity} cursor-pointer transition-all`,
        active && "ring-2 ring-current ring-offset-1 ring-offset-pentra-bg-void"
      )}
      style={{ padding: "3px 10px", fontSize: "11px" }}
    >
      {label}
      <span className="ml-1.5 font-mono opacity-70">{count}</span>
    </button>
  );
}

const STATUS_STYLES: Record<FindingStatus, string> = {
  open: "text-red-400 bg-red-500/10 border-red-500/20",
  confirmed: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  false_positive: "text-slate-400 bg-slate-500/10 border-slate-500/20",
  wont_fix: "text-slate-500 bg-slate-500/10 border-slate-500/20",
  resolved: "text-green-400 bg-green-500/10 border-green-500/20",
};

// ── Sub-components ────────────────────────────────────────────────────────────

function SortIcon({ active, dir }: { active: boolean; dir: SortDir }) {
  if (!active) return <ChevronsUpDown className="h-3 w-3 opacity-30" />;
  return dir === "asc" ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />;
}

function SubmitKBPanel({
  findingId,
  findingTitle,
  onClose,
}: {
  findingId: string;
  findingTitle: string;
  onClose: () => void;
}) {
  const [keyInsight, setKeyInsight] = useState("");
  const [technique, setTechnique] = useState("");
  const { mutate, isPending, isSuccess, error } = useSubmitFindingToKB(findingId);

  if (isSuccess)
    return (
      <div className="p-3 flex items-center gap-2 text-green-400 text-xs">
        <CheckCircle2 className="h-3.5 w-3.5 flex-shrink-0" />
        Submitted to Knowledge Base
        <button onClick={onClose} className="ml-auto text-muted-foreground hover:text-foreground">
          <X className="h-3 w-3" />
        </button>
      </div>
    );

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        mutate({ key_insight: keyInsight, technique });
      }}
      className="p-3 space-y-2 bg-muted/30 border-t border-border"
    >
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-foreground flex items-center gap-1">
          <BookMarked className="h-3 w-3 text-primary" />
          Submit to KB — <span className="text-muted-foreground font-normal truncate max-w-48">{findingTitle}</span>
        </span>
        <button type="button" onClick={onClose} className="text-muted-foreground hover:text-foreground">
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
      <div className="flex gap-2">
        <input
          value={keyInsight}
          onChange={(e) => setKeyInsight(e.target.value)}
          placeholder="Key insight (optional)"
          className="flex-1 text-xs bg-background border border-border rounded px-2 py-1 focus:outline-none focus:ring-1 focus:ring-primary"
        />
        <input
          value={technique}
          onChange={(e) => setTechnique(e.target.value)}
          placeholder="Attack technique (optional)"
          className="flex-1 text-xs bg-background border border-border rounded px-2 py-1 focus:outline-none focus:ring-1 focus:ring-primary"
        />
        <button
          type="submit"
          disabled={isPending}
          className="px-3 py-1 rounded bg-primary text-primary-foreground text-xs font-medium disabled:opacity-50 flex items-center gap-1"
        >
          {isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <BookMarked className="h-3 w-3" />}
          Submit
        </button>
      </div>
      {error && <p className="text-xs text-red-400">{error.message}</p>}
    </form>
  );
}

function PayloadPanel({
  finding,
  onClose,
}: {
  finding: Finding;
  onClose: () => void;
}) {
  const [paramName, setParamName] = useState("");
  const [count, setCount] = useState(8);
  const [copied, setCopied] = useState<string | null>(null);
  const { mutate, isPending, data, error } = useGeneratePayloads();

  const copy = (val: string) => {
    navigator.clipboard.writeText(val);
    setCopied(val);
    setTimeout(() => setCopied(null), 1500);
  };

  return (
    <div className="p-3 space-y-2 bg-muted/30 border-t border-border">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-foreground flex items-center gap-1">
          <Wand2 className="h-3 w-3 text-primary" />
          Payload Generator
        </span>
        <button type="button" onClick={onClose} className="text-muted-foreground hover:text-foreground">
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
      <div className="flex gap-2">
        <input
          type="text"
          placeholder="Parameter name (e.g. id)"
          value={paramName}
          onChange={(e) => setParamName(e.target.value)}
          className="flex-1 text-xs bg-background border border-border rounded px-2 py-1 focus:outline-none focus:ring-1 focus:ring-primary"
        />
        <select
          value={count}
          onChange={(e) => setCount(Number(e.target.value))}
          className="text-xs bg-background border border-border rounded px-1 py-1"
        >
          {[5, 8, 10, 15, 20].map((n) => (
            <option key={n} value={n}>{n}</option>
          ))}
        </select>
        <button
          type="button"
          onClick={() =>
            mutate({
              target_url: finding.target_url,
              parameter_name: paramName || "id",
              vuln_class: finding.vuln_class,
              http_method: finding.http_method,
              count,
            })
          }
          disabled={isPending}
          className="flex items-center gap-1 px-2.5 py-1 rounded text-xs font-medium bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
        >
          {isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Wand2 className="h-3 w-3" />}
          Generate
        </button>
      </div>
      {error && <p className="text-xs text-red-400">{error.message}</p>}
      {data && (
        <div className="space-y-1 max-h-48 overflow-y-auto">
          <p className="text-[10px] text-muted-foreground">{data.payloads.length} payloads · {data.knowledge_used} KB records</p>
          {data.payloads.map((p: GeneratedPayload, i: number) => (
            <div key={i} className="group flex items-start gap-2 rounded border border-border/50 bg-background/60 p-1.5">
              <div className="flex-1 min-w-0">
                <code className="text-xs font-mono break-all text-foreground">{p.value}</code>
                <p className="text-[10px] text-muted-foreground mt-0.5">{p.rationale}</p>
              </div>
              <button
                type="button"
                onClick={() => copy(p.value)}
                className="shrink-0 opacity-0 group-hover:opacity-100 p-0.5 hover:text-primary transition-opacity"
              >
                {copied === p.value ? <Check className="h-3 w-3 text-green-500" /> : <Copy className="h-3 w-3" />}
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function ExpandedDetail({ finding }: { finding: Finding }) {
  return (
    <div className="px-4 pb-3 pt-1 grid grid-cols-2 gap-x-8 gap-y-3 text-xs border-t border-border bg-muted/10">
      {finding.description && (
        <div className="col-span-2">
          <p className="text-muted-foreground mb-1 font-medium">Description</p>
          <p className="text-foreground/80 leading-relaxed whitespace-pre-wrap">{finding.description}</p>
        </div>
      )}
      <div>
        <p className="text-muted-foreground mb-1 font-medium">Discovered by</p>
        <p className="font-mono text-foreground/80">{finding.discovered_by}</p>
      </div>
      <div>
        <p className="text-muted-foreground mb-1 font-medium">Discovered at</p>
        <p className="font-mono text-foreground/80">{new Date(finding.discovered_at).toLocaleString()}</p>
      </div>
      {finding.cvss_score != null && (
        <div>
          <p className="text-muted-foreground mb-1 font-medium">CVSS Score</p>
          <p className="font-mono text-foreground/80">{finding.cvss_score.toFixed(1)}</p>
        </div>
      )}
      {finding.cve_data && (
        <div className="col-span-2">
          <p className="text-muted-foreground mb-1 font-medium">CVE Details</p>
          <p className="text-foreground/80 leading-relaxed">{finding.cve_data.description}</p>
          {finding.cve_data.references.length > 0 && (
            <div className="flex flex-wrap gap-2 mt-1">
              {finding.cve_data.references.slice(0, 3).map((ref) => (
                <a
                  key={ref}
                  href={ref}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline flex items-center gap-0.5"
                >
                  <ExternalLink className="h-2.5 w-2.5" />
                  {new URL(ref).hostname}
                </a>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────────────────────

export function FindingsTable({ findings }: FindingsTableProps) {
  const [sortField, setSortField] = useState<SortField>("severity");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [filterSeverity, setFilterSeverity] = useState<string>("all");
  const [filterStatus, setFilterStatus] = useState<string>("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [kbFindingId, setKbFindingId] = useState<string | null>(null);
  const [payloadFinding, setPayloadFinding] = useState<Finding | null>(null);

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortField(field);
      setSortDir("asc");
    }
  };

  const filtered = findings
    .filter((f) => filterSeverity === "all" || f.severity === filterSeverity)
    .filter((f) => filterStatus === "all" || f.status === filterStatus);

  const sorted = [...filtered].sort((a, b) => {
    let cmp: number;
    if (sortField === "severity") {
      cmp = (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9);
    } else if (sortField === "cvss_score") {
      cmp = (b.cvss_score ?? 0) - (a.cvss_score ?? 0);
    } else {
      cmp = String(a[sortField] ?? "").localeCompare(String(b[sortField] ?? ""));
    }
    return sortDir === "asc" ? cmp : -cmp;
  });

  // Summary counts per severity
  const counts = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <div className="flex flex-col h-full gap-3">
      {/* Summary pills */}
      <div className="flex items-center gap-2 flex-wrap">
        {(["critical", "high", "medium", "low", "info"] as const).map((sev) =>
          counts[sev] ? (
            <FilterChip
              key={sev}
              label={sev.charAt(0).toUpperCase() + sev.slice(1)}
              severity={sev}
              count={counts[sev]}
              active={filterSeverity === sev}
              onClick={() => setFilterSeverity(filterSeverity === sev ? "all" : sev)}
            />
          ) : null
        )}
        <div className="ml-auto flex items-center gap-2">
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="text-xs bg-background border border-border rounded px-2 py-1 text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          >
            <option value="all">All statuses</option>
            <option value="open">Open</option>
            <option value="confirmed">Confirmed</option>
            <option value="false_positive">False positive</option>
            <option value="wont_fix">Won't fix</option>
            <option value="resolved">Resolved</option>
          </select>
          <span className="text-xs text-muted-foreground">{sorted.length} / {findings.length}</span>
        </div>
      </div>

      {/* Table */}
      {sorted.length === 0 ? (
        <div className="flex flex-col items-center justify-center flex-1 text-muted-foreground py-12">
          <Bug className="h-8 w-8 mb-2 opacity-20" />
          <p className="text-sm">No findings match filters</p>
        </div>
      ) : (
        <div className="flex-1 overflow-auto rounded-lg border border-border">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-card border-b border-border z-10">
              <tr>
                {(
                  [
                    { field: "severity" as SortField, label: "Severity", width: "w-24" },
                    { field: "title" as SortField, label: "Title", width: "" },
                    { field: "vuln_class" as SortField, label: "Class", width: "w-32" },
                    { field: "status" as SortField, label: "Status", width: "w-28" },
                    { field: "cvss_score" as SortField, label: "CVSS", width: "w-16" },
                  ] as const
                ).map(({ field, label, width }) => (
                  <th
                    key={field}
                    className={cn(
                      "text-left px-3 py-2 font-medium text-muted-foreground cursor-pointer select-none hover:text-foreground transition-colors",
                      width
                    )}
                    onClick={() => toggleSort(field)}
                  >
                    <span className="flex items-center gap-1">
                      {label}
                      <SortIcon active={sortField === field} dir={sortDir} />
                    </span>
                  </th>
                ))}
                <th className="text-left px-3 py-2 font-medium text-muted-foreground w-20">CVE</th>
                <th className="px-3 py-2 w-16"></th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((f) => {
                const isExpanded = expandedId === f.id;
                const isKB = kbFindingId === f.id;
                const isPayload = payloadFinding?.id === f.id;

                return (
                  <>
                    <tr
                      key={f.id}
                      className={cn(
                        "border-b border-border/50 hover:bg-muted/20 transition-colors cursor-pointer",
                        isExpanded && "bg-muted/20"
                      )}
                      onClick={() => setExpandedId(isExpanded ? null : f.id)}
                    >
                      {/* Severity */}
                      <td className="px-3 py-2.5">
                        <SeverityBadge severity={f.severity} />
                      </td>

                      {/* Title + URL */}
                      <td className="px-3 py-2.5 max-w-0">
                        <p className="font-medium text-foreground truncate">{f.title}</p>
                        <p className="text-[10px] text-muted-foreground font-mono truncate mt-0.5">
                          <span className="text-primary/70">{f.http_method}</span>
                          {" "}
                          {f.target_url}
                        </p>
                      </td>

                      {/* Vuln class */}
                      <td className="px-3 py-2.5 text-muted-foreground font-mono">
                        {f.vuln_class}
                      </td>

                      {/* Status */}
                      <td className="px-3 py-2.5">
                        <span
                          className={cn(
                            "inline-flex items-center px-1.5 py-0.5 rounded border text-[10px]",
                            STATUS_STYLES[f.status] ?? ""
                          )}
                        >
                          {f.status.replace("_", " ")}
                        </span>
                      </td>

                      {/* CVSS */}
                      <td className="px-3 py-2.5 font-mono text-muted-foreground">
                        {f.cvss_score != null ? f.cvss_score.toFixed(1) : "—"}
                      </td>

                      {/* CVE IDs */}
                      <td className="px-3 py-2.5">
                        {f.cve_ids?.length > 0 ? (
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${f.cve_ids[0]}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            onClick={(e) => e.stopPropagation()}
                            className="inline-flex items-center gap-0.5 text-orange-400 hover:text-orange-300 font-mono"
                          >
                            {f.cve_ids[0]}
                            {f.cve_ids.length > 1 && (
                              <span className="text-muted-foreground">+{f.cve_ids.length - 1}</span>
                            )}
                          </a>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </td>

                      {/* Actions */}
                      <td className="px-3 py-2.5">
                        <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                          <button
                            title="Generate payloads"
                            onClick={() => setPayloadFinding(isPayload ? null : f)}
                            className={cn(
                              "p-1 rounded hover:bg-muted transition-colors",
                              isPayload ? "text-primary" : "text-muted-foreground hover:text-foreground"
                            )}
                          >
                            <Wand2 className="h-3.5 w-3.5" />
                          </button>
                          <button
                            title="Submit to Knowledge Base"
                            onClick={() => setKbFindingId(isKB ? null : f.id)}
                            className={cn(
                              "p-1 rounded hover:bg-muted transition-colors",
                              isKB ? "text-primary" : "text-muted-foreground hover:text-foreground"
                            )}
                          >
                            <BookMarked className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>

                    {/* Expanded detail */}
                    {isExpanded && (
                      <tr key={`${f.id}-detail`}>
                        <td colSpan={7} className="p-0">
                          <ExpandedDetail finding={f} />
                        </td>
                      </tr>
                    )}

                    {/* KB panel */}
                    {isKB && (
                      <tr key={`${f.id}-kb`}>
                        <td colSpan={7} className="p-0">
                          <SubmitKBPanel
                            findingId={f.id}
                            findingTitle={f.title}
                            onClose={() => setKbFindingId(null)}
                          />
                        </td>
                      </tr>
                    )}

                    {/* Payload panel */}
                    {isPayload && (
                      <tr key={`${f.id}-payload`}>
                        <td colSpan={7} className="p-0">
                          <PayloadPanel
                            finding={f}
                            onClose={() => setPayloadFinding(null)}
                          />
                        </td>
                      </tr>
                    )}
                  </>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
