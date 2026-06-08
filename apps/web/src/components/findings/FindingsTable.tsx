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
import {
  useSubmitFindingToKB,
  useGeneratePayloads,
  usePatchFinding,
} from "../../lib/api";
import type { GeneratedPayload } from "../../lib/api";
import type {
  Finding,
  FindingStatus,
  Severity,
} from "../../lib/types";
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

const SEVERITY_STYLES: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/30",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  low: "text-blue-400 bg-blue-400/10 border-blue-400/30",
  info: "text-slate-400 bg-slate-500/10 border-slate-500/30",
};

const STATUS_STYLES: Record<FindingStatus, string> = {
  open: "text-red-400 bg-red-500/10 border-red-500/20",
  confirmed: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  false_positive: "text-slate-400 bg-slate-500/10 border-slate-500/20",
  wont_fix: "text-slate-500 bg-slate-500/10 border-slate-500/20",
  resolved: "text-green-400 bg-green-500/10 border-green-500/20",
};

const STATUS_LABELS: Record<FindingStatus, string> = {
  open: "Open",
  confirmed: "Confirmed",
  false_positive: "False Positive",
  wont_fix: "Won't Fix",
  resolved: "Resolved",
};

const ALL_STATUSES: FindingStatus[] = [
  "open",
  "confirmed",
  "false_positive",
  "wont_fix",
  "resolved",
];

// ── Sub-components ────────────────────────────────────────────────────────────

function SortIcon({
  active,
  dir,
}: {
  active: boolean;
  dir: SortDir;
}) {
  if (!active) return <ChevronsUpDown className="h-3 w-3 opacity-30" />;
  return dir === "asc" ? (
    <ChevronUp className="h-3 w-3" />
  ) : (
    <ChevronDown className="h-3 w-3" />
  );
}

function StatusSelect({
  finding,
  engagementId,
}: {
  finding: Finding;
  engagementId: string;
}) {
  const { mutate, isPending } = usePatchFinding(engagementId);

  return (
    <div className="relative inline-flex items-center">
      {isPending && (
        <Loader2 className="absolute left-1.5 h-2.5 w-2.5 animate-spin text-muted-foreground z-10 pointer-events-none" />
      )}
      <select
        value={finding.status}
        onClick={(e) => e.stopPropagation()}
        onChange={(e) => {
          mutate({ id: finding.id, status: e.target.value as FindingStatus });
        }}
        disabled={isPending}
        className={cn(
          "text-[10px] font-medium border rounded px-1.5 py-0.5 cursor-pointer appearance-none pr-4",
          "bg-transparent focus:outline-none focus:ring-1 focus:ring-primary transition-colors",
          "disabled:opacity-60",
          STATUS_STYLES[finding.status],
          isPending && "pl-5",
        )}
      >
        {ALL_STATUSES.map((s) => (
          <option
            key={s}
            value={s}
            className="bg-background text-foreground font-normal"
          >
            {STATUS_LABELS[s]}
          </option>
        ))}
      </select>
      <ChevronDown className="absolute right-0.5 h-2 w-2 pointer-events-none opacity-50" />
    </div>
  );
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
  const { mutate, isPending, isSuccess, error } =
    useSubmitFindingToKB(findingId);

  if (isSuccess)
    return (
      <div className="p-3 flex items-center gap-2 text-green-400 text-xs">
        <CheckCircle2 className="h-3.5 w-3.5 flex-shrink-0" />
        Submitted to Knowledge Base
        <button
          onClick={onClose}
          className="ml-auto text-muted-foreground hover:text-foreground"
        >
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
          Submit to KB —{" "}
          <span className="text-muted-foreground font-normal truncate max-w-48">
            {findingTitle}
          </span>
        </span>
        <button
          type="button"
          onClick={onClose}
          className="text-muted-foreground hover:text-foreground"
        >
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
          {isPending ? (
            <Loader2 className="h-3 w-3 animate-spin" />
          ) : (
            <BookMarked className="h-3 w-3" />
          )}
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
        <button
          type="button"
          onClick={onClose}
          className="text-muted-foreground hover:text-foreground"
        >
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
            <option key={n} value={n}>
              {n}
            </option>
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
          {isPending ? (
            <Loader2 className="h-3 w-3 animate-spin" />
          ) : (
            <Wand2 className="h-3 w-3" />
          )}
          Generate
        </button>
      </div>
      {error && <p className="text-xs text-red-400">{error.message}</p>}
      {data && (
        <div className="space-y-1 max-h-48 overflow-y-auto">
          <p className="text-[10px] text-muted-foreground">
            {data.payloads.length} payloads · {data.knowledge_used} KB records
          </p>
          {data.payloads.map((p: GeneratedPayload, i: number) => (
            <div
              key={i}
              className="group flex items-start gap-2 rounded border border-border/50 bg-background/60 p-1.5"
            >
              <div className="flex-1 min-w-0">
                <code className="text-xs font-mono break-all text-foreground">
                  {p.value}
                </code>
                <p className="text-[10px] text-muted-foreground mt-0.5">
                  {p.rationale}
                </p>
              </div>
              <button
                type="button"
                onClick={() => copy(p.value)}
                className="shrink-0 opacity-0 group-hover:opacity-100 p-0.5 hover:text-primary transition-opacity"
              >
                {copied === p.value ? (
                  <Check className="h-3 w-3 text-green-500" />
                ) : (
                  <Copy className="h-3 w-3" />
                )}
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
          <p className="text-foreground/80 leading-relaxed whitespace-pre-wrap">
            {finding.description}
          </p>
        </div>
      )}
      <div>
        <p className="text-muted-foreground mb-1 font-medium">Discovered by</p>
        <p className="font-mono text-foreground/80">{finding.discovered_by}</p>
      </div>
      <div>
        <p className="text-muted-foreground mb-1 font-medium">Discovered at</p>
        <p className="font-mono text-foreground/80">
          {new Date(finding.discovered_at).toLocaleString()}
        </p>
      </div>
      {finding.cvss_score != null && (
        <div>
          <p className="text-muted-foreground mb-1 font-medium">CVSS Score</p>
          <p className="font-mono text-foreground/80">
            {finding.cvss_score.toFixed(1)}
          </p>
        </div>
      )}
      {finding.cvss_vector && (
        <div className={finding.cvss_score != null ? "" : "col-span-2"}>
          <p className="text-muted-foreground mb-1 font-medium">CVSS Vector</p>
          <p className="font-mono text-[10px] text-foreground/70 break-all leading-relaxed">
            {finding.cvss_vector}
          </p>
        </div>
      )}
      {finding.impact && (
        <div className="col-span-2">
          <p className="text-muted-foreground mb-1 font-medium">Impact</p>
          <p className="text-foreground/80 leading-relaxed">{finding.impact}</p>
        </div>
      )}
      {finding.remediation && (
        <div className="col-span-2">
          <p className="text-muted-foreground mb-1 font-medium">Remediation</p>
          <p className="text-foreground/80 leading-relaxed">{finding.remediation}</p>
        </div>
      )}
      {finding.chains && finding.chains.length > 0 && (
        <div className="col-span-2">
          <p className="text-xs text-slate-500 font-semibold uppercase tracking-wider mb-2">
            ⛓️ Attack Chains
          </p>
          <div className="space-y-2">
            {finding.chains.map((chain, i) => (
              <div
                key={i}
                className="bg-red-950/30 border border-red-900/40 rounded p-3"
              >
                <div className="flex items-center gap-2 mb-1">
                  <span className="inline-flex items-center rounded border border-red-800 px-1.5 py-0.5 text-xs font-semibold text-red-400">
                    {chain.upgraded_severity?.toUpperCase() ?? "CHAIN"}
                  </span>
                  <span className="text-sm font-medium text-red-300">
                    {chain.name}
                  </span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {chain.scenario}
                </p>
                {chain.business_impact && (
                  <p className="text-xs text-red-400 mt-1">
                    💥 {chain.business_impact}
                  </p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
      {finding.cve_data && (
        <div className="col-span-2">
          <p className="text-muted-foreground mb-1 font-medium">CVE Details</p>
          <p className="text-foreground/80 leading-relaxed">
            {finding.cve_data.description}
          </p>
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

export function FindingsTable({ engagementId, findings }: FindingsTableProps) {
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
    let cmp = 0;
    if (sortField === "severity") {
      cmp =
        (SEVERITY_ORDER[a.severity] ?? 9) -
        (SEVERITY_ORDER[b.severity] ?? 9);
    } else if (sortField === "cvss_score") {
      cmp = (b.cvss_score ?? 0) - (a.cvss_score ?? 0);
    } else {
      cmp = String(a[sortField] ?? "").localeCompare(
        String(b[sortField] ?? ""),
      );
    }
    return sortDir === "asc" ? cmp : -cmp;
  });

  // Summary counts per severity
  const counts = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});

  const Th = ({
    field,
    children,
    className,
  }: {
    field: SortField;
    children: React.ReactNode;
    className?: string;
  }) => (
    <th
      className={cn(
        "px-3 py-2 text-left text-[11px] font-medium text-muted-foreground cursor-pointer select-none",
        "hover:text-foreground transition-colors whitespace-nowrap",
        className,
      )}
      onClick={() => toggleSort(field)}
    >
      <span className="inline-flex items-center gap-1">
        {children}
        <SortIcon active={sortField === field} dir={sortDir} />
      </span>
    </th>
  );

  return (
    <div className="flex flex-col h-full gap-3">
      {/* Summary pills + filters */}
      <div className="flex items-center gap-2 flex-wrap">
        {(["critical", "high", "medium", "low", "info"] as const).map((sev) =>
          counts[sev] ? (
            <button
              key={sev}
              onClick={() =>
                setFilterSeverity(filterSeverity === sev ? "all" : sev)
              }
              className={cn(
                "inline-flex items-center gap-1 px-2 py-0.5 rounded border text-[11px] font-medium transition-colors",
                SEVERITY_STYLES[sev],
                filterSeverity === sev && "ring-1 ring-current",
              )}
            >
              {sev.charAt(0).toUpperCase() + sev.slice(1)}
              <span className="opacity-70">{counts[sev]}</span>
            </button>
          ) : null,
        )}
        <div className="ml-auto flex items-center gap-2">
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="text-xs bg-background border border-border rounded px-2 py-1 text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          >
            <option value="all">All statuses</option>
            {ALL_STATUSES.map((s) => (
              <option key={s} value={s}>
                {STATUS_LABELS[s]}
              </option>
            ))}
          </select>
          <span className="text-xs text-muted-foreground">
            {sorted.length} / {findings.length}
          </span>
        </div>
      </div>

      {/* Table */}
      {sorted.length === 0 ? (
        <div className="flex flex-col items-center justify-center flex-1 text-muted-foreground py-12">
          <Bug className="h-8 w-8 mb-2 opacity-30" />
          <p className="text-sm">No findings match filters</p>
        </div>
      ) : (
        <div className="overflow-auto rounded-md border border-border flex-1">
          <table className="w-full text-sm border-collapse">
            <thead className="sticky top-0 bg-background/95 backdrop-blur-sm z-10 border-b border-border">
              <tr>
                <Th field="severity" className="w-24">
                  Severity
                </Th>
                <Th field="title">Title / URL</Th>
                <Th field="vuln_class" className="w-36">
                  Vuln Class
                </Th>
                <Th field="status" className="w-36">
                  Status
                </Th>
                <Th field="cvss_score" className="w-20">
                  CVSS
                </Th>
                <th className="px-3 py-2 w-20" />
              </tr>
            </thead>
            <tbody>
              {sorted.map((finding) => {
                const isExpanded = expandedId === finding.id;
                const isKB = kbFindingId === finding.id;
                const isPayload = payloadFinding?.id === finding.id;

                return (
                  <>
                    <tr
                      key={finding.id}
                      onClick={() =>
                        setExpandedId(isExpanded ? null : finding.id)
                      }
                      className={cn(
                        "border-b border-border/50 cursor-pointer transition-colors",
                        isExpanded
                          ? "bg-muted/20"
                          : "hover:bg-muted/10",
                      )}
                    >
                      {/* Severity */}
                      <td className="px-3 py-2">
                        <span
                          className={cn(
                            "inline-flex items-center px-1.5 py-0.5 rounded border text-[10px] font-semibold uppercase tracking-wide",
                            SEVERITY_STYLES[finding.severity],
                          )}
                        >
                          {finding.severity}
                        </span>
                      </td>

                      {/* Title / URL */}
                      <td className="px-3 py-2">
                        <p className="font-medium text-foreground text-xs leading-snug">
                          {finding.title}
                        </p>
                        <p className="text-[10px] text-muted-foreground font-mono truncate max-w-xs mt-0.5">
                          {finding.http_method} {finding.target_url}
                        </p>
                        {finding.cve_ids.length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-1">
                            {finding.cve_ids.map((cve) => (
                              <span
                                key={cve}
                                className="text-[9px] font-mono border border-blue-500/30 text-blue-400 bg-blue-500/10 rounded px-1 py-0.5"
                              >
                                {cve}
                              </span>
                            ))}
                          </div>
                        )}
                      </td>

                      {/* Vuln Class */}
                      <td className="px-3 py-2 text-xs text-muted-foreground">
                        {finding.vuln_class}
                      </td>

                      {/* Status — inline editable dropdown */}
                      <td
                        className="px-3 py-2"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <StatusSelect
                          finding={finding}
                          engagementId={engagementId}
                        />
                      </td>

                      {/* CVSS */}
                      <td className="px-3 py-2 text-xs font-mono text-muted-foreground">
                        {finding.cvss_score != null
                          ? finding.cvss_score.toFixed(1)
                          : "—"}
                      </td>

                      {/* Actions */}
                      <td
                        className="px-3 py-2"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <div className="flex items-center gap-1">
                          <button
                            type="button"
                            title="Generate payloads"
                            onClick={() =>
                              setPayloadFinding(
                                isPayload ? null : finding,
                              )
                            }
                            className={cn(
                              "p-1 rounded hover:bg-muted transition-colors",
                              isPayload
                                ? "text-primary"
                                : "text-muted-foreground hover:text-foreground",
                            )}
                          >
                            <Wand2 className="h-3.5 w-3.5" />
                          </button>
                          <button
                            type="button"
                            title="Submit to Knowledge Base"
                            onClick={() =>
                              setKbFindingId(isKB ? null : finding.id)
                            }
                            className={cn(
                              "p-1 rounded hover:bg-muted transition-colors",
                              isKB
                                ? "text-primary"
                                : "text-muted-foreground hover:text-foreground",
                            )}
                          >
                            <BookMarked className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>

                    {/* Expanded detail row */}
                    {isExpanded && (
                      <tr key={`${finding.id}-detail`} className="bg-muted/5">
                        <td colSpan={6} className="p-0">
                          <ExpandedDetail finding={finding} />
                        </td>
                      </tr>
                    )}

                    {/* KB submit panel row */}
                    {isKB && (
                      <tr key={`${finding.id}-kb`}>
                        <td colSpan={6} className="p-0">
                          <SubmitKBPanel
                            findingId={finding.id}
                            findingTitle={finding.title}
                            onClose={() => setKbFindingId(null)}
                          />
                        </td>
                      </tr>
                    )}

                    {/* Payload panel row */}
                    {isPayload && (
                      <tr key={`${finding.id}-payload`}>
                        <td colSpan={6} className="p-0">
                          <PayloadPanel
                            finding={finding}
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
