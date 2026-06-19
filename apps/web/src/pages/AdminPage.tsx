import { useState } from "react";
import {
  Users,
  Target,
  FolderOpen,
  BookOpen,
  Loader2,
  Play,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Server,
} from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import axios from "axios";
import { useAuthStore } from "../lib/authStore";
import { cn } from "../lib/utils";
import { Navigate } from "react-router-dom";

// ── API client ─────────────────────────────────────────────────────────────

const BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

function authHeaders() {
  const token = useAuthStore.getState().accessToken;
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function fetchStats() {
  const res = await axios.get(`${BASE}/api/v1/admin/stats`, { headers: authHeaders() });
  return res.data as AdminStats;
}

async function triggerImport(body: BulkImportPayload) {
  const res = await axios.post(`${BASE}/api/v1/admin/knowledge/bulk-import`, body, {
    headers: authHeaders(),
  });
  return res.data as { task_id: string; message: string };
}

// ── Types ──────────────────────────────────────────────────────────────────

interface AdminStats {
  total_records: number;
  embedded_records: number;
  records_by_source: Record<string, number>;
  records_by_vuln_class: Record<string, number>;
  total_users: number;
  total_workspaces: number;
  total_engagements: number;
  total_findings: number;
}

interface BulkImportPayload {
  source: "h1_graphql" | "bugcrowd" | "rss_feeds" | "payloads_all_things";
  max_records: number;
}

interface ImportJob {
  task_id: string;
  source: string;
  started_at: string;
  status: "queued" | "running" | "done" | "error";
}

// ── Sub-components ─────────────────────────────────────────────────────────

function StatCard({
  icon: Icon,
  label,
  value,
  sub,
  color = "text-primary",
}: {
  icon: React.ElementType;
  label: string;
  value: number | string;
  sub?: string;
  color?: string;
}) {
  return (
    <div className="bg-card border border-border rounded-lg p-4 flex items-start gap-3">
      <span className={cn("mt-0.5", color)}>
        <Icon className="h-5 w-5" />
      </span>
      <div>
        <p className="text-2xl font-bold text-foreground">{value.toLocaleString()}</p>
        <p className="text-xs text-muted-foreground mt-0.5">{label}</p>
        {sub && <p className="text-[10px] text-muted-foreground mt-0.5 opacity-70">{sub}</p>}
      </div>
    </div>
  );
}

function BarChart({
  data,
  label,
  colorClass = "bg-primary/60",
}: {
  data: Record<string, number>;
  label: string;
  colorClass?: string;
}) {
  const entries = Object.entries(data)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 12);
  const max = entries[0]?.[1] ?? 1;

  return (
    <div className="bg-card border border-border rounded-lg p-4">
      <h3 className="text-sm font-semibold text-foreground mb-3">{label}</h3>
      <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
        {entries.length === 0 ? (
          <p className="text-xs text-muted-foreground">No data yet</p>
        ) : (
          entries.map(([key, count]) => (
            <div key={key} className="flex items-center gap-2">
              <span className="text-[10px] font-mono text-muted-foreground w-36 truncate flex-shrink-0">
                {key}
              </span>
              <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                <div
                  className={cn("h-full rounded-full transition-all", colorClass)}
                  style={{ width: `${(count / max) * 100}%` }}
                />
              </div>
              <span className="text-[10px] text-muted-foreground w-8 text-right flex-shrink-0">
                {count}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

// ── Import trigger panel ───────────────────────────────────────────────────

const SOURCES = [
  {
    key: "h1_graphql" as const,
    label: "HackerOne Hacktivity",
    description: "Public H1 disclosed reports via GraphQL",
    color: "text-green-400",
  },
  {
    key: "bugcrowd" as const,
    label: "Bugcrowd Disclosures",
    description: "Public Bugcrowd researcher disclosures",
    color: "text-blue-400",
  },
  {
    key: "rss_feeds" as const,
    label: "Security RSS Feeds",
    description: "Pentester.land, PortSwigger, NahamSec etc.",
    color: "text-yellow-400",
  },
  {
    key: "payloads_all_things" as const,
    label: "PayloadsAllTheThings",
    description: "Technique + payload cheatsheets",
    color: "text-purple-400",
  },
];

function ImportPanel() {
  const qc = useQueryClient();
  const [maxRecords, setMaxRecords] = useState(500);
  const [jobs, setJobs] = useState<ImportJob[]>([]);

  const importMutation = useMutation({
    mutationFn: triggerImport,
    onSuccess: (data, vars) => {
      setJobs((prev) => [
        {
          task_id: data.task_id,
          source: vars.source,
          started_at: new Date().toISOString(),
          status: "queued",
        },
        ...prev,
      ]);
      qc.invalidateQueries({ queryKey: ["admin-stats"] });
    },
  });

  return (
    <div className="bg-card border border-border rounded-lg p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-foreground">Bulk Import</h3>
        <div className="flex items-center gap-2">
          <label className="text-xs text-muted-foreground">Max records:</label>
          <select
            value={maxRecords}
            onChange={(e) => setMaxRecords(Number(e.target.value))}
            className="bg-background border border-border rounded px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
          >
            {[100, 500, 1000, 5000, 10000, 50000].map((n) => (
              <option key={n} value={n}>
                {n.toLocaleString()}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mb-4">
        {SOURCES.map((src) => (
          <button
            key={src.key}
            onClick={() => importMutation.mutate({ source: src.key, max_records: maxRecords })}
            disabled={importMutation.isPending}
            className="flex items-start gap-3 p-3 rounded-lg border border-border hover:bg-accent/50 transition-colors text-left disabled:opacity-50"
          >
            <Play className={cn("h-4 w-4 mt-0.5 flex-shrink-0", src.color)} />
            <div>
              <p className="text-xs font-medium text-foreground">{src.label}</p>
              <p className="text-[10px] text-muted-foreground mt-0.5">{src.description}</p>
            </div>
          </button>
        ))}
      </div>

      {/* Recent jobs */}
      {jobs.length > 0 && (
        <div className="space-y-1">
          <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1">
            Queued tasks
          </p>
          {jobs.map((job) => (
            <div
              key={job.task_id}
              className="flex items-center gap-2 text-xs px-2 py-1 rounded bg-background border border-border/50"
            >
              <CheckCircle2 className="h-3 w-3 text-green-400 flex-shrink-0" />
              <span className="text-muted-foreground font-mono">{job.source}</span>
              <span className="ml-auto text-[10px] text-muted-foreground">
                {job.task_id.slice(0, 8)}
              </span>
            </div>
          ))}
        </div>
      )}

      {importMutation.isError && (
        <div className="flex items-center gap-2 mt-2 text-xs text-red-400">
          <AlertTriangle className="h-3.5 w-3.5" />
          Failed to queue task — is the Celery worker running?
        </div>
      )}
    </div>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────

export default function AdminPage() {
  const user = useAuthStore((s) => s.user);

  const { data: stats, isLoading, error, refetch } = useQuery<AdminStats>({
    queryKey: ["admin-stats"],
    queryFn: fetchStats,
    refetchInterval: 30_000,
    enabled: !!user?.is_admin,
  });

  if (!user?.is_admin) {
    return <Navigate to="/" replace />;
  }

  return (
    <div className="flex-1 overflow-auto p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-foreground flex items-center gap-2">
            <Server className="h-5 w-5 text-primary" />
            Admin Dashboard
          </h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            Platform stats and knowledge base management
          </p>
        </div>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground border border-border rounded-md transition-colors"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh
        </button>
      </div>

      {isLoading && (
        <div className="flex items-center gap-2 text-muted-foreground text-sm py-12 justify-center">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading stats…
        </div>
      )}

      {error && (
        <div className="flex items-center gap-2 text-red-400 text-sm py-4">
          <AlertTriangle className="h-4 w-4" />
          Failed to load stats
        </div>
      )}

      {stats && (
        <div className="space-y-6">
          {/* Top stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <StatCard
              icon={BookOpen}
              label="KB Records"
              value={stats.total_records}
              sub={`${stats.embedded_records} embedded`}
              color="text-primary"
            />
            <StatCard
              icon={Users}
              label="Users"
              value={stats.total_users}
              color="text-blue-400"
            />
            <StatCard
              icon={Target}
              label="Engagements"
              value={stats.total_engagements}
              sub={`${stats.total_findings} findings`}
              color="text-yellow-400"
            />
            <StatCard
              icon={FolderOpen}
              label="Workspaces"
              value={stats.total_workspaces}
              color="text-green-400"
            />
          </div>

          {/* Charts + Import */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <BarChart
              data={stats.records_by_source}
              label="Records by Source"
              colorClass="bg-primary/60"
            />
            <BarChart
              data={stats.records_by_vuln_class}
              label="Records by Vuln Class"
              colorClass="bg-blue-500/60"
            />
            <ImportPanel />
          </div>

          {/* Embedded progress bar */}
          {stats.total_records > 0 && (
            <div className="bg-card border border-border rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-sm font-semibold text-foreground">Embedding Progress</h3>
                <span className="text-xs text-muted-foreground">
                  {stats.embedded_records} / {stats.total_records} indexed
                </span>
              </div>
              <div className="h-2 bg-muted rounded-full overflow-hidden">
                <div
                  className="h-full bg-primary rounded-full transition-all"
                  style={{
                    width: `${(stats.embedded_records / stats.total_records) * 100}%`,
                  }}
                />
              </div>
              <p className="text-[10px] text-muted-foreground mt-1.5">
                {Math.round((stats.embedded_records / stats.total_records) * 100)}% ready for RAG
                search — run the embed_pending_records worker task to index remaining records.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
