import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";

import {
  apiClient,
  useApproveAction,
  useWorkerHealth,
  useRecentFindings,
  type WorkerHealth,
} from "../lib/api";
import type { Finding } from "../lib/types";
import {
  Target,
  Shield,
  Bug,
  TrendingUp,
  ChevronRight,
  Plus,
  AlertTriangle,
  CheckCircle,
  Clock,
  Activity,
  Server,
  ArrowRight,
} from "lucide-react";

// ── Types ─────────────────────────────────────────────────────────────────────

interface AdminStats {
  total_engagements: number;
  total_findings: number;
  total_knowledge_records: number;
  total_workspaces: number;
  findings_by_severity?: Record<string, number>;
}

interface EngagementSummary {
  id: string;
  name: string;
  status: string;
  in_scope: string[];
  target_domain?: string;
  findings_count?: number;
  started_at?: string | null;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatDuration(startedAt: string | null | undefined): string {
  if (!startedAt) return "—";
  const ms = Date.now() - new Date(startedAt).getTime();
  if (ms < 0) return "—";
  const mins = Math.floor(ms / 60000);
  if (mins < 1) return "<1m";
  if (mins < 60) return `${mins}m`;
  const hrs = Math.floor(mins / 60);
  return `${hrs}h ${mins % 60}m`;
}

// ── Status config ─────────────────────────────────────────────────────────────

const STATUS_CONFIG = {
  planning: { label: "Planning", color: "text-pentra-text-muted border-pentra-border", icon: Clock },
  active: { label: "Active", color: "text-blue-400 border-blue-900", icon: Activity },
  completed: { label: "Done", color: "text-green-400 border-green-900", icon: CheckCircle },
  failed: { label: "Failed", color: "text-red-400 border-red-900", icon: AlertTriangle },
  paused: { label: "Paused", color: "text-yellow-400 border-yellow-900", icon: Clock },
  awaiting_approval: { label: "Awaiting", color: "text-yellow-400 border-yellow-900", icon: Clock },
  cancelled: { label: "Cancelled", color: "text-pentra-text-muted border-pentra-border", icon: AlertTriangle },
} as const;

// ── Severity config ───────────────────────────────────────────────────────────

const SEV_COLORS: Record<string, string> = {
  critical: "bg-red-900/60 text-red-300",
  high: "bg-orange-900/60 text-orange-300",
  medium: "bg-yellow-900/60 text-yellow-300",
  low: "bg-blue-900/60 text-blue-300",
  info: "bg-pentra-bg-card text-pentra-text-muted",
};

const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;

const SEV_BAR: Record<string, string> = {
  critical: "bg-red-500/70",
  high: "bg-orange-500/70",
  medium: "bg-yellow-500/70",
  low: "bg-blue-500/70",
  info: "bg-pentra-text-muted/30",
};

const SEV_LABEL: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-blue-400",
  info: "text-pentra-text-muted",
};

// ── Zone 1: System Status Bar ─────────────────────────────────────────────────

function SystemStatusBar({
  workerHealth,
  activeCount,
  pendingCount,
  onReviewPending,
}: {
  workerHealth: WorkerHealth | undefined;
  activeCount: number;
  pendingCount: number;
  onReviewPending: () => void;
}) {
  const isHealthy = workerHealth?.healthy ?? null;

  return (
    <div className="flex flex-wrap items-center gap-x-5 gap-y-2 px-4 py-2.5 bg-pentra-bg-card border border-pentra-border rounded-ds-lg text-xs">
      <div className="flex items-center gap-2">
        <span
          className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${
            isHealthy === null
              ? "bg-pentra-text-muted"
              : isHealthy
              ? "bg-green-400"
              : "bg-red-500"
          }`}
        />
        <Server
          size={12}
          className={
            isHealthy === null
              ? "text-pentra-text-muted"
              : isHealthy
              ? "text-green-400"
              : "text-red-400"
          }
        />
        <span
          className={
            isHealthy === null
              ? "text-pentra-text-muted"
              : isHealthy
              ? "text-green-400"
              : "text-red-400"
          }
        >
          {isHealthy === null
            ? "Checking worker..."
            : isHealthy
            ? "Worker healthy"
            : "Worker offline"}
        </span>
      </div>

      <span className="text-pentra-border hidden sm:block">·</span>

      <div className="flex items-center gap-1.5">
        <Activity
          size={12}
          className={activeCount > 0 ? "text-blue-400" : "text-pentra-text-muted"}
        />
        <span
          className={activeCount > 0 ? "text-blue-400 font-medium" : "text-pentra-text-muted"}
        >
          {activeCount} active scan{activeCount !== 1 ? "s" : ""}
        </span>
      </div>

      <span className="text-pentra-border hidden sm:block">·</span>

      {pendingCount > 0 ? (
        <button
          onClick={onReviewPending}
          className="flex items-center gap-1.5 text-yellow-400 font-medium hover:text-yellow-300 transition-colors"
        >
          <Clock size={12} />
          <span>{pendingCount} awaiting approval</span>
          <ArrowRight size={11} />
        </button>
      ) : (
        <div className="flex items-center gap-1.5 text-pentra-text-muted">
          <CheckCircle size={12} />
          <span>No pending approvals</span>
        </div>
      )}
    </div>
  );
}

// ── Stat card ─────────────────────────────────────────────────────────────────

function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  color,
  onClick,
  highlight,
}: {
  title: string;
  value: number | string;
  subtitle: string;
  icon: React.ElementType;
  color: string;
  onClick?: () => void;
  highlight?: boolean;
}) {
  return (
    <div
      className={`border rounded-ds-lg p-5 transition-all
        ${onClick ? "cursor-pointer hover:border-pentra-border-light hover:bg-pentra-bg-hover" : ""}
        ${highlight
          ? "bg-yellow-950/10 border-yellow-800/50"
          : "bg-pentra-bg-panel border-pentra-border"
        }`}
      onClick={onClick}
    >
      <div className="flex items-start justify-between">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wider text-pentra-text-muted">
            {title}
          </p>
          <p className={`text-3xl font-bold mt-1.5 ${color}`}>{value}</p>
          <p
            className={`text-xs mt-1 ${
              highlight ? "text-yellow-400/70" : "text-pentra-text-muted"
            }`}
          >
            {subtitle}
          </p>
        </div>
        <div
          className={`p-2.5 rounded-xl ${
            highlight ? "bg-yellow-900/20" : "bg-pentra-bg-card"
          }`}
        >
          <Icon size={20} className={color} />
        </div>
      </div>
    </div>
  );
}

// ── Zone 3 left: Active scan card ─────────────────────────────────────────────

function ActiveScanCard({
  engagement,
  onClick,
}: {
  engagement: EngagementSummary;
  onClick: () => void;
}) {
  const isAwaiting = engagement.status === "awaiting_approval";
  const approve = useApproveAction(engagement.id);
  const cfg =
    STATUS_CONFIG[engagement.status as keyof typeof STATUS_CONFIG] ??
    STATUS_CONFIG.planning;
  const StatusIcon = cfg.icon;
  const target = engagement.target_domain ?? engagement.in_scope?.[0] ?? "—";

  return (
    <div
      className={`rounded-ds-md border p-3.5 transition-all
        ${
          isAwaiting
            ? "border-yellow-800/50 bg-yellow-950/10"
            : "border-pentra-border bg-pentra-bg-panel hover:border-pentra-border-light hover:bg-pentra-bg-hover cursor-pointer"
        }`}
      onClick={isAwaiting ? undefined : onClick}
    >
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium text-pentra-text-primary truncate">
            {engagement.name}
          </p>
          <p className="text-xs text-pentra-text-muted truncate mt-0.5">{target}</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {engagement.started_at && (
            <span className="text-[11px] font-mono text-pentra-text-muted hidden sm:block">
              {formatDuration(engagement.started_at)}
            </span>
          )}
          <div
            className={`flex items-center gap-1 text-[11px] font-medium border rounded-full px-2 py-0.5 ${cfg.color}`}
          >
            <StatusIcon size={10} />
            {cfg.label}
          </div>
          {isAwaiting ? (
            <button
              onClick={(e) => {
                e.stopPropagation();
                approve.mutate({ action: "approve" });
              }}
              disabled={approve.isPending}
              className="text-xs px-2.5 py-1 bg-yellow-500/10 border border-yellow-700/60
                         text-yellow-300 rounded-md hover:bg-yellow-500/20 transition-colors
                         font-medium disabled:opacity-50"
            >
              {approve.isPending ? "..." : "Approve"}
            </button>
          ) : (
            <ChevronRight size={13} className="text-pentra-text-muted/40" />
          )}
        </div>
      </div>
      {isAwaiting && (
        <div className="mt-2 flex items-center justify-between">
          <p className="text-[11px] text-yellow-400/70">
            Agent is waiting for your approval to continue.
          </p>
          <button
            onClick={onClick}
            className="text-[11px] text-yellow-400 hover:text-yellow-300 transition-colors"
          >
            View details →
          </button>
        </div>
      )}
    </div>
  );
}

// ── Zone 3 right: Finding row ─────────────────────────────────────────────────

function FindingRow({
  finding,
  engagementName,
  onClick,
}: {
  finding: Finding;
  engagementName?: string;
  onClick: () => void;
}) {
  return (
    <div
      onClick={onClick}
      className="flex items-center gap-2.5 p-2.5 rounded-ds-md
                 bg-pentra-bg-panel border border-pentra-border
                 hover:border-pentra-border-light hover:bg-pentra-bg-hover
                 cursor-pointer transition-all"
    >
      <span
        className={`text-[10px] px-1.5 py-0.5 rounded font-semibold capitalize flex-shrink-0
          ${SEV_COLORS[finding.severity] ?? SEV_COLORS.info}`}
      >
        {finding.severity}
      </span>
      <p className="text-sm text-pentra-text-primary truncate flex-1">{finding.title}</p>
      <div className="flex items-center gap-2 shrink-0">
        {finding.vuln_class && (
          <span className="text-[10px] text-pentra-text-muted font-mono hidden md:block">
            {finding.vuln_class}
          </span>
        )}
        {engagementName && (
          <span className="text-[10px] text-pentra-text-muted/50 hidden lg:block truncate max-w-[100px]">
            {engagementName}
          </span>
        )}
      </div>
    </div>
  );
}

// ── Zone 4 left: Engagement card ──────────────────────────────────────────────

function EngagementCard({
  engagement,
  onClick,
}: {
  engagement: EngagementSummary;
  onClick: () => void;
}) {
  const cfg =
    STATUS_CONFIG[engagement.status as keyof typeof STATUS_CONFIG] ??
    STATUS_CONFIG.planning;
  const StatusIcon = cfg.icon;

  return (
    <div
      onClick={onClick}
      className="flex items-center justify-between p-3.5 rounded-ds-md
                 bg-pentra-bg-panel border border-pentra-border
                 hover:border-pentra-border-light hover:bg-pentra-bg-hover
                 cursor-pointer transition-all group"
    >
      <div className="flex items-center gap-3 min-w-0">
        <div className="p-1.5 rounded-lg bg-pentra-bg-card shrink-0">
          <Target size={14} className="text-pentra-text-muted" />
        </div>
        <div className="min-w-0">
          <p className="text-sm font-medium text-pentra-text-primary truncate">
            {engagement.name}
          </p>
          <p className="text-xs text-pentra-text-muted truncate mt-0.5">
            {engagement.target_domain ?? engagement.in_scope?.[0] ?? "—"}
          </p>
        </div>
      </div>
      <div className="flex items-center gap-2.5 shrink-0 ml-3">
        {(engagement.status === "active" || engagement.status === "awaiting_approval") && engagement.started_at && (
          <span className="text-[10px] font-mono text-pentra-text-muted/60 hidden sm:block">
            {formatDuration(engagement.started_at)}
          </span>
        )}
        {(engagement.findings_count ?? 0) > 0 && (
          <span className="text-xs border border-orange-900 text-orange-400 rounded px-1.5 py-0.5">
            {engagement.findings_count}
          </span>
        )}
        <div
          className={`flex items-center gap-1 text-[11px] font-medium border rounded-full px-2 py-0.5 ${cfg.color}`}
        >
          <StatusIcon size={10} />
          {cfg.label}
        </div>
        <ChevronRight
          size={13}
          className="text-pentra-text-muted/40 group-hover:text-pentra-text-muted transition-colors"
        />
      </div>
    </div>
  );
}

// ── Severity breakdown ────────────────────────────────────────────────────────

function SeverityBreakdown({ bySeverity }: { bySeverity: Record<string, number> }) {
  const total = SEV_ORDER.reduce((s, k) => s + (bySeverity[k] ?? 0), 0);
  if (total === 0)
    return (
      <div className="text-center py-8 text-pentra-text-muted text-sm border border-dashed border-pentra-border rounded-ds-lg">
        No findings recorded yet.
      </div>
    );

  return (
    <div className="bg-pentra-bg-panel border border-pentra-border rounded-ds-lg p-5">
      <div className="flex items-center justify-between mb-4">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-pentra-text-muted">
          All-time by Severity
        </p>
        <span className="text-[11px] font-mono text-pentra-text-muted">{total} total</span>
      </div>
      <div className="space-y-2.5">
        {SEV_ORDER.map((sev) => {
          const count = bySeverity[sev] ?? 0;
          const pct = total > 0 ? (count / total) * 100 : 0;
          return (
            <div key={sev} className="flex items-center gap-3">
              <span
                className={`w-14 text-[11px] font-semibold capitalize flex-shrink-0 ${SEV_LABEL[sev]}`}
              >
                {sev}
              </span>
              <div className="flex-1 h-1.5 rounded-full bg-pentra-bg-card overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-700 ${SEV_BAR[sev]}`}
                  style={{ width: `${pct}%` }}
                />
              </div>
              <span className="w-6 text-right text-[11px] font-mono text-pentra-text-muted flex-shrink-0">
                {count}
              </span>
              <span className="w-9 text-right text-[10px] font-mono text-pentra-text-muted/40 flex-shrink-0">
                {pct.toFixed(0)}%
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

export function DashboardPage() {
  const navigate = useNavigate();

  const { data: stats } = useQuery<AdminStats>({
    queryKey: ["dashboard-stats"],
    queryFn: () =>
      apiClient.get<AdminStats>("/api/v1/admin/stats").then((r) => r.data),
    refetchInterval: 30_000,
    retry: false,
  });

  const { data: engagements } = useQuery<EngagementSummary[]>({
    queryKey: ["recent-engagements"],
    queryFn: () =>
      apiClient
        .get<EngagementSummary[]>("/api/v1/engagements?limit=20")
        .then((r) => r.data),
    refetchInterval: 15_000,
  });

  const { data: workerHealth } = useWorkerHealth();
  const { data: recentFindings } = useRecentFindings(20);

  // ── Derived state ─────────────────────────────────────────────────────────

  const activeScans = (engagements ?? []).filter(
    (e) => e.status === "active" || e.status === "awaiting_approval"
  );
  const activeCount = (engagements ?? []).filter((e) => e.status === "active").length;
  const pendingCount = (engagements ?? []).filter(
    (e) => e.status === "awaiting_approval"
  ).length;
  const completedCount = (engagements ?? []).filter((e) => e.status === "completed").length;
  const firstPending = (engagements ?? []).find(
    (e) => e.status === "awaiting_approval"
  );

  const allTimeBySeverity = stats?.findings_by_severity ?? {};
  const criticalCount = allTimeBySeverity["critical"] ?? 0;
  const highCount = allTimeBySeverity["high"] ?? 0;

  const criticalHighFindings = (recentFindings ?? [])
    .filter((f) => f.severity === "critical" || f.severity === "high")
    .slice(0, 8);

  const engNameMap = Object.fromEntries(
    (engagements ?? []).map((e) => [e.id, e.name])
  );

  const totalEngagements =
    stats?.total_engagements ?? (engagements?.length ?? 0);
  const totalFindings = stats?.total_findings ?? 0;

  return (
    <div className="flex-1 w-full p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-[22px] font-bold text-pentra-text-primary">Dashboard</h1>
          <p className="text-[13px] text-pentra-text-secondary mt-0.5">
            AI Security Research Platform
          </p>
        </div>
        <button
          className="flex items-center gap-2 px-4 py-2 bg-pentra-accent hover:opacity-90 text-white rounded-ds-md text-sm font-medium transition-opacity"
          onClick={() => navigate("/scan/new")}
        >
          <Plus size={15} />
          New Scan
        </button>
      </div>

      {/* Zone 1 — System Status Bar */}
      <SystemStatusBar
        workerHealth={workerHealth}
        activeCount={activeCount}
        pendingCount={pendingCount}
        onReviewPending={() =>
          firstPending && navigate(`/engagements/${firstPending.id}`)
        }
      />

      {/* Zone 2 — Stats Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Engagements"
          value={totalEngagements}
          subtitle={`${activeCount} active · ${completedCount} done`}
          icon={Target}
          color="text-blue-400"
          onClick={() => navigate("/engagements")}
        />
        <StatCard
          title="Total Findings"
          value={totalFindings}
          subtitle={`${criticalCount} critical · ${highCount} high`}
          icon={Bug}
          color={criticalCount > 0 ? "text-red-400" : "text-orange-400"}
          onClick={() => navigate("/engagements")}
        />
        <StatCard
          title="Critical + High"
          value={criticalCount + highCount}
          subtitle={criticalCount + highCount > 0 ? `${criticalCount} critical · ${highCount} high` : "all clear"}
          icon={Shield}
          color={criticalCount > 0 ? "text-red-400" : "text-green-400"}
          onClick={() => navigate("/engagements")}
        />
        <StatCard
          title="Pending Approval"
          value={pendingCount > 0 ? pendingCount : "—"}
          subtitle={pendingCount > 0 ? "awaiting your review" : "all clear"}
          icon={pendingCount > 0 ? AlertTriangle : CheckCircle}
          color={pendingCount > 0 ? "text-yellow-400" : "text-green-400"}
          highlight={pendingCount > 0}
          onClick={
            pendingCount > 0
              ? () => firstPending && navigate(`/engagements/${firstPending.id}`)
              : undefined
          }
        />
      </div>

      {/* Zone 3 — Active Scans + Critical/High Findings */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-[11px] font-semibold text-pentra-text-muted uppercase tracking-wider flex items-center gap-1.5">
              <Activity size={12} className="text-blue-400" />
              Active Scans
            </h2>
            <button
              onClick={() => navigate("/engagements")}
              className="text-xs text-pentra-text-muted hover:text-pentra-text-secondary transition-colors"
            >
              All engagements →
            </button>
          </div>
          <div className="space-y-2">
            {activeScans.length === 0 ? (
              <div className="text-center py-8 text-pentra-text-muted text-sm border border-dashed border-pentra-border rounded-ds-lg">
                <Activity size={24} className="mx-auto mb-2 opacity-20" />
                No active scans
                <br />
                <button
                  onClick={() => navigate("/scan/new")}
                  className="mt-2 text-pentra-accent hover:opacity-80 text-xs"
                >
                  Start a new scan →
                </button>
              </div>
            ) : (
              activeScans.map((eng) => (
                <ActiveScanCard
                  key={eng.id}
                  engagement={eng}
                  onClick={() => navigate(`/engagements/${eng.id}`)}
                />
              ))
            )}
          </div>
        </div>

        <div>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-[11px] font-semibold text-pentra-text-muted uppercase tracking-wider flex items-center gap-1.5">
              <AlertTriangle size={12} className="text-red-400" />
              Critical &amp; High Findings
            </h2>
            <button
              onClick={() => navigate("/engagements")}
              className="text-xs text-pentra-text-muted hover:text-pentra-text-secondary transition-colors"
            >
              All findings →
            </button>
          </div>
          <div className="space-y-1.5">
            {criticalHighFindings.length === 0 ? (
              <div className="text-center py-8 text-pentra-text-muted text-sm border border-dashed border-pentra-border rounded-ds-lg">
                <Shield size={24} className="mx-auto mb-2 opacity-20" />
                No critical or high findings yet.
              </div>
            ) : (
              criticalHighFindings.map((f) => (
                <FindingRow
                  key={f.id}
                  finding={f}
                  engagementName={engNameMap[f.engagement_id]}
                  onClick={() =>
                    navigate(`/engagements/${f.engagement_id}?tab=findings`)
                  }
                />
              ))
            )}
          </div>
        </div>
      </div>

      {/* Zone 4 — Recent Engagements + Severity Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-[11px] font-semibold text-pentra-text-muted uppercase tracking-wider">
              Recent Engagements
            </h2>
            <button
              onClick={() => navigate("/engagements")}
              className="text-xs text-pentra-text-muted hover:text-pentra-text-secondary transition-colors"
            >
              View all →
            </button>
          </div>
          <div className="space-y-2">
            {!engagements || engagements.length === 0 ? (
              <div className="text-center py-8 text-pentra-text-muted text-sm border border-dashed border-pentra-border rounded-ds-lg">
                <Target size={24} className="mx-auto mb-2 opacity-20" />
                No engagements yet.
                <br />
                <button
                  onClick={() => navigate("/scan/new")}
                  className="mt-2 text-pentra-accent hover:opacity-80 text-xs"
                >
                  Create your first scan →
                </button>
              </div>
            ) : (
              engagements.slice(0, 5).map((eng) => (
                <EngagementCard
                  key={eng.id}
                  engagement={eng}
                  onClick={() => navigate(`/engagements/${eng.id}`)}
                />
              ))
            )}
          </div>
        </div>

        <div>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-[11px] font-semibold text-pentra-text-muted uppercase tracking-wider">
              Findings Distribution
            </h2>
          </div>
          <SeverityBreakdown bySeverity={allTimeBySeverity} />
        </div>
      </div>

      {/* Quick Actions */}
      <div>
        <h2 className="text-[11px] font-semibold text-pentra-text-muted uppercase tracking-wider mb-3">
          Quick Actions
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "Browse Knowledge Base", icon: BookOpen, path: "/knowledge", color: "text-purple-400" },
            { label: "New Scan", icon: Plus, path: "/scan/new", color: "text-pentra-accent" },
            { label: "All Engagements", icon: Shield, path: "/engagements", color: "text-blue-400" },
            { label: "Admin Panel", icon: TrendingUp, path: "/admin", color: "text-orange-400" },
          ].map(({ label, icon: Icon, path, color }) => (
            <button
              key={path}
              onClick={() => navigate(path)}
              className="flex items-center gap-2 p-3 rounded-ds-md
                         bg-pentra-bg-panel border border-pentra-border
                         hover:border-pentra-border-light hover:bg-pentra-bg-hover
                         transition-all text-left"
            >
              <Icon size={15} className={color} />
              <span className="text-xs text-pentra-text-secondary">{label}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

export default DashboardPage;
