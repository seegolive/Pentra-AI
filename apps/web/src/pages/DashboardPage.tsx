import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";

import { apiClient, useFindings } from "../lib/api";
import {
  Target,
  Shield,
  BookOpen,
  TrendingUp,
  ChevronRight,
  Plus,
  AlertTriangle,
  CheckCircle,
  Clock,
  Activity,
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
}

// ── Stat card ─────────────────────────────────────────────────────────────────

function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  color,
}: {
  title: string;
  value: number | string;
  subtitle: string;
  icon: React.ElementType;
  color: string;
}) {
  return (
    <div className="bg-pentra-bg-panel border border-pentra-border rounded-ds-lg p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wider text-pentra-text-muted">
            {title}
          </p>
          <p className={`text-3xl font-bold mt-1 ${color}`}>{value}</p>
          <p className="text-xs text-pentra-text-muted mt-1">{subtitle}</p>
        </div>
        <div className="p-3 rounded-xl bg-pentra-bg-card">
          <Icon size={22} className={color} />
        </div>
      </div>
    </div>
  );
}

// ── Status config ─────────────────────────────────────────────────────────────

const STATUS_CONFIG = {
  planning: {
    label: "Planning",
    color: "text-pentra-text-muted border-pentra-border",
    icon: Clock,
  },
  active: {
    label: "Active",
    color: "text-blue-400 border-blue-900",
    icon: Activity,
  },
  completed: {
    label: "Done",
    color: "text-green-400 border-green-900",
    icon: CheckCircle,
  },
  failed: {
    label: "Failed",
    color: "text-red-400 border-red-900",
    icon: AlertTriangle,
  },
  paused: {
    label: "Paused",
    color: "text-yellow-400 border-yellow-900",
    icon: Clock,
  },
  awaiting_approval: {
    label: "Awaiting",
    color: "text-yellow-400 border-yellow-900",
    icon: Clock,
  },
  cancelled: {
    label: "Cancelled",
    color: "text-pentra-text-muted border-pentra-border",
    icon: AlertTriangle,
  },
} as const;

// ── Engagement card ───────────────────────────────────────────────────────────

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
      className="flex items-center justify-between p-4 rounded-ds-md
                 bg-pentra-bg-panel border border-pentra-border
                 hover:border-pentra-border-light hover:bg-pentra-bg-hover
                 cursor-pointer transition-all group"
    >
      <div className="flex items-center gap-3 min-w-0">
        <div className="p-2 rounded-lg bg-pentra-bg-card">
          <Target size={16} className="text-pentra-text-muted" />
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

      <div className="flex items-center gap-3 shrink-0 ml-4">
        {(engagement.findings_count ?? 0) > 0 && (
          <span className="text-xs border border-orange-900 text-orange-400 rounded px-1.5 py-0.5">
            {engagement.findings_count} findings
          </span>
        )}
        <div
          className={`flex items-center gap-1 text-xs font-medium border rounded-full px-2 py-0.5 ${cfg.color}`}
        >
          <StatusIcon size={11} />
          {cfg.label}
        </div>
        <ChevronRight
          size={14}
          className="text-pentra-text-muted/40 group-hover:text-pentra-text-muted transition-colors"
        />
      </div>
    </div>
  );
}

// ── Severity colors ───────────────────────────────────────────────────────────

const SEV_COLORS: Record<string, string> = {
  critical: "bg-red-900/60 text-red-300",
  high: "bg-orange-900/60 text-orange-300",
  medium: "bg-yellow-900/60 text-yellow-300",
  low: "bg-blue-900/60 text-blue-300",
  info: "bg-pentra-bg-card text-pentra-text-muted",
};

// ── Severity breakdown ────────────────────────────────────────────────────────

const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;

const SEV_BAR: Record<string, string> = {
  critical: "bg-red-500/70",
  high:     "bg-orange-500/70",
  medium:   "bg-yellow-500/70",
  low:      "bg-blue-500/70",
  info:     "bg-pentra-text-muted/30",
};

const SEV_LABEL: Record<string, string> = {
  critical: "text-red-400",
  high:     "text-orange-400",
  medium:   "text-yellow-400",
  low:      "text-blue-400",
  info:     "text-pentra-text-muted",
};

function SeverityBreakdown({ bySeverity }: { bySeverity: Record<string, number> }) {
  const total = SEV_ORDER.reduce((s, k) => s + (bySeverity[k] ?? 0), 0);
  if (total === 0) return null;

  return (
    <div className="bg-pentra-bg-panel border border-pentra-border rounded-ds-lg p-5">
      <p className="text-[11px] font-semibold uppercase tracking-wider text-pentra-text-muted mb-4">
        Findings by Severity
      </p>
      <div className="space-y-2.5">
        {SEV_ORDER.map((sev) => {
          const count = bySeverity[sev] ?? 0;
          const pct = total > 0 ? (count / total) * 100 : 0;
          return (
            <div key={sev} className="flex items-center gap-3">
              <span className={`w-14 text-[11px] font-semibold capitalize flex-shrink-0 ${SEV_LABEL[sev]}`}>
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
        .get<EngagementSummary[]>("/api/v1/engagements?limit=5")
        .then((r) => r.data),
    refetchInterval: 30_000,
  });

  // Latest completed or active engagement
  const latestEng = (engagements ?? []).find(
    (e) => e.status === "completed" || e.status === "active"
  );

  const { data: latestFindings } = useFindings(latestEng?.id ?? "");

  const activeCount = (engagements ?? []).filter(
    (e) => e.status === "active"
  ).length;

  const kbRecords = stats?.total_knowledge_records ?? 0;
  const totalEngagements = stats?.total_engagements ?? (engagements?.length ?? 0);

  // Severity breakdown from latest scan
  const latestBySeverity = (latestFindings ?? []).reduce<Record<string, number>>(
    (acc, f) => { acc[f.severity] = (acc[f.severity] ?? 0) + 1; return acc; },
    {}
  );

  return (
    <div className="flex-1 w-full p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-[22px] font-bold text-pentra-text-primary">Dashboard</h1>
          <p className="text-[13px] text-pentra-text-secondary mt-1">
            Self-hosted AI Security Research Platform
          </p>
        </div>
        <button
          className="flex items-center gap-2 px-4 py-2 bg-pentra-accent hover:opacity-90 text-white rounded-ds-md text-sm font-medium transition-opacity"
          onClick={() => navigate("/scan/new")}
        >
          <Plus size={16} />
          New Scan
        </button>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Engagements"
          value={totalEngagements}
          subtitle={`${activeCount} active`}
          icon={Target}
          color="text-blue-400"
        />
        <StatCard
          title="Findings"
          value={latestFindings?.length ?? "—"}
          subtitle={latestEng ? `from ${latestEng.name}` : "latest scan"}
          icon={Shield}
          color="text-orange-400"
        />
        <StatCard
          title="KB Records"
          value={kbRecords > 0 ? kbRecords.toLocaleString() : "—"}
          subtitle="H1 + curated patterns"
          icon={BookOpen}
          color="text-purple-400"
        />
        <StatCard
          title="Workspaces"
          value={stats?.total_workspaces ?? "—"}
          subtitle="organized projects"
          icon={TrendingUp}
          color="text-green-400"
        />
      </div>

      {/* Severity breakdown — latest scan only */}
      {latestFindings && latestFindings.length > 0 && (
        <div className="space-y-1">
          <p className="text-[11px] text-pentra-text-muted font-medium">
            Scan:{" "}
            <span
              className="text-pentra-accent cursor-pointer hover:underline"
              onClick={() => latestEng && navigate(`/engagements/${latestEng.id}?tab=findings`)}
            >
              {latestEng?.name}
            </span>
            {" "}— {latestFindings.length} findings
          </p>
          <SeverityBreakdown bySeverity={latestBySeverity} />
        </div>
      )}

      {/* Two column layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent engagements */}
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
              <div
                className="text-center py-10 text-pentra-text-muted text-sm
                              border border-dashed border-pentra-border rounded-ds-lg"
              >
                <Target size={28} className="mx-auto mb-3 opacity-20" />
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

        {/* Recent findings — latest scan */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-[11px] font-semibold text-pentra-text-muted uppercase tracking-wider">
              Latest Scan Findings
            </h2>
            {latestEng && (
              <button
                onClick={() => navigate(`/engagements/${latestEng.id}?tab=findings`)}
                className="text-xs text-pentra-text-muted hover:text-pentra-text-secondary transition-colors"
              >
                View all →
              </button>
            )}
          </div>
          <div className="space-y-2">
            {!latestFindings || latestFindings.length === 0 ? (
              <div
                className="text-center py-10 text-pentra-text-muted text-sm
                              border border-dashed border-pentra-border rounded-ds-lg"
              >
                <Shield size={28} className="mx-auto mb-3 opacity-20" />
                No findings yet.
                <br />
                <span className="text-xs">
                  Run an engagement to discover vulnerabilities.
                </span>
              </div>
            ) : (
              [...latestFindings]
                .sort((a, b) => {
                  const order = ["critical", "high", "medium", "low", "info"];
                  return order.indexOf(a.severity) - order.indexOf(b.severity);
                })
                .slice(0, 8)
                .map((f) => (
                  <div
                    key={f.id}
                    onClick={() =>
                      navigate(`/engagements/${f.engagement_id}?tab=findings`)
                    }
                    className="flex items-center gap-3 p-3 rounded-ds-md
                               bg-pentra-bg-panel border border-pentra-border
                               hover:border-pentra-border-light hover:bg-pentra-bg-hover
                               cursor-pointer transition-all"
                  >
                    <span
                      className={`text-xs px-2 py-0.5 rounded font-medium capitalize flex-shrink-0
                      ${SEV_COLORS[f.severity] ?? SEV_COLORS.info}`}
                    >
                      {f.severity}
                    </span>
                    <p className="text-sm text-pentra-text-primary truncate flex-1">
                      {f.title}
                    </p>
                    <p className="text-xs text-pentra-text-muted shrink-0 font-mono hidden sm:block">
                      {f.vuln_class}
                    </p>
                  </div>
                ))
            )}
          </div>
        </div>
      </div>

      {/* Quick actions */}
      <div>
        <h2 className="text-[11px] font-semibold text-pentra-text-muted uppercase tracking-wider mb-3">
          Quick Actions
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            {
              label: "Browse Knowledge Base",
              icon: BookOpen,
              path: "/knowledge",
              color: "text-purple-400",
            },
            {
              label: "New Scan",
              icon: Plus,
              path: "/scan/new",
              color: "text-pentra-accent",
            },
            {
              label: "All Engagements",
              icon: Shield,
              path: "/engagements",
              color: "text-blue-400",
            },
            {
              label: "Admin Panel",
              icon: TrendingUp,
              path: "/admin",
              color: "text-orange-400",
            },
          ].map(({ label, icon: Icon, path, color }) => (
            <button
              key={path}
              onClick={() => navigate(path)}
              className="flex items-center gap-2 p-3 rounded-ds-md
                         bg-pentra-bg-panel border border-pentra-border
                         hover:border-pentra-border-light hover:bg-pentra-bg-hover
                         transition-all text-left"
            >
              <Icon size={16} className={color} />
              <span className="text-xs text-pentra-text-secondary">{label}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

export default DashboardPage;
