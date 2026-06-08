import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";

import { apiClient } from "../lib/api";
import type { Finding } from "../lib/types";
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
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs text-slate-500 font-medium uppercase tracking-wider">
            {title}
          </p>
          <p className={`text-3xl font-bold mt-1 ${color}`}>{value}</p>
          <p className="text-xs text-slate-500 mt-1">{subtitle}</p>
        </div>
        <div className="p-3 rounded-xl bg-slate-800">
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
    color: "text-slate-400 border-slate-700",
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
      className="flex items-center justify-between p-4 rounded-lg
                 bg-slate-900 border border-slate-800
                 hover:border-slate-700 hover:bg-slate-800/50
                 cursor-pointer transition-all group"
    >
      <div className="flex items-center gap-3 min-w-0">
        <div className="p-2 rounded-lg bg-slate-800">
          <Target size={16} className="text-slate-400" />
        </div>
        <div className="min-w-0">
          <p className="text-sm font-medium text-slate-200 truncate">
            {engagement.name}
          </p>
          <p className="text-xs text-slate-500 truncate mt-0.5">
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
          className="text-slate-600 group-hover:text-slate-400 transition-colors"
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
  info: "bg-slate-800 text-slate-400",
};

// ── Dashboard ─────────────────────────────────────────────────────────────────

export function DashboardPage() {
  const navigate = useNavigate();

  const { data: stats } = useQuery<AdminStats>({
    queryKey: ["dashboard-stats"],
    queryFn: () =>
      apiClient.get<AdminStats>("/api/v1/admin/stats").then((r) => r.data),
    refetchInterval: 30_000,
    retry: false, // non-admin gets 403 — fail silently
  });

  const { data: engagements } = useQuery<EngagementSummary[]>({
    queryKey: ["recent-engagements"],
    queryFn: () =>
      apiClient
        .get<EngagementSummary[]>("/api/v1/engagements?limit=5")
        .then((r) => r.data),
    refetchInterval: 30_000,
  });

  const { data: recentFindings } = useQuery<Finding[]>({
    queryKey: ["recent-findings"],
    queryFn: () =>
      apiClient
        .get<Finding[]>("/api/v1/findings/recent?limit=5")
        .then((r) => r.data),
    refetchInterval: 60_000,
  });

  const activeCount = (engagements ?? []).filter(
    (e) => e.status === "active"
  ).length;

  const totalFindings = stats?.total_findings ?? 0;
  const kbRecords = stats?.total_knowledge_records ?? 0;
  const totalEngagements = stats?.total_engagements ?? (engagements?.length ?? 0);

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-100">Dashboard</h1>
          <p className="text-sm text-slate-500 mt-1">
            Self-hosted AI Security Research Platform
          </p>
        </div>
        <button
          className="flex items-center gap-2 px-4 py-2 bg-green-700 hover:bg-green-600 text-white rounded-md text-sm font-medium transition-colors"
          onClick={() => navigate("/workspaces")}
        >
          <Plus size={16} />
          New Engagement
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
          value={totalFindings}
          subtitle="across all engagements"
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

      {/* Two column layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent engagements */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
              Recent Engagements
            </h2>
            <button
              onClick={() => navigate("/workspaces")}
              className="text-xs text-slate-500 hover:text-slate-300 transition-colors"
            >
              View all →
            </button>
          </div>
          <div className="space-y-2">
            {!engagements || engagements.length === 0 ? (
              <div
                className="text-center py-10 text-slate-600 text-sm
                              border border-dashed border-slate-800 rounded-lg"
              >
                <Target size={28} className="mx-auto mb-3 text-slate-700" />
                No engagements yet.
                <br />
                <button
                  onClick={() => navigate("/workspaces")}
                  className="mt-2 text-blue-500 hover:text-blue-400 text-xs"
                >
                  Create your first engagement →
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

        {/* Recent findings */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
              Recent Findings
            </h2>
          </div>
          <div className="space-y-2">
            {!recentFindings || recentFindings.length === 0 ? (
              <div
                className="text-center py-10 text-slate-600 text-sm
                              border border-dashed border-slate-800 rounded-lg"
              >
                <Shield size={28} className="mx-auto mb-3 text-slate-700" />
                No findings yet.
                <br />
                <span className="text-xs">
                  Run an engagement to discover vulnerabilities.
                </span>
              </div>
            ) : (
              recentFindings.map((f) => (
                <div
                  key={f.id}
                  onClick={() =>
                    navigate(`/engagements/${f.engagement_id}?tab=findings`)
                  }
                  className="flex items-center gap-3 p-3 rounded-lg bg-slate-900
                             border border-slate-800 hover:border-slate-700
                             cursor-pointer transition-all"
                >
                  <span
                    className={`text-xs px-2 py-0.5 rounded font-medium capitalize
                    ${SEV_COLORS[f.severity] ?? SEV_COLORS.info}`}
                  >
                    {f.severity}
                  </span>
                  <p className="text-sm text-slate-300 truncate flex-1">
                    {f.title}
                  </p>
                  <p className="text-xs text-slate-600 shrink-0 font-mono">
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
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">
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
              label: "New Workspace",
              icon: Plus,
              path: "/workspaces",
              color: "text-green-400",
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
              className="flex items-center gap-2 p-3 rounded-lg bg-slate-900
                         border border-slate-800 hover:border-slate-700
                         hover:bg-slate-800/50 transition-all text-left"
            >
              <Icon size={16} className={color} />
              <span className="text-xs text-slate-400">{label}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

export default DashboardPage;
