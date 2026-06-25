import { useRef } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  Plus,
  Loader2,
  Target,
  ChevronRight,
  CircleDot,
  CheckCircle2,
  XCircle,
  Clock,
  Play,
  AlertTriangle,
  Upload,
  ScanSearch,
} from "lucide-react";
import { useEngagements, useWorkspaces, useImportEngagement } from "../lib/api";
import type { Engagement, EngagementStatus } from "../lib/types";
import { cn } from "../lib/utils";

// ── Status badge ──────────────────────────────────────────────────────────────

const STATUS_CONFIG: Record<EngagementStatus, { label: string; icon: React.ReactNode; color: string }> = {
  planning: {
    label: "Planning",
    icon: <Clock className="h-3.5 w-3.5" />,
    color: "text-slate-400 bg-slate-400/10 border-slate-400/20",
  },
  active: {
    label: "Active",
    icon: <CircleDot className="h-3.5 w-3.5" />,
    color: "text-green-500 bg-green-500/10 border-green-500/20",
  },
  paused: {
    label: "Paused",
    icon: <AlertTriangle className="h-3.5 w-3.5" />,
    color: "text-yellow-500 bg-yellow-500/10 border-yellow-500/20",
  },
  completed: {
    label: "Completed",
    icon: <CheckCircle2 className="h-3.5 w-3.5" />,
    color: "text-blue-500 bg-blue-500/10 border-blue-500/20",
  },
  failed: {
    label: "Failed",
    icon: <XCircle className="h-3.5 w-3.5" />,
    color: "text-red-500 bg-red-500/10 border-red-500/20",
  },
  awaiting_approval: {
    label: "Awaiting",
    icon: <AlertTriangle className="h-3.5 w-3.5" />,
    color: "text-yellow-400 bg-yellow-400/10 border-yellow-400/20",
  },
  cancelled: {
    label: "Cancelled",
    icon: <XCircle className="h-3.5 w-3.5" />,
    color: "text-slate-500 bg-slate-500/10 border-slate-500/20",
  },
};

function StatusBadge({ status }: { status: EngagementStatus }) {
  const cfg = STATUS_CONFIG[status] ?? STATUS_CONFIG.planning;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-xs font-medium",
        cfg.color
      )}
    >
      {cfg.icon}
      {cfg.label}
    </span>
  );
}

// ── Engagement card ───────────────────────────────────────────────────────────

function EngagementCard({ eng, onClick }: { eng: Engagement; onClick: () => void }) {
  const scopeLabel = eng.in_scope.length === 1
    ? eng.in_scope[0]
    : `${eng.in_scope[0]} +${eng.in_scope.length - 1} more`;

  const startedDate = eng.started_at
    ? new Date(eng.started_at).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" })
    : null;

  const createdDate = new Date(eng.created_at).toLocaleDateString(undefined, {
    day: "numeric", month: "short", year: "numeric",
  });

  return (
    <button
      onClick={onClick}
      className={cn(
        "w-full text-left p-5 border border-pentra-border rounded-ds-lg bg-pentra-bg-card",
        "hover:border-pentra-accent/50 hover:bg-pentra-bg-hover transition-colors group"
      )}
    >
      <div className="flex items-start justify-between gap-4">
        {/* Left: title + meta */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <p className="font-semibold text-pentra-text-primary truncate">{eng.name}</p>
            <StatusBadge status={eng.status as EngagementStatus} />
            <span className="text-xs text-pentra-text-muted border border-pentra-border rounded px-1.5 py-0.5 font-mono">
              {eng.mode === "semi_auto" ? "Semi-Auto" : "Agentic"}
            </span>
            {eng.scan_preset && (
              <span className="text-xs text-pentra-accent border border-pentra-accent/30 rounded px-1.5 py-0.5 font-mono">
                {eng.scan_preset}
              </span>
            )}
          </div>

          {eng.description && (
            <p className="text-xs text-pentra-text-muted mt-1 truncate">{eng.description}</p>
          )}

          <div className="flex items-center flex-wrap gap-x-4 gap-y-1 mt-2">
            {/* Scope */}
            <span className="text-xs text-pentra-text-muted font-mono">
              <ScanSearch className="h-3 w-3 inline mr-1 opacity-60" />
              {scopeLabel}
            </span>
            {/* Model */}
            <span className="text-xs text-pentra-text-muted font-mono opacity-60">
              {eng.llm_model}
            </span>
            {/* Date */}
            <span className="text-xs text-pentra-text-muted opacity-50">
              {startedDate ? `Started ${startedDate}` : `Created ${createdDate}`}
            </span>
          </div>
        </div>

        {/* Right: action hint + chevron */}
        <div className="flex items-center gap-2 flex-shrink-0 mt-0.5">
          {eng.status === "planning" && (
            <span className="flex items-center gap-1 text-xs text-primary">
              <Play className="h-3 w-3" />
              Ready
            </span>
          )}
          <ChevronRight className="h-4 w-4 text-pentra-text-muted group-hover:text-pentra-text-primary transition-colors" />
        </div>
      </div>
    </button>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function EngagementsPage() {
  const { workspaceId } = useParams<{ workspaceId: string }>();
  const navigate = useNavigate();

  const { data: workspaces } = useWorkspaces();
  const { data: engagements, isLoading } = useEngagements(workspaceId);
  const importMutation = useImportEngagement(workspaceId ?? "");
  const fileInputRef = useRef<HTMLInputElement>(null);

  const workspace = workspaces?.find((w) => w.id === workspaceId);

  async function handleImportFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file || !workspaceId) return;
    try {
      const text = await file.text();
      const bundle = JSON.parse(text);
      await importMutation.mutateAsync({ bundle });
    } catch {
      alert("Invalid export file — please select a valid Pentra engagement JSON.");
    } finally {
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  }

  return (
    <div className="flex-1 w-full p-8">
      <div className="w-full max-w-4xl mx-auto">

        {/* Breadcrumb */}
        <div className="flex items-center gap-1.5 text-sm text-pentra-text-muted mb-6">
          <button
            onClick={() => navigate("/workspaces")}
            className="hover:text-pentra-text-primary transition-colors"
          >
            Workspaces
          </button>
          <ChevronRight className="h-3.5 w-3.5" />
          <span className="text-pentra-text-primary">{workspace?.name ?? "…"}</span>
        </div>

        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold text-pentra-text-primary">Engagements</h1>
            <p className="text-sm text-pentra-text-muted mt-1">
              {engagements?.length
                ? `${engagements.length} engagement${engagements.length !== 1 ? "s" : ""} in this workspace`
                : "Security testing engagements for this workspace"}
            </p>
          </div>

          {/* Action buttons — grouped on the right */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => fileInputRef.current?.click()}
              disabled={importMutation.isPending}
              title="Import engagement from JSON export"
              className="flex items-center gap-2 px-3 py-2 border border-pentra-border rounded-ds-md text-[13px] text-pentra-text-muted hover:text-pentra-text-primary hover:bg-pentra-bg-hover transition-colors disabled:opacity-50"
            >
              {importMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Upload className="h-4 w-4" />
              )}
              Import
            </button>
            <input
              ref={fileInputRef}
              type="file"
              accept=".json,application/json"
              className="hidden"
              onChange={handleImportFile}
            />

            <button
              onClick={() => navigate("/scan/new", { state: { workspaceId } })}
              className="flex items-center gap-2 px-4 py-2 bg-pentra-accent text-white rounded-ds-md text-[13px] font-medium hover:opacity-90 transition-colors"
            >
              <Plus className="h-4 w-4" />
              New Scan
            </button>
          </div>
        </div>

        {/* Engagement list */}
        {isLoading ? (
          <div className="flex items-center justify-center h-40 text-pentra-text-muted">
            <Loader2 className="h-5 w-5 animate-spin mr-2" />
            Loading…
          </div>
        ) : engagements?.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-64 text-pentra-text-muted border border-dashed border-pentra-border rounded-ds-lg gap-3">
            <Target className="h-12 w-12 opacity-20" />
            <div className="text-center">
              <p className="text-sm font-medium">No engagements yet</p>
              <p className="text-xs mt-1 opacity-60">Launch a new scan to start a penetration test</p>
            </div>
            <button
              onClick={() => navigate("/scan/new", { state: { workspaceId } })}
              className="mt-2 flex items-center gap-2 px-4 py-2 bg-pentra-accent text-white rounded-ds-md text-[13px] font-medium hover:opacity-90 transition-colors"
            >
              <Plus className="h-4 w-4" />
              New Scan
            </button>
          </div>
        ) : (
          <div className="space-y-3">
            {engagements?.map((eng: Engagement) => (
              <EngagementCard
                key={eng.id}
                eng={eng}
                onClick={() => navigate(`/engagements/${eng.id}`)}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
