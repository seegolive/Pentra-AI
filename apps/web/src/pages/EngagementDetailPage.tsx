import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  ChevronRight,
  Loader2,
  Play,
  CheckCircle2,
  XCircle,
  SkipForward,
  Wifi,
  WifiOff,
  Bug,
  ShieldAlert,
  ScrollText,
  Activity,
  Download,
} from "lucide-react";
import { useEngagement, useStartEngagement, useApproveAction, useFindings, downloadEngagementExport } from "../lib/api";
import { MonitoringPanel } from "../components/monitoring/MonitoringPanel";
import { FindingsTable } from "../components/findings/FindingsTable";
import { ReportViewer } from "../components/engagement/ReportViewer";
import type { FeedEvent, EngagementStatus } from "../lib/types";
import { useEngagementFeed } from "../hooks/useEngagementFeed";
import { cn } from "../lib/utils";

// ── Feed event row ─────────────────────────────────────────────────────────────

function FeedRow({ event }: { event: FeedEvent }) {
  const typeColors: Record<string, string> = {
    agent_start: "text-green-400",
    agent_step: "text-blue-400",
    agent_complete: "text-emerald-400",
    AWAITING_APPROVAL: "text-yellow-400 font-semibold",
    error: "text-red-400",
  };

  const typeIcons: Record<string, React.ReactNode> = {
    agent_start: <Play className="h-3 w-3" />,
    agent_step: <Activity className="h-3 w-3" />,
    agent_complete: <CheckCircle2 className="h-3 w-3" />,
    AWAITING_APPROVAL: <ShieldAlert className="h-3 w-3" />,
    error: <XCircle className="h-3 w-3" />,
  };

  const colorClass = typeColors[event.type] ?? "text-muted-foreground";

  return (
    <div className="flex items-start gap-2 py-1.5 px-2 hover:bg-white/5 rounded text-xs font-mono border-b border-border/30 last:border-0">
      <span className={cn("flex-shrink-0 mt-0.5", colorClass)}>
        {typeIcons[event.type] ?? <Activity className="h-3 w-3" />}
      </span>
      <span className={cn("flex-1", colorClass)}>
        {event.message ?? event.type}
        {event.data && (
          <span className="text-muted-foreground ml-2 text-[10px]">
            {JSON.stringify(event.data).slice(0, 120)}
          </span>
        )}
      </span>
      {event.timestamp && (
        <span className="text-muted-foreground text-[10px] flex-shrink-0">
          {new Date(event.timestamp).toLocaleTimeString()}
        </span>
      )}
    </div>
  );
}

// ── HITL Approval dialog ───────────────────────────────────────────────────────

interface ApprovalDialogProps {
  engagementId: string;
  phase: string;
  summary: string;
  onDone: () => void;
}

function ApprovalDialog({ engagementId, phase, summary, onDone }: ApprovalDialogProps) {
  const approveMutation = useApproveAction(engagementId);

  const send = async (action: "approve" | "skip") => {
    await approveMutation.mutateAsync({ action });
    onDone();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="w-full max-w-lg bg-card border border-yellow-500/40 rounded-xl shadow-2xl p-6">
        <div className="flex items-center gap-2 mb-4">
          <ShieldAlert className="h-5 w-5 text-yellow-400" />
          <h2 className="text-base font-semibold text-foreground">Approval Required</h2>
          <span className="ml-auto text-xs text-muted-foreground border border-border rounded px-2 py-0.5 font-mono">
            {phase}
          </span>
        </div>

        <p className="text-sm text-foreground/80 whitespace-pre-wrap leading-relaxed mb-6">
          {summary}
        </p>

        <div className="flex gap-2">
          <button
            onClick={() => send("approve")}
            disabled={approveMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-md text-sm font-medium hover:bg-green-500 disabled:opacity-50 transition-colors"
          >
            {approveMutation.isPending ? (
              <Loader2 className="h-3 w-3 animate-spin" />
            ) : (
              <CheckCircle2 className="h-3.5 w-3.5" />
            )}
            Approve
          </button>
          <button
            onClick={() => send("skip")}
            disabled={approveMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 bg-slate-700 text-foreground rounded-md text-sm font-medium hover:bg-slate-600 disabled:opacity-50 transition-colors"
          >
            <SkipForward className="h-3.5 w-3.5" />
            Skip
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Findings panel (wraps FindingsTable) ──────────────────────────────────────

function FindingsPanel({ engagementId }: { engagementId: string }) {
  const { data: findings, isLoading } = useFindings(engagementId);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center flex-1 text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" />
      </div>
    );
  }

  return (
    <FindingsTable
      engagementId={engagementId}
      findings={findings ?? []}
    />
  );
}

// ── Reports panel ─────────────────────────────────────────────────────────────

function ReportsPanel({ engagementId }: { engagementId: string }) {
  return <ReportViewer engagementId={engagementId} />;
}

// ── Main page ──────────────────────────────────────────────────────────────────

type Tab = "feed" | "findings" | "monitoring" | "reports";

export default function EngagementDetailPage() {
  const { engagementId } = useParams<{ engagementId: string }>();
  const navigate = useNavigate();
  const [tab, setTab] = useState<Tab>("feed");
  const [exporting, setExporting] = useState(false);

  async function handleExport() {
    if (!engagementId) return;
    setExporting(true);
    try {
      await downloadEngagementExport(engagementId);
    } finally {
      setExporting(false);
    }
  }

  const { data: engagement, isLoading } = useEngagement(engagementId);
  const startMutation = useStartEngagement(engagementId!);
  const { events, pendingApproval, connected, clearApproval } = useEngagementFeed(
    engagement?.status === "active" ? engagementId : undefined
  );

  if (isLoading) {
    return (
      <div className="flex-1 flex items-center justify-center text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" />
        Loading…
      </div>
    );
  }

  if (!engagement) {
    return (
      <div className="flex-1 flex items-center justify-center text-muted-foreground">
        Engagement not found
      </div>
    );
  }

  const statusColor: Record<EngagementStatus, string> = {
    planning: "text-slate-400",
    active: "text-green-400",
    paused: "text-yellow-400",
    completed: "text-blue-400",
    failed: "text-red-400",
  };

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="border-b border-border px-8 py-4 flex-shrink-0">
        <div className="flex items-center gap-1.5 text-sm text-muted-foreground mb-2">
          <button
            onClick={() => navigate("/workspaces")}
            className="hover:text-foreground transition-colors"
          >
            Workspaces
          </button>
          <ChevronRight className="h-3.5 w-3.5" />
          <button
            onClick={() => navigate(-1)}
            className="hover:text-foreground transition-colors"
          >
            Engagements
          </button>
          <ChevronRight className="h-3.5 w-3.5" />
          <span className="text-foreground">{engagement.name}</span>
        </div>

        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold text-foreground">{engagement.name}</h1>
            <span
              className={cn(
                "text-xs font-medium",
                statusColor[engagement.status as EngagementStatus] ?? "text-slate-400"
              )}
            >
              ● {engagement.status}
            </span>
            {engagement.status === "active" && (
              <span
                className={cn(
                  "flex items-center gap-1 text-xs",
                  connected ? "text-green-400" : "text-muted-foreground"
                )}
              >
                {connected ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
                {connected ? "Live" : "Disconnected"}
              </span>
            )}
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleExport}
              disabled={exporting}
              title="Export engagement as JSON"
              className="flex items-center gap-2 px-3 py-2 border border-border rounded-md text-sm text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
            >
              {exporting ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Download className="h-3.5 w-3.5" />
              )}
              Export
            </button>
            {engagement.status === "planning" && (
              <button
                onClick={() => startMutation.mutate()}
                disabled={startMutation.isPending}
                className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-md text-sm font-medium hover:bg-green-500 disabled:opacity-50 transition-colors"
              >
                {startMutation.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Play className="h-3.5 w-3.5" />
                )}
                Start Agent
              </button>
            )}
          </div>
        </div>

        {/* Scope pills */}
        <div className="flex flex-wrap gap-1.5 mt-3">
          {engagement.in_scope.map((s) => (
            <span
              key={s}
              className="text-xs font-mono px-2 py-0.5 bg-green-500/10 text-green-400 border border-green-500/20 rounded"
            >
              {s}
            </span>
          ))}
          {engagement.out_of_scope.map((s) => (
            <span
              key={s}
              className="text-xs font-mono px-2 py-0.5 bg-red-500/10 text-red-400 border border-red-500/20 rounded line-through opacity-70"
            >
              {s}
            </span>
          ))}
        </div>
      </div>

      {/* Tab bar */}
      <div className="flex border-b border-border px-8 flex-shrink-0 bg-background/50">
        {[
          { key: "feed" as Tab, label: "Live Feed", icon: <Activity className="h-3.5 w-3.5" /> },
          { key: "findings" as Tab, label: "Findings", icon: <Bug className="h-3.5 w-3.5" /> },
          { key: "monitoring" as Tab, label: "Monitoring", icon: <ShieldAlert className="h-3.5 w-3.5" /> },
          { key: "reports" as Tab, label: "Reports", icon: <Download className="h-3.5 w-3.5" /> },
        ].map(({ key, label, icon }) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={cn(
              "flex items-center gap-1.5 px-4 py-3 text-sm font-medium border-b-2 transition-colors",
              tab === key
                ? "border-primary text-foreground"
                : "border-transparent text-muted-foreground hover:text-foreground"
            )}
          >
            {icon}
            {label}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-hidden p-6">
        {tab === "feed" && (
          <div className="h-full flex flex-col">
            {engagement.status === "planning" ? (
              <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
                <ScrollText className="h-10 w-10 mb-3 opacity-20" />
                <p className="text-sm">Agent not started yet</p>
                <p className="text-xs mt-1 opacity-60">Click "Start Agent" to begin</p>
              </div>
            ) : events.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
                <Activity className="h-8 w-8 mb-2 opacity-20 animate-pulse" />
                <p className="text-sm">Waiting for agent events…</p>
              </div>
            ) : (
              <div className="flex-1 overflow-auto rounded-lg bg-background border border-border p-2">
                {events.map((ev, idx) => (
                  <FeedRow key={idx} event={ev} />
                ))}
              </div>
            )}
          </div>
        )}

        {tab === "findings" && engagementId && (
          <div className="h-full">
            <FindingsPanel engagementId={engagementId} />
          </div>
        )}

        {tab === "monitoring" && engagementId && (
          <div className="h-full">
            <MonitoringPanel engagementId={engagementId} />
          </div>
        )}

        {tab === "reports" && engagementId && (
          <div className="h-full overflow-auto">
            <ReportsPanel engagementId={engagementId} />
          </div>
        )}
      </div>

      {/* HITL overlay */}
      {pendingApproval && engagementId && (
        <ApprovalDialog
          engagementId={engagementId}
          phase={pendingApproval.phase}
          summary={pendingApproval.summary}
          onDone={clearApproval}
        />
      )}
    </div>
  );
}
