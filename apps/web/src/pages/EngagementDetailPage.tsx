import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  ChevronRight,
  ChevronDown,
  Loader2,
  Play,
  CheckCircle2,
  SkipForward,
  Wifi,
  WifiOff,
  Bug,
  ShieldAlert,
  ScrollText,
  Activity,
  Download,
  Zap,
  Cpu,
  ListChecks,
  AlertCircle,
  Square,
  Terminal,
  Globe,
} from "lucide-react";
import { useEngagement, useStartEngagement, useApproveAction, useFindings, downloadEngagementExport, useUpdateEngagementMode, useWorkspaces, useMonitoringAlerts, useStopEngagement } from "../lib/api";
import { MonitoringPanel } from "../components/monitoring/MonitoringPanel";
import { FindingsTable } from "../components/findings/FindingsTable";
import { ReportViewer } from "../components/engagement/ReportViewer";
import { ReconSurfaceTab } from "../components/engagement/ReconSurfaceTab";
import type { FeedEvent, EngagementStatus } from "../lib/types";
import { useEngagementFeed } from "../hooks/useEngagementFeed";
import { cn } from "../lib/utils";

// ── Feed helpers ──────────────────────────────────────────────────────────────

const NODE_LABELS: Record<string, string> = {
  plan: "Planning",
  hitl_plan: "Plan Review",
  recon: "Reconnaissance",
  hitl_recon: "Recon Review",
  vuln_hunt: "Vulnerability Hunt",
  hitl_exploit: "Exploit Review",
  report: "Report Generation",
};

const TYPE_META: Record<
  string,
  { label: string; color: string; icon: React.ReactNode }
> = {
  NODE_START: {
    label: "Node start",
    color: "text-blue-400",
    icon: <Play className="h-3 w-3" />,
  },
  NODE_COMPLETE: {
    label: "Node done",
    color: "text-emerald-400",
    icon: <CheckCircle2 className="h-3 w-3" />,
  },
  FINDINGS_UPDATED: {
    label: "Findings",
    color: "text-orange-400",
    icon: <ListChecks className="h-3 w-3" />,
  },
  AWAITING_APPROVAL: {
    label: "Approval",
    color: "text-yellow-400",
    icon: <ShieldAlert className="h-3 w-3" />,
  },
  LLM_STREAM: {
    label: "LLM",
    color: "text-violet-400",
    icon: <Cpu className="h-3 w-3" />,
  },
  error: {
    label: "Error",
    color: "text-red-400",
    icon: <AlertCircle className="h-3 w-3" />,
  },
  agent_start: {
    label: "Start",
    color: "text-green-400",
    icon: <Play className="h-3 w-3" />,
  },
  agent_step: {
    label: "Step",
    color: "text-blue-400",
    icon: <Activity className="h-3 w-3" />,
  },
  agent_complete: {
    label: "Complete",
    color: "text-emerald-400",
    icon: <CheckCircle2 className="h-3 w-3" />,
  },
  terminal_output: {
    label: "Terminal",
    color: "text-cyan-300",
    icon: <Terminal className="h-3 w-3" />,
  },
  RECON_UPDATE: {
    label: "Recon",
    color: "text-sky-400",
    icon: <Wifi className="h-3 w-3" />,
  },
  subscan_started: {
    label: "Subscan",
    color: "text-blue-400",
    icon: <Zap className="h-3 w-3" />,
  },
  subscan_complete: {
    label: "Subscan",
    color: "text-emerald-400",
    icon: <CheckCircle2 className="h-3 w-3" />,
  },
  agent_cancelled: {
    label: "Cancelled",
    color: "text-red-400",
    icon: <Square className="h-3 w-3" />,
  },
};

// ── Grouped item type ─────────────────────────────────────────────────────────

type FeedGroup =
  | { kind: "single"; event: FeedEvent }
  | { kind: "llm"; node: string; tokens: string[]; timestamp?: string };

/** Collapse consecutive LLM_STREAM tokens from the same node into groups.
 *  Input arrives newest-first (as stored in state). */
function groupFeedEvents(events: FeedEvent[]): FeedGroup[] {
  const result: FeedGroup[] = [];
  // events are newest-first; iterate in reverse (oldest-first) to detect runs
  const reversed = [...events].reverse();

  for (const ev of reversed) {
    if (ev.type === "LLM_STREAM") {
      const last = result[result.length - 1];
      if (last?.kind === "llm" && last.node === (ev.node ?? "")) {
        last.tokens.push(ev.token ?? "");
        if (ev.timestamp) last.timestamp = ev.timestamp;
      } else {
        result.push({
          kind: "llm",
          node: ev.node ?? "",
          tokens: [ev.token ?? ""],
          timestamp: ev.timestamp,
        });
      }
    } else {
      result.push({ kind: "single", event: ev });
    }
  }

  return result.reverse(); // back to newest-first
}

// ── Stat card ─────────────────────────────────────────────────────────────────

function StatCard({ label, value, color }: { label: string; value: number; color?: string }) {
  return (
    <div
      className="flex-1 min-w-0 rounded-ds-md border border-pentra-border bg-pentra-bg-pentra-bg-card px-3 py-2"
    >
      <p className="text-[10px] font-semibold uppercase tracking-wide text-pentra-text-muted">
        {label}
      </p>
      <p className="mt-0.5 text-xl font-bold text-pentra-text-primary" style={{ color: color }}>
        {value}
      </p>
    </div>
  );
}

// ── LLM stream group row ──────────────────────────────────────────────────────

function LLMStreamGroup({ group }: { group: Extract<FeedGroup, { kind: "llm" }> }) {
  const [expanded, setExpanded] = useState(false);
  const text = group.tokens.join("");
  const label = NODE_LABELS[group.node] ?? group.node ?? "LLM";
  const preview = text.slice(0, 80).replace(/\n/g, " ");

  return (
    <div className="border-b border-pentra-border/30 last:border-0">
      <button
        onClick={() => setExpanded((v) => !v)}
        className="w-full flex items-start gap-2 py-1.5 px-2 hover:bg-pentra-bg-hover rounded text-xs font-mono text-left"
      >
        <span className="flex-shrink-0 mt-0.5 text-violet-400">
          <Cpu className="h-3 w-3" />
        </span>
        <span className="flex-1 min-w-0">
          <span className="text-violet-400 font-medium">{label}</span>
          <span className="text-pentra-text-muted ml-2">
            LLM · {group.tokens.length} tokens
          </span>
          {!expanded && (
            <span className="block text-pentra-text-muted/70 truncate text-[10px] mt-0.5">
              {preview}{text.length > 80 ? "…" : ""}
            </span>
          )}
        </span>
        <span className="flex items-center gap-1 flex-shrink-0 text-pentra-text-muted">
          {group.timestamp && (
            <span className="text-[10px]">
              {new Date(group.timestamp).toLocaleTimeString()}
            </span>
          )}
          <ChevronDown
            className={cn(
              "h-3 w-3 transition-transform",
              expanded && "rotate-180"
            )}
          />
        </span>
      </button>
      {expanded && (
        <div className="mx-2 mb-1.5 px-3 py-2 rounded bg-violet-500/5 border border-violet-500/20 text-[11px] font-mono text-pentra-text-primary/80 whitespace-pre-wrap leading-relaxed max-h-80 overflow-auto">
          {text}
        </div>
      )}
    </div>
  );
}

// ── Single event row ──────────────────────────────────────────────────────────

function FeedRow({ event }: { event: FeedEvent }) {
  const meta = TYPE_META[event.type];
  const color = meta?.color ?? "text-pentra-text-muted";
  const icon = meta?.icon ?? <Activity className="h-3 w-3" />;
  const isTerminal = event.type === "terminal_output";
  const nodeLabel = event.node
    ? (NODE_LABELS[event.node] ?? event.node)
    : (meta?.label ?? event.type);

  let content = event.message;
  if (!content) {
    if (event.type === "NODE_START") content = "Started";
    else if (event.type === "NODE_COMPLETE") content = "Completed";
    else if (event.type === "FINDINGS_UPDATED") content = `${event.count ?? "?"} finding(s) discovered`;
    else content = meta?.label ?? event.type;
  }

  const ts = event.timestamp
    ? new Date(event.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
    : null;

  return (
    <div
      className="flex items-start gap-3 border-b border-pentra-border/20 px-3 py-2 transition-colors hover:bg-pentra-bg-hover last:border-0"
      style={{ animation: "fadeSlideIn 0.12s ease-out" }}
    >
      <span className="w-[58px] flex-shrink-0 pt-0.5 text-right font-mono text-[10px] text-pentra-text-muted">
        {ts ?? ""}
      </span>
      <span className={cn("mt-0.5 flex-shrink-0", color)}>{icon}</span>
      <span className="min-w-0 flex-1">
        <span className={cn("text-[11px] font-semibold", color)}>{nodeLabel}</span>
        {content && (
          <span
            className={cn(
              "block text-[11px] text-pentra-text-secondary",
              isTerminal
                ? "whitespace-pre-wrap break-words font-mono leading-relaxed text-cyan-100/80"
                : "truncate"
            )}
          >
            {content}
            {event.data && Object.keys(event.data).length > 0 && (
              <span className="ml-2 text-[10px] opacity-60">
                {JSON.stringify(event.data).slice(0, 100)}
              </span>
            )}
          </span>
        )}
      </span>
    </div>
  );
}

// ── Phase pipeline strip ──────────────────────────────────────────────────────

const PHASE_PIPELINE = [
  { key: "plan",         label: "Plan",      gate: false },
  { key: "hitl_plan",    label: "Review",    gate: true  },
  { key: "recon",        label: "Recon",     gate: false },
  { key: "hitl_recon",   label: "Review",    gate: true  },
  { key: "vuln_hunt",    label: "Hunt",      gate: false },
  { key: "hitl_exploit", label: "Review",    gate: true  },
  { key: "report",       label: "Report",    gate: false },
] as const;

type PhaseKey = typeof PHASE_PIPELINE[number]["key"];

function deriveActivePhase(events: FeedEvent[]): PhaseKey | null {
  for (const ev of events) {
    if (ev.type === "NODE_START" || ev.type === "AWAITING_APPROVAL") {
      const key = ev.node as PhaseKey;
      if (PHASE_PIPELINE.some((p) => p.key === key)) return key;
    }
  }
  return null;
}

function deriveCompletedPhases(events: FeedEvent[]): Set<PhaseKey> {
  const done = new Set<PhaseKey>();
  for (const ev of events) {
    if (ev.type === "NODE_COMPLETE" && ev.node) {
      done.add(ev.node as PhaseKey);
    }
  }
  return done;
}

function PhaseStrip({
  events,
  agentStatus,
}: {
  events: FeedEvent[];
  agentStatus: string;
}) {
  if (agentStatus === "idle") return null;

  const active = deriveActivePhase(events);
  const completed = deriveCompletedPhases(events);

  return (
    <div className="flex items-center gap-0 px-8 py-3 border-b border-pentra-border/60 bg-pentra-bg-card/30 flex-shrink-0 overflow-x-auto">
      {PHASE_PIPELINE.map((phase, idx) => {
        const isDone = completed.has(phase.key);
        const isActive = active === phase.key;
        const isAwaiting = isActive && phase.gate;

        return (
          <div key={phase.key} className="flex items-center">
            {/* Node */}
            <div className="flex flex-col items-center gap-1 min-w-[52px]">
              {phase.gate ? (
                // HITL gate — hexagon outline
                <div
                  className={cn(
                    "h-5 w-5 flex items-center justify-center text-[9px] font-bold transition-all duration-300",
                    "border rounded-sm rotate-45",
                    isDone
                      ? "border-pentra-accent/60 bg-pentra-accent/20 text-pentra-accent"
                      : isAwaiting
                      ? "border-yellow-500/80 bg-yellow-500/20 text-yellow-400 shadow-[0_0_8px_rgba(234,179,8,0.4)]"
                      : isActive
                      ? "border-pentra-accent bg-pentra-accent/10 text-pentra-accent animate-pulse"
                      : "border-pentra-border/50 bg-transparent text-pentra-text-muted/30"
                  )}
                >
                  <span className="-rotate-45 text-[8px]">⬡</span>
                </div>
              ) : (
                // Regular phase — circle
                <div
                  className={cn(
                    "h-4 w-4 rounded-full border-2 flex items-center justify-center transition-all duration-300",
                    isDone
                      ? "border-pentra-accent bg-pentra-accent"
                      : isActive
                      ? "border-pentra-accent bg-pentra-accent/20 animate-pulse shadow-[0_0_8px_rgba(99,102,241,0.5)]"
                      : "border-pentra-border/40 bg-transparent"
                  )}
                >
                  {isDone && <CheckCircle2 className="h-2 w-2 text-white" />}
                </div>
              )}
              <span
                className={cn(
                  "text-[9px] font-medium whitespace-nowrap",
                  isDone || isActive ? "text-pentra-text-secondary" : "text-pentra-text-muted/40"
                )}
              >
                {phase.label}
              </span>
            </div>

            {/* Connector line (not after last node) */}
            {idx < PHASE_PIPELINE.length - 1 && (
              <div
                className={cn(
                  "h-px w-8 mb-4 flex-shrink-0 transition-colors duration-300",
                  completed.has(phase.key) ? "bg-pentra-accent/40" : "bg-pentra-border/30"
                )}
              />
            )}
          </div>
        );
      })}
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
    <div className="fixed inset-0 z-50 flex items-end justify-center pb-8 bg-black/60 backdrop-blur-sm">
      <div
        className="mx-4 w-full max-w-2xl overflow-hidden rounded-ds-lg border shadow-2xl"
        style={{
          borderColor: "rgba(245,197,66,0.35)",
          background: "var(--bg-pentra-bg-card)",
          animation: "fadeUp 0.2s ease-out",
        }}
      >
        {/* Header */}
        <div
          className="flex items-center gap-2 border-b px-4 py-3"
          style={{ background: "rgba(245,197,66,0.06)", borderColor: "rgba(245,197,66,0.2)" }}
        >
          <ShieldAlert className="h-4 w-4 flex-shrink-0" style={{ color: "var(--status-waiting)" }} />
          <span className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
            Human-in-the-Loop Review Required
          </span>
          <span
            className="ml-auto rounded border px-2 py-0.5 font-mono text-[10px]"
            style={{ color: "var(--text-muted)", borderColor: "var(--border)" }}
          >
            {phase}
          </span>
        </div>

        {/* Summary */}
        <div className="max-h-48 overflow-auto px-4 py-3">
          <p
            className="whitespace-pre-wrap text-[13px] leading-relaxed"
            style={{ color: "var(--text-secondary)" }}
          >
            {summary}
          </p>
        </div>

        {/* Actions */}
        <div
          className="flex items-center gap-2 border-t px-4 py-3"
          style={{ borderColor: "var(--border)" }}
        >
          <button
            onClick={() => send("approve")}
            disabled={approveMutation.isPending}
            className="flex items-center gap-2 rounded-ds-md px-5 py-2 text-sm font-semibold text-white disabled:opacity-50 transition-opacity"
            style={{ background: "var(--status-complete)" }}
          >
            {approveMutation.isPending ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <CheckCircle2 className="h-3.5 w-3.5" />
            )}
            Approve &amp; Continue
          </button>
          <button
            onClick={() => send("skip")}
            disabled={approveMutation.isPending}
            className="flex items-center gap-2 rounded-ds-md px-4 py-2 text-sm font-medium disabled:opacity-50 transition-colors hover:bg-pentra-bg-hover"
            style={{ color: "var(--text-secondary)", border: "1px solid var(--border)" }}
          >
            <SkipForward className="h-3.5 w-3.5" />
            Skip
          </button>
          <span className="ml-auto text-[11px]" style={{ color: "var(--text-muted)" }}>
            Review required before agent proceeds
          </span>
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
      <div className="flex items-center justify-center flex-1 text-pentra-text-muted">
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

type Tab = "feed" | "findings" | "recon" | "monitoring" | "reports";

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
  const { data: workspaces } = useWorkspaces();
  const workspace = workspaces?.find((w) => w.id === engagement?.workspace_id);
  const startMutation = useStartEngagement(engagementId ?? "");
  const stopMutation = useStopEngagement(engagementId ?? "");
  const modeMutation = useUpdateEngagementMode(engagementId ?? "");
  const { events, pendingApproval, connected, agentStatus, clearApproval } = useEngagementFeed(
    (engagement?.status === "active" || engagement?.status === "awaiting_approval") ? engagementId : undefined
  );

  // Counters for tab badges
  const { data: findings } = useFindings(engagementId ?? "");
  const { data: unreadAlerts } = useMonitoringAlerts(engagementId ?? "", { is_read: false });
  const findingsCount = findings?.length ?? 0;
  const alertCount = unreadAlerts?.length ?? 0;

  if (isLoading) {
    return (
      <div className="flex-1 flex items-center justify-center text-pentra-text-muted">
        <Loader2 className="h-5 w-5 animate-spin mr-2" />
        Loading…
      </div>
    );
  }

  if (!engagement) {
    return (
      <div className="flex-1 flex items-center justify-center text-pentra-text-muted">
        Engagement not found
      </div>
    );
  }

  const statusColor: Record<EngagementStatus, string> = {
    planning: "text-slate-400",
    active: "text-green-400",
    awaiting_approval: "text-yellow-400",
    paused: "text-yellow-400",
    completed: "text-blue-400",
    failed: "text-red-400",
    cancelled: "text-slate-500",
  };

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="border-b border-pentra-border px-8 py-4 flex-shrink-0">
        <div className="flex items-center gap-1.5 text-sm text-pentra-text-muted mb-2">
          <button
            onClick={() => navigate("/workspaces")}
            className="hover:text-pentra-text-primary transition-colors"
          >
            Workspaces
          </button>
          {workspace && (
            <>
              <ChevronRight className="h-3.5 w-3.5" />
              <button
                onClick={() =>
                  navigate(`/workspaces/${workspace.id}/engagements`)
                }
                className="hover:text-pentra-text-primary transition-colors"
              >
                {workspace.name}
              </button>
            </>
          )}
          <ChevronRight className="h-3.5 w-3.5" />
          <button
            onClick={() => navigate(-1)}
            className="hover:text-pentra-text-primary transition-colors"
          >
            Engagements
          </button>
          <ChevronRight className="h-3.5 w-3.5" />
          <span className="text-pentra-text-primary">{engagement.name}</span>
        </div>

        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold text-pentra-text-primary">{engagement.name}</h1>
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
                  connected ? "text-green-400" : "text-pentra-text-muted"
                )}
              >
                {connected ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
                {connected ? "Live" : "Disconnected"}
              </span>
            )}
            {/* Task 20.4: Agent phase status badge */}
            {agentStatus !== "idle" && (
              <span
                className={cn(
                  "text-xs px-2 py-0.5 rounded-full border font-mono",
                  agentStatus === "running"
                    ? "bg-blue-500/10 text-blue-400 border-blue-500/30 animate-pulse"
                    : agentStatus === "waiting"
                    ? "bg-yellow-500/10 text-yellow-400 border-yellow-500/30"
                    : agentStatus === "completed"
                    ? "bg-green-500/10 text-green-400 border-green-500/30"
                    : "bg-pentra-bg-hover text-pentra-text-muted border-pentra-border"
                )}
              >
                {agentStatus === "running" ? "⚡ running" : agentStatus === "waiting" ? "⏸ awaiting approval" : "✓ completed"}
              </span>
            )}
          </div>

          <div className="flex items-center gap-2">
            {/* Auto Approve toggle — visible when engagement is active or awaiting approval */}
            {(engagement.status === "active" || engagement.status === "awaiting_approval") && (
              <button
                onClick={() => {
                  const next = engagement.mode === "agentic" ? "semi_auto" : "agentic";
                  modeMutation.mutate(next);
                }}
                disabled={modeMutation.isPending}
                title={
                  engagement.mode === "agentic"
                    ? "Auto Approve is ON — click to require manual approval"
                    : "Click to enable Auto Approve (agentic mode, no HITL prompts)"
                }
                className={cn(
                  "flex items-center gap-2 px-3 py-2 border rounded-ds-md text-sm font-medium transition-colors",
                  engagement.mode === "agentic"
                    ? "border-yellow-500/60 text-yellow-400 bg-yellow-500/10 hover:bg-yellow-500/20"
                    : "border-pentra-border text-pentra-text-muted hover:text-pentra-text-primary hover:bg-pentra-bg-hover"
                )}
              >
                {modeMutation.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Zap className={cn("h-3.5 w-3.5", engagement.mode === "agentic" ? "fill-yellow-400" : "")} />
                )}
                {engagement.mode === "agentic" ? "Auto Approve ON" : "Auto Approve"}
              </button>
            )}
            <button
              onClick={handleExport}
              disabled={exporting}
              title="Export engagement as JSON"
              className="flex items-center gap-2 px-3 py-2 border border-pentra-border rounded-ds-md text-sm text-pentra-text-muted hover:text-pentra-text-primary hover:bg-pentra-bg-hover transition-colors"
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
                className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-ds-md text-sm font-medium hover:bg-green-500 disabled:opacity-50 transition-colors"
              >
                {startMutation.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Play className="h-3.5 w-3.5" />
                )}
                Start Agent
              </button>
            )}
            {(engagement.status === "active" || engagement.status === "awaiting_approval") && (
              <button
                onClick={() => stopMutation.mutate()}
                disabled={stopMutation.isPending}
                className="flex items-center gap-2 px-4 py-2 bg-red-600/80 text-white rounded-ds-md text-sm font-medium hover:bg-red-600 disabled:opacity-50 transition-colors"
              >
                {stopMutation.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Square className="h-3.5 w-3.5" />
                )}
                Stop
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

      {/* Phase pipeline — visible once scan has started */}
      <PhaseStrip events={events} agentStatus={agentStatus} />

      {/* Tab bar */}
      <div className="flex border-b border-pentra-border px-8 flex-shrink-0 bg-pentra-bg-base/50">
        {[
          {
            key: "feed" as Tab,
            label: "Live Feed",
            icon: <Activity className="h-3.5 w-3.5" />,
            count: events.length > 0 ? events.length : undefined,
          },
          {
            key: "findings" as Tab,
            label: "Findings",
            icon: <Bug className="h-3.5 w-3.5" />,
            count: findingsCount > 0 ? findingsCount : undefined,
          },
          {
            key: "recon" as Tab,
            label: "Recon Surface",
            icon: <Globe className="h-3.5 w-3.5" />,
            count: undefined,
          },
          {
            key: "monitoring" as Tab,
            label: "Monitoring",
            icon: <ShieldAlert className="h-3.5 w-3.5" />,
            count: alertCount > 0 ? alertCount : undefined,
          },
          {
            key: "reports" as Tab,
            label: "Reports",
            icon: <Download className="h-3.5 w-3.5" />,
            count: undefined,
          },
        ].map(({ key, label, icon, count }) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={cn(
              "flex items-center gap-1.5 px-4 py-3 text-sm font-medium border-b-2 transition-colors",
              tab === key
                ? "border-pentra-accent text-pentra-text-primary"
                : "border-transparent text-pentra-text-muted hover:text-pentra-text-primary"
            )}
          >
            {icon}
            {label}
            {count !== undefined && (
              <span
                className={cn(
                  "inline-flex items-center justify-center min-w-[1.25rem] h-5 px-1 rounded-full text-[10px] font-semibold",
                  tab === key
                    ? "bg-primary/20 text-primary"
                    : "bg-pentra-bg-hover text-pentra-text-muted"
                )}
              >
                {count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-hidden p-6">
        {tab === "feed" && (
          <div className="h-full flex flex-col gap-3">
            {/* Stat overview */}
            {engagement.status !== "planning" && (
              <div className="flex gap-2 flex-shrink-0">
                <StatCard
                  label="Critical"
                  value={findings?.filter((f) => f.severity === "critical").length ?? 0}
                  color="var(--critical)"
                />
                <StatCard
                  label="High"
                  value={findings?.filter((f) => f.severity === "high").length ?? 0}
                  color="var(--high)"
                />
                <StatCard
                  label="Medium"
                  value={findings?.filter((f) => f.severity === "medium").length ?? 0}
                  color="var(--medium)"
                />
                <StatCard
                  label="Events"
                  value={events.length}
                  color="var(--accent)"
                />
              </div>
            )}
            {engagement.status === "planning" ? (
              <div className="flex flex-col items-center justify-center h-full text-pentra-text-muted">
                <ScrollText className="h-10 w-10 mb-3 opacity-20" />
                <p className="text-sm">Agent not started yet</p>
                <p className="text-xs mt-1 opacity-60">Click "Start Agent" to begin</p>
              </div>
            ) : events.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-pentra-text-muted">
                <Activity className="h-8 w-8 mb-2 opacity-20 animate-pulse" />
                <p className="text-sm">Waiting for agent events…</p>
              </div>
            ) : (
              <div className="flex-1 overflow-auto rounded-ds-lg bg-pentra-bg-base border border-pentra-border p-2">
                {groupFeedEvents(events).map((group, idx) =>
                  group.kind === "llm" ? (
                    <LLMStreamGroup key={idx} group={group} />
                  ) : (
                    <FeedRow key={idx} event={group.event} />
                  )
                )}
              </div>
            )}
          </div>
        )}

        {tab === "findings" && engagementId && (
          <div className="h-full">
            <FindingsPanel engagementId={engagementId} />
          </div>
        )}

        {tab === "recon" && engagementId && (
          <div className="h-full">
            <ReconSurfaceTab
              engagementId={engagementId}
              engagementStatus={engagement?.status ?? "planning"}
            />
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
