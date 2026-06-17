import { useNavigate } from "react-router-dom";
import { ExternalLink, CheckCircle2, OctagonX, Clock } from "lucide-react";
import { cn } from "../lib/utils";
import { useApproveAction, useStopEngagement } from "../lib/api";
import { toastSuccess, toastError } from "../lib/toast";
import type { Engagement, Finding, Severity } from "../lib/types";

interface EngagementOverviewCardProps {
  engagement: Engagement;
  findings: Finding[];
}

function severityCount(findings: Finding[], severity: Severity) {
  return findings.filter((f) => f.severity === severity).length;
}

function formatElapsed(startedAt: string | null) {
  if (!startedAt) return "—";
  const diff = Date.now() - new Date(startedAt).getTime();
  const h = Math.floor(diff / 3_600_000);
  const m = Math.floor((diff % 3_600_000) / 60_000);
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

const STATUS_DOT: Record<string, string> = {
  active: "bg-pentra-status-running animate-pulse",
  awaiting_approval: "bg-pentra-status-waiting",
  paused: "bg-pentra-status-waiting",
  planning: "bg-pentra-status-idle",
  completed: "bg-pentra-status-complete",
  failed: "bg-pentra-status-failed",
};

export function EngagementOverviewCard({ engagement, findings }: EngagementOverviewCardProps) {
  const navigate = useNavigate();
  const approve = useApproveAction(engagement.id);
  const stop = useStopEngagement(engagement.id);

  const critCount = severityCount(findings, "critical");
  const highCount = severityCount(findings, "high");
  const medCount = severityCount(findings, "medium");

  const handleApprove = async () => {
    try {
      await approve.mutateAsync({ action: "approve" });
      toastSuccess("Approved", "Engagement resumed");
    } catch {
      toastError("Failed", "Could not approve action");
    }
  };

  const handleStop = async () => {
    try {
      await stop.mutateAsync();
      toastSuccess("Stopped", engagement.name);
    } catch {
      toastError("Failed", "Could not stop engagement");
    }
  };

  return (
    <div className="rounded-ds-md border border-pentra-border bg-pentra-bg-card p-3 mx-ds-2 mb-ds-2">
      {/* Header */}
      <div className="flex items-center gap-2 mb-2">
        <div
          className={cn(
            "h-2 w-2 flex-shrink-0 rounded-full",
            STATUS_DOT[engagement.status] ?? "bg-pentra-status-idle"
          )}
        />
        <p className="truncate text-[12px] font-semibold text-pentra-text-primary flex-1">
          {engagement.name}
        </p>
        <span className="text-[10px] text-pentra-text-muted flex-shrink-0">
          {formatElapsed(engagement.started_at)}
        </span>
      </div>

      {/* KPI Grid */}
      <div className="grid grid-cols-4 gap-1 mb-2">
        {[
          { label: "Crit", count: critCount, color: "text-pentra-severity-critical" },
          { label: "High", count: highCount, color: "text-pentra-severity-high" },
          { label: "Med", count: medCount, color: "text-pentra-severity-medium" },
          { label: "All", count: findings.length, color: "text-pentra-text-primary" },
        ].map(({ label, count, color }) => (
          <div
            key={label}
            className="flex flex-col items-center rounded-ds-sm bg-pentra-bg-panel py-1"
          >
            <span className={cn("text-[14px] font-bold leading-none", color)}>{count}</span>
            <span className="text-[9px] text-pentra-text-muted mt-0.5">{label}</span>
          </div>
        ))}
      </div>

      {/* Actions */}
      <div className="flex gap-1">
        <button
          type="button"
          onClick={() => navigate(`/engagements/${engagement.id}`)}
          className="flex flex-1 items-center justify-center gap-1 rounded-ds-sm border border-pentra-border py-1 text-[11px] text-pentra-text-secondary transition-colors hover:bg-pentra-bg-hover hover:text-pentra-text-primary"
        >
          <ExternalLink className="h-3 w-3" />
          View
        </button>

        {engagement.status === "awaiting_approval" && (
          <button
            type="button"
            onClick={handleApprove}
            disabled={approve.isPending}
            className="flex flex-1 items-center justify-center gap-1 rounded-ds-sm bg-pentra-accent py-1 text-[11px] font-medium text-white transition-opacity hover:opacity-80 disabled:opacity-50"
          >
            <CheckCircle2 className="h-3 w-3" />
            Approve
          </button>
        )}

        {(engagement.status === "active" || engagement.status === "awaiting_approval") && (
          <button
            type="button"
            onClick={handleStop}
            disabled={stop.isPending}
            className="flex items-center justify-center gap-1 rounded-ds-sm border border-pentra-severity-critical/40 px-2 py-1 text-[11px] text-pentra-severity-critical transition-colors hover:bg-pentra-severity-critical/10 disabled:opacity-50"
          >
            <OctagonX className="h-3 w-3" />
          </button>
        )}

        {engagement.status === "planning" && (
          <span className="flex flex-1 items-center justify-center gap-1 rounded-ds-sm py-1 text-[11px] text-pentra-text-muted">
            <Clock className="h-3 w-3" />
            Planning
          </span>
        )}
      </div>
    </div>
  );
}
