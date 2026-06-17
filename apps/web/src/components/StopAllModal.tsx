import { useState } from "react";
import { OctagonX, Loader2, AlertTriangle } from "lucide-react";
import { cn } from "../lib/utils";
import { useQueryClient } from "@tanstack/react-query";
import { useStopEngagement } from "../lib/api";
import { toastSuccess, toastError } from "../lib/toast";
import type { Engagement } from "../lib/types";
import { apiClient } from "../lib/api";

interface StopAllModalProps {
  open: boolean;
  onClose: () => void;
  runningEngagements: Engagement[];
}

function StopButton({ engagement, onStopped }: { engagement: Engagement; onStopped: () => void }) {
  const stop = useStopEngagement(engagement.id);

  const handleStop = async () => {
    try {
      await stop.mutateAsync();
      onStopped();
    } catch {
      // handled by global error handler
    }
  };

  return (
    <button
      type="button"
      onClick={handleStop}
      disabled={stop.isPending}
      className="flex h-6 items-center gap-1 rounded-ds-sm border border-pentra-severity-critical/40 px-2 text-[11px] text-pentra-severity-critical transition-colors hover:bg-pentra-severity-critical/10 disabled:opacity-50"
    >
      {stop.isPending ? (
        <Loader2 className="h-3 w-3 animate-spin" />
      ) : (
        <OctagonX className="h-3 w-3" />
      )}
      Stop
    </button>
  );
}

export function StopAllModal({ open, onClose, runningEngagements }: StopAllModalProps) {
  const [stopping, setStopping] = useState(false);
  const [stoppedIds, setStoppedIds] = useState<Set<string>>(new Set());
  const qc = useQueryClient();

  if (!open) return null;

  const pendingEngagements = runningEngagements.filter((e) => !stoppedIds.has(e.id));

  const handleStopAll = async () => {
    setStopping(true);
    let successCount = 0;
    let errorCount = 0;

    for (const eng of pendingEngagements) {
      try {
        await apiClient.patch(`/api/v1/engagements/${eng.id}/stop`);
        setStoppedIds((prev) => new Set([...prev, eng.id]));
        successCount++;
      } catch {
        errorCount++;
      }
    }

    setStopping(false);
    qc.invalidateQueries({ queryKey: ["engagements"] });

    if (errorCount === 0) {
      toastSuccess("All engagements stopped", `${successCount} engagement(s) stopped successfully`);
      onClose();
    } else {
      toastError("Partial failure", `${successCount} stopped, ${errorCount} failed`);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative w-[420px] rounded-ds-lg border border-pentra-border bg-pentra-bg-panel shadow-2xl">
        <div className="flex items-center gap-3 border-b border-pentra-border px-4 py-3.5">
          <AlertTriangle className="h-5 w-5 text-pentra-severity-critical" />
          <h2 className="text-[15px] font-semibold text-pentra-text-primary">Stop Running Engagements</h2>
        </div>

        <div className="p-4">
          <p className="mb-3 text-[13px] text-pentra-text-secondary">
            The following engagements are currently running. Stopping them will interrupt the agent.
          </p>

          <div className="space-y-2 rounded-ds-md border border-pentra-border bg-pentra-bg-card p-2">
            {runningEngagements.map((eng) => (
              <div
                key={eng.id}
                className={cn(
                  "flex items-center justify-between rounded-ds-sm px-3 py-2",
                  stoppedIds.has(eng.id) && "opacity-50"
                )}
              >
                <div className="min-w-0">
                  <p className="truncate text-[13px] font-medium text-pentra-text-primary">{eng.name}</p>
                  <p className="text-[11px] text-pentra-text-muted capitalize">{eng.status.replace("_", " ")}</p>
                </div>
                {stoppedIds.has(eng.id) ? (
                  <span className="text-[11px] text-pentra-status-complete">Stopped</span>
                ) : (
                  <StopButton
                    engagement={eng}
                    onStopped={() => {
                      setStoppedIds((prev) => new Set([...prev, eng.id]));
                      qc.invalidateQueries({ queryKey: ["engagements"] });
                    }}
                  />
                )}
              </div>
            ))}
          </div>
        </div>

        <div className="flex items-center justify-end gap-2 border-t border-pentra-border px-4 py-3">
          <button
            type="button"
            onClick={onClose}
            className="rounded-ds-md border border-pentra-border px-3 py-1.5 text-[13px] text-pentra-text-secondary transition-colors hover:bg-pentra-bg-hover hover:text-pentra-text-primary"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleStopAll}
            disabled={stopping || pendingEngagements.length === 0}
            className="flex items-center gap-2 rounded-ds-md bg-pentra-severity-critical px-3 py-1.5 text-[13px] font-medium text-white transition-opacity hover:opacity-80 disabled:opacity-50"
          >
            {stopping ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <OctagonX className="h-3.5 w-3.5" />
            )}
            Stop All ({pendingEngagements.length})
          </button>
        </div>
      </div>
    </div>
  );
}
