import { useState } from "react";
import {
  Activity,
  Bell,
  BellOff,
  Filter,
  GitCompare,
  Loader2,
} from "lucide-react";
import { cn } from "../../lib/utils";
import {
  useMonitoringAlerts,
  useMarkAlertRead,
  useMarkAllAlertsRead,
  useReconSnapshots,
} from "../../lib/api";
import { AlertCard } from "./AlertCard";
import { SnapshotDiff } from "./SnapshotDiff";

type MonitoringView = "alerts" | "diff";
type AlertFilter = "all" | "unread" | "new_subdomain" | "new_port" | "new_endpoint" | "removed_subdomain";

interface MonitoringPanelProps {
  engagementId: string;
}

export function MonitoringPanel({ engagementId }: MonitoringPanelProps) {
  const [view, setView] = useState<MonitoringView>("alerts");
  const [filter, setFilter] = useState<AlertFilter>("all");

  const alertFilters = {
    is_read: filter === "unread" ? false : undefined,
    alert_type:
      filter !== "all" && filter !== "unread" ? filter : undefined,
  };

  const { data: alerts, isLoading: alertsLoading } = useMonitoringAlerts(
    engagementId,
    alertFilters
  );
  const { data: snapshots, isLoading: snapshotsLoading } = useReconSnapshots(engagementId);

  const markRead = useMarkAlertRead();
  const markAllRead = useMarkAllAlertsRead();

  const unreadCount = alerts?.filter((a) => !a.is_read).length ?? 0;

  const filterOptions: { key: AlertFilter; label: string }[] = [
    { key: "all", label: "All" },
    { key: "unread", label: "Unread" },
    { key: "new_subdomain", label: "Subdomains" },
    { key: "new_port", label: "Ports" },
    { key: "new_endpoint", label: "Endpoints" },
    { key: "removed_subdomain", label: "Removed" },
  ];

  return (
    <div className="h-full flex flex-col gap-4 overflow-hidden">
      {/* View toggle + actions */}
      <div className="flex items-center gap-3 flex-shrink-0">
        <div className="flex items-center gap-1 bg-background border border-border rounded-md p-0.5">
          <button
            onClick={() => setView("alerts")}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors",
              view === "alerts"
                ? "bg-primary/20 text-primary"
                : "text-muted-foreground hover:text-foreground"
            )}
          >
            <Bell className="h-3.5 w-3.5" />
            Alerts
            {unreadCount > 0 && (
              <span className="px-1.5 py-0.5 rounded-full bg-blue-500 text-white text-[10px] leading-none">
                {unreadCount}
              </span>
            )}
          </button>
          <button
            onClick={() => setView("diff")}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors",
              view === "diff"
                ? "bg-primary/20 text-primary"
                : "text-muted-foreground hover:text-foreground"
            )}
          >
            <GitCompare className="h-3.5 w-3.5" />
            Snapshot Diff
            {(snapshots?.length ?? 0) > 0 && (
              <span className="text-[10px] text-muted-foreground">
                ({snapshots?.length})
              </span>
            )}
          </button>
        </div>

        {view === "alerts" && unreadCount > 0 && (
          <button
            onClick={() => markAllRead.mutate({ engagementId })}
            disabled={markAllRead.isPending}
            className="flex items-center gap-1.5 ml-auto text-xs text-muted-foreground hover:text-foreground transition-colors disabled:opacity-50"
          >
            <BellOff className="h-3.5 w-3.5" />
            Mark all read
          </button>
        )}
      </div>

      {/* Alerts view */}
      {view === "alerts" && (
        <div className="flex-1 overflow-hidden flex flex-col gap-3">
          {/* Filter bar */}
          <div className="flex items-center gap-1.5 flex-shrink-0">
            <Filter className="h-3 w-3 text-muted-foreground flex-shrink-0" />
            {filterOptions.map((f) => (
              <button
                key={f.key}
                onClick={() => setFilter(f.key)}
                className={cn(
                  "px-2 py-0.5 rounded text-xs transition-colors",
                  filter === f.key
                    ? "bg-primary/20 text-primary font-medium"
                    : "text-muted-foreground hover:text-foreground"
                )}
              >
                {f.label}
              </button>
            ))}
          </div>

          {/* Alert list */}
          <div className="flex-1 overflow-y-auto pr-1 space-y-2">
            {alertsLoading ? (
              <div className="flex items-center gap-2 text-xs text-muted-foreground py-8 justify-center">
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                Loading alerts…
              </div>
            ) : !alerts || alerts.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <Activity className="h-8 w-8 mb-2 opacity-20" />
                <p className="text-sm">No alerts yet</p>
                <p className="text-xs mt-1 opacity-60">
                  Alerts appear when the agent detects surface changes
                </p>
              </div>
            ) : (
              alerts.map((alert) => (
                <AlertCard
                  key={alert.id}
                  alert={alert}
                  onMarkRead={
                    alert.is_read
                      ? undefined
                      : () =>
                          markRead.mutate({
                            engagementId,
                            alertId: alert.id,
                          })
                  }
                  isMarkingRead={markRead.isPending}
                />
              ))
            )}
          </div>
        </div>
      )}

      {/* Snapshot diff view */}
      {view === "diff" && (
        <div className="flex-1 overflow-y-auto">
          {snapshotsLoading ? (
            <div className="flex items-center gap-2 text-xs text-muted-foreground py-8 justify-center">
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              Loading snapshots…
            </div>
          ) : (
            <SnapshotDiff
              engagementId={engagementId}
              snapshots={snapshots ?? []}
            />
          )}
        </div>
      )}
    </div>
  );
}
