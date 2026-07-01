import { useState, useEffect } from "react";
import {
  Activity,
  Bell,
  BellOff,
  Filter,
  GitCompare,
  Globe,
  Server,
  Link,
  Loader2,
} from "lucide-react";
import { cn } from "../../lib/utils";
import {
  useMonitoringAlerts,
  useMarkAlertRead,
  useMarkAllAlertsRead,
  useMonitoringSchedule,
  useReconSnapshots,
  useScheduleMonitoring,
  useReconState,
} from "../../lib/api";
import { AlertCard } from "./AlertCard";
import { SnapshotDiff } from "./SnapshotDiff";

type MonitoringView = "alerts" | "diff" | "schedule" | "surface";
type AlertFilter = "all" | "unread" | "new_subdomain" | "new_port" | "new_endpoint" | "removed_subdomain";

interface MonitoringPanelProps {
  engagementId: string;
}

export function MonitoringPanel({ engagementId }: MonitoringPanelProps) {
  const [view, setView] = useState<MonitoringView>("alerts");
  const { data: reconState } = useReconState(engagementId);
  const [filter, setFilter] = useState<AlertFilter>("all");
  const [scheduleEnabled, setScheduleEnabled] = useState(false);
  const [scheduleInterval, setScheduleInterval] = useState(24);
  const { data: scheduleData } = useMonitoringSchedule(engagementId);
  const scheduleMutation = useScheduleMonitoring(engagementId);

  // Hydrate local form state from server once data loads
  useEffect(() => {
    if (scheduleData) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setScheduleEnabled(scheduleData.enabled);
       
      setScheduleInterval(scheduleData.interval_hours);
    }
  }, [scheduleData]);

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
          <button
            onClick={() => setView("schedule")}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors",
              view === "schedule"
                ? "bg-primary/20 text-primary"
                : "text-muted-foreground hover:text-foreground"
            )}
          >
            <Activity className="h-3.5 w-3.5" />
            Schedule
          </button>
          <button
            onClick={() => setView("surface")}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors",
              view === "surface"
                ? "bg-primary/20 text-primary"
                : "text-muted-foreground hover:text-foreground"
            )}
          >
            <Globe className="h-3.5 w-3.5" />
            Surface
            {(reconState?.total_subdomains ?? 0) > 0 && (
              <span className="text-[10px] text-muted-foreground">
                ({reconState?.total_subdomains})
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

      {/* Surface summary view */}
      {view === "surface" && (
        <div className="flex-1 overflow-y-auto space-y-4">
          {!reconState || reconState.total_subdomains === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Globe className="h-8 w-8 mb-2 opacity-20" />
              <p className="text-sm">No recon data available yet</p>
              <p className="text-xs mt-1 opacity-60">Run a scan to populate the attack surface.</p>
            </div>
          ) : (
            <>
              {/* Summary stats */}
              <div className="grid grid-cols-3 gap-2">
                {[
                  { label: "Subdomains", value: reconState.total_subdomains, sub: `${reconState.alive_count} alive`, icon: <Globe className="h-3.5 w-3.5" /> },
                  { label: "Ports", value: reconState.total_ports, icon: <Server className="h-3.5 w-3.5" /> },
                  { label: "Endpoints", value: reconState.total_endpoints, icon: <Link className="h-3.5 w-3.5" /> },
                ].map(({ label, value, sub, icon }) => (
                  <div key={label} className="rounded-md border border-border bg-muted/20 px-3 py-2">
                    <div className="flex items-center gap-1 text-[10px] text-muted-foreground mb-1">
                      {icon} {label}
                    </div>
                    <p className="text-lg font-bold text-foreground">{value}</p>
                    {sub && <p className="text-[10px] text-muted-foreground">{sub}</p>}
                  </div>
                ))}
              </div>

              {/* Snapshot history */}
              {(snapshots?.length ?? 0) > 0 && (
                <div>
                  <h3 className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                    Snapshot History
                  </h3>
                  <div className="space-y-1.5">
                    {snapshots?.slice(0, 5).map((snap, i) => (
                      <div
                        key={snap.id}
                        className="flex items-center gap-3 px-3 py-2 rounded border border-border bg-muted/20 text-xs"
                      >
                        <span className="text-[10px] text-muted-foreground font-mono">
                          #{snapshots.length - i}
                        </span>
                        <span className="text-muted-foreground flex-1">
                          {new Date(snap.snapshot_at).toLocaleString()}
                        </span>
                        <span className="text-foreground font-medium">
                          {snap.subdomains?.length ?? 0} hosts
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Tech stack */}
              {reconState.tech_stack.length > 0 && (
                <div>
                  <h3 className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                    Detected Technologies
                  </h3>
                  <div className="flex flex-wrap gap-1.5">
                    {reconState.tech_stack.map((t) => (
                      <span
                        key={t}
                        className="text-[10px] px-2 py-0.5 rounded border border-cyan-400/20 bg-cyan-400/5 text-cyan-300/80"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* Schedule view */}
      {view === "schedule" && (
        <div className="flex-1 overflow-y-auto">
          <div className="rounded-md border border-border bg-muted/30 p-5 space-y-5 max-w-sm">
            <div>
              <h3 className="text-sm font-semibold text-foreground mb-1">Continuous Monitoring</h3>
              <p className="text-xs text-muted-foreground">
                Periodically re-run recon and compare results to detect surface changes.
              </p>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-foreground">Enable monitoring</span>
              <button
                type="button"
                onClick={() => setScheduleEnabled((v) => !v)}
                className={cn(
                  "relative inline-flex h-5 w-9 items-center rounded-full transition-colors",
                  scheduleEnabled ? "bg-primary" : "bg-muted"
                )}
              >
                <span
                  className={cn(
                    "inline-block h-4 w-4 rounded-full bg-white shadow transition-transform",
                    scheduleEnabled ? "translate-x-4" : "translate-x-0.5"
                  )}
                />
              </button>
            </div>
            <div className={cn("space-y-2", !scheduleEnabled && "opacity-40 pointer-events-none")}>
              <label className="text-xs font-medium text-muted-foreground">
                Check every
              </label>
              <select
                value={scheduleInterval}
                onChange={(e) => setScheduleInterval(Number(e.target.value))}
                className="w-full bg-background border border-border rounded-md px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
              >
                {[6, 12, 24, 48, 72, 168].map((h) => (
                  <option key={h} value={h}>
                    {h < 24 ? `${h} hours` : `${h / 24} day${h / 24 > 1 ? "s" : ""}`}
                  </option>
                ))}
              </select>
            </div>
            <button
              type="button"
              disabled={scheduleMutation.isPending}
              onClick={() => scheduleMutation.mutate({ enabled: scheduleEnabled, interval_hours: scheduleInterval })}
              className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground text-xs font-medium rounded-md hover:bg-primary/90 disabled:opacity-50 transition-colors"
            >
              {scheduleMutation.isPending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Activity className="h-3.5 w-3.5" />
              )}
              {scheduleMutation.isSuccess ? "Saved!" : "Save Schedule"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
