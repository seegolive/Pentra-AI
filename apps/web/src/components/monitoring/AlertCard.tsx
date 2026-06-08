import { Globe, Server, Link, MinusCircle, CheckCircle2 } from "lucide-react";
import { cn } from "../../lib/utils";
import type { MonitoringAlert } from "../../lib/api";

const ALERT_META: Record<
  MonitoringAlert["alert_type"],
  { label: string; color: string; Icon: React.ElementType }
> = {
  new_subdomain: {
    label: "New Subdomain",
    color: "text-green-400 bg-green-400/10 border-green-400/20",
    Icon: Globe,
  },
  new_port: {
    label: "New Open Port",
    color: "text-yellow-400 bg-yellow-400/10 border-yellow-400/20",
    Icon: Server,
  },
  new_endpoint: {
    label: "New Endpoint",
    color: "text-blue-400 bg-blue-400/10 border-blue-400/20",
    Icon: Link,
  },
  removed_subdomain: {
    label: "Removed Subdomain",
    color: "text-slate-400 bg-slate-400/10 border-slate-400/20",
    Icon: MinusCircle,
  },
};

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60_000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

interface AlertCardProps {
  alert: MonitoringAlert;
  onMarkRead?: () => void;
  isMarkingRead?: boolean;
}

export function AlertCard({ alert, onMarkRead, isMarkingRead }: AlertCardProps) {
  const meta = ALERT_META[alert.alert_type] ?? {
    label: alert.alert_type,
    color: "text-muted-foreground bg-muted border-border",
    Icon: Globe,
  };
  const { Icon } = meta;

  return (
    <div
      className={cn(
        "flex items-start gap-3 p-3 rounded-lg border transition-colors",
        alert.is_read ? "border-border/40 bg-background/30 opacity-60" : "border-border bg-card"
      )}
    >
      {/* Icon badge */}
      <span
        className={cn(
          "flex-shrink-0 flex items-center justify-center h-7 w-7 rounded-md border text-xs",
          meta.color
        )}
      >
        <Icon className="h-3.5 w-3.5" />
      </span>

      {/* Content */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-0.5">
          <span className={cn("text-xs font-semibold", meta.color.split(" ")[0])}>
            {meta.label}
          </span>
          {!alert.is_read && (
            <span className="h-1.5 w-1.5 rounded-full bg-blue-400 flex-shrink-0" />
          )}
        </div>
        <p className="text-xs text-foreground font-mono truncate">
          {alert.detail.value
            ? String(alert.detail.value)
            : JSON.stringify(alert.detail).slice(0, 120)}
        </p>
        {Boolean(alert.detail.host) && (
          <p className="text-[10px] text-muted-foreground mt-0.5">
            host: {String(alert.detail.host as string)}
          </p>
        )}
      </div>

      {/* Time + action */}
      <div className="flex flex-col items-end gap-1.5 flex-shrink-0">
        <span className="text-[10px] text-muted-foreground whitespace-nowrap">
          {relativeTime(alert.created_at)}
        </span>
        {!alert.is_read && onMarkRead && (
          <button
            onClick={onMarkRead}
            disabled={isMarkingRead}
            className="flex items-center gap-1 text-[10px] text-muted-foreground hover:text-foreground transition-colors disabled:opacity-50"
          >
            <CheckCircle2 className="h-3 w-3" />
            Mark read
          </button>
        )}
      </div>
    </div>
  );
}
