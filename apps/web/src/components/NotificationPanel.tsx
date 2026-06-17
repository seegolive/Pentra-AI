import { useEffect } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  Info,
  XCircle,
  Trash2,
  CheckCheck,
} from "lucide-react";
import { cn } from "../lib/utils";
import { useNotifications } from "../hooks/useNotifications";
import type { NotificationItem, NotificationType } from "../hooks/useNotifications";

interface NotificationPanelProps {
  open: boolean;
  onClose: () => void;
}

function typeIcon(type: NotificationType) {
  switch (type) {
    case "FINDING_CONFIRMED":
      return <CheckCircle2 className="h-4 w-4 text-pentra-severity-high" />;
    case "AWAITING_APPROVAL":
      return <Clock className="h-4 w-4 text-pentra-status-waiting" />;
    case "ENGAGEMENT_COMPLETED":
      return <CheckCircle2 className="h-4 w-4 text-pentra-status-complete" />;
    case "AGENT_ERROR":
      return <XCircle className="h-4 w-4 text-pentra-severity-critical" />;
    default:
      return <Info className="h-4 w-4 text-pentra-accent" />;
  }
}

function formatTime(ts: string) {
  const d = new Date(ts);
  const now = Date.now();
  const diff = now - d.getTime();
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return d.toLocaleDateString();
}

function NotificationRow({ item }: { item: NotificationItem }) {
  return (
    <div
      className={cn(
        "flex items-start gap-3 rounded-ds-md px-3 py-2.5 transition-colors",
        !item.read && "bg-pentra-bg-hover"
      )}
    >
      <div className="mt-0.5 flex-shrink-0">{typeIcon(item.type)}</div>
      <div className="min-w-0 flex-1">
        <p className="text-[13px] font-medium text-pentra-text-primary leading-tight">
          {item.title}
        </p>
        {item.description && (
          <p className="mt-0.5 text-[11px] text-pentra-text-secondary leading-tight">
            {item.description}
          </p>
        )}
        <p className="mt-1 text-[10px] text-pentra-text-muted">{formatTime(item.timestamp)}</p>
      </div>
      {!item.read && (
        <div className="mt-1.5 h-1.5 w-1.5 flex-shrink-0 rounded-full bg-pentra-accent" />
      )}
    </div>
  );
}

export function NotificationPanel({ open, onClose }: NotificationPanelProps) {
  const { items, markAllRead, clearAll } = useNotifications();

  useEffect(() => {
    if (open) {
      markAllRead();
    }
  }, [open, markAllRead]);

  if (!open) return null;

  return (
    <div
      className="absolute right-0 top-[calc(100%+8px)] z-50 w-80 rounded-ds-lg border border-pentra-border bg-pentra-bg-panel shadow-2xl"
      role="dialog"
      aria-label="Notifications"
    >
      {/* Header */}
      <div className="flex items-center justify-between border-b border-pentra-border px-3 py-2.5">
        <span className="text-[13px] font-semibold text-pentra-text-primary">Notifications</span>
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={markAllRead}
            title="Mark all read"
            className="flex h-6 w-6 items-center justify-center rounded-ds-sm text-pentra-text-muted transition-colors hover:bg-pentra-bg-hover hover:text-pentra-text-secondary"
          >
            <CheckCheck className="h-3.5 w-3.5" />
          </button>
          <button
            type="button"
            onClick={clearAll}
            title="Clear all"
            className="flex h-6 w-6 items-center justify-center rounded-ds-sm text-pentra-text-muted transition-colors hover:bg-pentra-bg-hover hover:text-pentra-severity-critical"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* List */}
      <div className="max-h-80 overflow-y-auto">
        {items.length === 0 ? (
          <div className="flex flex-col items-center gap-2 py-8 text-pentra-text-muted">
            <AlertTriangle className="h-8 w-8 opacity-30" />
            <p className="text-[12px]">No notifications</p>
          </div>
        ) : (
          <div className="p-1.5 space-y-0.5">
            {items.map((item) => (
              <NotificationRow key={item.id} item={item} />
            ))}
          </div>
        )}
      </div>

      {/* Footer */}
      {items.length > 0 && (
        <div className="border-t border-pentra-border px-3 py-2">
          <button
            type="button"
            onClick={() => { onClose(); }}
            className="w-full text-center text-[11px] text-pentra-text-muted transition-colors hover:text-pentra-text-secondary"
          >
            Close
          </button>
        </div>
      )}
    </div>
  );
}
