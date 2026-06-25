import { useEffect } from "react";
import { CheckCircle2, XCircle, AlertTriangle, Info, X } from "lucide-react";
import { cn } from "../lib/utils";
import { useToastStore, type ToastItem, type ToastVariant } from "../lib/toast";

const ICON_MAP: Record<ToastVariant, React.ReactNode> = {
  success: <CheckCircle2 className="h-4 w-4 text-green-400 flex-shrink-0" />,
  error: <XCircle className="h-4 w-4 text-red-400 flex-shrink-0" />,
  warning: <AlertTriangle className="h-4 w-4 text-yellow-400 flex-shrink-0" />,
  info: <Info className="h-4 w-4 text-blue-400 flex-shrink-0" />,
};

const BORDER_MAP: Record<ToastVariant, string> = {
  success: "border-green-500/30",
  error: "border-red-500/30",
  warning: "border-yellow-500/30",
  info: "border-blue-500/30",
};

const AUTO_DISMISS_MS = 5000;

function ToastRow({ id, title, description, variant }: ToastItem) {
  const remove = useToastStore((s) => s.remove);

  useEffect(() => {
    const timer = setTimeout(() => remove(id), AUTO_DISMISS_MS);
    return () => clearTimeout(timer);
  }, [id, remove]);

  return (
    <div
      role="alert"
      className={cn(
        "flex items-start gap-3 w-80 rounded-ds-md border p-3 shadow-xl",
        "bg-pentra-bg-panel text-pentra-text-primary",
        BORDER_MAP[variant]
      )}
    >
      <span className="mt-0.5">{ICON_MAP[variant]}</span>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium leading-snug">{title}</p>
        {description && (
          <p className="text-xs text-pentra-text-muted mt-0.5 leading-snug">
            {description}
          </p>
        )}
      </div>
      <button
        onClick={() => remove(id)}
        aria-label="Dismiss"
        className="flex-shrink-0 text-pentra-text-muted hover:text-pentra-text-primary transition-colors"
      >
        <X className="h-3.5 w-3.5" />
      </button>
    </div>
  );
}

export function Toaster() {
  const toasts = useToastStore((s) => s.toasts);

  return (
    <div
      aria-live="polite"
      className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2 items-end"
    >
      {toasts.map((t) => (
        <ToastRow key={t.id} {...t} />
      ))}
    </div>
  );
}
