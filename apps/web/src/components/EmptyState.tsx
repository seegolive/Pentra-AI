import type { ReactNode } from "react";
import { cn } from "../lib/utils";

interface EmptyStateProps {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: { label: string; onClick: () => void };
  className?: string;
}

export function EmptyState({
  icon,
  title,
  description,
  action,
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center h-full py-16 text-muted-foreground",
        className
      )}
    >
      {icon && (
        <div className="mb-4 opacity-20 text-foreground">{icon}</div>
      )}
      <p className="text-sm font-medium text-foreground/70">{title}</p>
      {description && (
        <p className="text-xs mt-1.5 opacity-60 text-center max-w-xs">
          {description}
        </p>
      )}
      {action && (
        <button
          onClick={action.onClick}
          className="mt-4 px-4 py-2 text-xs bg-primary text-primary-foreground rounded-md hover:opacity-90 transition-opacity"
        >
          {action.label}
        </button>
      )}
    </div>
  );
}
