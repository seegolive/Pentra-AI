import { Loader2 } from "lucide-react";
import { cn } from "../lib/utils";

interface LoadingSpinnerProps {
  size?: "sm" | "md" | "lg";
  label?: string;
  className?: string;
}

const SIZE_MAP = {
  sm: "h-3 w-3",
  md: "h-5 w-5",
  lg: "h-8 w-8",
} as const;

export function LoadingSpinner({
  size = "md",
  label,
  className,
}: LoadingSpinnerProps) {
  return (
    <div
      className={cn(
        "flex items-center justify-center gap-2 text-muted-foreground",
        className
      )}
    >
      <Loader2 className={cn("animate-spin", SIZE_MAP[size])} />
      {label && <span className="text-sm">{label}</span>}
    </div>
  );
}
