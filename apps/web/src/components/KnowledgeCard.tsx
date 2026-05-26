import { ExternalLink } from "lucide-react";
import { cn, formatBounty, SEVERITY_COLORS, VULN_CLASS_LABELS } from "../lib/utils";
import type { KnowledgeSummary } from "../lib/types";

interface KnowledgeCardProps {
  record: KnowledgeSummary;
  onClick: (id: string) => void;
}

export function KnowledgeCard({ record, onClick }: KnowledgeCardProps) {
  return (
    <button
      type="button"
      onClick={() => onClick(record.id)}
      className={cn(
        "w-full text-left rounded-lg border p-4 transition-colors",
        "bg-card border-border hover:border-primary/40 hover:bg-accent/50",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary",
      )}
    >
      {/* Header row */}
      <div className="flex items-start justify-between gap-3">
        <p className="text-sm font-medium text-foreground line-clamp-2 flex-1">
          {record.title}
        </p>
        <span
          className={cn(
            "shrink-0 text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-full border",
            SEVERITY_COLORS[record.severity],
          )}
        >
          {record.severity}
        </span>
      </div>

      {/* Meta row */}
      <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <span className="font-mono bg-muted px-1.5 py-0.5 rounded text-foreground/80">
          {VULN_CLASS_LABELS[record.vuln_class] ?? record.vuln_class}
        </span>
        <span>{record.program}</span>
        {record.bounty_usd != null && (
          <span className="text-green-400 font-medium">{formatBounty(record.bounty_usd)}</span>
        )}
        {record.source_url && (
          <a
            href={record.source_url}
            target="_blank"
            rel="noopener noreferrer"
            onClick={(e) => e.stopPropagation()}
            className="ml-auto text-muted-foreground hover:text-primary"
            aria-label="Open source"
          >
            <ExternalLink className="h-3.5 w-3.5" />
          </a>
        )}
      </div>

      {/* Key insight */}
      {record.key_insight && (
        <p className="mt-2 text-xs text-muted-foreground line-clamp-2">
          {record.key_insight}
        </p>
      )}

      {/* Tech stack chips */}
      {record.tech_stack.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {record.tech_stack.slice(0, 4).map((t) => (
            <span
              key={t}
              className="text-[10px] bg-accent text-accent-foreground px-1.5 py-0.5 rounded"
            >
              {t}
            </span>
          ))}
          {record.tech_stack.length > 4 && (
            <span className="text-[10px] text-muted-foreground px-1 py-0.5">
              +{record.tech_stack.length - 4}
            </span>
          )}
        </div>
      )}
    </button>
  );
}
