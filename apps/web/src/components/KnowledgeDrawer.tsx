import { useEffect } from "react";
import { ExternalLink, X } from "lucide-react";
import { cn, formatBounty, SEVERITY_COLORS, VULN_CLASS_LABELS } from "../lib/utils";
import { useKnowledgeRecord } from "../lib/api";

interface KnowledgeDrawerProps {
  recordId: string | null;
  onClose: () => void;
}

export function KnowledgeDrawer({ recordId, onClose }: KnowledgeDrawerProps) {
  const { data: record, isLoading } = useKnowledgeRecord(recordId);

  // Close on Escape
  useEffect(() => {
    function handler(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [onClose]);

  const open = recordId != null;

  return (
    <>
      {/* Backdrop */}
      <div
        className={cn(
          "fixed inset-0 z-40 bg-black/50 transition-opacity",
          open ? "opacity-100 pointer-events-auto" : "opacity-0 pointer-events-none",
        )}
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Drawer panel */}
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Knowledge record detail"
        className={cn(
          "fixed right-0 top-0 z-50 h-full w-full max-w-2xl overflow-y-auto",
          "bg-card border-l border-border shadow-2xl",
          "transition-transform duration-300 ease-in-out",
          open ? "translate-x-0" : "translate-x-full",
        )}
      >
        {/* Sticky header */}
        <div className="sticky top-0 z-10 flex items-center justify-between bg-card/90 backdrop-blur px-6 py-4 border-b border-border">
          <h2 className="text-sm font-semibold text-foreground truncate max-w-[80%]">
            {isLoading ? "Loading…" : (record?.title ?? "—")}
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded hover:bg-accent text-muted-foreground hover:text-foreground"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {isLoading && (
          <div className="flex items-center justify-center h-64 text-muted-foreground text-sm">
            Loading record…
          </div>
        )}

        {record && !isLoading && (
          <div className="p-6 space-y-6">
            {/* Severity + vuln class + bounty */}
            <div className="flex flex-wrap gap-2 items-center">
              <span className={cn("text-xs font-semibold uppercase px-2.5 py-1 rounded-full border", SEVERITY_COLORS[record.severity])}>
                {record.severity}
              </span>
              <span className="text-xs font-mono bg-muted px-2 py-1 rounded text-foreground/80">
                {VULN_CLASS_LABELS[record.vuln_class] ?? record.vuln_class}
              </span>
              {record.vuln_subclass && (
                <span className="text-xs text-muted-foreground">{record.vuln_subclass}</span>
              )}
              {record.bounty_usd != null && (
                <span className="ml-auto text-green-400 font-semibold text-sm">
                  {formatBounty(record.bounty_usd)}
                </span>
              )}
            </div>

            {/* Program + source */}
            <div className="flex flex-wrap gap-x-6 gap-y-1 text-xs text-muted-foreground">
              <span><span className="text-foreground/60">Program:</span> {record.program}</span>
              <span><span className="text-foreground/60">Source:</span> {record.source}</span>
              {record.source_url && (
                <a
                  href={record.source_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 text-primary hover:underline"
                >
                  Report <ExternalLink className="h-3 w-3" />
                </a>
              )}
            </div>

            <Divider />

            {/* Key insight */}
            <Section title="Key Insight">
              <p className="text-sm text-foreground">{record.key_insight}</p>
            </Section>

            {/* Attack technique */}
            {record.attack_technique && (
              <Section title="Attack Technique">
                <p className="text-sm text-foreground">{record.attack_technique}</p>
              </Section>
            )}

            {/* Attack steps */}
            {record.attack_steps.length > 0 && (
              <Section title="Attack Steps">
                <ol className="list-decimal list-inside space-y-1">
                  {record.attack_steps.map((step, i) => (
                    <li key={i} className="text-sm text-foreground">
                      {step}
                    </li>
                  ))}
                </ol>
              </Section>
            )}

            {/* Payload pattern */}
            {record.payload_pattern && (
              <Section title="Payload Pattern">
                <pre className="text-xs bg-muted rounded p-3 overflow-x-auto font-mono text-foreground/90 whitespace-pre-wrap">
                  {record.payload_pattern}
                </pre>
              </Section>
            )}

            {/* Impact */}
            {record.impact && (
              <Section title="Impact">
                <p className="text-sm text-foreground">{record.impact}</p>
                {record.impact_category.length > 0 && (
                  <div className="mt-1 flex flex-wrap gap-1">
                    {record.impact_category.map((c) => (
                      <span key={c} className="text-[10px] bg-accent px-1.5 py-0.5 rounded text-accent-foreground">
                        {c}
                      </span>
                    ))}
                  </div>
                )}
              </Section>
            )}

            {/* Prerequisites */}
            {record.prerequisites.length > 0 && (
              <Section title="Prerequisites">
                <ul className="list-disc list-inside space-y-1">
                  {record.prerequisites.map((p, i) => (
                    <li key={i} className="text-sm text-foreground">{p}</li>
                  ))}
                </ul>
              </Section>
            )}

            {/* What tools missed */}
            {record.what_tools_missed && (
              <Section title="What Automated Tools Missed">
                <p className="text-sm text-foreground">{record.what_tools_missed}</p>
              </Section>
            )}

            {/* Chained with */}
            {record.chained_with.length > 0 && (
              <Section title="Chained With">
                <div className="flex flex-wrap gap-1">
                  {record.chained_with.map((c) => (
                    <span key={c} className="text-xs font-mono bg-muted px-2 py-0.5 rounded text-foreground/80">
                      {c}
                    </span>
                  ))}
                </div>
              </Section>
            )}

            {/* Tech stack + endpoint */}
            <Divider />
            <div className="grid grid-cols-2 gap-4">
              {record.tech_stack.length > 0 && (
                <div className="space-y-1">
                  <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Tech Stack</p>
                  <div className="flex flex-wrap gap-1">
                    {record.tech_stack.map((t) => (
                      <span key={t} className="text-[10px] bg-accent px-1.5 py-0.5 rounded text-accent-foreground">{t}</span>
                    ))}
                  </div>
                </div>
              )}
              {record.endpoint_pattern && (
                <div className="space-y-1">
                  <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Endpoint Pattern</p>
                  <code className="text-xs font-mono text-foreground/80">{record.endpoint_pattern}</code>
                </div>
              )}
              {record.http_method.length > 0 && (
                <div className="space-y-1">
                  <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">HTTP Methods</p>
                  <div className="flex flex-wrap gap-1">
                    {record.http_method.map((m) => (
                      <span key={m} className="text-[10px] font-mono bg-muted px-1.5 py-0.5 rounded text-foreground/80">{m}</span>
                    ))}
                  </div>
                </div>
              )}
              <div className="space-y-1">
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Auth Required</p>
                <span className={cn("text-xs", record.auth_required ? "text-yellow-500" : "text-green-400")}>
                  {record.auth_required ? "Yes" : "No"}
                </span>
              </div>
            </div>

            {/* Indicators */}
            {record.indicators.length > 0 && (
              <>
                <Divider />
                <Section title="Indicators">
                  <ul className="list-disc list-inside space-y-1">
                    {record.indicators.map((ind, i) => (
                      <li key={i} className="text-xs font-mono text-foreground/80">{ind}</li>
                    ))}
                  </ul>
                </Section>
              </>
            )}
          </div>
        )}
      </div>
    </>
  );
}

function Divider() {
  return <hr className="border-border" />;
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-2">
      <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{title}</p>
      {children}
    </div>
  );
}
