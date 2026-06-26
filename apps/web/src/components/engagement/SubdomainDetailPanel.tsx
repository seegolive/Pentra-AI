import { useState } from "react";
import {
  X,
  Server,
  Globe,
  Link,
  Cpu,
  Zap,
  Bug,
  ExternalLink,
  CheckCircle2,
  XCircle,
  Loader2,
} from "lucide-react";
import { cn } from "../../lib/utils";
import { useSubscan } from "../../lib/api";
import type { SubdomainInfo, PortInfo, EndpointInfo } from "../../lib/types";

interface SubdomainDetailPanelProps {
  engagementId: string;
  subdomain: SubdomainInfo;
  allPorts: PortInfo[];
  allEndpoints: EndpointInfo[];
  onClose: () => void;
}

const METHOD_COLORS: Record<string, string> = {
  GET: "text-emerald-400 bg-emerald-400/10 border-emerald-400/20",
  POST: "text-blue-400 bg-blue-400/10 border-blue-400/20",
  PUT: "text-yellow-400 bg-yellow-400/10 border-yellow-400/20",
  PATCH: "text-orange-400 bg-orange-400/10 border-orange-400/20",
  DELETE: "text-red-400 bg-red-400/10 border-red-400/20",
};

export function SubdomainDetailPanel({
  engagementId,
  subdomain,
  allPorts,
  allEndpoints,
  onClose,
}: SubdomainDetailPanelProps) {
  const [subscanDone, setSubscanDone] = useState(false);
  const subscanMutation = useSubscan(engagementId);

  const hostPorts = allPorts.filter((p) => p.host === subdomain.host);
  const hostEndpoints = allEndpoints.filter((e) =>
    e.url.includes(subdomain.host)
  );

  const scheme = subdomain.status_code === 443 ? "https" : "https";
  const targetUrl = `${scheme}://${subdomain.host}`;

  async function handleSubscan() {
    await subscanMutation.mutateAsync({ target_urls: [targetUrl] });
    setSubscanDone(true);
    setTimeout(() => setSubscanDone(false), 3000);
  }

  return (
    <div className="fixed inset-y-0 right-0 z-50 flex">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/40 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Panel */}
      <div className="relative ml-auto w-[480px] h-full bg-pentra-bg-card border-l border-pentra-border flex flex-col overflow-hidden shadow-2xl">
        {/* Header */}
        <div className="flex items-start gap-3 px-5 py-4 border-b border-pentra-border flex-shrink-0">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono text-sm font-semibold text-pentra-text-primary truncate">
                {subdomain.host}
              </span>
              <span
                className={cn(
                  "inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded-full border",
                  subdomain.is_alive
                    ? "text-emerald-400 bg-emerald-400/10 border-emerald-400/30"
                    : "text-red-400 bg-red-400/10 border-red-400/30"
                )}
              >
                {subdomain.is_alive ? (
                  <CheckCircle2 className="h-2.5 w-2.5" />
                ) : (
                  <XCircle className="h-2.5 w-2.5" />
                )}
                {subdomain.is_alive ? "Alive" : "Dead"}
              </span>
              {subdomain.findings_count > 0 && (
                <span className="inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded-full border text-red-400 bg-red-400/10 border-red-400/30">
                  <Bug className="h-2.5 w-2.5" />
                  {subdomain.findings_count} finding{subdomain.findings_count !== 1 ? "s" : ""}
                </span>
              )}
            </div>
            <p className="text-[11px] text-pentra-text-muted mt-0.5">
              {subdomain.source || "unknown source"}
            </p>
          </div>
          <button
            onClick={onClose}
            className="flex-shrink-0 p-1.5 rounded-md hover:bg-pentra-bg-hover text-pentra-text-muted hover:text-pentra-text-primary transition-colors"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5">
          {/* Info grid */}
          <div>
            <h3 className="text-[10px] font-semibold uppercase tracking-wider text-pentra-text-muted mb-2">
              Host Info
            </h3>
            <div className="grid grid-cols-2 gap-2">
              {[
                { label: "IP Address", value: subdomain.ip || "—", icon: <Server className="h-3 w-3" /> },
                {
                  label: "Status Code",
                  value: subdomain.status_code !== null ? String(subdomain.status_code) : "—",
                  icon: <Globe className="h-3 w-3" />,
                },
                { label: "Source", value: subdomain.source || "—", icon: <Link className="h-3 w-3" /> },
                {
                  label: "Ports Found",
                  value: String(hostPorts.length),
                  icon: <Server className="h-3 w-3" />,
                },
              ].map(({ label, value, icon }) => (
                <div
                  key={label}
                  className="rounded-ds-sm border border-pentra-border bg-pentra-bg-base/60 px-3 py-2"
                >
                  <div className="flex items-center gap-1.5 text-[10px] text-pentra-text-muted mb-0.5">
                    {icon}
                    {label}
                  </div>
                  <p className="font-mono text-xs text-pentra-text-primary">{value}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Tech stack */}
          {subdomain.tech_stack.length > 0 && (
            <div>
              <h3 className="text-[10px] font-semibold uppercase tracking-wider text-pentra-text-muted mb-2">
                Technology Stack
              </h3>
              <div className="flex flex-wrap gap-1.5">
                {subdomain.tech_stack.map((t) => (
                  <span
                    key={t}
                    className="inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded border text-cyan-300/80 bg-cyan-400/5 border-cyan-400/20"
                  >
                    <Cpu className="h-2.5 w-2.5" />
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Open ports */}
          {hostPorts.length > 0 && (
            <div>
              <h3 className="text-[10px] font-semibold uppercase tracking-wider text-pentra-text-muted mb-2">
                Open Ports ({hostPorts.length})
              </h3>
              <div className="space-y-1">
                {hostPorts.map((p, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-2 px-3 py-1.5 rounded border border-pentra-border bg-pentra-bg-base/40 text-xs font-mono"
                  >
                    <span className="text-yellow-400 font-semibold w-12">{p.port}</span>
                    <span className="text-pentra-text-muted w-8">{p.protocol}</span>
                    <span className="text-pentra-text-primary flex-1">{p.service || "—"}</span>
                    {p.version && (
                      <span className="text-pentra-text-muted text-[10px]">{p.version}</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Endpoints */}
          {hostEndpoints.length > 0 && (
            <div>
              <h3 className="text-[10px] font-semibold uppercase tracking-wider text-pentra-text-muted mb-2">
                Endpoints ({hostEndpoints.length})
              </h3>
              <div className="space-y-1 max-h-48 overflow-y-auto">
                {hostEndpoints.map((ep, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-2 px-2 py-1 rounded border border-pentra-border bg-pentra-bg-base/40 text-[11px] font-mono"
                  >
                    <span
                      className={cn(
                        "text-[9px] font-bold px-1.5 py-0.5 rounded border flex-shrink-0",
                        METHOD_COLORS[ep.method] ?? "text-slate-400 bg-slate-400/10 border-slate-400/20"
                      )}
                    >
                      {ep.method}
                    </span>
                    <span className="text-pentra-text-primary truncate flex-1">
                      {ep.url.replace(/^https?:\/\/[^/]+/, "")}
                    </span>
                    <span className="text-pentra-text-muted text-[9px] flex-shrink-0">
                      {ep.source}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {hostPorts.length === 0 && hostEndpoints.length === 0 && subdomain.tech_stack.length === 0 && (
            <div className="flex flex-col items-center justify-center py-10 text-pentra-text-muted">
              <Globe className="h-8 w-8 mb-2 opacity-30" />
              <p className="text-xs">No detailed data yet — scan in progress or host is unreachable.</p>
            </div>
          )}
        </div>

        {/* Footer actions */}
        <div className="flex items-center gap-2 px-5 py-3 border-t border-pentra-border flex-shrink-0">
          <a
            href={targetUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium border border-pentra-border bg-pentra-bg-base hover:bg-pentra-bg-hover text-pentra-text-muted hover:text-pentra-text-primary transition-colors"
          >
            <ExternalLink className="h-3 w-3" />
            Open in browser
          </a>
          <button
            onClick={handleSubscan}
            disabled={subscanMutation.isPending || subscanDone}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors",
              subscanDone
                ? "border border-emerald-400/30 bg-emerald-400/10 text-emerald-400"
                : "border border-pentra-accent/40 bg-pentra-accent/10 hover:bg-pentra-accent/20 text-pentra-accent"
            )}
          >
            {subscanMutation.isPending ? (
              <Loader2 className="h-3 w-3 animate-spin" />
            ) : subscanDone ? (
              <CheckCircle2 className="h-3 w-3" />
            ) : (
              <Zap className="h-3 w-3" />
            )}
            {subscanDone ? "Subscan queued!" : "Run subscan"}
          </button>
        </div>
      </div>
    </div>
  );
}
