import { useState, useMemo } from "react";
import {
  Globe,
  Server,
  Link,
  Cpu,
  Search,
  ChevronDown,
  ChevronUp,
  Loader2,
  ScanLine,
  Network,
  Bug,
  RefreshCw,
} from "lucide-react";
import { cn } from "../../lib/utils";
import { useReconState } from "../../lib/api";
import type { SubdomainInfo, PortInfo } from "../../lib/types";
import { SubdomainDetailPanel } from "./SubdomainDetailPanel";

interface ReconSurfaceTabProps {
  engagementId: string;
  engagementStatus: string;
}

type AliveFilter = "all" | "alive" | "dead";
type SortField = "host" | "findings_count" | "status_code";

const METHOD_COLORS: Record<string, string> = {
  GET: "text-emerald-400 bg-emerald-400/10 border-emerald-400/20",
  POST: "text-blue-400 bg-blue-400/10 border-blue-400/20",
  PUT: "text-yellow-400 bg-yellow-400/10 border-yellow-400/20",
  PATCH: "text-orange-400 bg-orange-400/10 border-orange-400/20",
  DELETE: "text-red-400 bg-red-400/10 border-red-400/20",
};

function statusCodeStyle(code: number | null) {
  if (code === null) return "text-slate-400 bg-slate-400/10 border-slate-400/20";
  if (code < 300) return "text-emerald-400 bg-emerald-400/10 border-emerald-400/20";
  if (code < 400) return "text-blue-400 bg-blue-400/10 border-blue-400/20";
  if (code === 403) return "text-yellow-400 bg-yellow-400/10 border-yellow-400/20";
  return "text-slate-400 bg-slate-400/10 border-slate-400/20";
}

function sourceLabel(source: string) {
  const map: Record<string, string> = {
    subfinder: "subfinder",
    subfinder_fallback: "subfinder",
    httpx: "httpx",
    httpx_probe: "httpx",
    crtsh: "crt.sh",
    crt_sh: "crt.sh",
    osint: "osint",
    katana: "katana",
    burp_proxy: "burp",
    ffuf: "ffuf",
  };
  return map[source] ?? source;
}

function StatCard({
  label,
  value,
  sub,
  icon,
  color,
}: {
  label: string;
  value: number | string;
  sub?: string;
  icon: React.ReactNode;
  color?: string;
}) {
  return (
    <div className="flex-1 min-w-0 rounded-ds-md border border-pentra-border bg-pentra-bg-card px-4 py-3">
      <div className="flex items-center gap-2 text-pentra-text-muted mb-1">
        <span className="opacity-60">{icon}</span>
        <span className="text-[10px] font-semibold uppercase tracking-wider">{label}</span>
      </div>
      <div className="flex items-baseline gap-2">
        <span
          className="text-2xl font-bold text-pentra-text-primary"
          style={{ color }}
        >
          {value}
        </span>
        {sub && (
          <span className="text-xs text-pentra-text-muted">{sub}</span>
        )}
      </div>
    </div>
  );
}

function HostPortsGroup({ host, ports }: { host: string; ports: PortInfo[] }) {
  const hostPorts = ports.filter((p) => p.host === host);
  if (hostPorts.length === 0) return null;
  return (
    <div className="flex items-start gap-3 py-1.5 border-b border-pentra-border/40 last:border-0">
      <span className="font-mono text-[11px] text-pentra-text-muted w-48 flex-shrink-0 truncate">
        {host}
      </span>
      <div className="flex flex-wrap gap-1">
        {hostPorts.map((p, i) => (
          <span
            key={i}
            className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded border border-yellow-400/20 bg-yellow-400/5 text-yellow-300/80 font-mono"
            title={`${p.service}${p.version ? ` ${p.version}` : ""}`}
          >
            {p.port}/{p.protocol}
            {p.service ? ` (${p.service})` : ""}
          </span>
        ))}
      </div>
    </div>
  );
}

export function ReconSurfaceTab({ engagementId, engagementStatus }: ReconSurfaceTabProps) {
  const isActive = engagementStatus === "active" || engagementStatus === "awaiting_approval";
  const { data, isLoading, dataUpdatedAt, refetch, isFetching } = useReconState(
    engagementId,
    true
  );

  const [aliveFilter, setAliveFilter] = useState<AliveFilter>("all");
  const [search, setSearch] = useState("");
  const [sortField, setSortField] = useState<SortField>("host");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [selectedSubdomain, setSelectedSubdomain] = useState<SubdomainInfo | null>(null);
  const [showPorts, setShowPorts] = useState(false);
  const [showEndpoints, setShowEndpoints] = useState(false);

  const subdomains = useMemo(() => data?.subdomains ?? [], [data?.subdomains]);
  const ports = data?.open_ports ?? [];
  const endpoints = data?.endpoints ?? [];

  const filteredSubdomains = useMemo(() => {
    let list = [...subdomains];

    if (aliveFilter === "alive") list = list.filter((s) => s.is_alive);
    else if (aliveFilter === "dead") list = list.filter((s) => !s.is_alive);

    if (search.trim()) {
      const q = search.trim().toLowerCase();
      list = list.filter((s) => s.host.toLowerCase().includes(q));
    }

    list.sort((a, b) => {
      let av: string | number, bv: string | number;
      if (sortField === "host") { av = a.host; bv = b.host; }
      else if (sortField === "findings_count") { av = a.findings_count; bv = b.findings_count; }
      else { av = a.status_code ?? 9999; bv = b.status_code ?? 9999; }
      if (sortDir === "asc") return av < bv ? -1 : av > bv ? 1 : 0;
      return av > bv ? -1 : av < bv ? 1 : 0;
    });

    return list;
  }, [subdomains, aliveFilter, search, sortField, sortDir]);

  function toggleSort(field: SortField) {
    if (sortField === field) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortField(field); setSortDir("asc"); }
  }

  const sortIcon = (field: SortField) => {
    if (sortField !== field) return <ChevronDown className="h-3 w-3 opacity-30" />;
    return sortDir === "asc"
      ? <ChevronUp className="h-3 w-3 text-pentra-accent" />
      : <ChevronDown className="h-3 w-3 text-pentra-accent" />;
  };

  // Group ports by unique host
  const hostsWithPorts = [...new Set(ports.map((p) => p.host))];

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-pentra-text-muted gap-3">
        <Loader2 className="h-7 w-7 animate-spin opacity-40" />
        <p className="text-sm">Loading recon data…</p>
      </div>
    );
  }

  if (!data || subdomains.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-pentra-text-muted gap-3">
        <ScanLine className="h-10 w-10 opacity-20" />
        <p className="text-sm font-medium">No recon data yet</p>
        <p className="text-xs opacity-60 text-center max-w-xs">
          {isActive
            ? "Recon is running — subdomain data will appear here as hosts are discovered."
            : "Start the engagement to begin subdomain enumeration and port scanning."}
        </p>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col gap-4 overflow-hidden">
      {/* Stats bar */}
      <div className="flex gap-3 flex-shrink-0">
        <StatCard
          label="Subdomains"
          value={data.total_subdomains}
          sub={`${data.alive_count} alive`}
          icon={<Globe className="h-3.5 w-3.5" />}
          color="var(--accent)"
        />
        <StatCard
          label="Open Ports"
          value={data.total_ports}
          sub={`${hostsWithPorts.length} hosts`}
          icon={<Server className="h-3.5 w-3.5" />}
          color={data.total_ports > 0 ? "var(--high)" : undefined}
        />
        <StatCard
          label="Endpoints"
          value={data.total_endpoints}
          icon={<Link className="h-3.5 w-3.5" />}
        />
        <StatCard
          label="Technologies"
          value={data.tech_stack.length}
          icon={<Cpu className="h-3.5 w-3.5" />}
          color={data.tech_stack.length > 0 ? "var(--medium)" : undefined}
        />
      </div>

      {/* Tech tags */}
      {data.tech_stack.length > 0 && (
        <div className="flex flex-wrap gap-1.5 flex-shrink-0">
          {data.tech_stack.map((t) => (
            <span
              key={t}
              className="inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded border text-cyan-300/80 bg-cyan-400/5 border-cyan-400/20"
            >
              <Cpu className="h-2.5 w-2.5" />
              {t}
            </span>
          ))}
        </div>
      )}

      {/* Controls */}
      <div className="flex items-center gap-2 flex-shrink-0">
        {/* Alive filter */}
        <div className="flex items-center bg-pentra-bg-base border border-pentra-border rounded-md p-0.5">
          {(["all", "alive", "dead"] as AliveFilter[]).map((f) => (
            <button
              key={f}
              onClick={() => setAliveFilter(f)}
              className={cn(
                "px-3 py-1 text-xs font-medium rounded transition-colors capitalize",
                aliveFilter === f
                  ? "bg-pentra-accent/20 text-pentra-accent"
                  : "text-pentra-text-muted hover:text-pentra-text-primary"
              )}
            >
              {f === "all" ? `All (${subdomains.length})` : f === "alive" ? `Alive (${data.alive_count})` : `Dead (${subdomains.length - data.alive_count})`}
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="flex-1 relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-pentra-text-muted" />
          <input
            type="text"
            placeholder="Filter subdomains…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs rounded-md border border-pentra-border bg-pentra-bg-base text-pentra-text-primary placeholder:text-pentra-text-muted focus:outline-none focus:border-pentra-accent/60"
          />
        </div>

        {/* Refresh */}
        <button
          onClick={() => refetch()}
          disabled={isFetching}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md border border-pentra-border text-xs text-pentra-text-muted hover:text-pentra-text-primary hover:bg-pentra-bg-hover transition-colors"
        >
          <RefreshCw className={cn("h-3 w-3", isFetching && "animate-spin")} />
          {dataUpdatedAt > 0 ? new Date(dataUpdatedAt).toLocaleTimeString() : "—"}
        </button>
      </div>

      {/* Subdomain table */}
      <div className="flex-1 overflow-auto rounded-ds-md border border-pentra-border min-h-0">
        <table className="w-full text-xs border-collapse">
          <thead className="sticky top-0 z-10 bg-pentra-bg-card border-b border-pentra-border">
            <tr>
              <th className="w-6 px-2 py-2" />
              <th className="text-left px-3 py-2">
                <button
                  onClick={() => toggleSort("host")}
                  className="flex items-center gap-1 font-semibold text-[10px] uppercase tracking-wider text-pentra-text-muted hover:text-pentra-text-primary transition-colors"
                >
                  Host {sortIcon("host")}
                </button>
              </th>
              <th className="text-left px-3 py-2 font-semibold text-[10px] uppercase tracking-wider text-pentra-text-muted">
                IP
              </th>
              <th className="text-left px-3 py-2">
                <button
                  onClick={() => toggleSort("status_code")}
                  className="flex items-center gap-1 font-semibold text-[10px] uppercase tracking-wider text-pentra-text-muted hover:text-pentra-text-primary transition-colors"
                >
                  Code {sortIcon("status_code")}
                </button>
              </th>
              <th className="text-left px-3 py-2 font-semibold text-[10px] uppercase tracking-wider text-pentra-text-muted">
                Stack
              </th>
              <th className="text-left px-3 py-2 font-semibold text-[10px] uppercase tracking-wider text-pentra-text-muted">
                Source
              </th>
              <th className="text-left px-3 py-2">
                <button
                  onClick={() => toggleSort("findings_count")}
                  className="flex items-center gap-1 font-semibold text-[10px] uppercase tracking-wider text-pentra-text-muted hover:text-pentra-text-primary transition-colors"
                >
                  <Bug className="h-3 w-3" /> {sortIcon("findings_count")}
                </button>
              </th>
            </tr>
          </thead>
          <tbody>
            {filteredSubdomains.length === 0 && (
              <tr>
                <td colSpan={7} className="text-center py-12 text-pentra-text-muted text-xs">
                  No subdomains match the current filter.
                </td>
              </tr>
            )}
            {filteredSubdomains.map((sub) => (
              <tr
                key={sub.host}
                onClick={() => setSelectedSubdomain(sub)}
                className="border-b border-pentra-border/40 last:border-0 hover:bg-pentra-bg-hover cursor-pointer transition-colors group"
              >
                {/* Alive dot */}
                <td className="px-2 py-2.5">
                  <span
                    className={cn(
                      "block w-2 h-2 rounded-full mx-auto",
                      sub.is_alive
                        ? "bg-emerald-400 shadow-[0_0_4px_1px_rgba(52,211,153,0.4)]"
                        : "bg-red-400/50"
                    )}
                  />
                </td>

                {/* Host */}
                <td className="px-3 py-2.5">
                  <span className="font-mono text-pentra-text-primary group-hover:text-pentra-accent transition-colors">
                    {sub.host}
                  </span>
                </td>

                {/* IP */}
                <td className="px-3 py-2.5 font-mono text-pentra-text-muted">
                  {sub.ip || "—"}
                </td>

                {/* Status code */}
                <td className="px-3 py-2.5">
                  {sub.status_code !== null ? (
                    <span
                      className={cn(
                        "inline-block text-[10px] font-bold px-1.5 py-0.5 rounded border",
                        statusCodeStyle(sub.status_code)
                      )}
                    >
                      {sub.status_code}
                    </span>
                  ) : (
                    <span className="text-pentra-text-muted/40">—</span>
                  )}
                </td>

                {/* Tech stack */}
                <td className="px-3 py-2.5">
                  <div className="flex flex-wrap gap-1">
                    {sub.tech_stack.slice(0, 2).map((t) => (
                      <span
                        key={t}
                        className="text-[9px] px-1.5 py-0.5 rounded border border-cyan-400/20 bg-cyan-400/5 text-cyan-300/70"
                      >
                        {t}
                      </span>
                    ))}
                    {sub.tech_stack.length > 2 && (
                      <span className="text-[9px] text-pentra-text-muted">
                        +{sub.tech_stack.length - 2}
                      </span>
                    )}
                  </div>
                </td>

                {/* Source */}
                <td className="px-3 py-2.5">
                  <span className="text-[9px] text-pentra-text-muted/70 font-mono">
                    {sourceLabel(sub.source)}
                  </span>
                </td>

                {/* Findings */}
                <td className="px-3 py-2.5">
                  {sub.findings_count > 0 ? (
                    <span className="inline-flex items-center gap-0.5 text-[10px] font-bold px-1.5 py-0.5 rounded border text-red-400 bg-red-400/10 border-red-400/30">
                      <Bug className="h-2.5 w-2.5" />
                      {sub.findings_count}
                    </span>
                  ) : (
                    <span className="text-pentra-text-muted/30 text-[10px]">—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Ports section (collapsible) */}
      {ports.length > 0 && (
        <div className="flex-shrink-0 border border-pentra-border rounded-ds-md overflow-hidden">
          <button
            onClick={() => setShowPorts((v) => !v)}
            className="w-full flex items-center gap-2 px-4 py-2.5 bg-pentra-bg-card hover:bg-pentra-bg-hover transition-colors text-left"
          >
            <Network className="h-3.5 w-3.5 text-yellow-400" />
            <span className="text-xs font-semibold text-pentra-text-primary">
              Open Ports
            </span>
            <span className="text-[10px] text-pentra-text-muted">
              {data.total_ports} port{data.total_ports !== 1 ? "s" : ""} across {hostsWithPorts.length} host{hostsWithPorts.length !== 1 ? "s" : ""}
            </span>
            <span className="ml-auto">
              {showPorts
                ? <ChevronUp className="h-3.5 w-3.5 text-pentra-text-muted" />
                : <ChevronDown className="h-3.5 w-3.5 text-pentra-text-muted" />}
            </span>
          </button>
          {showPorts && (
            <div className="px-4 py-2 bg-pentra-bg-base border-t border-pentra-border max-h-40 overflow-y-auto">
              {hostsWithPorts.map((host) => (
                <HostPortsGroup key={host} host={host} ports={ports} />
              ))}
            </div>
          )}
        </div>
      )}

      {/* Endpoints section (collapsible) */}
      {endpoints.length > 0 && (
        <div className="flex-shrink-0 border border-pentra-border rounded-ds-md overflow-hidden">
          <button
            onClick={() => setShowEndpoints((v) => !v)}
            className="w-full flex items-center gap-2 px-4 py-2.5 bg-pentra-bg-card hover:bg-pentra-bg-hover transition-colors text-left"
          >
            <Link className="h-3.5 w-3.5 text-blue-400" />
            <span className="text-xs font-semibold text-pentra-text-primary">
              Discovered Endpoints
            </span>
            <span className="text-[10px] text-pentra-text-muted">
              {data.total_endpoints} endpoint{data.total_endpoints !== 1 ? "s" : ""}
            </span>
            <span className="ml-auto">
              {showEndpoints
                ? <ChevronUp className="h-3.5 w-3.5 text-pentra-text-muted" />
                : <ChevronDown className="h-3.5 w-3.5 text-pentra-text-muted" />}
            </span>
          </button>
          {showEndpoints && (
            <div className="border-t border-pentra-border max-h-48 overflow-y-auto">
              <table className="w-full text-[11px] border-collapse">
                <tbody>
                  {endpoints.map((ep, i) => (
                    <tr key={i} className="border-b border-pentra-border/30 last:border-0 hover:bg-pentra-bg-hover">
                      <td className="px-3 py-1.5 w-14">
                        <span
                          className={cn(
                            "text-[9px] font-bold px-1.5 py-0.5 rounded border",
                            METHOD_COLORS[ep.method] ?? "text-slate-400 bg-slate-400/10 border-slate-400/20"
                          )}
                        >
                          {ep.method}
                        </span>
                      </td>
                      <td className="px-2 py-1.5 font-mono text-pentra-text-primary truncate max-w-xs">
                        {ep.url}
                      </td>
                      <td className="px-3 py-1.5 text-pentra-text-muted/60 text-[9px]">
                        {ep.source}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Subdomain detail panel */}
      {selectedSubdomain && (
        <SubdomainDetailPanel
          engagementId={engagementId}
          subdomain={selectedSubdomain}
          allPorts={ports}
          allEndpoints={endpoints}
          onClose={() => setSelectedSubdomain(null)}
        />
      )}
    </div>
  );
}
