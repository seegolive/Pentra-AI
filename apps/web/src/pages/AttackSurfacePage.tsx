import { useState, useMemo, useEffect } from "react";
import { useSearchParams, Link } from "react-router-dom";
import { X, Map as MapIcon, Info, RefreshCw } from "lucide-react";
import { cn } from "../lib/utils";
import { useEngagements, useEngagement, useFindings, useReconSnapshots, useSubscan } from "../lib/api";
import type { SubdomainInfo } from "../lib/api";
import type { Finding, Severity } from "../lib/types";

// ── Helpers ─────────────────────────────────────────────────────────────────

function extractBaseDomain(url: string): string {
  try {
    const u = new URL(url.startsWith("http") ? url : `https://${url}`);
    return u.hostname;
  } catch {
    return url.split("/")[0] || url;
  }
}

function nodeLabel(domain: string, isRoot: boolean): string {
  if (isRoot) {
    return domain.length > 12 ? domain.slice(0, 11) + "…" : domain;
  }
  // Show only the first segment so labels don't overlap in dense rings
  // e.g. "api.target.com" → "api", "staging.internal.example.com" → "staging"
  const first = domain.split(".")[0];
  return first.length > 10 ? first.slice(0, 9) + "…" : first;
}

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

function highestSeverity(findings: Finding[]): Severity {
  for (const sev of SEVERITY_ORDER) {
    if (findings.some((f) => f.severity === sev)) return sev;
  }
  return "info";
}

const SEVERITY_COLOR: Record<Severity | "root" | "clean", string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
  info: "var(--info)",
  root: "var(--accent)",
  clean: "#6b7280",
};

const SEVERITY_LABEL_COLOR: Record<Severity, string> = {
  critical: "text-pentra-severity-critical",
  high: "text-pentra-severity-high",
  medium: "text-pentra-severity-medium",
  low: "text-pentra-severity-low",
  info: "text-pentra-severity-info",
};

// ── Node Layout ──────────────────────────────────────────────────────────────

interface DomainNode {
  domain: string;
  findings: Finding[];
  severity: Severity;
  isRoot: boolean;
  x: number;
  y: number;
  r: number;
  color: string;
  showLabel: boolean;
}

interface RingMeta {
  label: string;
  radius: number;
}

function layoutNodes(
  domainMap: Map<string, Finding[]>,
  rootDomains: Set<string>,
  width: number,
  height: number,
  showAll: boolean,
): { nodes: DomainNode[]; rings: RingMeta[] } {
  const entries = Array.from(domainMap.entries());
  const roots = entries.filter(([d]) => rootDomains.has(d));
  const allNonRoot = entries.filter(([d]) => !rootDomains.has(d));

  const withFindings = allNonRoot.filter(([, f]) => f.length > 0);
  const clean = allNonRoot.filter(([, f]) => f.length === 0);
  const peripheral = showAll ? allNonRoot : withFindings;

  const nodes: DomainNode[] = [];
  const rings: RingMeta[] = [];
  const maxRadius = Math.min(width / 2, height / 2) - 52;

  // Root nodes — center cluster
  roots.forEach(([domain, findings], i) => {
    const angle = roots.length > 1 ? (i / roots.length) * 2 * Math.PI : 0;
    const r = Math.min(40, Math.max(22, 22 + findings.length * 3));
    nodes.push({
      domain, findings,
      severity: highestSeverity(findings),
      isRoot: true,
      x: width / 2 + (roots.length > 1 ? 40 * Math.cos(angle) : 0),
      y: height / 2 + (roots.length > 1 ? 40 * Math.sin(angle) : 0),
      r, color: SEVERITY_COLOR.root, showLabel: true,
    });
  });

  // Place a ring of nodes at the given radius, adapting node size to available arc space
  function placeRing(ringEntries: [string, Finding[]][], ringRadius: number) {
    const n = ringEntries.length;
    if (n === 0) return;
    const arcSpacing = (2 * Math.PI * ringRadius) / n;
    const showLabel = arcSpacing >= 28;

    ringEntries.forEach(([domain, findings], i) => {
      const angle = (i / n) * 2 * Math.PI - Math.PI / 2;
      const sev = highestSeverity(findings);
      // Shrink nodes to guarantee no circle overlap regardless of count
      const maxR = Math.max(6, Math.min(36, arcSpacing / 2 - 3));
      const r = findings.length > 0
        ? Math.min(maxR, Math.max(6, 6 + findings.length * 2))
        : Math.min(8, maxR);
      nodes.push({
        domain, findings, severity: sev, isRoot: false,
        x: width / 2 + ringRadius * Math.cos(angle),
        y: height / 2 + ringRadius * Math.sin(angle),
        r, showLabel,
        color: findings.length > 0 ? SEVERITY_COLOR[sev] : SEVERITY_COLOR.clean,
      });
    });
  }

  if (showAll && clean.length > 0 && withFindings.length > 0) {
    // Two rings: inner = hosts with findings, outer = clean hosts
    const innerMin = (withFindings.length * 44) / (2 * Math.PI);
    const innerRadius = Math.min(maxRadius * 0.56, Math.max(120, innerMin));

    const outerMin = (clean.length * 30) / (2 * Math.PI);
    const outerRadius = Math.min(maxRadius, Math.max(innerRadius + 52, innerRadius + outerMin));

    placeRing(withFindings, innerRadius);
    placeRing(clean, outerRadius);
    rings.push({ label: "with findings", radius: innerRadius });
    rings.push({ label: "clean hosts", radius: outerRadius });
  } else {
    // Single ring — expand radius so nodes don't overlap, capped to viewBox
    const n = peripheral.length;
    const minRadius = (n * 44) / (2 * Math.PI);
    const defaultRadius = Math.min(width, height) * (roots.length > 0 ? 0.35 : 0.32);
    const ringRadius = Math.min(maxRadius, Math.max(defaultRadius, minRadius));
    placeRing(peripheral, ringRadius);
  }

  return { nodes, rings };
}

// ── Detail Panel ─────────────────────────────────────────────────────────────

function DetailPanel({
  node,
  engagementId,
  onClose,
}: {
  node: DomainNode;
  engagementId: string;
  onClose: () => void;
}) {
  const subscan = useSubscan(engagementId);
  const [scanDone, setScanDone] = useState(false);

  function handleSubscan() {
    subscan.mutate(
      { target_urls: [node.domain] },
      {
        onSuccess: () => setScanDone(true),
        onError: () => setScanDone(false),
      }
    );
  }

  return (
    <div className="absolute right-0 top-0 h-full w-72 border-l border-pentra-border bg-pentra-bg-panel overflow-y-auto">
      <div className="flex items-center justify-between border-b border-pentra-border px-4 py-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5">
            {node.isRoot && (
              <span className="text-[9px] font-bold uppercase tracking-wider text-pentra-accent bg-pentra-accent/10 px-1.5 py-0.5 rounded-sm">
                root
              </span>
            )}
            <h3 className="text-[13px] font-semibold text-pentra-text-primary truncate">
              {node.domain}
            </h3>
          </div>
          <p className="text-[10px] text-pentra-text-muted mt-0.5">
            {node.findings.length} finding{node.findings.length !== 1 ? "s" : ""}
          </p>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="flex h-6 w-6 flex-shrink-0 items-center justify-center rounded-ds-sm text-pentra-text-muted hover:bg-pentra-bg-hover hover:text-pentra-text-secondary"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>

      <div className="p-3 space-y-2">
        {node.findings.length === 0 ? (
          <p className="text-[12px] text-pentra-text-muted italic">No findings on this host yet.</p>
        ) : (
          node.findings.map((f) => (
            <Link
              key={f.id}
              to={`/engagements/${f.engagement_id}`}
              className="block rounded-ds-md border border-pentra-border bg-pentra-bg-card p-2.5 space-y-1 transition-colors hover:border-pentra-border-focus hover:bg-pentra-bg-hover"
            >
              <div className="flex items-start gap-2">
                <span
                  className={cn("text-[10px] font-bold uppercase shrink-0", SEVERITY_LABEL_COLOR[f.severity])}
                >
                  {f.severity}
                </span>
                <p className="text-[12px] font-medium text-pentra-text-primary flex-1 leading-snug line-clamp-2">
                  {f.title}
                </p>
              </div>
              <p className="text-[10px] font-mono text-pentra-text-muted truncate">{f.target_url}</p>
              {f.vuln_class && (
                <p className="text-[10px] text-pentra-text-muted">{f.vuln_class}</p>
              )}
            </Link>
          ))
        )}

        <div className="pt-2">
          {scanDone ? (
            <div className="w-full rounded-ds-md border border-pentra-border py-2 text-[12px] text-center text-pentra-severity-low">
              Subscan queued ✓
            </div>
          ) : (
            <button
              type="button"
              onClick={handleSubscan}
              disabled={subscan.isPending}
              className={cn(
                "flex w-full items-center justify-center gap-2 rounded-ds-md border py-2 text-[12px] transition-colors",
                subscan.isPending
                  ? "border-pentra-border text-pentra-text-muted cursor-not-allowed opacity-60"
                  : "border-pentra-accent/40 text-pentra-accent hover:bg-pentra-accent/10"
              )}
            >
              <RefreshCw className={cn("h-3.5 w-3.5", subscan.isPending && "animate-spin")} />
              {subscan.isPending ? "Queuing…" : `Run Subscan on ${node.domain}`}
            </button>
          )}
          {subscan.isError && (
            <p className="mt-1 text-[10px] text-pentra-severity-critical text-center">
              Subscan endpoint not available
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Attack Surface Canvas ─────────────────────────────────────────────────────

function AttackSurfaceCanvas({
  findings,
  subdomains,
  rootDomains,
  engagementId,
}: {
  findings: Finding[];
  subdomains: SubdomainInfo[];
  rootDomains: string[];
  engagementId: string;
}) {
  const [selectedDomain, setSelectedDomain] = useState<string | null>(null);
  const [showAll, setShowAll] = useState(false);

  // Close detail panel and reset mode when switching engagements
  useEffect(() => {
    setSelectedDomain(null);
    setShowAll(false);
  }, [engagementId]);

  const rootSet = useMemo(() => new Set(rootDomains.map(extractBaseDomain)), [rootDomains]);

  const domainMap = useMemo(() => {
    const m: Map<string, Finding[]> = new Map();

    // Seed all recon subdomains (with empty findings arrays)
    for (const sub of subdomains) {
      const d = extractBaseDomain(sub.host);
      if (d && !m.has(d)) m.set(d, []);
    }

    // Seed root domains
    for (const root of rootDomains) {
      const d = extractBaseDomain(root);
      if (d && !m.has(d)) m.set(d, []);
    }

    // Populate findings
    for (const f of findings) {
      const d = extractBaseDomain(f.target_url);
      if (!m.has(d)) m.set(d, []);
      m.get(d)!.push(f);
    }

    return m;
  }, [findings, subdomains, rootDomains]);

  const cleanCount = useMemo(() => {
    let count = 0;
    for (const [domain, f] of domainMap.entries()) {
      if (!rootSet.has(domain) && f.length === 0) count++;
    }
    return count;
  }, [domainMap, rootSet]);

  const W = 700;
  const H = 480;
  const { nodes, rings } = useMemo(
    () => layoutNodes(domainMap, rootSet, W, H, showAll),
    [domainMap, rootSet, showAll],
  );

  const selectedNode = nodes.find((n) => n.domain === selectedDomain) ?? null;

  return (
    <div className="relative flex-1 overflow-hidden rounded-ds-lg border border-pentra-border bg-pentra-bg-card">
      {/* Dot grid background */}
      <div
        className="absolute inset-0"
        style={{
          backgroundImage: "radial-gradient(circle, var(--border) 1px, transparent 1px)",
          backgroundSize: "24px 24px",
        }}
      />

      {/* Stats badge — pointer-events-none so SVG nodes below remain clickable */}
      <div className="pointer-events-none absolute top-3 left-3 z-10 flex items-center gap-2 rounded-ds-md border border-pentra-border bg-pentra-bg-panel/90 px-3 py-1.5 backdrop-blur-sm">
        <span className="text-[11px] text-pentra-text-secondary">
          <span className="font-semibold text-pentra-text-primary">{nodes.length}</span> hosts ·{" "}
          <span className="font-semibold text-pentra-text-primary">{findings.length}</span> findings
        </span>
      </div>

      {/* Mode toggle — only shown when there are clean hosts to hide/show */}
      {cleanCount > 0 && (
        <button
          type="button"
          onClick={() => setShowAll((v) => !v)}
          className="absolute top-3 right-3 z-10 flex items-center gap-1.5 rounded-ds-md border border-pentra-border bg-pentra-bg-panel/90 px-3 py-1.5 backdrop-blur-sm text-[11px] text-pentra-text-secondary transition-colors hover:border-pentra-border-focus hover:text-pentra-text-primary"
        >
          {showAll ? (
            <><span className="text-pentra-accent text-[8px]">●</span> Findings only</>
          ) : (
            <>+ {cleanCount} clean hosts</>
          )}
        </button>
      )}

      {/* SVG Canvas — right edge shrinks when detail panel is open so no nodes are blocked */}
      <div className={cn("absolute inset-0", selectedNode && "right-72")}>
        <svg
          viewBox={`0 0 ${W} ${H}`}
          className="h-full w-full"
          style={{ maxHeight: "100%" }}
        >
        {/* Ring labels — shown in multi-ring mode */}
        {rings.map((ring) => (
          <text
            key={ring.label}
            x={W / 2}
            y={H / 2 - ring.radius - 8}
            textAnchor="middle"
            fill="var(--text-muted)"
            fontSize={8}
            letterSpacing={1}
            className="select-none uppercase"
          >
            {ring.label}
          </text>
        ))}

        {/* Lines: peripheral → nearest root */}
        {nodes
          .filter((n) => !n.isRoot)
          .map((b) => {
            const root = nodes
              .filter((n) => n.isRoot)
              .reduce<DomainNode | null>((closest, r) => {
                if (!closest) return r;
                const dClosest = Math.hypot(b.x - closest.x, b.y - closest.y);
                const dR = Math.hypot(b.x - r.x, b.y - r.y);
                return dR < dClosest ? r : closest;
              }, null);
            if (!root) return null;
            return (
              <line
                key={`line-${b.domain}`}
                x1={root.x}
                y1={root.y}
                x2={b.x}
                y2={b.y}
                stroke="var(--border-light)"
                strokeWidth={1}
                strokeDasharray="4 4"
                opacity={0.4}
              />
            );
          })}

        {/* Nodes */}
        {nodes.map((node) => (
          <g
            key={node.domain}
            onClick={() => setSelectedDomain(node.domain === selectedDomain ? null : node.domain)}
            className="cursor-pointer group"
          >
            {/* Native browser tooltip — full domain name always visible on hover */}
            <title>{node.domain}{node.findings.length > 0 ? ` · ${node.findings.length} finding${node.findings.length !== 1 ? "s" : ""}` : " · clean"}</title>
            {/* Glow halo — expands on hover */}
            <circle
              cx={node.x}
              cy={node.y}
              r={node.r + 6}
              fill={node.color}
              opacity={node.domain === selectedDomain ? 0.3 : node.isRoot ? 0.15 : 0.08}
              className="transition-all duration-150 group-hover:opacity-30"
            />
            {/* Main circle — brightens on hover */}
            <circle
              cx={node.x}
              cy={node.y}
              r={node.r}
              fill={node.color}
              opacity={0.85}
              stroke={node.domain === selectedDomain ? "white" : node.isRoot ? "rgba(255,255,255,0.4)" : "transparent"}
              strokeWidth={node.isRoot ? 2 : 1.5}
              className="transition-all duration-150 group-hover:opacity-100 group-hover:stroke-white group-hover:[stroke-width:1.5]"
            />
            {/* Finding count or root indicator */}
            <text
              x={node.x}
              y={node.y + 4}
              textAnchor="middle"
              fill="white"
              fontSize={node.isRoot ? 10 : 11}
              fontWeight="bold"
              className="select-none"
            >
              {node.isRoot ? "●" : node.findings.length > 0 ? node.findings.length : "·"}
            </text>
            {/* Domain label — hidden when nodes are too dense */}
            {node.showLabel && (
              <text
                x={node.x}
                y={node.y + node.r + 14}
                textAnchor="middle"
                fill="var(--text-secondary)"
                fontSize={9}
                className="select-none"
              >
                {nodeLabel(node.domain, node.isRoot)}
              </text>
            )}
          </g>
        ))}
        </svg>
      </div>

      {/* Detail Panel */}
      {selectedNode && (
        <DetailPanel
          node={selectedNode}
          engagementId={engagementId}
          onClose={() => setSelectedDomain(null)}
        />
      )}

      {/* Legend — pointer-events-none so SVG nodes below remain clickable */}
      <div className="pointer-events-none absolute bottom-3 left-3 flex items-center gap-3 rounded-ds-md border border-pentra-border bg-pentra-bg-panel/90 px-3 py-1.5 backdrop-blur-sm">
        <div className="flex items-center gap-1">
          <div className="h-2.5 w-2.5 rounded-full" style={{ background: SEVERITY_COLOR.root }} />
          <span className="text-[10px] text-pentra-text-muted">root</span>
        </div>
        {(["critical", "high", "medium", "low"] as const).map((sev) => (
          <div key={sev} className="flex items-center gap-1">
            <div className="h-2.5 w-2.5 rounded-full" style={{ background: SEVERITY_COLOR[sev] }} />
            <span className="text-[10px] capitalize text-pentra-text-muted">{sev}</span>
          </div>
        ))}
        <div className="flex items-center gap-1">
          <div className="h-2.5 w-2.5 rounded-full" style={{ background: SEVERITY_COLOR.clean }} />
          <span className="text-[10px] text-pentra-text-muted">clean</span>
        </div>
      </div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────

function AttackSurfaceContent({ engagementId }: { engagementId: string }) {
  const { data: engagement, isLoading: engLoading } = useEngagement(engagementId);
  const { data: findings = [], isLoading: findingsLoading } = useFindings(engagementId);
  const { data: snapshots = [], isLoading: snapLoading } = useReconSnapshots(engagementId, 1);

  const isLoading = engLoading || findingsLoading || snapLoading;

  if (isLoading) {
    return (
      <div className="flex flex-1 items-center justify-center text-pentra-text-muted text-[13px] gap-2">
        <RefreshCw className="h-4 w-4 animate-spin" />
        Loading attack surface…
      </div>
    );
  }

  // Latest snapshot subdomains
  const latestSnapshot = snapshots[0] ?? null;
  const subdomains = latestSnapshot?.subdomains ?? [];

  // Root domains from engagement scope
  const rootDomains = engagement?.in_scope ?? [];

  const hasData = findings.length > 0 || subdomains.length > 0 || rootDomains.length > 0;

  if (!hasData) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-3 rounded-ds-lg border border-pentra-border bg-pentra-bg-card text-pentra-text-muted">
        <Info className="h-10 w-10 opacity-30" />
        <p className="text-[13px]">No recon data yet — start the engagement to populate the map.</p>
      </div>
    );
  }

  return (
    <AttackSurfaceCanvas
      findings={findings}
      subdomains={subdomains}
      rootDomains={rootDomains}
      engagementId={engagementId}
    />
  );
}

export default function AttackSurfacePage() {
  const { data: engagements = [] } = useEngagements();
  const [sp, setSp] = useSearchParams();
  const selectedId = sp.get("engagement_id") ?? "";

  function setSelectedId(id: string) {
    const next = new URLSearchParams(sp);
    if (id) next.set("engagement_id", id);
    else next.delete("engagement_id");
    setSp(next, { replace: true });
  }

  return (
    <div className="flex min-h-full flex-col gap-4 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-[20px] font-bold text-pentra-text-primary flex items-center gap-2">
            <MapIcon className="h-5 w-5 text-pentra-accent" />
            Attack Surface
          </h1>
          <p className="text-[13px] text-pentra-text-secondary mt-0.5">
            Visual map of discovered domains and findings
          </p>
        </div>

        <select
          value={selectedId}
          onChange={(e) => setSelectedId(e.target.value)}
          className="rounded-ds-md border border-pentra-border bg-pentra-bg-input px-3 py-2 text-[13px] text-pentra-text-primary outline-none focus:border-pentra-border-focus min-w-[220px]"
        >
          <option value="">Select engagement…</option>
          {engagements.map((eng) => (
            <option key={eng.id} value={eng.id}>
              {eng.name}
            </option>
          ))}
        </select>
      </div>

      {/* Canvas */}
      <div className="flex flex-1">
        {!selectedId ? (
          <div className="flex flex-1 flex-col items-center justify-center gap-3 rounded-ds-lg border border-pentra-border bg-pentra-bg-card">
            <MapIcon className="h-12 w-12 text-pentra-text-muted opacity-30" />
            <p className="text-[13px] text-pentra-text-muted">
              Select an engagement to explore attack surface
            </p>
          </div>
        ) : (
          <AttackSurfaceContent engagementId={selectedId} />
        )}
      </div>
    </div>
  );
}
