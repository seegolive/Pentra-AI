import { useState, useMemo } from "react";
import { X, Map as MapIcon, Info } from "lucide-react";
import { cn } from "../lib/utils";
import { useEngagements, useFindings } from "../lib/api";
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

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

function highestSeverity(findings: Finding[]): Severity {
  for (const sev of SEVERITY_ORDER) {
    if (findings.some((f) => f.severity === sev)) return sev;
  }
  return "info";
}

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
  info: "var(--info)",
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
  x: number;
  y: number;
  r: number;
}

function layoutNodes(domains: Map<string, Finding[]>, width: number, height: number): DomainNode[] {
  const entries = Array.from(domains.entries());
  const n = entries.length;
  if (n === 0) return [];

  const nodes: DomainNode[] = entries.map(([domain, findings], i) => {
    const angle = (i / n) * 2 * Math.PI - Math.PI / 2;
    const radius = Math.min(width, height) * 0.32;
    const x = width / 2 + radius * Math.cos(angle);
    const y = height / 2 + radius * Math.sin(angle);
    const r = Math.min(40, Math.max(20, 20 + findings.length * 3));
    return { domain, findings, severity: highestSeverity(findings), x, y, r };
  });

  return nodes;
}

// ── Detail Panel ─────────────────────────────────────────────────────────────

function DetailPanel({
  node,
  onClose,
}: {
  node: DomainNode;
  onClose: () => void;
}) {
  return (
    <div className="absolute right-0 top-0 h-full w-72 border-l border-pentra-border bg-pentra-bg-panel overflow-y-auto">
      <div className="flex items-center justify-between border-b border-pentra-border px-4 py-3">
        <h3 className="text-[13px] font-semibold text-pentra-text-primary truncate">{node.domain}</h3>
        <button
          type="button"
          onClick={onClose}
          className="flex h-6 w-6 items-center justify-center rounded-ds-sm text-pentra-text-muted hover:bg-pentra-bg-hover hover:text-pentra-text-secondary"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>

      <div className="p-3 space-y-2">
        <p className="text-[11px] text-pentra-text-muted">{node.findings.length} finding(s)</p>

        {node.findings.map((f) => (
          <div
            key={f.id}
            className="rounded-ds-md border border-pentra-border bg-pentra-bg-card p-2.5 space-y-1"
          >
            <div className="flex items-start gap-2">
              <span
                className={cn("text-[10px] font-bold uppercase", SEVERITY_LABEL_COLOR[f.severity])}
              >
                {f.severity}
              </span>
              <p className="text-[12px] font-medium text-pentra-text-primary flex-1 leading-snug">{f.title}</p>
            </div>
            <p className="text-[10px] font-mono text-pentra-text-muted truncate">{f.target_url}</p>
          </div>
        ))}

        <div className="pt-2">
          <button
            type="button"
            disabled
            title="Coming soon"
            className="w-full rounded-ds-md border border-pentra-border py-2 text-[12px] text-pentra-text-muted cursor-not-allowed opacity-50"
          >
            Run Subscan (Coming soon)
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Attack Surface Canvas ─────────────────────────────────────────────────────

function AttackSurfaceCanvas({
  findings,
}: {
  findings: Finding[];
}) {
  const [selectedDomain, setSelectedDomain] = useState<string | null>(null);

  const domainMap = useMemo(() => {
    const m: Map<string, Finding[]> = new Map();
    for (const f of findings) {
      const d = extractBaseDomain(f.target_url);
      if (!m.has(d)) m.set(d, []);
      m.get(d)!.push(f);
    }
    return m;
  }, [findings]);

  const W = 700;
  const H = 480;
  const nodes = useMemo(() => layoutNodes(domainMap, W, H), [domainMap]);

  const selectedNode = nodes.find((n) => n.domain === selectedDomain) ?? null;

  return (
    <div className="relative flex-1 overflow-hidden rounded-ds-lg border border-pentra-border bg-pentra-bg-card">
      {/* Dot grid background via inline style */}
      <div
        className="absolute inset-0"
        style={{
          backgroundImage: "radial-gradient(circle, var(--border) 1px, transparent 1px)",
          backgroundSize: "24px 24px",
        }}
      />

      {/* SVG Canvas */}
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="relative h-full w-full"
        style={{ maxHeight: "100%" }}
      >
        {/* Lines between adjacent nodes */}
        {nodes.map((a, i) =>
          nodes.slice(i + 1).map((b) => (
            <line
              key={`${a.domain}-${b.domain}`}
              x1={a.x}
              y1={a.y}
              x2={b.x}
              y2={b.y}
              stroke="var(--border-light)"
              strokeWidth={1}
              strokeDasharray="4 4"
              opacity={0.5}
            />
          ))
        )}

        {/* Nodes */}
        {nodes.map((node) => (
          <g
            key={node.domain}
            onClick={() => setSelectedDomain(node.domain === selectedDomain ? null : node.domain)}
            className="cursor-pointer"
          >
            <circle
              cx={node.x}
              cy={node.y}
              r={node.r + 4}
              fill={SEVERITY_COLOR[node.severity]}
              opacity={node.domain === selectedDomain ? 0.25 : 0.1}
            />
            <circle
              cx={node.x}
              cy={node.y}
              r={node.r}
              fill={SEVERITY_COLOR[node.severity]}
              opacity={0.8}
              stroke={node.domain === selectedDomain ? "white" : "transparent"}
              strokeWidth={2}
            />
            <text
              x={node.x}
              y={node.y + node.r + 14}
              textAnchor="middle"
              fill="var(--text-secondary)"
              fontSize={10}
              className="select-none"
            >
              {node.domain}
            </text>
            <text
              x={node.x}
              y={node.y + 4}
              textAnchor="middle"
              fill="white"
              fontSize={11}
              fontWeight="bold"
              className="select-none"
            >
              {node.findings.length}
            </text>
          </g>
        ))}
      </svg>

      {/* Detail Panel */}
      {selectedNode && (
        <DetailPanel node={selectedNode} onClose={() => setSelectedDomain(null)} />
      )}

      {/* Legend */}
      <div className="absolute bottom-3 left-3 flex items-center gap-3 rounded-ds-md border border-pentra-border bg-pentra-bg-panel/90 px-3 py-1.5 backdrop-blur-sm">
        {SEVERITY_ORDER.slice(0, 4).map((sev) => (
          <div key={sev} className="flex items-center gap-1">
            <div
              className="h-2.5 w-2.5 rounded-full"
              style={{ background: SEVERITY_COLOR[sev] }}
            />
            <span className="text-[10px] capitalize text-pentra-text-muted">{sev}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────

function AttackSurfaceContent({ engagementId }: { engagementId: string }) {
  const { data: findings = [], isLoading } = useFindings(engagementId);

  if (isLoading) {
    return (
      <div className="flex flex-1 items-center justify-center text-pentra-text-muted text-[13px]">
        Loading findings...
      </div>
    );
  }

  if (findings.length === 0) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-3 text-pentra-text-muted">
        <Info className="h-10 w-10 opacity-30" />
        <p className="text-[13px]">No findings for this engagement yet.</p>
      </div>
    );
  }

  return <AttackSurfaceCanvas findings={findings} />;
}

export default function AttackSurfacePage() {
  const { data: engagements = [] } = useEngagements();
  const [selectedId, setSelectedId] = useState<string>("");

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
          <option value="">Select engagement...</option>
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
            <p className="text-[13px] text-pentra-text-muted">Select an engagement to explore attack surface</p>
          </div>
        ) : (
          <AttackSurfaceContent engagementId={selectedId} />
        )}
      </div>
    </div>
  );
}
