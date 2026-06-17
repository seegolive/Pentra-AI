import { useMemo } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  ResponsiveContainer,
  Cell,
} from "recharts";
import { BarChart2 } from "lucide-react";
import { useEngagements, useFindings } from "../lib/api";
import type { Engagement, Finding } from "../lib/types";

// ── Severity colors (match CSS vars) ────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  critical: "#ff3b5c",
  high: "#ff7b2f",
  medium: "#f5c542",
  low: "#4caf94",
  info: "#4d9fff",
};

// ── KPI Card ──────────────────────────────────────────────────────────────────

function KpiCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="flex flex-col gap-1 rounded-ds-md border border-pentra-border bg-pentra-bg-card p-4">
      <p className="text-[11px] font-semibold uppercase tracking-wider text-pentra-text-muted">{label}</p>
      <p className="text-[28px] font-bold text-pentra-text-primary leading-none">{value}</p>
      {sub && <p className="text-[11px] text-pentra-text-muted">{sub}</p>}
    </div>
  );
}

// ── Custom tooltip ────────────────────────────────────────────────────────────

interface TooltipProps {
  active?: boolean;
  payload?: Array<{ name: string; value: number; color: string }>;
  label?: string;
}

function CustomTooltip({ active, payload, label }: TooltipProps) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-ds-md border border-pentra-border bg-pentra-bg-panel px-3 py-2 shadow-xl">
      <p className="text-[12px] font-semibold text-pentra-text-primary mb-1">{label}</p>
      {payload.map((entry) => (
        <p key={entry.name} className="text-[11px]" style={{ color: entry.color }}>
          {entry.name}: {entry.value}
        </p>
      ))}
    </div>
  );
}

// ── Per-engagement findings loader ────────────────────────────────────────────
// We load findings lazily per engagement. Render one component per completed eng.

function EngagementFindingsLoader({
  engagement,
  onData,
}: {
  engagement: Engagement;
  onData: (id: string, findings: Finding[]) => void;
}) {
  const { data } = useFindings(engagement.id);
  useMemo(() => {
    if (data) onData(engagement.id, data);
  }, [data, engagement.id, onData]);
  return null;
}

// ── Main Chart Components ─────────────────────────────────────────────────────

interface FindingsMap {
  [engagementId: string]: Finding[];
}

function StackedSeverityChart({
  engagements,
  findingsMap,
}: {
  engagements: Engagement[];
  findingsMap: FindingsMap;
}) {
  const data = engagements.slice(-10).map((eng) => {
    const findings = findingsMap[eng.id] ?? [];
    return {
      name: eng.name.length > 12 ? eng.name.slice(0, 12) + "…" : eng.name,
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
      info: findings.filter((f) => f.severity === "info").length,
    };
  });

  return (
    <div className="rounded-ds-md border border-pentra-border bg-pentra-bg-card p-4">
      <h3 className="text-[13px] font-semibold text-pentra-text-primary mb-4">
        Findings by Severity (last 10 engagements)
      </h3>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={data} margin={{ top: 4, right: 8, bottom: 4, left: 0 }}>
          <XAxis
            dataKey="name"
            tick={{ fill: "var(--text-muted)", fontSize: 10 }}
            axisLine={{ stroke: "var(--border)" }}
            tickLine={false}
          />
          <YAxis
            tick={{ fill: "var(--text-muted)", fontSize: 10 }}
            axisLine={false}
            tickLine={false}
            allowDecimals={false}
          />
          <Tooltip content={<CustomTooltip />} cursor={{ fill: "var(--bg-hover)" }} />
          <Legend
            wrapperStyle={{ fontSize: 11, color: "var(--text-secondary)" }}
            iconSize={10}
          />
          {(["critical", "high", "medium", "low", "info"] as const).map((sev) => (
            <Bar key={sev} dataKey={sev} stackId="a" fill={SEV_COLOR[sev]} maxBarSize={32} />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function VulnClassChart({ findings }: { findings: Finding[] }) {
  // Top 10 vuln classes
  const classCounts: Record<string, number> = {};
  for (const f of findings) {
    classCounts[f.vuln_class] = (classCounts[f.vuln_class] ?? 0) + 1;
  }

  const data = Object.entries(classCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([name, count]) => ({ name, count }));

  return (
    <div className="rounded-ds-md border border-pentra-border bg-pentra-bg-card p-4">
      <h3 className="text-[13px] font-semibold text-pentra-text-primary mb-4">
        Top Vulnerability Classes
      </h3>
      {data.length === 0 ? (
        <div className="flex h-[220px] items-center justify-center text-[13px] text-pentra-text-muted">
          No findings data
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={220}>
          <BarChart
            layout="vertical"
            data={data}
            margin={{ top: 0, right: 8, bottom: 0, left: 60 }}
          >
            <XAxis
              type="number"
              tick={{ fill: "var(--text-muted)", fontSize: 10 }}
              axisLine={false}
              tickLine={false}
              allowDecimals={false}
            />
            <YAxis
              type="category"
              dataKey="name"
              width={60}
              tick={{ fill: "var(--text-secondary)", fontSize: 10 }}
              axisLine={{ stroke: "var(--border)" }}
              tickLine={false}
            />
            <Tooltip content={<CustomTooltip />} cursor={{ fill: "var(--bg-hover)" }} />
            <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={16}>
              {data.map((_, i) => (
                <Cell
                  key={i}
                  fill={Object.values(SEV_COLOR)[i % Object.values(SEV_COLOR).length]}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function TrendsPage() {
  const { data: allEngagements = [] } = useEngagements();

  // Only load findings for completed engagements, capped at 10
  const completedEngagements = useMemo(
    () => allEngagements.filter((e) => e.status === "completed").slice(-10),
    [allEngagements]
  );

  const [findingsMap, setFindingsMap] = useMemo(() => {
    const map: FindingsMap = {};
    const setter = (id: string, findings: Finding[]) => {
      map[id] = findings;
    };
    return [map, setter] as const;
  }, []);

  // Aggregate all findings across completed engagements
  const allFindings = useMemo(
    () => Object.values(findingsMap).flat(),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [findingsMap]
  );

  const totalEngagements = allEngagements.length;
  const totalFindings = allFindings.length;
  const critHigh = allFindings.filter((f) => f.severity === "critical" || f.severity === "high").length;
  const avgPerEng = completedEngagements.length > 0
    ? (allFindings.length / completedEngagements.length).toFixed(1)
    : "0";

  return (
    <div className="flex min-h-full flex-col gap-6 p-6">
      {/* Header */}
      <div>
        <h1 className="text-[20px] font-bold text-pentra-text-primary flex items-center gap-2">
          <BarChart2 className="h-5 w-5 text-pentra-accent" />
          Trends
        </h1>
        <p className="text-[13px] text-pentra-text-secondary mt-0.5">
          Aggregate security metrics across engagements
        </p>
      </div>

      {/* Hidden loaders for completed engagements */}
      {completedEngagements.map((eng) => (
        <EngagementFindingsLoader key={eng.id} engagement={eng} onData={setFindingsMap} />
      ))}

      {/* KPI Row */}
      <div className="grid grid-cols-4 gap-3">
        <KpiCard label="Total Engagements" value={totalEngagements} />
        <KpiCard label="Total Findings" value={totalFindings} sub="across completed scans" />
        <KpiCard
          label="Critical + High"
          value={critHigh}
          sub={totalFindings > 0 ? `${Math.round((critHigh / totalFindings) * 100)}% of all findings` : undefined}
        />
        <KpiCard
          label="Avg / Engagement"
          value={avgPerEng}
          sub="completed engagements only"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-2 gap-4">
        <StackedSeverityChart
          engagements={completedEngagements}
          findingsMap={findingsMap}
        />
        <VulnClassChart findings={allFindings} />
      </div>

      {completedEngagements.length === 0 && (
        <div className="flex flex-1 flex-col items-center justify-center gap-2 rounded-ds-lg border border-pentra-border bg-pentra-bg-card">
          <BarChart2 className="h-10 w-10 text-pentra-text-muted opacity-30" />
          <p className="text-[13px] text-pentra-text-muted">Complete engagements to see trends</p>
        </div>
      )}
    </div>
  );
}
