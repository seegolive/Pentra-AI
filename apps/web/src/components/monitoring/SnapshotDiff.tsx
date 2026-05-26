import { useState } from "react";
import { GitCompare, Loader2, ChevronDown } from "lucide-react";
import { cn } from "../../lib/utils";
import { useSnapshotDiff } from "../../lib/api";
import type { ReconSnapshot } from "../../lib/api";

interface SnapshotDiffProps {
  engagementId: string;
  snapshots: ReconSnapshot[];
}

type DiffTab = "subdomains" | "ports" | "endpoints" | "tech";

export function SnapshotDiff({ engagementId, snapshots }: SnapshotDiffProps) {
  const [snapshotA, setSnapshotA] = useState<string | undefined>(
    snapshots.length > 1 ? snapshots[snapshots.length - 1].id : undefined
  );
  const [snapshotB, setSnapshotB] = useState<string | undefined>(
    snapshots.length > 0 ? snapshots[0].id : undefined
  );
  const [diffTab, setDiffTab] = useState<DiffTab>("subdomains");

  const { data: diff, isLoading, error } = useSnapshotDiff(engagementId, snapshotA, snapshotB);

  if (snapshots.length < 2) {
    return (
      <div className="flex flex-col items-center justify-center py-10 text-muted-foreground">
        <GitCompare className="h-8 w-8 mb-2 opacity-20" />
        <p className="text-sm">Need at least 2 snapshots to compare</p>
      </div>
    );
  }

  const tabs: { key: DiffTab; label: string; count: number }[] = [
    {
      key: "subdomains",
      label: "Subdomains",
      count: (diff?.new_subdomains.length ?? 0) + (diff?.removed_subdomains.length ?? 0),
    },
    { key: "ports", label: "Ports", count: Object.keys(diff?.new_ports ?? {}).length },
    { key: "endpoints", label: "Endpoints", count: diff?.new_endpoints.length ?? 0 },
    { key: "tech", label: "Tech Stack", count: diff?.new_tech.length ?? 0 },
  ];

  return (
    <div className="space-y-4">
      {/* Snapshot selectors */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex flex-col gap-1">
          <label className="text-[10px] text-muted-foreground uppercase tracking-wide">Baseline</label>
          <div className="relative">
            <select
              value={snapshotA}
              onChange={(e) => setSnapshotA(e.target.value)}
              className="appearance-none bg-background border border-border rounded px-3 py-1.5 text-xs pr-7 focus:outline-none focus:ring-1 focus:ring-primary"
            >
              {snapshots.map((s) => (
                <option key={s.id} value={s.id}>
                  {new Date(s.snapshot_at).toLocaleString()} ({s.subdomains.length} subs)
                </option>
              ))}
            </select>
            <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 h-3 w-3 text-muted-foreground pointer-events-none" />
          </div>
        </div>

        <GitCompare className="h-4 w-4 text-muted-foreground mt-4 flex-shrink-0" />

        <div className="flex flex-col gap-1">
          <label className="text-[10px] text-muted-foreground uppercase tracking-wide">Compare</label>
          <div className="relative">
            <select
              value={snapshotB}
              onChange={(e) => setSnapshotB(e.target.value)}
              className="appearance-none bg-background border border-border rounded px-3 py-1.5 text-xs pr-7 focus:outline-none focus:ring-1 focus:ring-primary"
            >
              {snapshots.map((s) => (
                <option key={s.id} value={s.id}>
                  {new Date(s.snapshot_at).toLocaleString()} ({s.subdomains.length} subs)
                </option>
              ))}
            </select>
            <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 h-3 w-3 text-muted-foreground pointer-events-none" />
          </div>
        </div>
      </div>

      {isLoading && (
        <div className="flex items-center gap-2 text-xs text-muted-foreground py-4">
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
          Computing diff…
        </div>
      )}

      {error && (
        <p className="text-xs text-red-400">Failed to compute diff: {String(error)}</p>
      )}

      {diff && (
        <>
          {/* Tab bar */}
          <div className="flex gap-1 border-b border-border pb-0">
            {tabs.map((t) => (
              <button
                key={t.key}
                onClick={() => setDiffTab(t.key)}
                className={cn(
                  "flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium border-b-2 -mb-px transition-colors",
                  diffTab === t.key
                    ? "border-primary text-foreground"
                    : "border-transparent text-muted-foreground hover:text-foreground"
                )}
              >
                {t.label}
                {t.count > 0 && (
                  <span className="px-1.5 py-0.5 rounded-full bg-primary/20 text-primary text-[10px]">
                    {t.count}
                  </span>
                )}
              </button>
            ))}
          </div>

          {/* Diff content */}
          <div className="space-y-1 max-h-72 overflow-y-auto pr-1">
            {diffTab === "subdomains" && (
              <>
                {diff.new_subdomains.map((s) => (
                  <div key={s} className="flex items-center gap-2 px-2 py-1 rounded text-xs font-mono bg-green-500/5 border border-green-500/20">
                    <span className="text-green-400 font-bold">+</span>
                    <span className="text-green-300">{s}</span>
                  </div>
                ))}
                {diff.removed_subdomains.map((s) => (
                  <div key={s} className="flex items-center gap-2 px-2 py-1 rounded text-xs font-mono bg-red-500/5 border border-red-500/20">
                    <span className="text-red-400 font-bold">-</span>
                    <span className="text-red-300 line-through opacity-70">{s}</span>
                  </div>
                ))}
                {diff.new_subdomains.length === 0 && diff.removed_subdomains.length === 0 && (
                  <p className="text-xs text-muted-foreground py-4 text-center">No subdomain changes</p>
                )}
              </>
            )}

            {diffTab === "ports" && (
              <>
                {Object.entries(diff.new_ports).map(([host, ports]) => (
                  <div key={host} className="flex items-start gap-2 px-2 py-1 rounded text-xs font-mono bg-yellow-500/5 border border-yellow-500/20">
                    <span className="text-yellow-400 font-bold">+</span>
                    <span className="text-foreground">{host}</span>
                    <span className="text-yellow-300 ml-auto">{ports.join(", ")}</span>
                  </div>
                ))}
                {Object.keys(diff.new_ports).length === 0 && (
                  <p className="text-xs text-muted-foreground py-4 text-center">No new open ports</p>
                )}
              </>
            )}

            {diffTab === "endpoints" && (
              <>
                {diff.new_endpoints.map((e) => (
                  <div key={e} className="flex items-center gap-2 px-2 py-1 rounded text-xs font-mono bg-blue-500/5 border border-blue-500/20">
                    <span className="text-blue-400 font-bold">+</span>
                    <span className="text-blue-300">{e}</span>
                  </div>
                ))}
                {diff.new_endpoints.length === 0 && (
                  <p className="text-xs text-muted-foreground py-4 text-center">No new endpoints</p>
                )}
              </>
            )}

            {diffTab === "tech" && (
              <>
                {diff.new_tech.map((t) => (
                  <div key={t} className="flex items-center gap-2 px-2 py-1 rounded text-xs font-mono bg-purple-500/5 border border-purple-500/20">
                    <span className="text-purple-400 font-bold">+</span>
                    <span className="text-purple-300">{t}</span>
                  </div>
                ))}
                {diff.new_tech.length === 0 && (
                  <p className="text-xs text-muted-foreground py-4 text-center">No new technology detected</p>
                )}
              </>
            )}
          </div>
        </>
      )}
    </div>
  );
}
