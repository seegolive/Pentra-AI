import { useState, useRef } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  Plus,
  Loader2,
  Target,
  ChevronRight,
  CircleDot,
  CheckCircle2,
  XCircle,
  Clock,
  Play,
  AlertTriangle,
  Upload,
} from "lucide-react";
import { useEngagements, useWorkspaces, useCreateEngagement, useImportEngagement } from "../lib/api";
import type { Engagement, EngagementStatus } from "../lib/types";
import { cn } from "../lib/utils";

const STATUS_CONFIG: Record<EngagementStatus, { label: string; icon: React.ReactNode; color: string }> = {
  planning: {
    label: "Planning",
    icon: <Clock className="h-3.5 w-3.5" />,
    color: "text-slate-400 bg-slate-400/10 border-slate-400/20",
  },
  active: {
    label: "Active",
    icon: <CircleDot className="h-3.5 w-3.5" />,
    color: "text-green-500 bg-green-500/10 border-green-500/20",
  },
  paused: {
    label: "Paused",
    icon: <AlertTriangle className="h-3.5 w-3.5" />,
    color: "text-yellow-500 bg-yellow-500/10 border-yellow-500/20",
  },
  completed: {
    label: "Completed",
    icon: <CheckCircle2 className="h-3.5 w-3.5" />,
    color: "text-blue-500 bg-blue-500/10 border-blue-500/20",
  },
  failed: {
    label: "Failed",
    icon: <XCircle className="h-3.5 w-3.5" />,
    color: "text-red-500 bg-red-500/10 border-red-500/20",
  },
};

function StatusBadge({ status }: { status: EngagementStatus }) {
  const cfg = STATUS_CONFIG[status] ?? STATUS_CONFIG.planning;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-xs font-medium",
        cfg.color
      )}
    >
      {cfg.icon}
      {cfg.label}
    </span>
  );
}

interface CreateEngagementFormProps {
  workspaceId: string;
  onClose: () => void;
}

function CreateEngagementForm({ workspaceId, onClose }: CreateEngagementFormProps) {
  const createMutation = useCreateEngagement();

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [mode, setMode] = useState<"semi_auto" | "agentic">("semi_auto");
  const [inScopeRaw, setInScopeRaw] = useState("");
  const [outOfScopeRaw, setOutOfScopeRaw] = useState("");
  const [llmModel, setLlmModel] = useState("qwen2.5-coder:32b");
  const [opsecMode, setOpsecMode] = useState(false);
  const [jitterMs, setJitterMs] = useState(500);

  // H1 scope import
  const [h1Handle, setH1Handle] = useState("");
  const [h1Loading, setH1Loading] = useState(false);
  const [h1Error, setH1Error] = useState<string | null>(null);

  const importH1Scope = async () => {
    const handle = h1Handle.trim();
    if (!handle) return;
    setH1Loading(true);
    setH1Error(null);
    try {
      const BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";
      const token = (JSON.parse(localStorage.getItem("pentra-auth") ?? "{}") as any)?.state?.accessToken as string | undefined;
      const res = await fetch(`${BASE}/api/v1/h1/programs/${encodeURIComponent(handle)}/scope`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: "Unknown error" }));
        throw new Error(err.detail ?? `HTTP ${res.status}`);
      }
      const data = await res.json();
      setInScopeRaw(data.in_scope.join("\n"));
      setOutOfScopeRaw(data.out_of_scope.join("\n"));
      if (!name.trim() && data.program_name) setName(data.program_name);
    } catch (err: any) {
      setH1Error(err.message ?? "Failed to fetch scope");
    } finally {
      setH1Loading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const inScope = inScopeRaw
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    if (!name.trim() || inScope.length === 0) return;

    await createMutation.mutateAsync({
      workspace_id: workspaceId,
      name: name.trim(),
      description: description.trim() || undefined,
      mode,
      in_scope: inScope,
      out_of_scope: outOfScopeRaw
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean),
      llm_model: llmModel,
      opsec_mode: opsecMode,
      request_jitter_ms: opsecMode ? jitterMs : 0,
    });
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-lg bg-card border border-border rounded-xl shadow-2xl p-6 space-y-4"
      >
        <h2 className="text-lg font-semibold text-foreground">New Engagement</h2>

        <div className="space-y-2">
          <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
            Name *
          </label>
          <input
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. HackerOne – Acme Corp Q2"
            className="w-full px-3 py-2 bg-background border border-border rounded-md text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </div>

        <div className="space-y-2">
          <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
            Description
          </label>
          <input
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Optional notes"
            className="w-full px-3 py-2 bg-background border border-border rounded-md text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-2">
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
              Mode
            </label>
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value as "semi_auto" | "agentic")}
              className="w-full px-3 py-2 bg-background border border-border rounded-md text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            >
              <option value="semi_auto">Semi-Auto (HITL)</option>
              <option value="agentic">Fully Agentic</option>
            </select>
          </div>
          <div className="space-y-2">
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
              LLM Model
            </label>

            <select
              value={llmModel}
              onChange={(e) => setLlmModel(e.target.value)}
              className="w-full px-3 py-2 bg-background border border-border rounded-md text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            >
              <option value="qwen2.5-coder:32b">qwen2.5-coder:32b</option>
              <option value="qwen2.5-coder:7b">qwen2.5-coder:7b (fast)</option>
              <option value="deepseek-r1:32b">deepseek-r1:32b (reasoning)</option>
            </select>
          </div>
        </div>

        {mode === "agentic" && (
          <div className="flex items-start gap-2 rounded-md border border-yellow-500/40 bg-yellow-500/10 px-3 py-2.5 text-xs text-yellow-300">
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-yellow-400" />
            <span>
              <strong>Mode Agentic</strong> — semua fase (planning, recon, vuln hunting) berjalan otomatis tanpa konfirmasi.{" "}
              Hanya <strong>exploit validation</strong> yang selalu meminta persetujuan manual sebelum mengirim payload aktif.
            </span>
          </div>
        )}

        {/* OPSEC mode toggle */}
        <div className="rounded-md border border-border bg-muted/20 px-3 py-3 space-y-3">
          <label className="flex items-center gap-3 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={opsecMode}
              onChange={(e) => setOpsecMode(e.target.checked)}
              className="h-4 w-4 rounded border-border accent-primary"
            />
            <div>
              <p className="text-sm font-medium text-foreground">OPSEC Mode</p>
              <p className="text-xs text-muted-foreground">Add random jitter delay between tool calls to blend traffic patterns</p>
            </div>
          </label>
          {opsecMode && (
            <div className="flex items-center gap-3 pl-7">
              <label className="text-xs text-muted-foreground whitespace-nowrap">Max jitter</label>
              <input
                type="range"
                min={100}
                max={10000}
                step={100}
                value={jitterMs}
                onChange={(e) => setJitterMs(Number(e.target.value))}
                className="flex-1"
              />
              <span className="text-xs font-mono text-foreground w-16 text-right">
                {jitterMs >= 1000 ? `${(jitterMs / 1000).toFixed(1)}s` : `${jitterMs}ms`}
              </span>
            </div>
          )}
        </div>

        <div className="space-y-2">
          <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
            Import Scope from HackerOne <span className="normal-case font-normal">(optional)</span>
          </label>
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={h1Handle}
              onChange={(e) => setH1Handle(e.target.value)}
              placeholder="Program handle (e.g. shopify)"
              className="flex-1 px-3 py-2 bg-background border border-border rounded-md text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            />
            <button
              type="button"
              onClick={importH1Scope}
              disabled={h1Loading || !h1Handle.trim()}
              className="shrink-0 flex items-center gap-1.5 px-3 py-2 border border-border rounded-md text-sm text-foreground hover:bg-muted disabled:opacity-50 transition-colors"
            >
              {h1Loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
              Import
            </button>
          </div>
          {h1Error && (
            <p className="text-xs text-red-400">{h1Error}</p>
          )}
        </div>

        <div className="space-y-2">
          <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
            In-Scope targets * <span className="normal-case font-normal">(one per line)</span>
          </label>
          <textarea
            value={inScopeRaw}
            onChange={(e) => setInScopeRaw(e.target.value)}
            placeholder={"target.com\n*.api.target.com\n192.168.1.0/24"}
            rows={4}
            className="w-full px-3 py-2 bg-background border border-border rounded-md text-sm font-mono text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary resize-none"
          />
        </div>

        <div className="space-y-2">
          <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
            Out-of-Scope <span className="normal-case font-normal">(one per line)</span>
          </label>
          <textarea
            value={outOfScopeRaw}
            onChange={(e) => setOutOfScopeRaw(e.target.value)}
            placeholder={"admin.target.com\npayments.target.com"}
            rows={2}
            className="w-full px-3 py-2 bg-background border border-border rounded-md text-sm font-mono text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary resize-none"
          />
        </div>

        <div className="flex gap-2 pt-2">
          <button
            type="submit"
            disabled={createMutation.isPending || !name.trim() || !inScopeRaw.trim()}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 disabled:opacity-50 transition-colors"
          >
            {createMutation.isPending && <Loader2 className="h-3 w-3 animate-spin" />}
            Create Engagement
          </button>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}

export default function EngagementsPage() {
  const { workspaceId } = useParams<{ workspaceId: string }>();
  const navigate = useNavigate();

  const { data: workspaces } = useWorkspaces();
  const { data: engagements, isLoading } = useEngagements(workspaceId);
  const [showCreate, setShowCreate] = useState(false);
  const importMutation = useImportEngagement(workspaceId ?? "");
  const fileInputRef = useRef<HTMLInputElement>(null);

  async function handleImportFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file || !workspaceId) return;
    try {
      const text = await file.text();
      const bundle = JSON.parse(text);
      await importMutation.mutateAsync({ bundle });
    } catch {
      alert("Invalid export file — please select a valid Pentra engagement JSON.");
    } finally {
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  }

  const workspace = workspaces?.find((w) => w.id === workspaceId);

  return (
    <div className="flex-1 p-8">
      <div className="max-w-4xl mx-auto">
        {/* Breadcrumb */}
        <div className="flex items-center gap-1.5 text-sm text-muted-foreground mb-6">
          <button
            onClick={() => navigate("/workspaces")}
            className="hover:text-foreground transition-colors"
          >
            Workspaces
          </button>
          <ChevronRight className="h-3.5 w-3.5" />
          <span className="text-foreground">{workspace?.name ?? "…"}</span>
        </div>

        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold text-foreground">Engagements</h1>
            <p className="text-sm text-muted-foreground mt-1">
              Security testing engagements for this workspace
            </p>
          </div>
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 transition-colors"
          >
            <Plus className="h-4 w-4" />
            New Engagement
          </button>
          <button
            onClick={() => fileInputRef.current?.click()}
            disabled={importMutation.isPending}
            className="flex items-center gap-2 px-3 py-2 border border-border rounded-md text-sm text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
          >
            {importMutation.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Upload className="h-4 w-4" />
            )}
            Import
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".json,application/json"
            className="hidden"
            onChange={handleImportFile}
          />
        </div>

        {/* List */}
        {isLoading ? (
          <div className="flex items-center justify-center h-40 text-muted-foreground">
            <Loader2 className="h-5 w-5 animate-spin mr-2" />
            Loading…
          </div>
        ) : engagements?.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-60 text-muted-foreground border border-dashed border-border rounded-lg">
            <Target className="h-10 w-10 mb-3 opacity-30" />
            <p className="text-sm">No engagements yet</p>
            <p className="text-xs mt-1 opacity-60">Create one to start a penetration test</p>
          </div>
        ) : (
          <div className="space-y-3">
            {engagements?.map((eng: Engagement) => (
              <button
                key={eng.id}
                onClick={() => navigate(`/engagements/${eng.id}`)}
                className={cn(
                  "w-full text-left p-5 border border-border rounded-lg bg-card",
                  "hover:border-primary/50 hover:bg-card/80 transition-colors group"
                )}
              >
                <div className="flex items-center justify-between">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3">
                      <p className="font-medium text-foreground truncate">{eng.name}</p>
                      <StatusBadge status={eng.status as EngagementStatus} />
                      <span className="text-xs text-muted-foreground border border-border rounded px-1.5 py-0.5">
                        {eng.mode === "semi_auto" ? "Semi-Auto" : "Agentic"}
                      </span>
                    </div>
                    {eng.description && (
                      <p className="text-xs text-muted-foreground mt-1 truncate">{eng.description}</p>
                    )}
                    <div className="flex items-center gap-3 mt-2">
                      <span className="text-xs text-muted-foreground">
                        {eng.in_scope.length} in-scope target{eng.in_scope.length !== 1 ? "s" : ""}
                      </span>
                      <span className="text-xs text-muted-foreground font-mono opacity-60">
                        {eng.llm_model}
                      </span>
                      {eng.started_at && (
                        <span className="text-xs text-muted-foreground opacity-60">
                          Started {new Date(eng.started_at).toLocaleDateString()}
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 ml-4">
                    {eng.status === "planning" && (
                      <span className="flex items-center gap-1 text-xs text-primary">
                        <Play className="h-3 w-3" />
                        Ready to start
                      </span>
                    )}
                    <ChevronRight className="h-4 w-4 text-muted-foreground group-hover:text-foreground transition-colors" />
                  </div>
                </div>
              </button>
            ))}
          </div>
        )}
      </div>

      {showCreate && workspaceId && (
        <CreateEngagementForm workspaceId={workspaceId} onClose={() => setShowCreate(false)} />
      )}
    </div>
  );
}
