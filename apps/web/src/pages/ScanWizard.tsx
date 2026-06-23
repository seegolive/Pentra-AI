import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Zap,
  Wind,
  Globe,
  EyeOff,
  KeyRound,
  Cpu,
  CheckCircle2,
  ChevronRight,
  ChevronLeft,
  Loader2,
  ScanSearch,
  Layers,
  ShieldCheck,
} from "lucide-react";
import { cn } from "../lib/utils";
import { useCreateEngagement } from "../lib/api";
import { toastSuccess, toastError } from "../lib/toast";
import { useWorkspaces } from "../lib/api";

// ── Types ──────────────────────────────────────────────────────────────────

interface ScanPreset {
  id: string;
  name: string;
  description: string;
  eta: string;
  icon: React.ReactNode;
  model: string;
  recommended?: boolean;
  opsec?: boolean;
}

const PRESETS: ScanPreset[] = [
  {
    id: "quick",
    name: "Quick",
    description: "Rapid surface scan — subdomain enum + port scan only",
    eta: "~5 min",
    icon: <Zap className="h-5 w-5" />,
    model: "qwen2.5-coder:7b",
  },
  {
    id: "fast",
    name: "Fast",
    description: "Standard scan with lightweight vuln detection",
    eta: "~15 min",
    icon: <Wind className="h-5 w-5" />,
    model: "qwen2.5-coder:7b",
  },
  {
    id: "full",
    name: "Full",
    description: "Comprehensive recon + vuln hunt + exploitation chains",
    eta: "~45 min",
    icon: <Globe className="h-5 w-5" />,
    model: "qwen2.5-coder:32b",
  },
  {
    id: "stealth",
    name: "Stealth",
    description: "Low-noise scan with request jitter to evade detection",
    eta: "~60 min",
    icon: <EyeOff className="h-5 w-5" />,
    model: "qwen2.5-coder:32b",
    opsec: true,
  },
  {
    id: "authenticated",
    name: "Authenticated",
    description: "Scan with session auth — deeper endpoint coverage",
    eta: "~30 min",
    icon: <KeyRound className="h-5 w-5" />,
    model: "qwen2.5-coder:32b",
  },
  {
    id: "pentra-ft",
    name: "Pentra-FT",
    description: "Fine-tuned model optimized for pentest workflows — 8× more effective",
    eta: "~30 min",
    icon: <Cpu className="h-5 w-5" />,
    model: "pentra-ft",
    recommended: true,
  },
];

// ── Step Indicator ──────────────────────────────────────────────────────────

const STEPS = ["Target & Scope", "Scan Preset", "Authentication", "Review & Launch"];

function StepIndicator({ current }: { current: number }) {
  return (
    <div className="flex items-center justify-center gap-0 mb-8">
      {STEPS.map((label, i) => (
        <div key={i} className="flex items-center">
          <div className="flex flex-col items-center gap-1">
            <div
              className={cn(
                "flex h-7 w-7 items-center justify-center rounded-full border-2 text-[12px] font-bold transition-colors",
                i < current
                  ? "border-pentra-accent bg-pentra-accent text-white"
                  : i === current
                  ? "border-pentra-accent bg-pentra-bg-panel text-pentra-accent"
                  : "border-pentra-border bg-pentra-bg-panel text-pentra-text-muted"
              )}
            >
              {i < current ? <CheckCircle2 className="h-3.5 w-3.5" /> : i + 1}
            </div>
            <span
              className={cn(
                "text-[10px] font-medium whitespace-nowrap",
                i === current ? "text-pentra-text-primary" : "text-pentra-text-muted"
              )}
            >
              {label}
            </span>
          </div>
          {i < STEPS.length - 1 && (
            <div
              className={cn(
                "h-0.5 w-12 mx-1 mt-[-14px] transition-colors",
                i < current ? "bg-pentra-accent" : "bg-pentra-border"
              )}
            />
          )}
        </div>
      ))}
    </div>
  );
}

// ── Step 1: Target & Scope ──────────────────────────────────────────────────

interface TargetData {
  domain: string;
  inScope: string;
  outScope: string;
  engagementName: string;
  scanSequential: boolean;
  autoApproveExploitValidation: boolean;
}

function Step1({ data, onChange }: { data: TargetData; onChange: (d: TargetData) => void }) {
  return (
    <div className="space-y-4">
      <div>
        <label className="block text-[12px] font-semibold text-pentra-text-secondary mb-1.5">
          Target Domain <span className="text-pentra-severity-critical">*</span>
        </label>
        <input
          type="text"
          placeholder="example.com"
          value={data.domain}
          onChange={(e) => {
            const domain = e.target.value.replace(/^https?:\/\//, "");
            const autoName = domain ? `${domain} scan` : "";
            onChange({
              ...data,
              domain,
              engagementName: data.engagementName || autoName,
            });
          }}
          className="w-full rounded-ds-md border border-pentra-border bg-pentra-bg-input px-3 py-2 text-[13px] text-pentra-text-primary placeholder:text-pentra-text-muted outline-none focus:border-pentra-border-focus"
        />
        <p className="mt-1 text-[11px] text-pentra-text-muted">Do not include http:// or https://</p>
      </div>

      <div>
        <label className="block text-[12px] font-semibold text-pentra-text-secondary mb-1.5">
          Engagement Name
        </label>
        <input
          type="text"
          placeholder="Auto-generated from domain"
          value={data.engagementName}
          onChange={(e) => onChange({ ...data, engagementName: e.target.value })}
          className="w-full rounded-ds-md border border-pentra-border bg-pentra-bg-input px-3 py-2 text-[13px] text-pentra-text-primary placeholder:text-pentra-text-muted outline-none focus:border-pentra-border-focus"
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-[12px] font-semibold text-pentra-text-secondary mb-1.5">
            In-Scope (one per line)
          </label>
          <textarea
            rows={4}
            placeholder={"*.example.com\n10.0.0.0/24"}
            value={data.inScope}
            onChange={(e) => onChange({ ...data, inScope: e.target.value })}
            className="w-full resize-none rounded-ds-md border border-pentra-border bg-pentra-bg-input px-3 py-2 text-[13px] font-mono text-pentra-text-primary placeholder:text-pentra-text-muted outline-none focus:border-pentra-border-focus"
          />
        </div>
        <div>
          <label className="block text-[12px] font-semibold text-pentra-text-secondary mb-1.5">
            Out-of-Scope (one per line)
          </label>
          <textarea
            rows={4}
            placeholder={"admin.example.com\npay.example.com"}
            value={data.outScope}
            onChange={(e) => onChange({ ...data, outScope: e.target.value })}
            className="w-full resize-none rounded-ds-md border border-pentra-border bg-pentra-bg-input px-3 py-2 text-[13px] font-mono text-pentra-text-primary placeholder:text-pentra-text-muted outline-none focus:border-pentra-border-focus"
          />
        </div>
      </div>

      {/* ── Approval Policy ─────────────────────────────────────────────── */}
      <div>
        <label className="block text-[12px] font-semibold text-pentra-text-secondary mb-2">
          Approval Policy
        </label>
        <div className="grid grid-cols-2 gap-3">
          <button
            type="button"
            onClick={() => onChange({ ...data, autoApproveExploitValidation: false })}
            className={cn(
              "flex items-start gap-3 rounded-ds-md border p-3 text-left transition-all",
              !data.autoApproveExploitValidation
                ? "border-pentra-accent bg-pentra-accent-glow"
                : "border-pentra-border bg-pentra-bg-card hover:border-pentra-border-light"
            )}
          >
            <div className={cn(
              "mt-0.5 flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-ds-sm",
              !data.autoApproveExploitValidation ? "bg-pentra-accent text-white" : "bg-pentra-bg-panel text-pentra-text-muted"
            )}>
              <ShieldCheck className="h-3.5 w-3.5" />
            </div>
            <div>
              <p className="text-[12px] font-semibold text-pentra-text-primary">Manual exploit approval</p>
              <p className="mt-0.5 text-[11px] text-pentra-text-muted leading-snug">
                Pause before exploit validation for an explicit human decision.
              </p>
            </div>
          </button>

          <button
            type="button"
            onClick={() => onChange({ ...data, autoApproveExploitValidation: true })}
            className={cn(
              "flex items-start gap-3 rounded-ds-md border p-3 text-left transition-all",
              data.autoApproveExploitValidation
                ? "border-pentra-accent bg-pentra-accent-glow"
                : "border-pentra-border bg-pentra-bg-card hover:border-pentra-border-light"
            )}
          >
            <div className={cn(
              "mt-0.5 flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-ds-sm",
              data.autoApproveExploitValidation ? "bg-pentra-accent text-white" : "bg-pentra-bg-panel text-pentra-text-muted"
            )}>
              <Zap className="h-3.5 w-3.5" />
            </div>
            <div>
              <p className="text-[12px] font-semibold text-pentra-text-primary">Initial approval only</p>
              <p className="mt-0.5 text-[11px] text-pentra-text-muted leading-snug">
                Continue through exploit validation automatically after the scan is started.
              </p>
            </div>
          </button>
        </div>
      </div>

      {/* ── Subdomain Scan Mode ──────────────────────────────────────────── */}
      <div>
        <label className="block text-[12px] font-semibold text-pentra-text-secondary mb-2">
          Subdomain Scan Mode
        </label>
        <div className="grid grid-cols-2 gap-3">
          {/* Concurrent (default) */}
          <button
            type="button"
            onClick={() => onChange({ ...data, scanSequential: false })}
            className={cn(
              "flex items-start gap-3 rounded-ds-md border p-3 text-left transition-all",
              !data.scanSequential
                ? "border-pentra-accent bg-pentra-accent-glow"
                : "border-pentra-border bg-pentra-bg-card hover:border-pentra-border-light"
            )}
          >
            <div className={cn(
              "mt-0.5 flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-ds-sm",
              !data.scanSequential ? "bg-pentra-accent text-white" : "bg-pentra-bg-panel text-pentra-text-muted"
            )}>
              <Layers className="h-3.5 w-3.5" />
            </div>
            <div>
              <p className="text-[12px] font-semibold text-pentra-text-primary">Concurrent</p>
              <p className="mt-0.5 text-[11px] text-pentra-text-muted leading-snug">
                Scan all subdomains simultaneously — faster (~5×) but higher traffic volume.
              </p>
            </div>
          </button>

          {/* Sequential */}
          <button
            type="button"
            onClick={() => onChange({ ...data, scanSequential: true })}
            className={cn(
              "flex items-start gap-3 rounded-ds-md border p-3 text-left transition-all",
              data.scanSequential
                ? "border-pentra-accent bg-pentra-accent-glow"
                : "border-pentra-border bg-pentra-bg-card hover:border-pentra-border-light"
            )}
          >
            <div className={cn(
              "mt-0.5 flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-ds-sm",
              data.scanSequential ? "bg-pentra-accent text-white" : "bg-pentra-bg-panel text-pentra-text-muted"
            )}>
              <ScanSearch className="h-3.5 w-3.5" />
            </div>
            <div>
              <p className="text-[12px] font-semibold text-pentra-text-primary">
                Sequential <span className="text-[10px] font-normal text-pentra-text-muted ml-1">per-subdomain</span>
              </p>
              <p className="mt-0.5 text-[11px] text-pentra-text-muted leading-snug">
                Passive → sleep → active per subdomain. Avoids traffic bursts. Recommended for bug bounty.
              </p>
            </div>
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Step 2: Scan Preset ──────────────────────────────────────────────────────

function Step2({ selected, onSelect }: { selected: string; onSelect: (id: string) => void }) {
  return (
    <div className="grid grid-cols-2 gap-3">
      {PRESETS.map((preset) => (
        <button
          key={preset.id}
          type="button"
          onClick={() => onSelect(preset.id)}
          className={cn(
            "relative flex flex-col gap-2 rounded-ds-md border p-4 text-left transition-all",
            selected === preset.id
              ? "border-pentra-accent bg-pentra-accent-glow"
              : "border-pentra-border bg-pentra-bg-card hover:border-pentra-border-light hover:bg-pentra-bg-hover"
          )}
        >
          {preset.recommended && (
            <span className="absolute right-2 top-2 rounded-full bg-pentra-accent px-2 py-0.5 text-[9px] font-bold text-white">
              Recommended
            </span>
          )}
          <div
            className={cn(
              "flex h-9 w-9 items-center justify-center rounded-ds-md",
              selected === preset.id
                ? "bg-pentra-accent text-white"
                : "bg-pentra-bg-panel text-pentra-text-muted"
            )}
          >
            {preset.icon}
          </div>
          <div>
            <p className="text-[13px] font-semibold text-pentra-text-primary">{preset.name}</p>
            <p className="mt-0.5 text-[11px] text-pentra-text-secondary leading-snug">{preset.description}</p>
          </div>
          <p className="text-[10px] text-pentra-text-muted">{preset.eta}</p>
        </button>
      ))}
    </div>
  );
}

// ── Step 3: Authentication ──────────────────────────────────────────────────

interface AuthData {
  enabled: boolean;
  authType: "cookie" | "bearer" | "basic";
  credential: string;
  username: string;
  password: string;
}

function Step3({ data, onChange }: { data: AuthData; onChange: (d: AuthData) => void }) {
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <button
          type="button"
          role="switch"
          aria-checked={data.enabled}
          onClick={() => onChange({ ...data, enabled: !data.enabled })}
          className={cn(
            "relative h-5 w-9 rounded-full transition-colors",
            data.enabled ? "bg-pentra-accent" : "bg-pentra-border"
          )}
        >
          <span
            className={cn(
              "absolute top-0.5 h-4 w-4 rounded-full bg-white shadow transition-transform",
              data.enabled ? "left-[calc(100%-18px)]" : "left-0.5"
            )}
          />
        </button>
        <label className="text-[13px] font-medium text-pentra-text-primary">Enable authentication</label>
      </div>

      {data.enabled && (
        <div className="space-y-3 rounded-ds-md border border-pentra-border bg-pentra-bg-card p-4">
          <div>
            <label className="block text-[12px] font-semibold text-pentra-text-secondary mb-1.5">Auth Type</label>
            <select
              value={data.authType}
              onChange={(e) => onChange({ ...data, authType: e.target.value as AuthData["authType"] })}
              className="w-full rounded-ds-md border border-pentra-border bg-pentra-bg-input px-3 py-2 text-[13px] text-pentra-text-primary outline-none focus:border-pentra-border-focus"
            >
              <option value="cookie">Cookie</option>
              <option value="bearer">Bearer Token</option>
              <option value="basic">Basic Auth</option>
            </select>
          </div>

          {(data.authType === "cookie" || data.authType === "bearer") && (
            <div>
              <label className="block text-[12px] font-semibold text-pentra-text-secondary mb-1.5">
                {data.authType === "cookie" ? "Cookie Value" : "Bearer Token"}
              </label>
              <input
                type="password"
                placeholder={data.authType === "cookie" ? "session=abc123" : "eyJhbGci..."}
                value={data.credential}
                onChange={(e) => onChange({ ...data, credential: e.target.value })}
                className="w-full rounded-ds-md border border-pentra-border bg-pentra-bg-input px-3 py-2 text-[13px] font-mono text-pentra-text-primary placeholder:text-pentra-text-muted outline-none focus:border-pentra-border-focus"
              />
            </div>
          )}

          {data.authType === "basic" && (
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[12px] font-semibold text-pentra-text-secondary mb-1.5">Username</label>
                <input
                  type="text"
                  value={data.username}
                  onChange={(e) => onChange({ ...data, username: e.target.value })}
                  className="w-full rounded-ds-md border border-pentra-border bg-pentra-bg-input px-3 py-2 text-[13px] text-pentra-text-primary outline-none focus:border-pentra-border-focus"
                />
              </div>
              <div>
                <label className="block text-[12px] font-semibold text-pentra-text-secondary mb-1.5">Password</label>
                <input
                  type="password"
                  value={data.password}
                  onChange={(e) => onChange({ ...data, password: e.target.value })}
                  className="w-full rounded-ds-md border border-pentra-border bg-pentra-bg-input px-3 py-2 text-[13px] text-pentra-text-primary outline-none focus:border-pentra-border-focus"
                />
              </div>
            </div>
          )}
        </div>
      )}

      {!data.enabled && (
        <div className="rounded-ds-md border border-pentra-border bg-pentra-bg-card p-6 text-center">
          <p className="text-[13px] text-pentra-text-muted">Authentication is disabled. The scan will run unauthenticated.</p>
        </div>
      )}
    </div>
  );
}

// ── Step 4: Review & Launch ─────────────────────────────────────────────────

function ReviewRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-start gap-4 border-b border-pentra-border py-2.5 last:border-0">
      <span className="w-28 flex-shrink-0 text-[12px] font-semibold text-pentra-text-muted">{label}</span>
      <span className="text-[13px] text-pentra-text-primary break-all">{value}</span>
    </div>
  );
}

// ── Main Wizard ──────────────────────────────────────────────────────────────

export default function ScanWizard() {
  const navigate = useNavigate();
  const create = useCreateEngagement();
  const { data: workspaces } = useWorkspaces();

  const [step, setStep] = useState(0);
  const [target, setTarget] = useState<TargetData>({
    domain: "",
    inScope: "",
    outScope: "",
    engagementName: "",
    scanSequential: false,
    autoApproveExploitValidation: false,
  });
  const [preset, setPreset] = useState("fast");
  const [auth, setAuth] = useState<AuthData>({
    enabled: false,
    authType: "bearer",
    credential: "",
    username: "",
    password: "",
  });

  const selectedPreset = PRESETS.find((p) => p.id === preset) ?? PRESETS[1];

  const canNext = () => {
    if (step === 0) return target.domain.trim().length > 0;
    return true;
  };

  const handleLaunch = async () => {
    const workspaceId = workspaces?.[0]?.id;
    if (!workspaceId) {
      toastError("No workspace", "Please create a workspace first");
      return;
    }

    const inScope = target.inScope
      ? target.inScope.split("\n").map((s) => s.trim()).filter(Boolean)
      : [target.domain];
    const outScope = target.outScope
      ? target.outScope.split("\n").map((s) => s.trim()).filter(Boolean)
      : [];

    try {
      const eng = await create.mutateAsync({
        workspace_id: workspaceId,
        name: target.engagementName || `${target.domain} scan`,
        mode: target.autoApproveExploitValidation ? "agentic" : "semi_auto",
        in_scope: inScope,
        out_of_scope: outScope,
        llm_model: selectedPreset.model,
        opsec_mode: selectedPreset.opsec ?? false,
        request_jitter_ms: selectedPreset.opsec ? 2000 : 0,
        scan_sequential: target.scanSequential,
        auto_approve_exploit_validation: target.autoApproveExploitValidation,
      });
      toastSuccess("Engagement created", eng.name);
      navigate(`/engagements/${eng.id}`);
    } catch {
      toastError("Failed to create engagement");
    }
  };

  return (
    <div className="flex min-h-full items-start justify-center bg-pentra-bg-base p-8">
      <div className="w-full max-w-2xl">
        <div className="mb-6">
          <h1 className="text-[22px] font-bold text-pentra-text-primary">New Scan</h1>
          <p className="text-[13px] text-pentra-text-secondary mt-1">Configure and launch a security engagement</p>
        </div>

        <StepIndicator current={step} />

        <div className="rounded-ds-lg border border-pentra-border bg-pentra-bg-panel p-6">
          {step === 0 && <Step1 data={target} onChange={setTarget} />}
          {step === 1 && <Step2 selected={preset} onSelect={setPreset} />}
          {step === 2 && <Step3 data={auth} onChange={setAuth} />}
          {step === 3 && (
            <div>
              <h3 className="text-[14px] font-semibold text-pentra-text-primary mb-4">Review Configuration</h3>
              <div className="rounded-ds-md border border-pentra-border bg-pentra-bg-card px-4">
                <ReviewRow label="Target" value={target.domain || "—"} />
                <ReviewRow label="Name" value={target.engagementName || `${target.domain} scan`} />
                <ReviewRow
                  label="In-Scope"
                  value={
                    target.inScope
                      ? target.inScope.split("\n").filter(Boolean).join(", ")
                      : target.domain
                  }
                />
                {target.outScope && (
                  <ReviewRow
                    label="Out-of-Scope"
                    value={target.outScope.split("\n").filter(Boolean).join(", ")}
                  />
                )}
                <ReviewRow label="Preset" value={`${selectedPreset.name} (${selectedPreset.eta})`} />
                <ReviewRow label="Model" value={selectedPreset.model} />
                <ReviewRow
                  label="Mode"
                  value={target.autoApproveExploitValidation ? "Agentic" : "Semi-auto"}
                />
                <ReviewRow
                  label="Auth Mode"
                  value={auth.enabled ? auth.authType : "None (unauthenticated)"}
                />
                <ReviewRow label="Opsec Mode" value={selectedPreset.opsec ? "Enabled" : "Disabled"} />
                <ReviewRow
                  label="Scan Mode"
                  value={target.scanSequential ? "Sequential (per-subdomain, traffic-safe)" : "Concurrent (default)"}
                />
                <ReviewRow
                  label="Approval"
                  value={target.autoApproveExploitValidation ? "Initial approval only" : "Manual exploit approval"}
                />
              </div>
            </div>
          )}
        </div>

        {/* Navigation */}
        <div className="flex items-center justify-between mt-4">
          <button
            type="button"
            onClick={() => setStep((s) => Math.max(0, s - 1))}
            disabled={step === 0}
            className="flex items-center gap-1.5 rounded-ds-md border border-pentra-border px-4 py-2 text-[13px] text-pentra-text-secondary transition-colors hover:bg-pentra-bg-hover hover:text-pentra-text-primary disabled:opacity-40"
          >
            <ChevronLeft className="h-4 w-4" />
            Back
          </button>

          {step < 3 ? (
            <button
              type="button"
              onClick={() => setStep((s) => Math.min(3, s + 1))}
              disabled={!canNext()}
              className="flex items-center gap-1.5 rounded-ds-md bg-pentra-accent px-4 py-2 text-[13px] font-medium text-white transition-opacity hover:opacity-80 disabled:opacity-40"
            >
              Next
              <ChevronRight className="h-4 w-4" />
            </button>
          ) : (
            <button
              type="button"
              onClick={handleLaunch}
              disabled={create.isPending}
              className="flex items-center gap-2 rounded-ds-md bg-pentra-accent px-5 py-2 text-[13px] font-medium text-white transition-opacity hover:opacity-80 disabled:opacity-50"
            >
              {create.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <CheckCircle2 className="h-4 w-4" />
              )}
              Launch Scan
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
