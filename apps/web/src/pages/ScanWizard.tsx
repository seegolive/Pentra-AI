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
  Bot,
  AlertTriangle,
  Network,
  Bug,
  Crosshair,
  BrainCircuit,
  Radar,
  FlaskConical,
  Siren,
  Lock,
  Unlock,
  Activity,
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
  fullBypass?: boolean;
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

// ── Technique definitions ──────────────────────────────────────────────────

interface Technique {
  id: string;
  phase: "recon" | "passive" | "active" | "llm" | "chain";
  name: string;
  detail: string;
  icon: React.ReactNode;
}

const ALL_TECHNIQUES: Technique[] = [
  // Recon
  { id: "subfinder", phase: "recon", name: "Subfinder", detail: "Subdomain enumeration — all sources", icon: <Network className="h-3 w-3" /> },
  { id: "httpx", phase: "recon", name: "httpx", detail: "Live host probing + tech detection", icon: <Activity className="h-3 w-3" /> },
  { id: "nmap", phase: "recon", name: "nmap", detail: "Port scan + service fingerprint", icon: <Radar className="h-3 w-3" /> },
  { id: "wayback", phase: "recon", name: "Waybackurls", detail: "Historical endpoint discovery", icon: <Globe className="h-3 w-3" /> },
  { id: "screenshot", phase: "recon", name: "Screenshot", detail: "Playwright visual capture per host", icon: <ScanSearch className="h-3 w-3" /> },
  // Passive
  { id: "nuclei-passive", phase: "passive", name: "Nuclei Passive", detail: "exposure · misconfig · default-login · disclosure", icon: <Bug className="h-3 w-3" /> },
  { id: "headers", phase: "passive", name: "Header Analysis", detail: "Missing CSP · HSTS · X-Frame-Options", icon: <ShieldCheck className="h-3 w-3" /> },
  { id: "waf-probe", phase: "passive", name: "WAF + Rate-limit Probe", detail: "Detect WAF type + safe RPS per host", icon: <Lock className="h-3 w-3" /> },
  // Active
  { id: "nuclei-active", phase: "active", name: "Nuclei Active", detail: "CVE · sqli · xss · lfi · rce · ssti · ssrf · injection", icon: <Bug className="h-3 w-3" /> },
  { id: "ffuf", phase: "active", name: "ffuf Directory Brute", detail: "Endpoint + parameter discovery", icon: <Crosshair className="h-3 w-3" /> },
  { id: "dalfox", phase: "active", name: "Dalfox XSS", detail: "DOM + reflected + stored XSS", icon: <FlaskConical className="h-3 w-3" /> },
  { id: "crlf", phase: "active", name: "CRLFuzz", detail: "CRLF injection + header injection", icon: <FlaskConical className="h-3 w-3" /> },
  { id: "cors", phase: "active", name: "CORS Probe", detail: "Origin reflection + wildcard detection", icon: <Unlock className="h-3 w-3" /> },
  { id: "csrf", phase: "active", name: "CSRF Probe", detail: "Token absence + SameSite validation", icon: <Unlock className="h-3 w-3" /> },
  { id: "ssrf", phase: "active", name: "SSRF Probe", detail: "Blind + semi-blind SSRF via Collaborator", icon: <Siren className="h-3 w-3" /> },
  { id: "lfi", phase: "active", name: "LFI Scanner", detail: "Path traversal · /etc/passwd · log poisoning", icon: <FlaskConical className="h-3 w-3" /> },
  { id: "sqli", phase: "active", name: "SQLi Prover", detail: "Error-based · boolean · time-based blind", icon: <Bug className="h-3 w-3" /> },
  { id: "waf-bypass", phase: "active", name: "WAF Bypass Variants", detail: "URL-encode · double-encode · hex-encode per payload", icon: <Unlock className="h-3 w-3" /> },
  // LLM
  { id: "burp-history", phase: "llm", name: "Burp Proxy Analysis", detail: "LLM reads proxy history → injection candidates", icon: <BrainCircuit className="h-3 w-3" /> },
  { id: "llm-react", phase: "llm", name: "LLM ReAct Loop", detail: "Craft → Send → Analyze per candidate (LocatedMemory)", icon: <BrainCircuit className="h-3 w-3" /> },
  { id: "collaborator", phase: "llm", name: "Collaborator OOB", detail: "Burp Pro blind SSRF/XXE/XSS detection", icon: <Siren className="h-3 w-3" /> },
  { id: "kb-rag", phase: "llm", name: "HackerOne RAG", detail: "50k+ H1 reports → target-relevant technique hints", icon: <BrainCircuit className="h-3 w-3" /> },
  // Chain
  { id: "triage", phase: "chain", name: "AI Triage", detail: "LLM scores every finding + CVSS estimation", icon: <Bot className="h-3 w-3" /> },
  { id: "do-not-stop", phase: "chain", name: "DO-NOT-STOP Chaining", detail: "Re-enters vuln hunt for chain-required findings (3 rounds max)", icon: <Zap className="h-3 w-3" /> },
  { id: "report", phase: "chain", name: "Auto Report", detail: "Markdown + H1 bug report format per finding", icon: <CheckCircle2 className="h-3 w-3" /> },
];

const PHASE_META: Record<Technique["phase"], { label: string; color: string; bg: string }> = {
  recon:   { label: "Recon",       color: "text-blue-400",   bg: "bg-blue-900/30 border-blue-700/40" },
  passive: { label: "Passive",     color: "text-yellow-400", bg: "bg-yellow-900/30 border-yellow-700/40" },
  active:  { label: "Active",      color: "text-orange-400", bg: "bg-orange-900/30 border-orange-700/40" },
  llm:     { label: "LLM Active",  color: "text-purple-400", bg: "bg-purple-900/30 border-purple-700/40" },
  chain:   { label: "AI Chain",    color: "text-pentra-accent", bg: "bg-pentra-accent-glow border-pentra-accent/30" },
};

function TechniquesPanel() {
  const phases: Technique["phase"][] = ["recon", "passive", "active", "llm", "chain"];
  return (
    <div className="mt-4 rounded-ds-lg border border-orange-500/30 bg-orange-950/20 p-4 space-y-3">
      <div className="flex items-center gap-2 mb-1">
        <Bot className="h-4 w-4 text-orange-400" />
        <span className="text-[12px] font-bold text-orange-300 tracking-wide uppercase">All Techniques Active</span>
        <span className="ml-auto text-[10px] text-pentra-text-muted">{ALL_TECHNIQUES.length} modules</span>
      </div>
      {phases.map((phase) => {
        const meta = PHASE_META[phase];
        const items = ALL_TECHNIQUES.filter((t) => t.phase === phase);
        return (
          <div key={phase}>
            <p className={cn("text-[10px] font-bold uppercase tracking-widest mb-1.5", meta.color)}>
              {meta.label}
            </p>
            <div className="flex flex-wrap gap-1.5">
              {items.map((t) => (
                <div
                  key={t.id}
                  title={t.detail}
                  className={cn(
                    "flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium cursor-default",
                    meta.color, meta.bg
                  )}
                >
                  {t.icon}
                  {t.name}
                </div>
              ))}
            </div>
          </div>
        );
      })}
      <p className="text-[10px] text-pentra-text-muted pt-1 border-t border-pentra-border">
        Hover any badge for details · Collaborator OOB requires Burp Suite Pro
      </p>
    </div>
  );
}

// ── Full Bypass Banner ─────────────────────────────────────────────────────

interface FullBypassBannerProps {
  enabled: boolean;
  onToggle: () => void;
}

function FullBypassBanner({ enabled, onToggle }: FullBypassBannerProps) {
  return (
    <div
      className={cn(
        "relative overflow-hidden rounded-ds-lg border-2 p-4 transition-all duration-300 cursor-pointer select-none",
        enabled
          ? "border-orange-500 bg-gradient-to-br from-orange-950/60 via-red-950/40 to-orange-950/60"
          : "border-pentra-border bg-pentra-bg-card hover:border-orange-500/40"
      )}
      onClick={onToggle}
    >
      {/* Animated glow when enabled */}
      {enabled && (
        <div className="pointer-events-none absolute inset-0 rounded-ds-lg bg-gradient-to-br from-orange-500/10 via-transparent to-red-500/10 animate-pulse" />
      )}

      <div className="relative flex items-start gap-4">
        {/* Icon */}
        <div
          className={cn(
            "flex-shrink-0 flex h-12 w-12 items-center justify-center rounded-ds-md transition-colors",
            enabled ? "bg-orange-500 text-white shadow-lg shadow-orange-500/40" : "bg-pentra-bg-panel text-pentra-text-muted"
          )}
        >
          <Bot className="h-6 w-6" />
        </div>

        {/* Text */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <span className={cn("text-[14px] font-bold", enabled ? "text-orange-300" : "text-pentra-text-primary")}>
              Full Bypass Mode
            </span>
            {enabled && (
              <span className="rounded-full bg-orange-500 px-2 py-0.5 text-[9px] font-black text-white tracking-wider animate-pulse">
                ACTIVE
              </span>
            )}
          </div>
          <p className="text-[11px] text-pentra-text-muted leading-snug">
            {enabled
              ? "Zero human intervention — LLM drives every decision autonomously end-to-end. All 25 attack modules active."
              : "Activate to run all techniques fully automated — no approval gates, no pauses."}
          </p>

          {enabled && (
            <div className="flex flex-wrap gap-2 mt-2">
              {[
                { icon: <Bot className="h-3 w-3" />, label: "mode: agentic" },
                { icon: <Zap className="h-3 w-3" />, label: "auto-approve all" },
                { icon: <Layers className="h-3 w-3" />, label: "concurrent scan" },
                { icon: <Cpu className="h-3 w-3" />, label: "pentra-ft:latest" },
                { icon: <Activity className="h-3 w-3" />, label: "0ms jitter" },
              ].map(({ icon, label }) => (
                <span key={label} className="flex items-center gap-1 rounded-full bg-orange-900/50 border border-orange-700/50 px-2 py-0.5 text-[10px] text-orange-300">
                  {icon} {label}
                </span>
              ))}
            </div>
          )}
        </div>

        {/* Toggle */}
        <div className="flex-shrink-0 flex flex-col items-center gap-1">
          <div
            className={cn(
              "relative h-6 w-11 rounded-full transition-colors duration-200",
              enabled ? "bg-orange-500" : "bg-pentra-border"
            )}
          >
            <span
              className={cn(
                "absolute top-1 h-4 w-4 rounded-full bg-white shadow transition-transform duration-200",
                enabled ? "left-[calc(100%-18px)]" : "left-1"
              )}
            />
          </div>
          <span className={cn("text-[9px] font-bold", enabled ? "text-orange-400" : "text-pentra-text-muted")}>
            {enabled ? "ON" : "OFF"}
          </span>
        </div>
      </div>

      {/* Warning strip */}
      {enabled && (
        <div className="relative mt-3 flex items-center gap-2 rounded-ds-md bg-orange-900/30 border border-orange-700/40 px-3 py-2">
          <AlertTriangle className="h-3.5 w-3.5 flex-shrink-0 text-orange-400" />
          <p className="text-[10px] text-orange-300">
            Full Bypass bypasses all HITL gates. Ensure you have written authorization before launching.
          </p>
        </div>
      )}
    </div>
  );
}

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

function Step1({
  data,
  onChange,
  fullBypass,
}: {
  data: TargetData;
  onChange: (d: TargetData) => void;
  fullBypass: boolean;
}) {
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
            onChange({ ...data, domain, engagementName: data.engagementName || autoName });
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
            Additional In-Scope Assets
            <span className="ml-1.5 text-[10px] font-normal text-pentra-text-muted">(optional, one per line)</span>
          </label>
          <textarea
            rows={4}
            placeholder={"*.example.com\napi.example.com\n10.0.0.0/24"}
            value={data.inScope}
            onChange={(e) => onChange({ ...data, inScope: e.target.value })}
            className="w-full resize-none rounded-ds-md border border-pentra-border bg-pentra-bg-input px-3 py-2 text-[13px] font-mono text-pentra-text-primary placeholder:text-pentra-text-muted outline-none focus:border-pentra-border-focus"
          />
          <p className="mt-1 text-[10px] text-pentra-text-muted">
            Wildcards (*.x.com), subdomains, IP CIDRs. Target domain is always included.
          </p>
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

      {/* Approval Policy — locked when fullBypass */}
      <div>
        <label className="flex items-center gap-2 text-[12px] font-semibold text-pentra-text-secondary mb-2">
          Approval Policy
          {fullBypass && (
            <span className="rounded-full bg-orange-900/50 border border-orange-700/40 px-2 py-0.5 text-[9px] text-orange-400 font-bold">
              LOCKED — Full Bypass
            </span>
          )}
        </label>
        <div className={cn("grid grid-cols-2 gap-3", fullBypass && "opacity-50 pointer-events-none")}>
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

      {/* Subdomain Scan Mode — locked when fullBypass */}
      <div>
        <label className="flex items-center gap-2 text-[12px] font-semibold text-pentra-text-secondary mb-2">
          Subdomain Scan Mode
          {fullBypass && (
            <span className="rounded-full bg-orange-900/50 border border-orange-700/40 px-2 py-0.5 text-[9px] text-orange-400 font-bold">
              LOCKED — Concurrent
            </span>
          )}
        </label>
        <div className={cn("grid grid-cols-2 gap-3", fullBypass && "opacity-50 pointer-events-none")}>
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

function Step2({
  selected,
  onSelect,
  fullBypass,
  onToggleFullBypass,
}: {
  selected: string;
  onSelect: (id: string) => void;
  fullBypass: boolean;
  onToggleFullBypass: () => void;
}) {
  return (
    <div className="space-y-4">
      {/* Full Bypass Banner — top of preset step */}
      <FullBypassBanner enabled={fullBypass} onToggle={onToggleFullBypass} />

      {/* Preset Grid — dimmed when fullBypass */}
      <div>
        <label className="flex items-center gap-2 text-[12px] font-semibold text-pentra-text-secondary mb-2">
          Scan Preset
          {fullBypass && (
            <span className="rounded-full bg-orange-900/50 border border-orange-700/40 px-2 py-0.5 text-[9px] text-orange-400 font-bold">
              OVERRIDDEN — pentra-ft:latest
            </span>
          )}
        </label>
        <div className={cn("grid grid-cols-2 gap-3", fullBypass && "opacity-40 pointer-events-none")}>
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
              <div className={cn(
                "flex h-9 w-9 items-center justify-center rounded-ds-md",
                selected === preset.id ? "bg-pentra-accent text-white" : "bg-pentra-bg-panel text-pentra-text-muted"
              )}>
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
      </div>

      {/* Technique Panel — shown only when fullBypass */}
      {fullBypass && <TechniquesPanel />}
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
          <span className={cn(
            "absolute top-0.5 h-4 w-4 rounded-full bg-white shadow transition-transform",
            data.enabled ? "left-[calc(100%-18px)]" : "left-0.5"
          )} />
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

function ReviewRow({ label, value, highlight }: { label: string; value: string; highlight?: boolean }) {
  return (
    <div className="flex items-start gap-4 border-b border-pentra-border py-2.5 last:border-0">
      <span className="w-32 flex-shrink-0 text-[12px] font-semibold text-pentra-text-muted">{label}</span>
      <span className={cn("text-[13px] break-all", highlight ? "text-orange-300 font-semibold" : "text-pentra-text-primary")}>
        {value}
      </span>
    </div>
  );
}

// ── Main Wizard ──────────────────────────────────────────────────────────────

export default function ScanWizard() {
  const navigate = useNavigate();
  const create = useCreateEngagement();
  const { data: workspaces } = useWorkspaces();

  const [step, setStep] = useState(0);
  const [fullBypass, setFullBypass] = useState(false);
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

  // Effective values — fullBypass overrides all scan settings
  const effectiveMode = fullBypass ? "agentic" : (target.autoApproveExploitValidation ? "agentic" : "semi_auto");
  const effectiveAutoApprove = fullBypass ? true : target.autoApproveExploitValidation;
  const effectiveSequential = fullBypass ? false : target.scanSequential;
  const effectiveModel = fullBypass ? (PRESETS.find((p) => p.id === "pentra-ft")?.model ?? PRESETS[2].model) : selectedPreset.model;
  const effectiveJitter = fullBypass ? 0 : (selectedPreset.opsec ? 2000 : 0);
  const effectiveOpsec = fullBypass ? false : (selectedPreset.opsec ?? false);

  const canNext = () => {
    if (step === 0) return target.domain.trim().length > 0;
    return true;
  };

  const handleToggleFullBypass = () => {
    setFullBypass((v) => !v);
  };

  const handleLaunch = async () => {
    const workspaceId = workspaces?.[0]?.id;
    if (!workspaceId) {
      toastError("No workspace", "Please create a workspace first");
      return;
    }

    const inScopeRaw = target.inScope
      ? target.inScope.split("\n").map((s) => s.trim()).filter(Boolean)
      : [];
    // Always include the bare domain as the first in_scope entry so the backend
    // can reliably derive the primary domain for subfinder/crt.sh/OSINT.
    const inScope = inScopeRaw.includes(target.domain) || !target.domain
      ? (inScopeRaw.length > 0 ? inScopeRaw : [target.domain])
      : [target.domain, ...inScopeRaw];
    const outScope = target.outScope
      ? target.outScope.split("\n").map((s) => s.trim()).filter(Boolean)
      : [];

    try {
      const eng = await create.mutateAsync({
        workspace_id: workspaceId,
        name: target.engagementName || `${target.domain} scan${fullBypass ? " [FULL BYPASS]" : ""}`,
        mode: effectiveMode,
        in_scope: inScope,
        out_of_scope: outScope,
        llm_model: effectiveModel,
        scan_preset: fullBypass ? "pentra-ft" : preset,
        opsec_mode: effectiveOpsec,
        request_jitter_ms: effectiveJitter,
        scan_sequential: effectiveSequential,
        auto_approve_exploit_validation: effectiveAutoApprove,
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
        <div className="mb-6 flex items-start justify-between">
          <div>
            <h1 className="text-[22px] font-bold text-pentra-text-primary">New Scan</h1>
            <p className="text-[13px] text-pentra-text-secondary mt-1">Configure and launch a security engagement</p>
          </div>
          {fullBypass && (
            <div className="flex items-center gap-2 rounded-ds-md bg-orange-900/40 border border-orange-500/40 px-3 py-1.5">
              <div className="h-2 w-2 rounded-full bg-orange-500 animate-pulse" />
              <span className="text-[11px] font-bold text-orange-300">FULL BYPASS MODE</span>
            </div>
          )}
        </div>

        <StepIndicator current={step} />

        <div className={cn(
          "rounded-ds-lg border bg-pentra-bg-panel p-6 transition-colors",
          fullBypass ? "border-orange-500/40" : "border-pentra-border"
        )}>
          {step === 0 && <Step1 data={target} onChange={setTarget} fullBypass={fullBypass} />}
          {step === 1 && (
            <Step2
              selected={preset}
              onSelect={setPreset}
              fullBypass={fullBypass}
              onToggleFullBypass={handleToggleFullBypass}
            />
          )}
          {step === 2 && <Step3 data={auth} onChange={setAuth} />}
          {step === 3 && (
            <div>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-[14px] font-semibold text-pentra-text-primary">Review Configuration</h3>
                {fullBypass && (
                  <span className="flex items-center gap-1.5 rounded-full bg-orange-900/50 border border-orange-500/40 px-3 py-1 text-[10px] font-bold text-orange-300">
                    <Bot className="h-3 w-3" />
                    FULL BYPASS ACTIVE
                  </span>
                )}
              </div>
              <div className="rounded-ds-md border border-pentra-border bg-pentra-bg-card px-4">
                <ReviewRow label="Target" value={target.domain || "—"} />
                <ReviewRow label="Name" value={target.engagementName || `${target.domain} scan`} />
                <ReviewRow
                  label="In-Scope"
                  value={(() => {
                    const extra = target.inScope ? target.inScope.split("\n").map(s => s.trim()).filter(Boolean) : [];
                    const all = extra.includes(target.domain) ? extra : [target.domain, ...extra].filter(Boolean);
                    return all.join(", ") || target.domain;
                  })()}
                />
                {target.outScope && (
                  <ReviewRow label="Out-of-Scope" value={target.outScope.split("\n").filter(Boolean).join(", ")} />
                )}
                <ReviewRow
                  label="Preset"
                  value={fullBypass ? "Full Bypass (all modules)" : `${selectedPreset.name} (${selectedPreset.eta})`}
                  highlight={fullBypass}
                />
                <ReviewRow label="Model" value={effectiveModel} highlight={fullBypass} />
                <ReviewRow label="Mode" value={effectiveMode === "agentic" ? "Agentic (zero HITL)" : "Semi-auto"} highlight={fullBypass && effectiveMode === "agentic"} />
                <ReviewRow
                  label="Auto-Approve"
                  value={effectiveAutoApprove ? "All gates bypassed — LLM decides" : "Manual exploit approval"}
                  highlight={fullBypass}
                />
                <ReviewRow
                  label="Scan Mode"
                  value={effectiveSequential ? "Sequential (per-subdomain)" : "Concurrent (all parallel)"}
                />
                <ReviewRow label="Jitter" value={effectiveJitter === 0 ? "None (0ms)" : `Up to ${effectiveJitter}ms`} />
                <ReviewRow label="Auth" value={auth.enabled ? auth.authType : "None (unauthenticated)"} />
                {fullBypass && (
                  <ReviewRow
                    label="Techniques"
                    value={`${ALL_TECHNIQUES.length} modules · ${ALL_TECHNIQUES.filter(t => t.phase === "active").length} active attack tools · LLM ReAct loop`}
                    highlight
                  />
                )}
              </div>

              {/* Warning box on review if fullBypass */}
              {fullBypass && (
                <div className="mt-4 flex items-start gap-3 rounded-ds-md bg-orange-950/40 border border-orange-500/30 p-3">
                  <AlertTriangle className="h-4 w-4 flex-shrink-0 text-orange-400 mt-0.5" />
                  <div>
                    <p className="text-[12px] font-semibold text-orange-300">Full Bypass Mode — No human gates</p>
                    <p className="text-[11px] text-orange-400/80 mt-0.5">
                      This engagement will run autonomously from start to finish. The LLM will plan, recon, hunt, exploit, and report without pausing for approval. Ensure you have written authorization.
                    </p>
                  </div>
                </div>
              )}

              {/* Technique summary on review */}
              {fullBypass && <TechniquesPanel />}
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
              className={cn(
                "flex items-center gap-1.5 rounded-ds-md px-4 py-2 text-[13px] font-medium text-white transition-opacity hover:opacity-80 disabled:opacity-40",
                fullBypass ? "bg-orange-500" : "bg-pentra-accent"
              )}
            >
              Next
              <ChevronRight className="h-4 w-4" />
            </button>
          ) : (
            <button
              type="button"
              onClick={handleLaunch}
              disabled={create.isPending}
              className={cn(
                "flex items-center gap-2 rounded-ds-md px-5 py-2 text-[13px] font-medium text-white transition-opacity hover:opacity-80 disabled:opacity-50",
                fullBypass ? "bg-orange-500 shadow-lg shadow-orange-500/30" : "bg-pentra-accent"
              )}
            >
              {create.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : fullBypass ? (
                <Bot className="h-4 w-4" />
              ) : (
                <CheckCircle2 className="h-4 w-4" />
              )}
              {fullBypass ? "Launch Full Bypass" : "Launch Scan"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
