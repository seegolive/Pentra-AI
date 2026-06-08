import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import {
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Loader2,
  Eye,
  EyeOff,
  ChevronRight,
  ChevronLeft,
  Wifi,
  WifiOff,
} from "lucide-react";
import { cn } from "../lib/utils";

const BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

// ── Types ──────────────────────────────────────────────────────────────────

interface SetupStatus {
  is_configured: boolean;
  requires_setup: boolean;
  kb_record_count: number;
  ollama_reachable: boolean;
}

type Step = 1 | 2 | 3 | 4;

// ── Step components ────────────────────────────────────────────────────────

function StepIndicator({ current, total }: { current: Step; total: number }) {
  return (
    <div className="flex items-center gap-2 mb-8">
      {Array.from({ length: total }, (_, i) => i + 1).map((n) => (
        <div key={n} className="flex items-center gap-2">
          <div
            className={cn(
              "h-7 w-7 rounded-full flex items-center justify-center text-xs font-bold transition-colors",
              n < current
                ? "bg-primary text-primary-foreground"
                : n === current
                  ? "bg-primary/20 text-primary border border-primary"
                  : "bg-muted text-muted-foreground"
            )}
          >
            {n < current ? <CheckCircle2 className="h-4 w-4" /> : n}
          </div>
          {n < total && (
            <div
              className={cn(
                "h-px w-8 transition-colors",
                n < current ? "bg-primary" : "bg-border"
              )}
            />
          )}
        </div>
      ))}
    </div>
  );
}

// ── Step 1: Admin Account ─────────────────────────────────────────────────

function StepAdminAccount({
  onNext,
  data,
  setData,
}: {
  onNext: () => void;
  data: { username: string; email: string; password: string; confirmPassword: string };
  setData: React.Dispatch<React.SetStateAction<typeof data>>;
}) {
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState("");

  const validate = () => {
    if (data.username.length < 3) return "Username must be at least 3 characters";
    if (!data.email.includes("@")) return "Invalid email address";
    if (data.password.length < 8) return "Password must be at least 8 characters";
    if (data.password !== data.confirmPassword) return "Passwords do not match";
    return "";
  };

  const handleNext = () => {
    const err = validate();
    if (err) { setError(err); return; }
    setError("");
    onNext();
  };

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-bold text-foreground">Create Admin Account</h2>
        <p className="text-sm text-muted-foreground mt-1">
          This will be the primary administrator account for Pentra AI.
        </p>
      </div>

      <div className="space-y-3">
        {[
          { key: "username", label: "Username", type: "text", placeholder: "admin" },
          { key: "email", label: "Email", type: "email", placeholder: "admin@pentra.local" },
        ].map(({ key, label, type, placeholder }) => (
          <div key={key}>
            <label className="block text-xs font-medium text-muted-foreground mb-1">{label}</label>
            <input
              type={type}
              value={data[key as keyof typeof data]}
              onChange={(e) => setData((d) => ({ ...d, [key]: e.target.value }))}
              placeholder={placeholder}
              className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>
        ))}

        {["password", "confirmPassword"].map((key) => (
          <div key={key}>
            <label className="block text-xs font-medium text-muted-foreground mb-1">
              {key === "password" ? "Password" : "Confirm Password"}
            </label>
            <div className="relative">
              <input
                type={showPw ? "text" : "password"}
                value={data[key as keyof typeof data]}
                onChange={(e) => setData((d) => ({ ...d, [key]: e.target.value }))}
                placeholder="••••••••••••"
                className="w-full bg-background border border-border rounded-md px-3 py-2 pr-9 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
              />
              <button
                type="button"
                onClick={() => setShowPw(!showPw)}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
              >
                {showPw ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </div>
        ))}
      </div>

      {error && (
        <p className="text-xs text-red-400 flex items-center gap-1.5">
          <XCircle className="h-3.5 w-3.5" />
          {error}
        </p>
      )}

      <button
        onClick={handleNext}
        className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 transition-colors"
      >
        Continue
        <ChevronRight className="h-4 w-4" />
      </button>
    </div>
  );
}

// ── Step 2: Ollama / LLM Check ────────────────────────────────────────────

function StepOllama({
  onNext,
  onBack,
  status,
}: {
  onNext: () => void;
  onBack: () => void;
  status: SetupStatus | null;
}) {
  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-bold text-foreground">LLM Backend (Ollama)</h2>
        <p className="text-sm text-muted-foreground mt-1">
          Pentra AI uses Ollama for all local LLM inference. Ensure it is running on your host machine.
        </p>
      </div>

      <div
        className={cn(
          "flex items-center gap-3 p-4 rounded-lg border",
          status?.ollama_reachable
            ? "bg-green-500/5 border-green-500/20"
            : "bg-red-500/5 border-red-500/20"
        )}
      >
        {status?.ollama_reachable ? (
          <Wifi className="h-5 w-5 text-green-400 flex-shrink-0" />
        ) : (
          <WifiOff className="h-5 w-5 text-red-400 flex-shrink-0" />
        )}
        <div>
          <p
            className={cn(
              "text-sm font-medium",
              status?.ollama_reachable ? "text-green-400" : "text-red-400"
            )}
          >
            {status?.ollama_reachable ? "Ollama is reachable" : "Ollama not reachable"}
          </p>
          <p className="text-xs text-muted-foreground mt-0.5">
            {status?.ollama_reachable
              ? "LLM inference is ready"
              : "Make sure Ollama is running: ollama serve"}
          </p>
        </div>
      </div>

      <div className="bg-card border border-border rounded-lg p-4 space-y-2">
        <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
          Recommended models
        </p>
        {[
          { cmd: "ollama pull bge-m3", desc: "Embedding (required)" },
          { cmd: "ollama pull qwen2.5-coder:7b", desc: "Fast LLM" },
          { cmd: "ollama pull qwen2.5-coder:32b", desc: "Default LLM" },
        ].map(({ cmd, desc }) => (
          <div key={cmd} className="flex items-center justify-between">
            <code className="text-xs font-mono text-primary">{cmd}</code>
            <span className="text-[10px] text-muted-foreground">{desc}</span>
          </div>
        ))}
      </div>

      <div className="flex gap-2">
        <button
          onClick={onBack}
          className="flex items-center gap-1.5 px-4 py-2 border border-border rounded-md text-sm text-muted-foreground hover:text-foreground transition-colors"
        >
          <ChevronLeft className="h-4 w-4" />
          Back
        </button>
        <button
          onClick={onNext}
          className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 transition-colors"
        >
          Continue
          <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}

// ── Step 3: Seed KB ───────────────────────────────────────────────────────

function StepSeedKB({
  onNext,
  onBack,
  seedKB,
  setSeedKB,
  status,
}: {
  onNext: () => void;
  onBack: () => void;
  seedKB: boolean;
  setSeedKB: (v: boolean) => void;
  status: SetupStatus | null;
}) {
  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-bold text-foreground">Knowledge Base</h2>
        <p className="text-sm text-muted-foreground mt-1">
          The knowledge base powers RAG-assisted vulnerability hunting.
          Currently has {status?.kb_record_count ?? 0} records.
        </p>
      </div>

      <div className="space-y-2">
        {[
          {
            value: true,
            label: "Import HackerOne dataset now",
            sub: "Queue ~1,000 H1 public disclosures in background (recommended)",
          },
          {
            value: false,
            label: "Skip — I'll do this later",
            sub: "You can import from the /admin page at any time",
          },
        ].map((opt) => (
          <label
            key={String(opt.value)}
            className={cn(
              "flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors",
              seedKB === opt.value
                ? "bg-primary/5 border-primary/40"
                : "border-border hover:bg-accent/30"
            )}
          >
            <input
              type="radio"
              name="seed"
              checked={seedKB === opt.value}
              onChange={() => setSeedKB(opt.value)}
              className="mt-0.5 accent-primary"
            />
            <div>
              <p className="text-sm font-medium text-foreground">{opt.label}</p>
              <p className="text-xs text-muted-foreground mt-0.5">{opt.sub}</p>
            </div>
          </label>
        ))}
      </div>

      <div className="flex gap-2">
        <button
          onClick={onBack}
          className="flex items-center gap-1.5 px-4 py-2 border border-border rounded-md text-sm text-muted-foreground hover:text-foreground transition-colors"
        >
          <ChevronLeft className="h-4 w-4" />
          Back
        </button>
        <button
          onClick={onNext}
          className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 transition-colors"
        >
          Continue
          <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}

// ── Step 4: Confirm & Submit ──────────────────────────────────────────────

function StepConfirm({
  onBack,
  onSubmit,
  adminData,
  seedKB,
  isLoading,
  error,
}: {
  onBack: () => void;
  onSubmit: () => void;
  adminData: { username: string; email: string };
  seedKB: boolean;
  isLoading: boolean;
  error: string;
}) {
  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-bold text-foreground">Confirm Setup</h2>
        <p className="text-sm text-muted-foreground mt-1">Review your configuration before finalizing.</p>
      </div>

      <div className="bg-card border border-border rounded-lg divide-y divide-border">
        {[
          { label: "Admin username", value: adminData.username },
          { label: "Admin email", value: adminData.email },
          { label: "Seed knowledge base", value: seedKB ? "Yes — import H1 dataset" : "No — skip" },
        ].map(({ label, value }) => (
          <div key={label} className="flex items-center justify-between px-4 py-2.5">
            <span className="text-xs text-muted-foreground">{label}</span>
            <span className="text-xs font-medium text-foreground">{value}</span>
          </div>
        ))}
      </div>

      {error && (
        <p className="text-xs text-red-400 flex items-center gap-1.5">
          <XCircle className="h-3.5 w-3.5" />
          {error}
        </p>
      )}

      <div className="flex gap-2">
        <button
          onClick={onBack}
          disabled={isLoading}
          className="flex items-center gap-1.5 px-4 py-2 border border-border rounded-md text-sm text-muted-foreground hover:text-foreground transition-colors disabled:opacity-50"
        >
          <ChevronLeft className="h-4 w-4" />
          Back
        </button>
        <button
          onClick={onSubmit}
          disabled={isLoading}
          className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 transition-colors disabled:opacity-50"
        >
          {isLoading ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <CheckCircle2 className="h-4 w-4" />
          )}
          {isLoading ? "Setting up…" : "Complete Setup"}
        </button>
      </div>
    </div>
  );
}

// ── Main wizard ────────────────────────────────────────────────────────────

export default function SetupPage() {
  const navigate = useNavigate();
  const [step, setStep] = useState<Step>(1);
  const [status, setStatus] = useState<SetupStatus | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");

  const [adminData, setAdminData] = useState({
    username: "",
    email: "",
    password: "",
    confirmPassword: "",
  });
  const [seedKB, setSeedKB] = useState(true);

  // Fetch setup status on mount
  useEffect(() => {
    axios
      .get<SetupStatus>(`${BASE}/api/v1/setup/status`)
      .then((r) => {
        setStatus(r.data);
        // If already configured, redirect to login
        if (!r.data.requires_setup) {
          navigate("/login", { replace: true });
        }
      })
      .catch(() => {});
  }, [navigate]);

  const handleSubmit = async () => {
    setIsLoading(true);
    setError("");
    try {
      await axios.post(`${BASE}/api/v1/setup/initialize`, {
        admin: {
          username: adminData.username,
          email: adminData.email,
          password: adminData.password,
        },
        seed_knowledge: seedKB,
      });
      navigate("/login", { replace: true });
    } catch (err: unknown) {
      const detail =
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
        "Setup failed. Check that the API is running.";
      setError(detail);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="flex items-center gap-3 mb-8 justify-center">
          <ShieldCheck className="h-8 w-8 text-primary" />
          <span className="text-2xl font-bold text-foreground tracking-tight">Pentra AI</span>
        </div>

        <div className="bg-card border border-border rounded-xl p-6 shadow-lg">
          <StepIndicator current={step} total={4} />

          {step === 1 && (
            <StepAdminAccount
              onNext={() => setStep(2)}
              data={adminData}
              setData={setAdminData}
            />
          )}
          {step === 2 && (
            <StepOllama
              onNext={() => setStep(3)}
              onBack={() => setStep(1)}
              status={status}
            />
          )}
          {step === 3 && (
            <StepSeedKB
              onNext={() => setStep(4)}
              onBack={() => setStep(2)}
              seedKB={seedKB}
              setSeedKB={setSeedKB}
              status={status}
            />
          )}
          {step === 4 && (
            <StepConfirm
              onBack={() => setStep(3)}
              onSubmit={handleSubmit}
              adminData={adminData}
              seedKB={seedKB}
              isLoading={isLoading}
              error={error}
            />
          )}
        </div>

        <p className="text-center text-xs text-muted-foreground mt-4">
          Step {step} of 4 — Pentra AI First-Run Setup
        </p>
      </div>
    </div>
  );
}
