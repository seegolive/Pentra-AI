import { useState } from "react";
import {
  User,
  Lock,
  CheckCircle2,
  AlertCircle,
  Loader2,
  Info,
  Cpu,
  Calendar,
  Tag,
} from "lucide-react";
import { useAuthStore } from "../lib/authStore";
import { useChangePassword, useVersionInfo } from "../lib/api";
import { APP_VERSION, BUILD_DATE } from "../lib/version";
import { cn } from "../lib/utils";

// ── Section wrapper ────────────────────────────────────────────────────────────

function Section({
  title,
  icon,
  children,
}: {
  title: string;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="bg-card border border-border rounded-xl overflow-hidden">
      <div className="flex items-center gap-2.5 px-6 py-4 border-b border-border bg-background/40">
        <span className="text-muted-foreground">{icon}</span>
        <h2 className="text-sm font-semibold text-foreground">{title}</h2>
      </div>
      <div className="px-6 py-5">{children}</div>
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-border/50 last:border-0">
      <span className="text-sm text-muted-foreground">{label}</span>
      <span className="text-sm font-mono text-foreground">{value}</span>
    </div>
  );
}

// ── Change Password form ───────────────────────────────────────────────────────

function ChangePasswordForm() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [success, setSuccess] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  const { mutate, isPending, error } = useChangePassword();

  const apiError =
    error instanceof Error ? error.message : error ? String(error) : null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError(null);
    setSuccess(false);

    if (next.length < 8) {
      setLocalError("New password must be at least 8 characters.");
      return;
    }
    if (next !== confirm) {
      setLocalError("New passwords do not match.");
      return;
    }

    mutate(
      { current_password: current, new_password: next },
      {
        onSuccess: () => {
          setSuccess(true);
          setCurrent("");
          setNext("");
          setConfirm("");
        },
      }
    );
  };

  const displayError = localError ?? apiError;

  return (
    <form onSubmit={handleSubmit} className="space-y-4 max-w-sm">
      <div>
        <label htmlFor="cp-current" className="block text-xs font-medium text-muted-foreground mb-1.5">
          Current Password
        </label>
        <input
          id="cp-current"
          type="password"
          value={current}
          onChange={(e) => setCurrent(e.target.value)}
          required
          autoComplete="current-password"
          className="w-full px-3 py-2 text-sm bg-background border border-border rounded-md focus:outline-none focus:ring-1 focus:ring-primary"
        />
      </div>

      <div>
        <label htmlFor="cp-new" className="block text-xs font-medium text-muted-foreground mb-1.5">
          New Password
        </label>
        <input
          id="cp-new"
          type="password"
          value={next}
          onChange={(e) => setNext(e.target.value)}
          required
          autoComplete="new-password"
          className="w-full px-3 py-2 text-sm bg-background border border-border rounded-md focus:outline-none focus:ring-1 focus:ring-primary"
        />
      </div>

      <div>
        <label htmlFor="cp-confirm" className="block text-xs font-medium text-muted-foreground mb-1.5">
          Confirm New Password
        </label>
        <input
          id="cp-confirm"
          type="password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          required
          autoComplete="new-password"
          className={cn(
            "w-full px-3 py-2 text-sm bg-background border rounded-md focus:outline-none focus:ring-1 focus:ring-primary",
            confirm && next && confirm !== next
              ? "border-red-500/60"
              : "border-border"
          )}
        />
      </div>

      {displayError && (
        <div className="flex items-center gap-2 text-xs text-red-400">
          <AlertCircle className="h-3.5 w-3.5 flex-shrink-0" />
          {displayError}
        </div>
      )}

      {success && (
        <div className="flex items-center gap-2 text-xs text-green-400">
          <CheckCircle2 className="h-3.5 w-3.5 flex-shrink-0" />
          Password changed successfully.
        </div>
      )}

      <button
        type="submit"
        disabled={isPending}
        className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground text-sm font-medium rounded-md hover:opacity-90 disabled:opacity-50 transition-opacity"
      >
        {isPending ? (
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
        ) : (
          <Lock className="h-3.5 w-3.5" />
        )}
        Update Password
      </button>
    </form>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────────

export default function SettingsPage() {
  const user = useAuthStore((s) => s.user);
  const { data: versionInfo } = useVersionInfo();

  return (
    <div className="flex-1 overflow-auto p-6">
      <div className="max-w-2xl mx-auto space-y-6">
        {/* Page header */}
        <div>
          <h1 className="text-xl font-bold text-foreground">Settings</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Profile, security, and system information.
          </p>
        </div>

        {/* Profile */}
        <Section title="Profile" icon={<User className="h-4 w-4" />}>
          <div className="space-y-0">
            <InfoRow label="Username" value={user?.username ?? "—"} />
            <InfoRow label="Email" value={user?.email ?? "—"} />
            <InfoRow
              label="Role"
              value={user?.is_admin ? "Administrator" : "Operator"}
            />
          </div>
        </Section>

        {/* Change password */}
        <Section
          title="Change Password"
          icon={<Lock className="h-4 w-4" />}
        >
          <ChangePasswordForm />
        </Section>

        {/* System info */}
        <Section
          title="System Information"
          icon={<Info className="h-4 w-4" />}
        >
          <div className="space-y-0">
            <InfoRow
              label="API Version"
              value={versionInfo?.version ?? APP_VERSION}
            />
            <InfoRow
              label="Frontend Version"
              value={APP_VERSION}
            />
            <InfoRow
              label="Build Date"
              value={versionInfo?.build_date ?? BUILD_DATE}
            />
            <InfoRow
              label="Phase"
              value={versionInfo?.phase ?? "Phase 2 — Agent Engine"}
            />
          </div>

          {/* Icon legend */}
          <div className="mt-4 flex flex-wrap gap-4 text-xs text-muted-foreground">
            <span className="flex items-center gap-1.5">
              <Cpu className="h-3.5 w-3.5" /> Ollama (local LLM)
            </span>
            <span className="flex items-center gap-1.5">
              <Calendar className="h-3.5 w-3.5" /> Release date
            </span>
            <span className="flex items-center gap-1.5">
              <Tag className="h-3.5 w-3.5" /> Semantic versioning
            </span>
          </div>
        </Section>
      </div>
    </div>
  );
}
